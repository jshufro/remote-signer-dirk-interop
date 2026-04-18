package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jshufro/remote-signer-dirk-interop/generated"
	"github.com/jshufro/remote-signer-dirk-interop/generated/api"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/errors"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/fork"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/signer"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type Service[AccountType any] struct {
	signer  signer.RemoteSigner[AccountType]
	timeout time.Duration
	log     *slog.Logger
}

const StatusCodeLabel = "status_code"
const SignableTypeLabel = "signable_type"

var (
	publicKeysRequestsCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "remote_signer_dirk_interop_public_keys_requests_total",
		Help: "Total number of public keys requests",
	})
	publicKeysResponseCounts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "remote_signer_dirk_interop_public_keys_response_counts",
		Help: "Total number of public keys response counts",
	}, []string{StatusCodeLabel})
	signRequestsCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "remote_signer_dirk_interop_sign_requests_total",
		Help: "Total number of sign requests",
	}, []string{SignableTypeLabel})
	signResponseCounts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "remote_signer_dirk_interop_sign_response_counts",
		Help: "Total number of sign response counts",
	}, []string{SignableTypeLabel, StatusCodeLabel})
	signDurationHistogramVec = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "remote_signer_dirk_interop_sign_duration_seconds",
		Help: "Duration of sign requests",
	}, []string{SignableTypeLabel})

	metricsRegisterOnce = sync.Once{}
)

func NewService[AccountType any](
	signer signer.RemoteSigner[AccountType],
) (*Service[AccountType], error) {
	out := &Service[AccountType]{
		signer: signer,
		log:    slog.Default(),
	}

	metricsRegisterOnce.Do(func() {
		prometheus.MustRegister(publicKeysRequestsCounter)
		prometheus.MustRegister(publicKeysResponseCounts)
		prometheus.MustRegister(signRequestsCounter)
		prometheus.MustRegister(signResponseCounts)
		prometheus.MustRegister(signDurationHistogramVec)
	})

	return out, nil
}

func (s *Service[AccountType]) SetLogger(log *slog.Logger) {
	s.log = log
}

func (s *Service[AccountType]) SetTimeout(timeout time.Duration) {
	s.timeout = timeout
}

func (s *Service[AccountType]) timeoutContext(r *http.Request) (context.Context, context.CancelFunc) {
	if s.timeout > 0 {
		return context.WithTimeout(r.Context(), s.timeout)
	}
	return r.Context(), func() {}
}

func (s *Service[AccountType]) PUBLICKEYLIST(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := s.timeoutContext(r)
	defer cancel()

	ctx, span := otel.Tracer("remote-signer-dirk-interop").Start(ctx, "PUBLICKEYLIST")
	defer span.End()

	s.log.Info("PUBLICKEYLIST request", "path", r.URL.Path)
	publicKeysRequestsCounter.Inc()
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}

	keys, err := s.signer.GetPublicKeys(ctx)
	if err != nil {
		s.log.Error("failed to get public keys", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		statusCode := s.writeErrorJSON(w, err)
		publicKeysResponseCounts.WithLabelValues(strconv.Itoa(statusCode)).Inc()
		return
	}

	resp := make([]string, len(keys))
	for i, key := range keys {
		resp[i] = "0x" + hex.EncodeToString(key[:])
	}
	s.writeJSON(w, http.StatusOK, resp)
	publicKeysResponseCounts.WithLabelValues("200").Inc()
	span.SetStatus(codes.Ok, "OK")
}

type GenericBody struct {
	Type     string         `json:"type"`
	ForkInfo *fork.ForkInfo `json:"fork_info,omitempty"`
}

func (s *Service[AccountType]) getSignature(ctx context.Context, account AccountType, signable any, typeName string, forkInfo *fork.ForkInfo) ([96]byte, error) {
	ctx, span := otel.Tracer("remote-signer-dirk-interop").Start(ctx, "getSignature",
		trace.WithAttributes(attribute.String("signable_type", typeName)))
	defer span.End()

	// Start the signing duration timer
	signingDurationTimer := prometheus.NewTimer(signDurationHistogramVec.WithLabelValues(typeName))
	defer signingDurationTimer.ObserveDuration()

	// Sign the object
	signature, signerErr := generated.Sign(ctx, s.signer, account, signable, forkInfo)
	if signerErr != nil {
		s.log.Error("failed to sign object", "error", signerErr.Error())
		return [96]byte{}, signerErr
	}
	return signature, nil
}

func (s *Service[AccountType]) writeSignatureResponse(w http.ResponseWriter, acceptHeader string, signature [96]byte) {

	signatureString := "0x" + hex.EncodeToString(signature[:])
	// If the request is for a text/plain response, write the signature directly
	if acceptHeader == "text/plain" {
		s.writeTextPlain(w, http.StatusOK, signatureString)
		return
	}

	// Create a response
	response := api.SigningResponse{
		Signature: signatureString,
	}
	s.writeJSON(w, http.StatusOK, response)
}

func (s *Service[AccountType]) SIGN(w http.ResponseWriter, r *http.Request, identifier string) {
	ctx, cancel := s.timeoutContext(r)
	defer cancel()

	ctx, span := otel.Tracer("remote-signer-dirk-interop").Start(ctx, "SIGN")
	defer span.End()

	s.log.Info("SIGN request", "path", r.URL.Path, "identifier", identifier)

	// Create a public key from the identifier
	identifier = strings.TrimPrefix(identifier, "0x")
	pubkeySlice, err := hex.DecodeString(identifier)
	if err != nil || len(pubkeySlice) != 48 {
		s.log.Error("failed to decode public key", "error", err)
		err = errors.BadRequest("invalid identifier; expected 0x-prefixed 48-byte compressed BLS public key: %w", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		statusCode := s.writeErrorJSON(w, err)
		signRequestsCounter.WithLabelValues("UNKNOWN").Inc()
		signResponseCounts.WithLabelValues("UNKNOWN", strconv.Itoa(statusCode)).Inc()
		return
	}
	pubkey := [48]byte(pubkeySlice)
	account, err := s.signer.GetAccountForPubkey(ctx, pubkey)
	if err != nil {
		s.log.Error("failed to get account for pubkey", "error", err, "pubkey", identifier)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		statusCode := s.writeErrorJSON(w, err)
		signRequestsCounter.WithLabelValues("UNKNOWN").Inc()
		signResponseCounts.WithLabelValues("UNKNOWN", strconv.Itoa(statusCode)).Inc()
		return
	}

	bodyCopy := bytes.NewBuffer(nil)
	// Create a tee reader from the request body to the copy
	teeReader := io.TeeReader(r.Body, bodyCopy)

	// Start by parsing the request body into GenericBody
	var genericBody GenericBody
	err = json.NewDecoder(teeReader).Decode(&genericBody)
	if err != nil {
		s.log.Error("failed to decode request body", "error", err)
		err = errors.BadRequest("failed to decode request body: %w", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		statusCode := s.writeErrorJSON(w, err)
		signRequestsCounter.WithLabelValues("UNKNOWN").Inc()
		signResponseCounts.WithLabelValues("UNKNOWN", strconv.Itoa(statusCode)).Inc()
		return
	}

	signRequestsCounter.WithLabelValues(genericBody.Type).Inc()

	// Get a full signable struct from the type
	signable, err := generated.StringToSignableType(genericBody.Type)
	if err != nil {
		s.log.Error("failed to get signable type", "error", err)
		err = errors.BadRequest("unknown signing type: %w", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		statusCode := s.writeErrorJSON(w, err)
		signResponseCounts.WithLabelValues(genericBody.Type, strconv.Itoa(statusCode)).Inc()
		return
	}

	s.log.Debug("signable body", "body", bodyCopy.String())

	// Unmarshal the request body into the signable struct
	err = json.NewDecoder(bodyCopy).Decode(signable)
	if err != nil {
		s.log.Error("failed to unmarshal request body", "error", err)
		err = errors.BadRequest("failed to unmarshal request body: %w", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		statusCode := s.writeErrorJSON(w, err)
		signResponseCounts.WithLabelValues(genericBody.Type, strconv.Itoa(statusCode)).Inc()
		return
	}

	signature, err := s.getSignature(ctx, account, signable, genericBody.Type, genericBody.ForkInfo)
	if err != nil {
		s.log.Error("failed to get signature", "error", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		statusCode := s.writeErrorJSON(w, err)
		signResponseCounts.WithLabelValues(genericBody.Type, strconv.Itoa(statusCode)).Inc()
		return
	}

	signResponseCounts.WithLabelValues(genericBody.Type, "200").Inc()
	span.SetStatus(codes.Ok, "OK")
	s.writeSignatureResponse(w, r.Header.Get("Accept"), signature)

}

func (s *Service[AccountType]) writeTextPlain(w http.ResponseWriter, status int, signature string) {

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	_, err := w.Write([]byte(signature))
	if err != nil {
		s.log.Error("failed to write signature", "error", err)
	}
}

// writeJSON serializes v as JSON and writes it with the given status code.
func (s *Service[AccountType]) writeJSON(w http.ResponseWriter, status int, v any) {

	if v == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		return
	}
	out := bytes.NewBuffer(nil)
	if err := json.NewEncoder(out).Encode(v); err != nil {
		s.log.Warn("failed to write JSON response", "error", err)
		s.writeErrorJSON(w, errors.InternalServerError())
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := io.Copy(w, out); err != nil {
		s.log.Warn("failed to write JSON response", "error", err)
	}
}

// writeErrorJSON writes a structured JSON error response.
// returns the HTTP status code
func (s *Service[AccountType]) writeErrorJSON(w http.ResponseWriter, err error) int {
	if signerErr, ok := err.(errors.SignerError); ok {
		s.writeJSON(w, signerErr.HttpCode, map[string]any{
			"error": signerErr.Error(),
		})
		return signerErr.HttpCode
	}
	s.writeJSON(w, http.StatusInternalServerError, map[string]any{
		"error": err.Error(),
	})
	return http.StatusInternalServerError
}
