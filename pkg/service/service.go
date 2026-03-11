package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jshufro/remote-signer-dirk-interop/internal/api"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/signer"
)

type Service struct {
	signer  signer.RemoteSigner
	timeout time.Duration
	log     *slog.Logger
}

func NewService(
	signer signer.RemoteSigner,
	listener net.Listener,
) (*Service, error) {
	out := &Service{
		signer: signer,
		log:    slog.Default(),
	}

	return out, nil
}

func (s *Service) SetLogger(log *slog.Logger) {
	s.log = log
}

func (s *Service) SetTimeout(timeout time.Duration) {
	s.timeout = timeout
}

func (s *Service) PUBLICKEYLIST(w http.ResponseWriter, r *http.Request) {
	s.log.Info("PUBLICKEYLIST request", "path", r.URL.Path)
	ctx := r.Context()
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}

	keys, err := s.signer.GetPublicKeys(ctx)
	if err != nil {
		s.log.Error("failed to get public keys", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp := make([]string, len(keys))
	for i, key := range keys {
		resp[i] = "0x" + hex.EncodeToString(key[:])
	}
	respBody, err := json.Marshal(resp)
	if err != nil {
		s.log.Error("failed to marshal response", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(respBody)
	if err != nil {
		s.log.Error("failed to write response", "error", err)
		return
	}
}

type GenericBody struct {
	Type string `json:"type"`
}

func (s *Service) SIGN(w http.ResponseWriter, r *http.Request, identifier string) {
	s.log.Info("SIGN request", "path", r.URL.Path, "identifier", identifier)
	ctx := r.Context()
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}

	// Create a public key from the identifier
	identifier = strings.TrimPrefix(identifier, "0x")
	pubkeySlice, err := hex.DecodeString(identifier)
	if err != nil || len(pubkeySlice) != 48 {
		s.log.Error("failed to decode public key", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	pubkey := [48]byte(pubkeySlice)

	bodyCopy := bytes.NewBuffer(nil)
	// Create a tee reader from the request body to the copy
	teeReader := io.TeeReader(r.Body, bodyCopy)

	// Start by parsing the request body into GenericBody
	var genericBody GenericBody
	err = json.NewDecoder(teeReader).Decode(&genericBody)
	if err != nil {
		s.log.Error("failed to decode request body", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get a full signable struct from the type
	signable, err := api.StringToSignableType(genericBody.Type)
	if err != nil {
		s.log.Error("failed to get signable type", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.log.Debug("signable body", "body", bodyCopy.String())

	// Unmarshal the request body into the signable struct
	err = json.NewDecoder(bodyCopy).Decode(signable)
	if err != nil {
		s.log.Error("failed to unmarshal request body", "error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Sign the object
	signature, signerErr := api.Sign(ctx, s.signer, pubkey, signable)
	if signerErr != nil {
		s.log.Error("failed to sign object", "error", signerErr.Error())
		w.WriteHeader(signerErr.HttpCode)
		return
	}

	// Create a response
	response := api.SigningResponse{
		Signature: "0x" + hex.EncodeToString(signature[:]),
	}

	// Serialize the response to the writer
	respBody, err := json.Marshal(response)
	if err != nil {
		s.log.Error("failed to marshal response", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(respBody)
	if err != nil {
		s.log.Error("failed to write response", "error", err)
	}
}
