package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jshufro/remote-signer-dirk-interop/internal/api"
	"github.com/jshufro/remote-signer-dirk-interop/internal/errors"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/signer"
)

type Service[AccountType any] struct {
	signer  signer.RemoteSigner[AccountType]
	timeout time.Duration
	log     *slog.Logger
}

func NewService[AccountType any](
	signer signer.RemoteSigner[AccountType],
) (*Service[AccountType], error) {
	out := &Service[AccountType]{
		signer: signer,
		log:    slog.Default(),
	}

	return out, nil
}

func (s *Service[AccountType]) SetLogger(log *slog.Logger) {
	s.log = log
}

func (s *Service[AccountType]) SetTimeout(timeout time.Duration) {
	s.timeout = timeout
}

func (s *Service[AccountType]) PUBLICKEYLIST(w http.ResponseWriter, r *http.Request) {
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
		s.writeErrorJSON(w, err)
		return
	}

	resp := make([]string, len(keys))
	for i, key := range keys {
		resp[i] = "0x" + hex.EncodeToString(key[:])
	}
	s.writeJSON(w, http.StatusOK, resp)
}

type GenericBody struct {
	Type string `json:"type"`
}

func (s *Service[AccountType]) SIGN(w http.ResponseWriter, r *http.Request, identifier string) {
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
		s.writeErrorJSON(w, errors.BadRequest("invalid identifier; expected 0x-prefixed 48-byte compressed BLS public key: %w", err))
		return
	}
	pubkey := [48]byte(pubkeySlice)
	account, err := s.signer.GetAccountForPubkey(ctx, pubkey)
	if err != nil {
		s.log.Error("failed to get account for pubkey", "error", err, "pubkey", identifier)
		s.writeErrorJSON(w, err)
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
		s.writeErrorJSON(w, errors.BadRequest("failed to decode request body: %w", err))
		return
	}

	// Get a full signable struct from the type
	signable, err := api.StringToSignableType(genericBody.Type)
	if err != nil {
		s.log.Error("failed to get signable type", "error", err)
		s.writeErrorJSON(w, errors.BadRequest("unknown signing type: %w", err))
		return
	}

	s.log.Debug("signable body", "body", bodyCopy.String())

	// Unmarshal the request body into the signable struct
	err = json.NewDecoder(bodyCopy).Decode(signable)
	if err != nil {
		s.log.Error("failed to unmarshal request body", "error", err)
		s.writeErrorJSON(w, errors.BadRequest("failed to unmarshal request body: %w", err))
		return
	}

	// Sign the object
	signature, signerErr := api.Sign(ctx, s.signer, account, signable)
	if signerErr != nil {
		s.log.Error("failed to sign object", "error", signerErr.Error())
		s.writeErrorJSON(w, signerErr)
		return
	}

	// Create a response
	response := api.SigningResponse{
		Signature: "0x" + hex.EncodeToString(signature[:]),
	}

	s.writeJSON(w, http.StatusOK, response)
}

// writeJSON serializes v as JSON and writes it with the given status code.
func (s *Service[AccountType]) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.Warn("failed to write JSON response", "error", err)
	}
}

// writeErrorJSON writes a structured JSON error response.
func (s *Service[AccountType]) writeErrorJSON(w http.ResponseWriter, err error) {
	if signerErr, ok := err.(errors.SignerError); ok {
		s.writeJSON(w, signerErr.HttpCode, map[string]any{
			"error": signerErr.Error(),
		})
		return
	}
	s.writeJSON(w, http.StatusInternalServerError, map[string]any{
		"error": err.Error(),
	})
}
