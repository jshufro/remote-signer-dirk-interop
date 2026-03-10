package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"time"

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

func (s *Service) SIGN(w http.ResponseWriter, r *http.Request, identifier string) {
	s.log.Info("SIGN request", "path", r.URL.Path)

	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte("[]"))
	if err != nil {
		s.log.Error("failed to write response", "error", err)
	}
}
