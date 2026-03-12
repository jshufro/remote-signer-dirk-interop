package signer

import (
	"context"

	"github.com/jshufro/remote-signer-dirk-interop/internal/api"
	"github.com/jshufro/remote-signer-dirk-interop/internal/errors"
)

type RemoteSigner interface {
	api.Signer
	PublicKeysProvider
}

type PublicKeysProvider interface {
	GetPublicKeys(ctx context.Context) ([][48]byte, errors.SignerError)
}
