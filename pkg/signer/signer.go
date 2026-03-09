package signer

import (
	"context"

	"github.com/jshufro/remote-signer-dirk-interop/internal/api"
)

type RemoteSigner interface {
	api.Signer
	PublicKeysProvider
}

type PublicKeysProvider interface {
	GetPublicKeys(ctx context.Context) ([48]byte, error)
}
