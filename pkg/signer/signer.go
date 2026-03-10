package signer

import (
	"context"
)

type RemoteSigner interface {
	//api.Signer
	PublicKeysProvider
}

type PublicKeysProvider interface {
	GetPublicKeys(ctx context.Context) ([][48]byte, error)
}
