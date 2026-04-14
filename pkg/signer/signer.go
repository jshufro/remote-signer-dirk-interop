package signer

import (
	"context"

	api "github.com/jshufro/remote-signer-dirk-interop/generated"
)

type RemoteSigner[AccountType any] interface {
	api.Signer[AccountType]
	PublicKeysProvider
	// GetAccountForPubkey returns the account for a given public key.
	// If the account is not found, it should return a PublicKeyNotFound error.
	GetAccountForPubkey(context.Context, [48]byte) (AccountType, error)
}

type PublicKeysProvider interface {
	GetPublicKeys(ctx context.Context) ([][48]byte, error)
}
