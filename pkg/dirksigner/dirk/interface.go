package dirk

import (
	"context"

	e2wt "github.com/wealdtech/go-eth2-wallet-types/v2"
)

type DirkAccount interface {
	e2wt.AccountProtectingSigner
	e2wt.AccountPublicKeyProvider
}

type DirkSigner interface {
	GetAccounts(ctx context.Context) []DirkAccount
}
