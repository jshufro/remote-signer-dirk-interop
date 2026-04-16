package dirk

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"

	tlsprovider "github.com/jshufro/remote-signer-dirk-interop/pkg/tls"
	"github.com/rs/zerolog"
	e2t "github.com/wealdtech/go-eth2-types/v2"
	e2wd "github.com/wealdtech/go-eth2-wallet-dirk"
	e2wt "github.com/wealdtech/go-eth2-wallet-types/v2"
	"google.golang.org/grpc/credentials"
)

type Dirk struct {
	wallet e2wt.Wallet
}

// type assertion that Dirk implements the DirkSigner interface
var _ DirkSigner = (*Dirk)(nil)

type dirkAccount struct {
	account e2wt.Account
}

func (d *dirkAccount) PublicKey() e2t.PublicKey {
	if compositePublickKeyProvider, ok := d.account.(e2wt.AccountCompositePublicKeyProvider); ok {
		return compositePublickKeyProvider.CompositePublicKey()
	}
	return d.account.(e2wt.AccountPublicKeyProvider).PublicKey()
}

// type assertion that dirkAccount implements the DirkAccount interface
var _ DirkAccount = (*dirkAccount)(nil)

func (d *dirkAccount) SignBeaconAttestation(
	ctx context.Context,
	slot uint64,
	committeeIndex uint64,
	blockRoot []byte,
	sourceEpoch uint64,
	sourceRoot []byte,
	targetEpoch uint64,
	targetRoot []byte,
	domain []byte,
) (e2t.Signature, error) {
	signer := d.account.(e2wt.AccountProtectingSigner)
	return signer.SignBeaconAttestation(ctx, slot, committeeIndex, blockRoot, sourceEpoch, sourceRoot, targetEpoch, targetRoot, domain)
}

func (d *dirkAccount) SignBeaconProposal(
	ctx context.Context,
	slot uint64,
	proposerIndex uint64,
	parentRoot []byte,
	stateRoot []byte,
	bodyRoot []byte,
	domain []byte,
) (e2t.Signature, error) {
	signer := d.account.(e2wt.AccountProtectingSigner)
	return signer.SignBeaconProposal(ctx, slot, proposerIndex, parentRoot, stateRoot, bodyRoot, domain)
}

func (d *dirkAccount) SignGeneric(
	ctx context.Context,
	message []byte,
	domain []byte,
) (e2t.Signature, error) {
	signer := d.account.(e2wt.AccountProtectingSigner)
	return signer.SignGeneric(ctx, message, domain)
}

func slogLevelToZerologLevel(level slog.Level) zerolog.Level {
	switch level {
	case slog.LevelDebug:
		return zerolog.DebugLevel
	case slog.LevelInfo:
		return zerolog.InfoLevel
	case slog.LevelWarn:
		return zerolog.WarnLevel
	case slog.LevelError:
		return zerolog.ErrorLevel
	}
	return zerolog.TraceLevel
}
func NewDirk(
	ctx context.Context,
	walletName string,
	endpoints []*e2wd.Endpoint,
	tlsProvider tlsprovider.TLSProvider,
	rootCA *x509.CertPool,
	logLevel slog.Level,
	extraE2WDParameters ...e2wd.Parameter,
) (*Dirk, error) {
	var err error
	tlsConfig := &tls.Config{
		GetClientCertificate: tlsProvider.GetClientCertificate,
		RootCAs:              rootCA,
	}
	credentials := credentials.NewTLS(tlsConfig)
	zerologLevel := slogLevelToZerologLevel(logLevel)

	parameters := append(extraE2WDParameters,
		e2wd.WithName(walletName),
		e2wd.WithEndpoints(endpoints),
		e2wd.WithCredentials(credentials),
		e2wd.WithLogLevel(zerologLevel),
	)
	wallet, err := e2wd.Open(ctx, parameters...)
	if err != nil {
		return nil, fmt.Errorf("failed to open wallet: %w", err)
	}
	return &Dirk{wallet: wallet}, nil
}

func (d *Dirk) GetAccounts(ctx context.Context) []DirkAccount {
	out := make([]DirkAccount, 0)
	for account := range d.wallet.Accounts(ctx) {
		out = append(out, &dirkAccount{account: account})
	}
	return out
}
