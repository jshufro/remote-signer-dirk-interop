package dirksigner

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/jshufro/remote-signer-dirk-interop/internal/api"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/signer"
	tlsprovider "github.com/jshufro/remote-signer-dirk-interop/pkg/tls"
	"google.golang.org/grpc/credentials"

	e2wd "github.com/wealdtech/go-eth2-wallet-dirk"
	e2wt "github.com/wealdtech/go-eth2-wallet-types/v2"
)

type DirkSigner struct {
	wallet      e2wt.Wallet
	endpoints   []*e2wd.Endpoint
	walletName  string
	rootCA      *x509.CertPool
	tlsProvider *tlsprovider.TLSProvider
}

func init() {
	// Initialize the BLS library
	if err := bls.Init(bls.BLS12_381); err != nil {
		panic(err)
	}
}

// static assertion that DirkSigner implements the RemoteSigner interface
var _ signer.RemoteSigner = (*DirkSigner)(nil)

func NewDirkSigner(endpoints []*e2wd.Endpoint, wallet string, rootCA *x509.CertPool, tlsProvider *tlsprovider.TLSProvider) *DirkSigner {
	return &DirkSigner{
		endpoints:   endpoints,
		walletName:  wallet,
		rootCA:      rootCA,
		tlsProvider: tlsProvider,
	}
}

func (d *DirkSigner) Open(ctx context.Context) error {
	tlsConfig := &tls.Config{
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := d.tlsProvider.GetCertificate()
			if err != nil {
				return nil, err
			}
			return cert, nil
		},
	}
	if d.rootCA != nil {
		tlsConfig.RootCAs = d.rootCA
	}
	credentials := credentials.NewTLS(tlsConfig)
	var err error
	d.wallet, err = e2wd.Open(ctx,
		e2wd.WithName(d.walletName),
		e2wd.WithEndpoints(d.endpoints),
		e2wd.WithCredentials(credentials),
	)
	return err
}

func (d *DirkSigner) GetPublicKeys(ctx context.Context) ([][48]byte, error) {

	accounts := d.wallet.Accounts(ctx)
	out := make([][48]byte, 0)
	for account := range accounts {
		out = append(out, ([48]byte)(account.PublicKey().Marshal()))
	}

	return out, nil
}

func (d *DirkSigner) AggregationSlotSigning(ctx context.Context, obj *api.AggregationSlotSigning) ([96]byte, error) {
	return [96]byte{}, nil
}

func (d *DirkSigner) AggregateAndProofSigning(ctx context.Context, obj *api.AggregateAndProofSigning) ([96]byte, error) {
	return [96]byte{}, nil
}

func (d *DirkSigner) AggregateAndProofSigningV2(ctx context.Context, obj *api.AggregateAndProofSigningV2) ([96]byte, error) {
	return [96]byte{}, nil
}

func (d *DirkSigner) AttestationSigning(ctx context.Context, obj *api.AttestationSigning) ([96]byte, error) {
	return [96]byte{}, nil
}

func (d *DirkSigner) BlockSigning(ctx context.Context, obj *api.BlockSigning) ([96]byte, error) {
	return [96]byte{}, nil
}

func (d *DirkSigner) BeaconBlockSigning(ctx context.Context, obj *api.BeaconBlockSigning) ([96]byte, error) {
	return [96]byte{}, nil
}

func (d *DirkSigner) DepositSigning(ctx context.Context, obj *api.DepositSigning) ([96]byte, error) {
	return [96]byte{}, nil
}

func (d *DirkSigner) RandaoRevealSigning(ctx context.Context, obj *api.RandaoRevealSigning) ([96]byte, error) {
	return [96]byte{}, nil
}

func (d *DirkSigner) VoluntaryExitSigning(ctx context.Context, obj *api.VoluntaryExitSigning) ([96]byte, error) {
	return [96]byte{}, nil
}

func (d *DirkSigner) SyncCommitteeMessageSigning(ctx context.Context, obj *api.SyncCommitteeMessageSigning) ([96]byte, error) {
	return [96]byte{}, nil
}

func (d *DirkSigner) SyncCommitteeSelectionProofSigning(ctx context.Context, obj *api.SyncCommitteeSelectionProofSigning) ([96]byte, error) {
	return [96]byte{}, nil
}

func (d *DirkSigner) SyncCommitteeContributionAndProofSigning(ctx context.Context, obj *api.SyncCommitteeContributionAndProofSigning) ([96]byte, error) {
	return [96]byte{}, nil
}

func (d *DirkSigner) ValidatorRegistrationSigning(ctx context.Context, obj *api.ValidatorRegistrationSigning) ([96]byte, error) {
	return [96]byte{}, nil
}
