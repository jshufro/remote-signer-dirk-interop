package dirksigner

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	"github.com/herumi/bls-eth-go-binary/bls"
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
