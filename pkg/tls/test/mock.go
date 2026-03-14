package test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/attestantio/dirk/testing/resources"
	tlsprovider "github.com/jshufro/remote-signer-dirk-interop/pkg/tls"
)

type Client string

const (
	ClientTest01 Client = "client-test01"
	ClientTest02 Client = "client-test02"
	ClientTest03 Client = "client-test03"
)

func CA() []byte {
	return resources.CACrt
}

func CAPool() *x509.CertPool {
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(CA())
	return caPool
}

func ClientCertPair(client Client) ([]byte, []byte, error) {
	switch client {
	case ClientTest01:
		return resources.ClientTest01Crt, resources.ClientTest01Key, nil
	case ClientTest02:
		return resources.ClientTest02Crt, resources.ClientTest02Key, nil
	case ClientTest03:
		return resources.ClientTest03Crt, resources.ClientTest03Key, nil
	}
	return nil, nil, fmt.Errorf("unknown client: %s", client)
}

type mockTLSProvider struct {
	cert *tls.Certificate
}

func (m *mockTLSProvider) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return m.cert, nil
}

func NewMockTLSProvider(client Client) tlsprovider.TLSProvider {
	cert, key, err := ClientCertPair(client)
	if err != nil {
		panic(err)
	}
	certPair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		panic(err)
	}
	return &mockTLSProvider{
		cert: &certPair,
	}
}
