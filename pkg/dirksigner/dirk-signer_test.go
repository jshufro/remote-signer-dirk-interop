package dirksigner

import (
	"bytes"
	"log/slog"
	"testing"

	tlstest "github.com/jshufro/remote-signer-dirk-interop/pkg/tls/test"
	e2t "github.com/wealdtech/go-eth2-types/v2"
	e2wd "github.com/wealdtech/go-eth2-wallet-dirk"
)

// Most of the coverage is in end-to-end tests,
// this file just covers some odds and ends.

func TestNilLogger(t *testing.T) {
	dirk := NewDirkSigner(
		[]byte{0x00, 0x00, 0x00, 0x00},
		[]*e2wd.Endpoint{},
		"Wallet 1",
		nil,
		tlstest.NewMockTLSProvider(tlstest.ClientTest01),
		nil,
	)
	if dirk.log != slog.Default() {
		t.Fatalf("expected default logger, got %v", dirk.log)
	}
}

type fakeSignature struct {
	marshalError bool
}

func (f *fakeSignature) Marshal() []byte {
	if f.marshalError {
		return []byte{0x00}
	}
	return bytes.Repeat([]byte{1}, 96)
}

func (f *fakeSignature) Verify([]byte, e2t.PublicKey) bool {
	return true
}

func (f *fakeSignature) VerifyAggregate([][]byte, []e2t.PublicKey) bool {
	return true
}

func (f *fakeSignature) VerifyAggregateCommon([]byte, []e2t.PublicKey) bool {
	return true
}

func TestReturnSignatureError(t *testing.T) {
	dirk := NewDirkSigner(
		[]byte{0x00, 0x00, 0x00, 0x00},
		[]*e2wd.Endpoint{},
		"Wallet 1",
		nil,
		tlstest.NewMockTLSProvider(tlstest.ClientTest01),
		nil,
	)

	signature := &fakeSignature{marshalError: true}
	_, err := dirk.returnSignature(signature)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
}

func TestEmptyEndpointsError(t *testing.T) {
	dirk := NewDirkSigner(
		[]byte{0x00, 0x00, 0x00, 0x00},
		[]*e2wd.Endpoint{},
		"Wallet 1",
		nil,
		tlstest.NewMockTLSProvider(tlstest.ClientTest01),
		nil,
	)

	err := dirk.Open(t.Context(), slog.LevelInfo)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
}
