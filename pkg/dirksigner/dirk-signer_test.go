package dirksigner

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	e2t "github.com/wealdtech/go-eth2-types/v2"
	e2wd "github.com/wealdtech/go-eth2-wallet-dirk"

	api "github.com/jshufro/remote-signer-dirk-interop/generated"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/domains"
	tlstest "github.com/jshufro/remote-signer-dirk-interop/pkg/tls/test"
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

func TestCalculateDomainError(t *testing.T) {
	dirk := NewDirkSigner(
		[]byte{0x00, 0x00, 0x00, 0x00},
		[]*e2wd.Endpoint{},
		"Wallet 1",
		nil,
		tlstest.NewMockTLSProvider(tlstest.ClientTest01),
		nil,
	)

	_, err := dirk.calculateDomain(domains.DomainAggregateAndProof, struct {
		Fork                  api.Fork `json:"fork"`
		GenesisValidatorsRoot string   `json:"genesis_validators_root"`
	}{
		Fork: api.Fork{
			CurrentVersion:  "0x00000000",
			PreviousVersion: "0x00000000",
			Epoch:           "101",
		},
		GenesisValidatorsRoot: "0x0000000000000000000000000000000000000000000000000000000000000000",
	}, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = dirk.calculateDomain(domains.DomainAggregateAndProof, struct {
		Fork                  api.Fork `json:"fork"`
		GenesisValidatorsRoot string   `json:"genesis_validators_root"`
	}{
		Fork: api.Fork{
			CurrentVersion:  "0x00000000",
			PreviousVersion: "0x00000000",
			Epoch:           "invalid",
		},
		GenesisValidatorsRoot: "0x0000000000000000000000000000000000000000000000000000000000000000",
	}, 100)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse fork epoch") {
		t.Fatalf("error is not correct: %v", err)
	}
}

func TestAggregationSlotSigning(t *testing.T) {
	dirk := NewDirkSigner(
		[]byte{0x00, 0x00, 0x00, 0x00},
		[]*e2wd.Endpoint{},
		"Wallet 1",
		nil,
		tlstest.NewMockTLSProvider(tlstest.ClientTest01),
		nil,
	)

	// Invalid AggregationSlot.Slot should return a BadRequest error
	_, err := dirk.AggregationSlotSigning(t.Context(), nil, &api.AggregationSlotSigning{
		AggregationSlot: struct {
			Slot string `json:"slot,omitempty"`
		}{
			Slot: "invalid",
		},
	})
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}

	// Invalid
}
