package dirksigner

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	e2t "github.com/wealdtech/go-eth2-types/v2"
	e2wd "github.com/wealdtech/go-eth2-wallet-dirk"

	"github.com/jshufro/remote-signer-dirk-interop/generated/api"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/domains"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/fork"
	tlstest "github.com/jshufro/remote-signer-dirk-interop/pkg/tls/test"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/typeconv"
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

	gvr, err := typeconv.DecodeHex("0x0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("failed to decode genesis validators root: %v", err)
	}
	_, err = dirk.calculateDomain(domains.DomainAggregateAndProof, &fork.ForkInfo{
		Fork: fork.Fork{
			CurrentVersion:  []byte{0x00, 0x00, 0x00, 0x00},
			PreviousVersion: []byte{0x00, 0x00, 0x00, 0x00},
			Epoch:           100,
		},
		GenesisValidatorsRoot: gvr,
	}, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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
	}, nil)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
}

func TestAggregateAndProofSigningV2(t *testing.T) {
	dirk := NewDirkSigner(
		[]byte{0x00, 0x00, 0x00, 0x00},
		[]*e2wd.Endpoint{},
		"Wallet 1",
		nil,
		tlstest.NewMockTLSProvider(tlstest.ClientTest01),
		nil,
	)

	jsonMsg := `{
		"type": "AGGREGATE_AND_PROOF_V2",
		"aggregate_and_proof": {
			"version": "invalid"
		}
	}`

	obj := &api.AggregateAndProofSigningV2{}
	err := json.Unmarshal([]byte(jsonMsg), obj)
	if err != nil {
		t.Fatalf("failed to unmarshal json: %v", err)
	}

	// invalid discriminator should return a BadRequest error
	_, err = dirk.AggregateAndProofSigningV2(t.Context(), nil, obj, nil)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "unknown aggregate and proof type") {
		t.Fatalf("expected error `unknown aggregate and proof type`, got `%v`", err)
	}
}
