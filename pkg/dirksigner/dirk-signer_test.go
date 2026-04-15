package dirksigner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	e2t "github.com/wealdtech/go-eth2-types/v2"
	e2wd "github.com/wealdtech/go-eth2-wallet-dirk"

	"github.com/jshufro/remote-signer-dirk-interop/generated/api"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/dirksigner/dirk"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/domains"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/errors"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/fork"
	tlstest "github.com/jshufro/remote-signer-dirk-interop/pkg/tls/test"
)

// Most of the coverage is in end-to-end tests,
// this file just covers some odds and ends.

var validForkVersion = domains.ForkVersion{0x00, 0x00, 0x00, 0x00}

func TestNilLogger(t *testing.T) {
	dirk := NewDirkSigner(
		validForkVersion,
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
		validForkVersion,
		[]*e2wd.Endpoint{},
		"Wallet 1",
		nil,
		tlstest.NewMockTLSProvider(tlstest.ClientTest01),
		nil,
	)

	signature := &fakeSignature{marshalError: true}
	_, err := dirk.signature(signature)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
}

func TestEmptyEndpointsError(t *testing.T) {
	dirk := NewDirkSigner(
		validForkVersion,
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

var _ dirk.DirkSigner = (*fakeDirk)(nil)

type fakeDirk struct {
	accounts []fakeDirkAccount
}

func (f *fakeDirk) GetAccounts(ctx context.Context) []dirk.DirkAccount {
	out := make([]dirk.DirkAccount, len(f.accounts))
	for i, account := range f.accounts {
		out[i] = &account
	}
	return out
}

var _ dirk.DirkAccount = (*fakeDirkAccount)(nil)

type fakeDirkAccount struct {
	publicKey   e2t.PublicKey
	shouldError bool
}

func (f *fakeDirkAccount) PublicKey() e2t.PublicKey {
	return f.publicKey
}

func (f *fakeDirkAccount) SignBeaconAttestation(ctx context.Context, slot uint64, committeeIndex uint64, blockRoot []byte, sourceEpoch uint64, sourceRoot []byte, targetEpoch uint64, targetRoot []byte, domain []byte) (e2t.Signature, error) {
	if f.shouldError {
		return nil, errors.InternalServerError()
	}
	return nil, nil
}

func (f *fakeDirkAccount) SignBeaconProposal(ctx context.Context, slot uint64, proposerIndex uint64, parentRoot []byte, stateRoot []byte, bodyRoot []byte, domain []byte) (e2t.Signature, error) {
	if f.shouldError {
		return nil, errors.InternalServerError()
	}
	return nil, nil
}

func (f *fakeDirkAccount) SignGeneric(ctx context.Context, message []byte, domain []byte) (e2t.Signature, error) {
	if f.shouldError {
		return nil, errors.InternalServerError()
	}
	return nil, nil
}

var _ ssz.HashRoot = (*erroringHashRoot)(nil)

type erroringHashRoot struct {
	shouldError bool
}

func (e *erroringHashRoot) HashTreeRoot() ([32]byte, error) {
	if e.shouldError {
		return [32]byte{}, errors.InternalServerError()
	}
	return [32]byte{}, nil
}

func (e *erroringHashRoot) GetTree() (*ssz.Node, error) {
	return nil, nil
}

func (e *erroringHashRoot) HashTreeRootWith(hh ssz.HashWalker) error {
	return nil
}

func TestErroringHashRoot(t *testing.T) {
	logBuf := bytes.Buffer{}
	dirk := NewDirkSigner(
		validForkVersion,
		[]*e2wd.Endpoint{},
		"Wallet 1",
		nil,
		tlstest.NewMockTLSProvider(tlstest.ClientTest01),
		slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{})),
	)
	_, err := dirk.signHashRoot(t.Context(), nil, &erroringHashRoot{shouldError: true}, validForkInfo.WithDomainType(domains.DomainSelectionProof).Domain(0))
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "internal_server_error") {
		t.Fatalf("expected error `internal_server_error`, got `%v`", err)
	}
	if !strings.Contains(logBuf.String(), "failed to compute hash tree root") {
		t.Fatalf("expected log to contain `failed to compute hash tree root`, got `%v`", logBuf.String())
	}
}

var emptyGenesisValidatorsRoot = ([32]byte{})
var validForkInfo = &fork.ForkInfo{
	Fork:                  fork.Fork{CurrentVersion: []byte{0x00, 0x00, 0x00, 0x20}, PreviousVersion: []byte{0x00, 0x00, 0x00, 0x10}, Epoch: 100},
	GenesisValidatorsRoot: emptyGenesisValidatorsRoot[:],
}

func TestSignGenericError(t *testing.T) {
	logBuf := bytes.Buffer{}
	dirk := NewDirkSigner(
		validForkVersion,
		[]*e2wd.Endpoint{},
		"Wallet 1",
		nil,
		tlstest.NewMockTLSProvider(tlstest.ClientTest01),
		slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{})),
	)
	fakeAccount := fakeDirkAccount{shouldError: true}
	dirk.dirk = &fakeDirk{accounts: []fakeDirkAccount{fakeAccount}}
	_, err := dirk.sign(t.Context(), &fakeAccount, [32]byte{}, validForkInfo.WithDomainType(domains.DomainSelectionProof).Domain(0))
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "internal_server_error") {
		t.Fatalf("expected error `internal_server_error`, got `%v`", err)
	}
	if !strings.Contains(logBuf.String(), "failed to sign generic") {
		t.Fatalf("expected log to contain `failed to sign generic`, got `%v`", logBuf.String())
	}
}

func TestAggregationSlotSigning(t *testing.T) {
	dirk := NewDirkSigner(
		validForkVersion,
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
		validForkVersion,
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

	jsonMsg = `{
		"type": "AGGREGATE_AND_PROOF_V2",
		"aggregate_and_proof": {
			"version": true
		}
	}`

	obj = &api.AggregateAndProofSigningV2{}
	err = json.Unmarshal([]byte(jsonMsg), obj)
	if err != nil {
		t.Fatalf("failed to unmarshal json: %v", err)
	}

	// discriminator of wrong type should return a BadRequest error
	_, err = dirk.AggregateAndProofSigningV2(t.Context(), nil, obj, nil)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "failed to get discriminator") {
		t.Fatalf("expected error `failed to get discriminator`, got `%v`", err)
	}

	jsonMsg = `{
		"type": "AGGREGATE_AND_PROOF_V2",
		"aggregate_and_proof": {
			"version": "PHASE0",
			"data": true
		}
	}`

	obj = &api.AggregateAndProofSigningV2{}
	err = json.Unmarshal([]byte(jsonMsg), obj)
	if err != nil {
		t.Fatalf("failed to unmarshal json: %v", err)
	}

	// data of wrong type should return a BadRequest error
	_, err = dirk.AggregateAndProofSigningV2(t.Context(), nil, obj, nil)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "failed to get phase0 aggregate and proof") {
		t.Fatalf("expected error `failed to get phase0 aggregate and proof`, got `%v`", err)
	}

	jsonMsg = `{
		"type": "AGGREGATE_AND_PROOF_V2",
		"aggregate_and_proof": {
			"version": "ELECTRA",
			"data": true
		}
	}`

	obj = &api.AggregateAndProofSigningV2{}
	err = json.Unmarshal([]byte(jsonMsg), obj)
	if err != nil {
		t.Fatalf("failed to unmarshal json: %v", err)
	}

	// data of wrong type should return a BadRequest error
	_, err = dirk.AggregateAndProofSigningV2(t.Context(), nil, obj, nil)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "failed to get electra aggregate and proof") {
		t.Fatalf("expected error `failed to get electra aggregate and proof`, got `%v`", err)
	}
}

func TestAttestationSigningError(t *testing.T) {
	dirk := NewDirkSigner(
		validForkVersion,
		[]*e2wd.Endpoint{},
		"Wallet 1",
		nil,
		tlstest.NewMockTLSProvider(tlstest.ClientTest01),
		nil,
	)

	fakeAccount := fakeDirkAccount{shouldError: true}
	dirk.dirk = &fakeDirk{accounts: []fakeDirkAccount{fakeAccount}}
	_, err := dirk.AttestationSigning(t.Context(), &fakeAccount, &api.AttestationSigning{
		Attestation: api.AttestationData{
			Slot:            100,
			Index:           100,
			BeaconBlockRoot: [32]byte{},
			Source: &phase0.Checkpoint{
				Epoch: 99,
				Root:  [32]byte{},
			},
			Target: &phase0.Checkpoint{
				Epoch: 100,
				Root:  [32]byte{},
			},
		},
	}, validForkInfo)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "internal_server_error") {
		t.Fatalf("expected error `internal_server_error`, got `%v`", err)
	}
}

func TestBeaconBlockSigning(t *testing.T) {
	logBuf := bytes.Buffer{}
	dirk := NewDirkSigner(
		validForkVersion,
		[]*e2wd.Endpoint{},
		"Wallet 1",
		nil,
		tlstest.NewMockTLSProvider(tlstest.ClientTest01),
		slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{})),
	)

	jsonMsg := `{
		"type": "BLOCK_V2",
		"beacon_block": {
			"version": "invalid"
		}
	}`

	obj := &api.BeaconBlockSigning{}
	err := json.Unmarshal([]byte(jsonMsg), obj)
	if err != nil {
		t.Fatalf("failed to unmarshal json: %v", err)
	}

	// invalid discriminator should return a BadRequest error
	_, err = dirk.BeaconBlockSigning(t.Context(), nil, obj, nil)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "unknown block type") {
		t.Fatalf("expected error `unknown block type`, got `%v`", err)
	}

	jsonMsg = `{
		"type": "BLOCK_V2",
		"beacon_block": {
			"version": true
		}
	}`

	obj = &api.BeaconBlockSigning{}
	err = json.Unmarshal([]byte(jsonMsg), obj)
	if err != nil {
		t.Fatalf("failed to unmarshal json: %v", err)
	}

	// discriminator of wrong type should return a BadRequest error
	_, err = dirk.BeaconBlockSigning(t.Context(), nil, obj, nil)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "failed to get discriminator") {
		t.Fatalf("expected error `failed to get discriminator`, got `%v`", err)
	}

	for _, forkver := range []string{"PHASE0", "ALTAIR", "BELLATRIX", "CAPELLA", "DENEB", "ELECTRA", "FULU"} {
		dataField := func() string {
			switch forkver {
			case "PHASE0":
				return "block"
			case "ALTAIR":
				return "block"
			case "BELLATRIX", "CAPELLA", "DENEB", "ELECTRA", "FULU":
				return "block_header"
			default:
				panic("update this test consistently")
			}
		}()
		jsonMsg = fmt.Sprintf(`{
			"type": "BLOCK_V2",
			"beacon_block": {
				"version": "%s",
				"%s": true
			}
		}`, forkver, dataField)

		obj = &api.BeaconBlockSigning{}
		err = json.Unmarshal([]byte(jsonMsg), obj)
		if err != nil {
			t.Fatalf("failed to unmarshal json: %v", err)
		}

		// data of wrong type should return a BadRequest error
		_, err = dirk.BeaconBlockSigning(t.Context(), nil, obj, validForkInfo)
		if err == nil {
			t.Fatalf("expected error, got %v", err)
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("failed to get %s block", strings.ToLower(forkver))) {
			t.Fatalf("expected error `failed to get %s block`, got `%v`", strings.ToLower(forkver), err)
		}
	}

	jsonMsg = `{
		"type": "BLOCK_V2",
		"beacon_block": {
			"version": "FULU",
			"block_header": {
				"slot": "100",
				"proposer_index": "100",
				"parent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
				"state_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
				"body_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
			} 
		}
	}`

	obj = &api.BeaconBlockSigning{}
	err = json.Unmarshal([]byte(jsonMsg), obj)
	if err != nil {
		t.Fatalf("failed to unmarshal json: %v", err)
	}

	// Make sure signature errors are handled as well
	logBuf.Reset()
	_, err = dirk.BeaconBlockSigning(t.Context(), &fakeDirkAccount{shouldError: true}, obj, validForkInfo)

	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "internal_server_error") {
		t.Fatalf("expected error `internal_server_error`, got `%v`", err)
	}
	if !strings.Contains(logBuf.String(), "failed to sign beacon proposal") {
		t.Fatalf("expected log to contain `failed to sign beacon proposal`, got `%v`", logBuf.String())
	}
}

func TestDepositSigningError(t *testing.T) {
	logBuf := bytes.Buffer{}
	dirk := NewDirkSigner(
		validForkVersion,
		[]*e2wd.Endpoint{},
		"Wallet 1",
		nil,
		tlstest.NewMockTLSProvider(tlstest.ClientTest01),
		slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{})),
	)

	// Test invalid GenesisForkVersion hex in the deposit signing request
	jsonMsg := `{
		"type": "DEPOSIT",
		"deposit": {
			"genesis_fork_version": "invalid",
			"pubkey": "0x0000000000000000000000000000000000000000000000000000000000000000",
			"withdrawal_credentials": "0x0000000000000000000000000000000000000000000000000000000000000000",
			"amount": "1000000000"
		}
	}`
	obj := &api.DepositSigning{}
	err := json.Unmarshal([]byte(jsonMsg), obj)
	if err != nil {
		t.Fatalf("failed to unmarshal json: %v", err)
	}

	_, err = dirk.DepositSigning(t.Context(), nil, obj)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "failed to decode genesis fork version") {
		t.Fatalf("expected error `failed to decode genesis fork version`, got `%v`", err)
	}

	// Test invalid GenesisForkVersion length in the deposit signing request
	jsonMsg = `{
		"type": "DEPOSIT",
		"deposit": {
			"genesis_fork_version": "0x0000000099",
			"pubkey": "0x0000000000000000000000000000000000000000000000000000000000000000",
			"withdrawal_credentials": "0x0000000000000000000000000000000000000000000000000000000000000000",
			"amount": "1000000000"
		}
	}`
	obj = &api.DepositSigning{}
	err = json.Unmarshal([]byte(jsonMsg), obj)
	if err != nil {
		t.Fatalf("failed to unmarshal json: %v", err)
	}

	_, err = dirk.DepositSigning(t.Context(), nil, obj)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "failed to decode genesis fork version: hex string is 5 bytes") {
		t.Fatalf("expected error `failed to decode genesis fork version: hex string is 5 bytes`, got `%v`", err)
	}

	// Test invalid pubkey in the deposit signing request
	jsonMsg = `{
		"type": "DEPOSIT",
		"deposit": {
			"genesis_fork_version": "0x00000000",
			"pubkey": "invalid",
			"withdrawal_credentials": "0x0000000000000000000000000000000000000000000000000000000000000000",
			"amount": "1000000000"
		}
	}`
	obj = &api.DepositSigning{}
	err = json.Unmarshal([]byte(jsonMsg), obj)
	if err != nil {
		t.Fatalf("failed to unmarshal json: %v", err)
	}

	_, err = dirk.DepositSigning(t.Context(), nil, obj)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "failed to convert deposit to hash root: failed to decode pubkey") {
		t.Fatalf("expected error `failed to convert deposit to hash root: failed to decode pubkey`, got `%v`", err)
	}
}

func TestRandaoRevealSigningError(t *testing.T) {
	logBuf := bytes.Buffer{}
	dirk := NewDirkSigner(
		validForkVersion,
		[]*e2wd.Endpoint{},
		"Wallet 1",
		nil,
		tlstest.NewMockTLSProvider(tlstest.ClientTest01),
		slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{})),
	)

	// Test invalid epoch in the randao reveal signing request
	jsonMsg := `{
		"type": "RANDAO_REVEAL",
		"randao_reveal": {
			"epoch": "invalid"
		}
	}`
	obj := &api.RandaoRevealSigning{}
	err := json.Unmarshal([]byte(jsonMsg), obj)
	if err != nil {
		t.Fatalf("failed to unmarshal json: %v", err)
	}

	_, err = dirk.RandaoRevealSigning(t.Context(), nil, obj, validForkInfo)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "failed to parse epoch") {
		t.Fatalf("expected error `failed to parse epoch`, got `%v`", err)
	}
}

func TestSyncCommitteeMessageSigningError(t *testing.T) {
	logBuf := bytes.Buffer{}
	dirk := NewDirkSigner(
		[4]byte{0x00, 0x00, 0x00, 0x00},
		[]*e2wd.Endpoint{},
		"Wallet 1",
		nil,
		tlstest.NewMockTLSProvider(tlstest.ClientTest01),
		slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{})),
	)

	// Test invalid slot in the sync committee message signing request
	jsonMsg := `{
		"type": "SYNC_COMMITTEE_MESSAGE",
		"sync_committee_message": {
			"slot": "invalid",
			"beacon_block_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
		}
	}`
	obj := &api.SyncCommitteeMessageSigning{}
	err := json.Unmarshal([]byte(jsonMsg), obj)
	if err != nil {
		t.Fatalf("failed to unmarshal json: %v", err)
	}

	_, err = dirk.SyncCommitteeMessageSigning(t.Context(), nil, obj, validForkInfo)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "failed to parse slot") {
		t.Fatalf("expected error `failed to parse slot`, got `%v`", err)
	}

	// Test invalid beacon block root in the sync committee message signing request
	jsonMsg = `{
		"type": "SYNC_COMMITTEE_MESSAGE",
		"sync_committee_message": {
			"slot": "100",
			"beacon_block_root": "invalid"
		}
	}`
	obj = &api.SyncCommitteeMessageSigning{}
	err = json.Unmarshal([]byte(jsonMsg), obj)
	if err != nil {
		t.Fatalf("failed to unmarshal json: %v", err)
	}

	_, err = dirk.SyncCommitteeMessageSigning(t.Context(), nil, obj, validForkInfo)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "failed to decode beacon block root") {
		t.Fatalf("expected error `failed to decode beacon block root`, got `%v`", err)
	}

	// Test invalid beacon block root length in the sync committee message signing request
	jsonMsg = `{
		"type": "SYNC_COMMITTEE_MESSAGE",
		"sync_committee_message": {
			"slot": "100",
			"beacon_block_root": "0x000000000000000000000000000000000000000000000000000000000000000099"
		}
	}`
	obj = &api.SyncCommitteeMessageSigning{}
	err = json.Unmarshal([]byte(jsonMsg), obj)
	if err != nil {
		t.Fatalf("failed to unmarshal json: %v", err)
	}

	_, err = dirk.SyncCommitteeMessageSigning(t.Context(), nil, obj, validForkInfo)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	}
	if !strings.Contains(err.Error(), "beacon block root is not 32 bytes") {
		t.Fatalf("expected error `beacon block root is not 32 bytes`, got `%v`", err)
	}
}
