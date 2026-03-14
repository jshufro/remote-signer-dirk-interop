package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jshufro/remote-signer-dirk-interop/internal/api"
	"github.com/jshufro/remote-signer-dirk-interop/internal/errors"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/signer"
)

type fakeSigner struct {
}

type fakeAccount struct {
}

// Type assertion to satisfy the signer.PublicKeysProvider interface
var _ signer.RemoteSigner[fakeAccount] = (*fakeSigner)(nil)

func (f *fakeSigner) GetPublicKeys(ctx context.Context) ([][48]byte, error) {
	return [][48]byte{}, nil
}

func (f *fakeSigner) GetAccountForPubkey(ctx context.Context, pubkey [48]byte) (fakeAccount, error) {
	return fakeAccount{}, nil
}

func (f *fakeSigner) AggregationSlotSigning(ctx context.Context, pubkey fakeAccount, obj *api.AggregationSlotSigning) ([96]byte, error) {
	return [96]byte{1}, nil
}

// Satisfy the api.Signer interface with stubs; not used in this test.
func (f *fakeSigner) AggregateAndProofSigningV2(context.Context, fakeAccount, *api.AggregateAndProofSigningV2) ([96]byte, error) {
	return [96]byte{}, errors.InternalServerError()
}
func (f *fakeSigner) AttestationSigning(context.Context, fakeAccount, *api.AttestationSigning) ([96]byte, error) {
	return [96]byte{}, errors.InternalServerError()
}
func (f *fakeSigner) BeaconBlockSigning(context.Context, fakeAccount, *api.BeaconBlockSigning) ([96]byte, error) {
	return [96]byte{}, errors.InternalServerError()
}
func (f *fakeSigner) DepositSigning(context.Context, fakeAccount, *api.DepositSigning) ([96]byte, error) {
	return [96]byte{}, errors.InternalServerError()
}
func (f *fakeSigner) RandaoRevealSigning(context.Context, fakeAccount, *api.RandaoRevealSigning) ([96]byte, error) {
	return [96]byte{}, errors.InternalServerError()
}
func (f *fakeSigner) VoluntaryExitSigning(context.Context, fakeAccount, *api.VoluntaryExitSigning) ([96]byte, error) {
	return [96]byte{}, errors.InternalServerError()
}
func (f *fakeSigner) SyncCommitteeMessageSigning(context.Context, fakeAccount, *api.SyncCommitteeMessageSigning) ([96]byte, error) {
	return [96]byte{}, errors.InternalServerError()
}
func (f *fakeSigner) SyncCommitteeSelectionProofSigning(context.Context, fakeAccount, *api.SyncCommitteeSelectionProofSigning) ([96]byte, error) {
	return [96]byte{}, errors.InternalServerError()
}
func (f *fakeSigner) SyncCommitteeContributionAndProofSigning(context.Context, fakeAccount, *api.SyncCommitteeContributionAndProofSigning) ([96]byte, error) {
	return [96]byte{}, errors.InternalServerError()
}
func (f *fakeSigner) ValidatorRegistrationSigning(context.Context, fakeAccount, *api.ValidatorRegistrationSigning) ([96]byte, error) {
	return [96]byte{}, errors.InternalServerError()
}

func TestSIGN_Success(t *testing.T) {
	fs := &fakeSigner{}
	svc, err := NewService[fakeAccount](fs)
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}
	svc.SetTimeout(1 * time.Second)

	pubkey := [48]byte{}
	for i := range pubkey {
		pubkey[i] = byte(i)
	}
	identifier := "0x" + hex.EncodeToString(pubkey[:])

	body := map[string]any{
		"type": "AGGREGATION_SLOT",
		"aggregation_slot": map[string]any{
			"slot": "123",
		},
		"fork_info": map[string]any{
			"fork": map[string]any{
				"previous_version": "0x00000000",
				"current_version":  "0x00000000",
				"epoch":            "0",
			},
			"genesis_validators_root": "0x" + hex.EncodeToString(make([]byte, 32)),
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/eth2/sign/"+identifier, bytes.NewReader(raw))
	w := httptest.NewRecorder()

	svc.SIGN(w, req, identifier)
	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", res.StatusCode)
	}

	var resp api.SigningResponse
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Signature == "" {
		t.Fatalf("expected non-empty signature in response")
	}
}
