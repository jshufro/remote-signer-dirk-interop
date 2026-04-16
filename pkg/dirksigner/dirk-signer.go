package dirksigner

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"

	ssz "github.com/ferranbt/fastssz"
	"github.com/jshufro/remote-signer-dirk-interop/generated/api"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/dirksigner/dirk"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/domains"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/errors"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/fork"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/signer"
	tlsprovider "github.com/jshufro/remote-signer-dirk-interop/pkg/tls"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/typeconv"

	"github.com/herumi/bls-eth-go-binary/bls"
	e2t "github.com/wealdtech/go-eth2-types/v2"
	e2wd "github.com/wealdtech/go-eth2-wallet-dirk"
	e2wt "github.com/wealdtech/go-eth2-wallet-types/v2"
)

type DirkSigner struct {
	EnableDirkMetrics  bool                // If true, Dirk registers metrics with the Prometheus registry
	GenesisForkVersion domains.ForkVersion // Genesis fork version must be configured for validator_registration
	RootCA             *x509.CertPool

	dirk dirk.DirkSigner

	accounts sync.Map
	started  atomic.Bool
	logger   *slog.Logger
}

func init() {
	// Initialize the BLS library
	if err := bls.Init(bls.BLS12_381); err != nil {
		panic(err)
	}
}

// static assertion that DirkSigner implements the RemoteSigner interface
var _ signer.RemoteSigner[e2wt.AccountProtectingSigner] = (*DirkSigner)(nil)

type dirkMetricsMonitor struct{}

func (d *dirkMetricsMonitor) Presenter() string {
	return "prometheus"
}

func (d *DirkSigner) SetLogger(logger *slog.Logger) {
	d.logger = logger
}

func (d *DirkSigner) Log() *slog.Logger {
	if d.logger == nil {
		return slog.Default()
	}
	return d.logger
}

func (d *DirkSigner) Open(
	ctx context.Context,
	walletName string,
	endpoints []*e2wd.Endpoint,
	tlsProvider tlsprovider.TLSProvider,
	logLevel slog.Level,
) error {
	var err error

	if d.started.Swap(true) {
		return fmt.Errorf("dirk signer already started")
	}

	extraE2WDParameters := []e2wd.Parameter{}
	if d.EnableDirkMetrics {
		extraE2WDParameters = append(extraE2WDParameters, e2wd.WithMonitor(&dirkMetricsMonitor{}))
	}
	d.dirk, err = dirk.NewDirk(ctx, walletName, endpoints, tlsProvider, d.RootCA, logLevel, extraE2WDParameters...)
	if err != nil {
		return fmt.Errorf("failed to create dirk: %w", err)
	}

	// Prime the account pubkey map
	_ = d.getPublicKeys(ctx)

	return nil
}

func (d *DirkSigner) getPublicKeys(ctx context.Context) [][48]byte {
	accounts := d.dirk.GetAccounts(ctx)
	out := make([][48]byte, 0)
	for _, account := range accounts {
		pubkey := account.PublicKey()
		pubkeyBytes := ([48]byte)(pubkey.Marshal())
		out = append(out, pubkeyBytes)
		d.accounts.Store(pubkeyBytes, account)
	}

	return out
}

func (d *DirkSigner) GetPublicKeys(ctx context.Context) ([][48]byte, error) {

	return d.getPublicKeys(ctx), nil
}

func (d *DirkSigner) GetAccountForPubkey(ctx context.Context, pubkey [48]byte) (e2wt.AccountProtectingSigner, error) {
	account, ok := d.accounts.Load(pubkey)
	if ok {
		aps, ok := account.(e2wt.AccountProtectingSigner)
		if !ok {
			d.Log().Error("account is not a protecting signer", "pubkey", hex.EncodeToString(pubkey[:]))
			return nil, errors.InternalServerError()
		}
		return aps, nil
	}

	return nil, errors.PublicKeyNotFound("account not found for pubkey: %s", hex.EncodeToString(pubkey[:]))
}

func (d *DirkSigner) signature(signature e2t.Signature) ([96]byte, error) {
	b, err := typeconv.SignatureToBytes(signature)
	if err != nil {
		return d.returnUnexpectedFailure("produced invalid signature", err)
	}

	return b, nil
}

func (d *DirkSigner) sign(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	htr [32]byte,
	domain domains.Domain,
) ([96]byte, error) {
	signature, err := account.SignGeneric(ctx, htr[:], domain[:])
	if err != nil {
		return d.returnUnexpectedFailure("failed to sign generic", err)
	}

	return d.signature(signature)
}

func (d *DirkSigner) signHashRoot(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	htr ssz.HashRoot,
	domain domains.Domain,
) ([96]byte, error) {
	htrResult, err := htr.HashTreeRoot()
	if err != nil {
		return d.returnUnexpectedFailure("failed to compute hash tree root", err)
	}

	return d.sign(ctx, account, htrResult, domain)
}

func (d *DirkSigner) returnUnexpectedFailure(msg string, err error) ([96]byte, error) {
	d.Log().Warn(msg, "error", err)
	return [96]byte{}, errors.InternalServerError()
}

func (d *DirkSigner) AggregationSlotSigning(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.AggregationSlotSigning,
	forkInfo *fork.ForkInfo,
) ([96]byte, error) {

	slotStr := obj.AggregationSlot.Slot
	slot, err := strconv.ParseUint(slotStr, 10, 64)
	if err != nil {
		return [96]byte{}, errors.BadRequest("failed to parse slot: %w", err)
	}
	// Simply right-pad the slot to 32 bytes
	hashTreeRoot := typeconv.Uint64ToHashTreeRoot(slot)

	epoch := slot / 32

	domain := forkInfo.WithDomainType(domains.DomainSelectionProof).Domain(epoch)

	return d.sign(ctx, account, hashTreeRoot, domain)
}

func (d *DirkSigner) AggregateAndProofSigningV2(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.AggregateAndProofSigningV2,
	forkInfo *fork.ForkInfo,
) ([96]byte, error) {
	aggregateAndProof := obj.AggregateAndProof
	discriminator, err := aggregateAndProof.Discriminator()
	if err != nil {
		d.Log().Warn("failed to get discriminator", "error", err)
		return [96]byte{}, errors.BadRequest("failed to get discriminator: %w", err)
	}

	var htr ssz.HashRoot
	var epoch uint64
	switch discriminator {
	case "PHASE0", "ALTAIR", "BELLATRIX", "CAPELLA", "DENEB":
		phase0AggregateAndProof, err := aggregateAndProof.AsAggregateAndProofRequestPhase0()
		if err != nil {
			return [96]byte{}, errors.BadRequest("failed to get phase0 aggregate and proof: %w", err)
		}
		epoch = uint64(phase0AggregateAndProof.Data.Aggregate.Data.Slot / 32)
		htr = &phase0AggregateAndProof.Data
	case "ELECTRA", "FULU":
		electraAggregateAndProof, err := aggregateAndProof.AsAggregateAndProofRequestElectra()
		if err != nil {
			return [96]byte{}, errors.BadRequest("failed to get electra aggregate and proof: %w", err)
		}
		epoch = uint64(electraAggregateAndProof.Data.Aggregate.Data.Slot / 32)
		htr = &electraAggregateAndProof.Data
	default:
		d.Log().Warn("unknown aggregate and proof type", "discriminator", discriminator)
		return [96]byte{}, errors.BadRequest("unknown aggregate and proof type: %s", discriminator)
	}

	domain := forkInfo.WithDomainType(domains.DomainAggregateAndProof).Domain(epoch)

	return d.signHashRoot(ctx, account, htr, domain)
}

func (d *DirkSigner) AttestationSigning(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.AttestationSigning,
	forkInfo *fork.ForkInfo,
) ([96]byte, error) {
	attestation := obj.Attestation
	epoch := uint64(attestation.Slot / 32)
	domain := forkInfo.WithDomainType(domains.DomainBeaconAttester).Domain(epoch)
	signature, err := account.SignBeaconAttestation(
		ctx,
		uint64(attestation.Slot),
		uint64(attestation.Index),
		attestation.BeaconBlockRoot[:],
		uint64(attestation.Source.Epoch),
		attestation.Source.Root[:],
		uint64(attestation.Target.Epoch),
		attestation.Target.Root[:],
		domain[:],
	)
	if err != nil {
		return d.returnUnexpectedFailure("failed to sign beacon attestation", err)
	}

	return d.signature(signature)
}

func (d *DirkSigner) BeaconBlockSigning(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.BeaconBlockSigning,
	forkInfo *fork.ForkInfo,
) ([96]byte, error) {
	block := obj.BeaconBlock
	discriminator, err := block.Discriminator()
	if err != nil {
		return [96]byte{}, errors.BadRequest("failed to get discriminator: %w", err)
	}

	var header api.BeaconBlockHeader

	switch discriminator {
	case "PHASE0":
		phase0Block, err := block.AsBlockRequestPhase0()
		if err != nil {
			return [96]byte{}, errors.BadRequest("failed to get phase0 block: %w", err)
		}
		bodyRoot, err := phase0Block.Block.Body.HashTreeRoot()
		if err != nil {
			return [96]byte{}, errors.BadRequest("failed to get body root: %w", err)
		}

		header = api.BeaconBlockHeader{
			Slot:          phase0Block.Block.Slot,
			ProposerIndex: phase0Block.Block.ProposerIndex,
			ParentRoot:    phase0Block.Block.ParentRoot,
			StateRoot:     phase0Block.Block.StateRoot,
			BodyRoot:      bodyRoot,
		}
	case "ALTAIR":
		altairBlock, err := block.AsBlockRequestAltair()
		if err != nil {
			return [96]byte{}, errors.BadRequest("failed to get altair block: %w", err)
		}
		bodyRoot, err := altairBlock.Block.Body.HashTreeRoot()
		if err != nil {
			return [96]byte{}, errors.BadRequest("failed to get body root: %w", err)
		}

		header = api.BeaconBlockHeader{
			Slot:          altairBlock.Block.Slot,
			ProposerIndex: altairBlock.Block.ProposerIndex,
			ParentRoot:    altairBlock.Block.ParentRoot,
			StateRoot:     altairBlock.Block.StateRoot,
			BodyRoot:      bodyRoot,
		}
	case "BELLATRIX":
		bellatrixBlock, err := block.AsBlockRequestBellatrix()
		if err != nil {
			return [96]byte{}, errors.BadRequest("failed to get bellatrix block: %w", err)
		}
		header = bellatrixBlock.BlockHeader

	case "CAPELLA":
		capellaBlock, err := block.AsBlockRequestCapella()
		if err != nil {
			return [96]byte{}, errors.BadRequest("failed to get capella block: %w", err)
		}
		header = capellaBlock.BlockHeader
	case "DENEB":
		denebBlock, err := block.AsBlockRequestDeneb()
		if err != nil {
			return [96]byte{}, errors.BadRequest("failed to get deneb block: %w", err)
		}
		header = denebBlock.BlockHeader
	case "ELECTRA":
		electraBlock, err := block.AsBlockRequestElectra()
		if err != nil {
			return [96]byte{}, errors.BadRequest("failed to get electra block: %w", err)
		}
		header = electraBlock.BlockHeader
	case "FULU":
		fuluBlock, err := block.AsBlockRequestFulu()
		if err != nil {
			return [96]byte{}, errors.BadRequest("failed to get fulu block: %w", err)
		}
		header = fuluBlock.BlockHeader
	default:
		d.Log().Warn("unknown block type", "discriminator", discriminator)
		return [96]byte{}, errors.BadRequest("unknown block type: %s", discriminator)
	}

	epoch := uint64(header.Slot / 32)
	domain := forkInfo.WithDomainType(domains.DomainBeaconProposer).Domain(epoch)
	signature, err := account.SignBeaconProposal(
		ctx,
		uint64(header.Slot),
		uint64(header.ProposerIndex),
		header.ParentRoot[:],
		header.StateRoot[:],
		header.BodyRoot[:],
		domain[:],
	)
	if err != nil {
		return d.returnUnexpectedFailure("failed to sign beacon proposal", err)
	}

	return d.signature(signature)
}

func (d *DirkSigner) DepositSigning(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.DepositSigning,
) ([96]byte, error) {
	// Grab the genesis fork version string first
	genesisForkVersion, err := typeconv.DecodeForkVersion(obj.Deposit.GenesisForkVersion)
	if err != nil {
		return [96]byte{}, errors.BadRequest("failed to decode genesis fork version: %w", err)
	}
	deposit, err := typeconv.DepositSigningToHashRoot(obj)
	if err != nil {
		return [96]byte{}, errors.BadRequest("failed to convert deposit to hash root: %w", err)
	}

	domain := domains.DepositDomain(genesisForkVersion)

	return d.signHashRoot(ctx, account, deposit, domain)
}

func (d *DirkSigner) RandaoRevealSigning(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.RandaoRevealSigning,
	forkInfo *fork.ForkInfo,
) ([96]byte, error) {

	randaoReveal := obj.RandaoReveal.Epoch
	epoch, err := strconv.ParseUint(randaoReveal, 10, 64)
	if err != nil {
		return [96]byte{}, errors.BadRequest("failed to parse epoch: %w", err)
	}

	hashTreeRoot := typeconv.Uint64ToHashTreeRoot(epoch)
	domain := forkInfo.WithDomainType(domains.DomainRandao).Domain(epoch)

	return d.sign(ctx, account, hashTreeRoot, domain)
}

func (d *DirkSigner) VoluntaryExitSigning(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.VoluntaryExitSigning,
	forkInfo *fork.ForkInfo,
) ([96]byte, error) {
	epoch := uint64(obj.VoluntaryExit.Epoch)
	domain := forkInfo.WithDomainType(domains.DomainVoluntaryExit).Domain(epoch)

	return d.signHashRoot(ctx, account, &obj.VoluntaryExit, domain)
}

func (d *DirkSigner) SyncCommitteeMessageSigning(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.SyncCommitteeMessageSigning,
	forkInfo *fork.ForkInfo,
) ([96]byte, error) {
	slot, err := strconv.ParseUint(obj.SyncCommitteeMessage.Slot, 10, 64)
	if err != nil {
		return [96]byte{}, errors.BadRequest("failed to parse slot: %w", err)
	}
	beaconBlockRoot, err := typeconv.DecodeHex(obj.SyncCommitteeMessage.BeaconBlockRoot)
	if err != nil {
		return [96]byte{}, errors.BadRequest("failed to decode beacon block root: %w", err)
	}

	if len(beaconBlockRoot) != 32 {
		return [96]byte{}, errors.BadRequest("beacon block root is not 32 bytes")
	}

	htr := [32]byte{}
	copy(htr[:], beaconBlockRoot)

	epoch := slot / 32

	domain := forkInfo.WithDomainType(domains.DomainSyncCommittee).Domain(epoch)

	return d.sign(ctx, account, htr, domain)
}

func (d *DirkSigner) SyncCommitteeSelectionProofSigning(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.SyncCommitteeSelectionProofSigning,
	forkInfo *fork.ForkInfo,
) ([96]byte, error) {
	epoch := uint64(obj.SyncAggregatorSelectionData.Slot / 32)
	domain := forkInfo.WithDomainType(domains.DomainSyncCommiteeSelectionProof).Domain(epoch)

	return d.signHashRoot(ctx, account, &obj.SyncAggregatorSelectionData, domain)
}

func (d *DirkSigner) SyncCommitteeContributionAndProofSigning(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.SyncCommitteeContributionAndProofSigning,
	forkInfo *fork.ForkInfo,
) ([96]byte, error) {
	epoch := uint64(obj.ContributionAndProof.Contribution.Slot / 32)
	domain := forkInfo.WithDomainType(domains.DomainSyncContributionAndProof).Domain(epoch)

	return d.signHashRoot(ctx, account, &obj.ContributionAndProof, domain)
}

func (d *DirkSigner) ValidatorRegistrationSigning(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.ValidatorRegistrationSigning,
) ([96]byte, error) {
	domain := domains.ValidatorRegistrationDomain(d.GenesisForkVersion)

	return d.signHashRoot(ctx, account, &obj.ValidatorRegistration, domain)
}
