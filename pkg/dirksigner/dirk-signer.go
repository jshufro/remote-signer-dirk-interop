package dirksigner

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	"github.com/OffchainLabs/prysm/v7/beacon-chain/core/signing"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/jshufro/remote-signer-dirk-interop/generated/api"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/dirksigner/dirk"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/domains"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/errors"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/fork"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/signer"
	tlsprovider "github.com/jshufro/remote-signer-dirk-interop/pkg/tls"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/typeconv"

	e2t "github.com/wealdtech/go-eth2-types/v2"
	e2wd "github.com/wealdtech/go-eth2-wallet-dirk"
	e2wt "github.com/wealdtech/go-eth2-wallet-types/v2"
)

type DirkSigner struct {
	genesisForkVersion []byte
	endpoints          []*e2wd.Endpoint
	walletName         string
	rootCA             *x509.CertPool
	tlsProvider        tlsprovider.TLSProvider
	log                *slog.Logger

	dirk     dirk.DirkSigner
	accounts sync.Map
}

func init() {
	// Initialize the BLS library
	if err := bls.Init(bls.BLS12_381); err != nil {
		panic(err)
	}
}

// static assertion that DirkSigner implements the RemoteSigner interface
var _ signer.RemoteSigner[e2wt.AccountProtectingSigner] = (*DirkSigner)(nil)

func NewDirkSigner(
	genesisForkVersion []byte,
	endpoints []*e2wd.Endpoint,
	wallet string,
	rootCA *x509.CertPool,
	tlsProvider tlsprovider.TLSProvider,
	log *slog.Logger,
) *DirkSigner {
	if log == nil {
		log = slog.Default()
	}
	return &DirkSigner{
		genesisForkVersion: genesisForkVersion,
		endpoints:          endpoints,
		walletName:         wallet,
		rootCA:             rootCA,
		tlsProvider:        tlsProvider,
		log:                log,
		accounts:           sync.Map{},
	}
}

func (d *DirkSigner) Open(ctx context.Context, logLevel slog.Level) error {
	var err error
	d.dirk, err = dirk.NewDirk(ctx, d.walletName, d.endpoints, d.tlsProvider, d.rootCA, logLevel)
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
			d.log.Error("account is not a protecting signer", "pubkey", hex.EncodeToString(pubkey[:]))
			return nil, errors.BadRequest("account is not a protecting signer")
		}
		return aps, nil
	}

	return nil, errors.PublicKeyNotFound("account not found for pubkey: %s", hex.EncodeToString(pubkey[:]))
}

func (d *DirkSigner) calculateDomain(
	domainType domains.DomainType,
	forkInfo *fork.ForkInfo,
	epoch uint64,
) ([]byte, error) {
	out, err := forkInfo.ComputeDomain(domainType, epoch)
	if err != nil {
		d.log.Error("failed to compute domain", "error", err)
		return nil, errors.InternalServerError()
	}
	d.log.Debug("computed domain", "domain", fmt.Sprintf("%#x", out))
	return out, nil
}

func (d *DirkSigner) returnSignature(signature e2t.Signature) ([96]byte, error) {
	b := signature.Marshal()
	if len(b) != 96 {
		return d.returnUnexpectedFailure("produced signature is not 96 bytes", fmt.Errorf("signature is %d bytes", len(b)))
	}
	return [96]byte(b), nil
}

func (d *DirkSigner) returnSignGeneric(ctx context.Context, account e2wt.AccountProtectingSigner, htr [32]byte, domain []byte) ([96]byte, error) {
	signature, err := account.SignGeneric(ctx, htr[:], domain)
	if err != nil {
		d.log.Warn("failed to sign generic", "error", err)
		return [96]byte{}, errors.InternalServerError()
	}
	return d.returnSignature(signature)
}

func (d *DirkSigner) sign(ctx context.Context, account e2wt.AccountProtectingSigner, htr [32]byte, domainType domains.DomainType, forkInfo *fork.ForkInfo, epoch uint64) ([96]byte, error) {
	domain, err := d.calculateDomain(domainType, forkInfo, epoch)
	if err != nil {
		d.log.Warn("failed to compute domain", "error", err)
		return [96]byte{}, errors.InternalServerError()
	}
	return d.returnSignGeneric(ctx, account, htr, domain)
}

func (d *DirkSigner) returnUnexpectedFailure(msg string, err error) ([96]byte, error) {
	d.log.Warn(msg, "error", err)
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
	hasher := ssz.NewHasher()
	hasher.AppendUint64(slot)
	hasher.FillUpTo32()
	hashTreeRoot, err := hasher.HashRoot()
	if err != nil {
		return d.returnUnexpectedFailure("failed to compute hash tree root", err)
	}

	epoch := slot / 32

	return d.sign(ctx, account, hashTreeRoot, domains.DomainSelectionProof, forkInfo, epoch)
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
		d.log.Warn("failed to get discriminator", "error", err)
		return [96]byte{}, errors.BadRequest("failed to get discriminator: %w", err)
	}

	var htr func() ([32]byte, error)
	var epoch uint64
	switch discriminator {
	case "PHASE0", "ALTAIR", "BELLATRIX", "CAPELLA", "DENEB":
		phase0AggregateAndProof, err := aggregateAndProof.AsAggregateAndProofRequestPhase0()
		if err != nil {
			return [96]byte{}, errors.BadRequest("failed to get phase0 aggregate and proof: %w", err)
		}
		epoch = uint64(phase0AggregateAndProof.Data.Aggregate.Data.Slot / 32)
		htr = phase0AggregateAndProof.Data.HashTreeRoot
	case "ELECTRA", "FULU":
		electraAggregateAndProof, err := aggregateAndProof.AsAggregateAndProofRequestElectra()
		if err != nil {
			return [96]byte{}, errors.BadRequest("failed to get electra aggregate and proof: %w", err)
		}
		epoch = uint64(electraAggregateAndProof.Data.Aggregate.Data.Slot / 32)
		htr = electraAggregateAndProof.Data.HashTreeRoot
	default:
		d.log.Warn("unknown aggregate and proof type", "discriminator", discriminator)
		return [96]byte{}, errors.BadRequest("unknown aggregate and proof type: %s", discriminator)
	}

	hashTreeRoot, err := htr()
	if err != nil {
		return d.returnUnexpectedFailure("failed to compute hash tree root", err)
	}

	return d.sign(ctx, account, hashTreeRoot, domains.DomainAggregateAndProof, forkInfo, epoch)
}

func (d *DirkSigner) AttestationSigning(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.AttestationSigning,
	forkInfo *fork.ForkInfo,
) ([96]byte, error) {
	attestation := obj.Attestation
	epoch := uint64(attestation.Slot / 32)
	domain, err := d.calculateDomain(
		domains.DomainBeaconAttester,
		forkInfo,
		epoch,
	)
	if err != nil {
		return d.returnUnexpectedFailure("failed to compute domain", err)
	}

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
	return d.returnSignature(signature)
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
		d.log.Warn("unknown block type", "discriminator", discriminator)
		return [96]byte{}, errors.BadRequest("unknown block type: %s", discriminator)
	}

	epoch := uint64(header.Slot / 32)
	domain, err := d.calculateDomain(
		domains.DomainBeaconProposer,
		forkInfo,
		epoch,
	)
	if err != nil {
		return d.returnUnexpectedFailure("failed to compute domain", err)
	}
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
	return d.returnSignature(signature)
}

func (d *DirkSigner) DepositSigning(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.DepositSigning,
) ([96]byte, error) {
	// Grab the genesis fork version string first
	genesisForkVersion, err := typeconv.DecodeHex(obj.Deposit.GenesisForkVersion)
	if err != nil {
		return [96]byte{}, errors.BadRequest("failed to decode genesis fork version: %w", err)
	}
	if len(genesisForkVersion) != 4 {
		return [96]byte{}, errors.BadRequest("genesis fork version is not 4 bytes")
	}
	// Round-trip the obj.Deposit to a phase0.DepositMessage via json
	// The payload to this api has an extra field and this is removes it plus gives us
	// a type that implements ssz.HashRoot
	depositMessageJson, err := json.Marshal(obj.Deposit)
	if err != nil {
		return [96]byte{}, errors.BadRequest("failed to remarshal deposit: %w", err)
	}
	deposit := &phase0.DepositMessage{}
	err = json.Unmarshal(depositMessageJson, deposit)
	if err != nil {
		return [96]byte{}, errors.BadRequest("failed to unmarshal deposit: %w", err)
	}

	hashTreeRoot, err := deposit.HashTreeRoot()
	if err != nil {
		return [96]byte{}, errors.InternalServerError()
	}

	// For deposits, only genesis fork version is needed
	// genesis validators root must be nil
	domain, err := signing.ComputeDomain(
		domains.DomainDeposit,
		genesisForkVersion,
		nil, /* genesis validators root */
	)
	if err != nil {
		return d.returnUnexpectedFailure("failed to compute domain", err)
	}

	return d.returnSignGeneric(ctx, account, hashTreeRoot, domain)
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
	hasher := ssz.NewHasher()
	hasher.AppendUint64(epoch)
	hasher.FillUpTo32()
	hashTreeRoot, err := hasher.HashRoot()
	if err != nil {
		return d.returnUnexpectedFailure("failed to compute hash tree root", err)
	}

	return d.sign(ctx, account, hashTreeRoot, domains.DomainRandao, forkInfo, epoch)
}

func (d *DirkSigner) VoluntaryExitSigning(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.VoluntaryExitSigning,
	forkInfo *fork.ForkInfo,
) ([96]byte, error) {
	hashTreeRoot, err := obj.VoluntaryExit.HashTreeRoot()
	if err != nil {
		return d.returnUnexpectedFailure("failed to compute hash tree root", err)
	}

	epoch := uint64(obj.VoluntaryExit.Epoch)

	return d.sign(ctx, account, hashTreeRoot, domains.DomainVoluntaryExit, forkInfo, epoch)
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

	return d.sign(ctx, account, htr, domains.DomainSyncCommittee, forkInfo, epoch)
}

func (d *DirkSigner) SyncCommitteeSelectionProofSigning(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.SyncCommitteeSelectionProofSigning,
	forkInfo *fork.ForkInfo,
) ([96]byte, error) {
	hashTreeRoot, err := obj.SyncAggregatorSelectionData.HashTreeRoot()
	if err != nil {
		return d.returnUnexpectedFailure("failed to compute hash tree root", err)
	}

	epoch := uint64(obj.SyncAggregatorSelectionData.Slot / 32)

	return d.sign(ctx, account, hashTreeRoot, domains.DomainSyncCommiteeSelectionProof, forkInfo, epoch)
}

func (d *DirkSigner) SyncCommitteeContributionAndProofSigning(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.SyncCommitteeContributionAndProofSigning,
	forkInfo *fork.ForkInfo,
) ([96]byte, error) {
	hashTreeRoot, err := obj.ContributionAndProof.HashTreeRoot()
	if err != nil {
		return d.returnUnexpectedFailure("failed to compute hash tree root", err)
	}

	epoch := uint64(obj.ContributionAndProof.Contribution.Slot / 32)

	return d.sign(ctx, account, hashTreeRoot, domains.DomainSyncContributionAndProof, forkInfo, epoch)
}

func (d *DirkSigner) ValidatorRegistrationSigning(
	ctx context.Context,
	account e2wt.AccountProtectingSigner,
	obj *api.ValidatorRegistrationSigning,
) ([96]byte, error) {

	hashTreeRoot, err := obj.ValidatorRegistration.HashTreeRoot()
	if err != nil {
		return d.returnUnexpectedFailure("failed to compute hash tree root", err)
	}

	// Compute the domain
	// For validator registrations, only genesis fork version is needed
	// genesis validators root must be nil
	domain, err := signing.ComputeDomain(
		domains.DomainApplicationBuilder,
		d.genesisForkVersion,
		nil, /* genesis validators root */
	)
	if err != nil {
		return d.returnUnexpectedFailure("failed to compute domain", err)
	}

	return d.returnSignGeneric(ctx, account, hashTreeRoot, domain)
}
