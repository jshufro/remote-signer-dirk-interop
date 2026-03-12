package dirksigner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/OffchainLabs/prysm/v7/beacon-chain/core/signing"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/jshufro/remote-signer-dirk-interop/internal/api"
	"github.com/jshufro/remote-signer-dirk-interop/internal/domains"
	"github.com/jshufro/remote-signer-dirk-interop/internal/errors"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/dirksigner/accountcache"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/signer"
	tlsprovider "github.com/jshufro/remote-signer-dirk-interop/pkg/tls"
	"google.golang.org/grpc/credentials"

	e2t "github.com/wealdtech/go-eth2-types/v2"
	e2wd "github.com/wealdtech/go-eth2-wallet-dirk"
	e2wt "github.com/wealdtech/go-eth2-wallet-types/v2"
)

type DirkSigner struct {
	genesisForkVersion []byte
	wallet             e2wt.Wallet
	endpoints          []*e2wd.Endpoint
	walletName         string
	rootCA             *x509.CertPool
	tlsProvider        *tlsprovider.TLSProvider
	log                *slog.Logger

	accountsCache accountcache.AccountCache
}

func init() {
	// Initialize the BLS library
	if err := bls.Init(bls.BLS12_381); err != nil {
		panic(err)
	}
}

// static assertion that DirkSigner implements the RemoteSigner interface
var _ signer.RemoteSigner = (*DirkSigner)(nil)

func NewDirkSigner(
	genesisForkVersion []byte,
	endpoints []*e2wd.Endpoint,
	wallet string,
	rootCA *x509.CertPool,
	tlsProvider *tlsprovider.TLSProvider,
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
		accountsCache:      accountcache.AccountCache{},
	}
}

func (d *DirkSigner) Open(ctx context.Context, logLevel slog.Level) error {
	tlsConfig := &tls.Config{
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := d.tlsProvider.GetCertificate()
			if err != nil {
				return nil, fmt.Errorf("failed to get certificate: %w", err)
			}
			return cert, nil
		},
	}
	if d.rootCA != nil {
		tlsConfig.RootCAs = d.rootCA
	}
	zerologLevel := slogLevelToZerologLevel(logLevel)
	credentials := credentials.NewTLS(tlsConfig)
	var err error
	d.wallet, err = e2wd.Open(ctx,
		e2wd.WithName(d.walletName),
		e2wd.WithEndpoints(d.endpoints),
		e2wd.WithCredentials(credentials),
		e2wd.WithLogLevel(zerologLevel),
	)
	if err != nil {
		return fmt.Errorf("failed to open wallet: %w", err)
	}

	// While we're here, prime the cache
	_, err = d.GetPublicKeys(ctx)
	if err != nil {
		return fmt.Errorf("failed to get public keys: %w", err)
	}
	return err
}

func (d *DirkSigner) GetPublicKeys(ctx context.Context) ([][48]byte, error) {

	accounts := d.wallet.Accounts(ctx)
	out := make([][48]byte, 0)
	for account := range accounts {
		var pubkey e2t.PublicKey
		// Check if it's a distributed account
		if distributedAccount, ok := account.(e2wt.AccountCompositePublicKeyProvider); ok {
			pubkey = distributedAccount.CompositePublicKey()
		} else {
			pubkey = account.PublicKey()
		}
		pubkeyBytes := ([48]byte)(pubkey.Marshal())
		d.accountsCache.Set(pubkeyBytes, account)
		out = append(out, pubkeyBytes)
	}

	return out, nil
}

func (d *DirkSigner) getAccount(pubkey [48]byte) e2wt.AccountProtectingSigner {
	account := d.accountsCache.Get(pubkey)
	if account != nil {
		return account.(e2wt.AccountProtectingSigner)
	}

	return nil
}

func (d *DirkSigner) AggregationSlotSigning(ctx context.Context, pubkey [48]byte, obj *api.AggregationSlotSigning) ([96]byte, *errors.SignerError) {

	slotStr := obj.AggregationSlot.Slot
	slot, err := strconv.ParseUint(slotStr, 10, 64)
	if err != nil {
		d.log.Warn("failed to parse slot", "error", err)
		return [96]byte{}, errors.ErrBadRequest
	}
	hasher := ssz.NewHasher()
	hasher.AppendUint64(slot)
	hasher.FillUpTo32()
	hashTreeRoot, err := hasher.HashRoot()
	if err != nil {
		d.log.Warn("failed to compute hash tree root", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	// Compute the domain
	domain, err := d.calculateDomain(
		domains.DomainSelectionProof,
		obj.ForkInfo.GenesisValidatorsRoot,
		&obj.ForkInfo.Fork,
	)
	if err != nil {
		d.log.Warn("failed to compute domain", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	account := d.getAccount(pubkey)
	if account == nil {
		d.log.Warn("account not found in cache", "pubkey", hex.EncodeToString(pubkey[:]))
		return [96]byte{}, errors.ErrPublicKeyNotFound
	}

	signature, err := account.SignGeneric(ctx, hashTreeRoot[:], domain[:])
	if err != nil {
		d.log.Warn("failed to sign randao reveal", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}
	d.log.Debug("signed randao reveal", "pubkey", hex.EncodeToString(pubkey[:]))
	return returnSignature(signature)
}

func (d *DirkSigner) AggregateAndProofSigningV2(ctx context.Context, pubkey [48]byte, obj *api.AggregateAndProofSigningV2) ([96]byte, *errors.SignerError) {
	aggregateAndProof := obj.AggregateAndProof
	discriminator, err := aggregateAndProof.Discriminator()
	if err != nil {
		d.log.Warn("failed to get discriminator", "error", err)
		return [96]byte{}, errors.ErrBadRequest
	}

	var hashTreeRoot [32]byte
	switch discriminator {
	case "PHASE0":
		fallthrough
	case "ALTAIR":
		fallthrough
	case "BELLATRIX":
		fallthrough
	case "CAPELLA":
		fallthrough
	case "DENEB":
		phase0AggregateAndProof, err := aggregateAndProof.AsAggregateAndProofRequestPhase0()
		if err != nil {
			d.log.Warn("failed to get phase0 aggregate and proof", "error", err)
			return [96]byte{}, errors.ErrBadRequest
		}
		hashTreeRoot, err = phase0AggregateAndProof.Data.HashTreeRoot()
		if err != nil {
			d.log.Warn("failed to compute hash tree root", "error", err)
			return [96]byte{}, errors.ErrInternalServerError
		}
	case "ELECTRA":
		fallthrough
	case "FULU":
		electraAggregateAndProof, err := aggregateAndProof.AsAggregateAndProofRequestElectra()
		if err != nil {
			d.log.Warn("failed to get electra aggregate and proof", "error", err)
			return [96]byte{}, errors.ErrBadRequest
		}
		hashTreeRoot, err = electraAggregateAndProof.Data.HashTreeRoot()
		if err != nil {
			d.log.Warn("failed to compute hash tree root", "error", err)
			return [96]byte{}, errors.ErrInternalServerError
		}
	default:
		d.log.Error("unknown aggregate and proof type", "discriminator", discriminator)
		return [96]byte{}, errors.ErrBadRequest
	}

	domain, err := d.calculateDomain(
		domains.DomainAggregateAndProof,
		obj.ForkInfo.GenesisValidatorsRoot,
		&obj.ForkInfo.Fork,
	)
	if err != nil {
		d.log.Warn("failed to compute domain", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	account := d.getAccount(pubkey)
	if account == nil {
		d.log.Warn("account not found in cache", "pubkey", hex.EncodeToString(pubkey[:]))
		return [96]byte{}, errors.ErrPublicKeyNotFound
	}

	signature, err := account.SignGeneric(ctx, hashTreeRoot[:], domain[:])
	if err != nil {
		d.log.Warn("failed to sign aggregate and proof", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}
	d.log.Debug("signed aggregate and proof", "pubkey", hex.EncodeToString(pubkey[:]))
	return returnSignature(signature)
}

func (d *DirkSigner) AttestationSigning(ctx context.Context, pubkey [48]byte, obj *api.AttestationSigning) ([96]byte, *errors.SignerError) {
	attestation := obj.Attestation
	domain, err := d.calculateDomain(
		domains.DomainBeaconAttester,
		obj.ForkInfo.GenesisValidatorsRoot,
		&obj.ForkInfo.Fork,
	)
	if err != nil {
		d.log.Warn("failed to compute domain", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	account := d.getAccount(pubkey)
	if account == nil {
		d.log.Warn("account not found in cache", "pubkey", hex.EncodeToString(pubkey[:]))
		return [96]byte{}, errors.ErrPublicKeyNotFound
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
		d.log.Warn("failed to sign beacon attestation", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}
	d.log.Debug("signed beacon attestation", "pubkey", hex.EncodeToString(pubkey[:]))
	return returnSignature(signature)
}

func (d *DirkSigner) BeaconBlockSigning(ctx context.Context, pubkey [48]byte, obj *api.BeaconBlockSigning) ([96]byte, *errors.SignerError) {
	block := obj.BeaconBlock
	discriminator, err := block.Discriminator()
	if err != nil {
		d.log.Warn("failed to get discriminator", "error", err)
		return [96]byte{}, errors.ErrBadRequest
	}
	account := d.getAccount(pubkey)
	if account == nil {
		d.log.Warn("account not found in cache", "pubkey", hex.EncodeToString(pubkey[:]))
		return [96]byte{}, errors.ErrPublicKeyNotFound
	}

	// Compute the domain
	domain, err := d.calculateDomain(
		domains.DomainBeaconProposer,
		obj.ForkInfo.GenesisValidatorsRoot,
		&obj.ForkInfo.Fork,
	)
	if err != nil {
		d.log.Warn("failed to compute domain", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	var header api.BeaconBlockHeader
	switch discriminator {
	case "PHASE0":
		phase0Block, err := block.AsBlockRequestPhase0()
		if err != nil {
			d.log.Warn("failed to get phase0 block", "error", err)
			return [96]byte{}, errors.ErrBadRequest
		}
		bodyRoot, err := phase0Block.Block.Body.HashTreeRoot()
		if err != nil {
			d.log.Warn("failed to get body root", "error", err)
			return [96]byte{}, errors.ErrBadRequest
		}
		signature, err := account.SignBeaconProposal(
			ctx,
			uint64(phase0Block.Block.Slot),
			uint64(phase0Block.Block.ProposerIndex),
			phase0Block.Block.ParentRoot[:],
			phase0Block.Block.StateRoot[:],
			bodyRoot[:],
			domain[:],
		)
		if err != nil {
			d.log.Warn("failed to sign beacon proposal", "error", err)
			return [96]byte{}, errors.ErrInternalServerError
		}
		d.log.Debug("signed beacon proposal", "pubkey", hex.EncodeToString(pubkey[:]))
		return returnSignature(signature)
	case "ALTAIR":
		altairBlock, err := block.AsBlockRequestAltair()
		if err != nil {
			d.log.Warn("failed to get altair block", "error", err)
			return [96]byte{}, errors.ErrBadRequest
		}
		bodyRoot, err := altairBlock.Block.Body.HashTreeRoot()
		if err != nil {
			d.log.Warn("failed to get body root", "error", err)
			return [96]byte{}, errors.ErrBadRequest
		}
		signature, err := account.SignBeaconProposal(
			ctx,
			uint64(altairBlock.Block.Slot),
			uint64(altairBlock.Block.ProposerIndex),
			altairBlock.Block.ParentRoot[:],
			altairBlock.Block.StateRoot[:],
			bodyRoot[:],
			domain[:],
		)
		if err != nil {
			d.log.Warn("failed to sign beacon proposal", "error", err)
			return [96]byte{}, errors.ErrInternalServerError
		}
		d.log.Debug("signed beacon proposal", "pubkey", hex.EncodeToString(pubkey[:]))
		return returnSignature(signature)
	case "BELLATRIX":
		bellatrixBlock, err := block.AsBlockRequestBellatrix()
		if err != nil {
			d.log.Warn("failed to get bellatrix block", "error", err)
			return [96]byte{}, errors.ErrBadRequest
		}
		header = bellatrixBlock.BlockHeader
	case "CAPELLA":
		capellaBlock, err := block.AsBlockRequestCapella()
		if err != nil {
			d.log.Warn("failed to get capella block", "error", err)
			return [96]byte{}, errors.ErrBadRequest
		}
		header = capellaBlock.BlockHeader
	case "DENEB":
		denebBlock, err := block.AsBlockRequestDeneb()
		if err != nil {
			d.log.Warn("failed to get deneb block", "error", err)
			return [96]byte{}, errors.ErrBadRequest
		}
		header = denebBlock.BlockHeader
	case "ELECTRA":
		electraBlock, err := block.AsBlockRequestElectra()
		if err != nil {
			d.log.Warn("failed to get electra block", "error", err)
			return [96]byte{}, errors.ErrBadRequest
		}
		header = electraBlock.BlockHeader
	case "FULU":
		fuluBlock, err := block.AsBlockRequestFulu()
		if err != nil {
			d.log.Warn("failed to get fulu block", "error", err)
			return [96]byte{}, errors.ErrBadRequest
		}
		header = fuluBlock.BlockHeader
	default:
		d.log.Error("unknown block type", "discriminator", discriminator)
		return [96]byte{}, errors.ErrBadRequest
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
		d.log.Warn("failed to sign beacon proposal", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}
	d.log.Debug("signed beacon proposal", "pubkey", hex.EncodeToString(pubkey[:]))
	return returnSignature(signature)
}

func (d *DirkSigner) DepositSigning(ctx context.Context, pubkey [48]byte, obj *api.DepositSigning) ([96]byte, *errors.SignerError) {
	// Round-trip the obj.Deposit to a phase0.DepositMessage via json
	depositMessageJson, err := json.Marshal(obj.Deposit)
	if err != nil {
		d.log.Warn("failed to marshal deposit", "error", err)
		return [96]byte{}, errors.ErrBadRequest
	}
	deposit := &phase0.DepositMessage{}
	err = json.Unmarshal(depositMessageJson, deposit)
	if err != nil {
		d.log.Warn("failed to unmarshal deposit", "error", err)
		return [96]byte{}, errors.ErrBadRequest
	}

	// Compute the hash tree root
	hashTreeRoot, err := deposit.HashTreeRoot()
	if err != nil {
		d.log.Warn("failed to compute hash tree root", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	// Compute the domain
	// For deposits, only genesis fork version is needed
	// genesis validators root must be nil
	domain, err := signing.ComputeDomain(
		domains.DomainDeposit,
		d.genesisForkVersion,
		nil, /* genesis validators root */
	)
	if err != nil {
		d.log.Warn("failed to compute domain", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	account := d.getAccount(pubkey)
	if account == nil {
		d.log.Warn("account not found in cache", "pubkey", hex.EncodeToString(pubkey[:]))
		return [96]byte{}, errors.ErrPublicKeyNotFound
	}

	signature, err := account.SignGeneric(ctx, hashTreeRoot[:], domain[:])
	if err != nil {
		d.log.Warn("failed to sign deposit", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}
	d.log.Debug("signed deposit", "pubkey", hex.EncodeToString(pubkey[:]))
	return returnSignature(signature)
}

func (d *DirkSigner) RandaoRevealSigning(ctx context.Context, pubkey [48]byte, obj *api.RandaoRevealSigning) ([96]byte, *errors.SignerError) {

	randaoReveal := obj.RandaoReveal.Epoch
	epoch, err := strconv.ParseUint(randaoReveal, 10, 64)
	if err != nil {
		d.log.Warn("failed to parse epoch", "error", err)
		return [96]byte{}, errors.ErrBadRequest
	}
	hasher := ssz.NewHasher()
	hasher.AppendUint64(epoch)
	hasher.FillUpTo32()
	hashTreeRoot, err := hasher.HashRoot()
	if err != nil {
		d.log.Warn("failed to compute hash tree root", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	// Compute the domain
	domain, err := d.calculateDomain(
		domains.DomainRandao,
		obj.ForkInfo.GenesisValidatorsRoot,
		&obj.ForkInfo.Fork,
	)
	if err != nil {
		d.log.Warn("failed to compute domain", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	account := d.getAccount(pubkey)
	if account == nil {
		d.log.Warn("account not found in cache", "pubkey", hex.EncodeToString(pubkey[:]))
		return [96]byte{}, errors.ErrPublicKeyNotFound
	}

	signature, err := account.SignGeneric(ctx, hashTreeRoot[:], domain[:])
	if err != nil {
		d.log.Warn("failed to sign randao reveal", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}
	d.log.Debug("signed randao reveal", "pubkey", hex.EncodeToString(pubkey[:]))
	return returnSignature(signature)
}

func (d *DirkSigner) VoluntaryExitSigning(ctx context.Context, pubkey [48]byte, obj *api.VoluntaryExitSigning) ([96]byte, *errors.SignerError) {
	hashTreeRoot, err := obj.VoluntaryExit.HashTreeRoot()
	if err != nil {
		d.log.Warn("failed to compute hash tree root", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	// Compute the domain
	domain, err := d.calculateDomain(
		domains.DomainVoluntaryExit,
		obj.ForkInfo.GenesisValidatorsRoot,
		&obj.ForkInfo.Fork,
	)
	if err != nil {
		d.log.Warn("failed to compute domain", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	account := d.getAccount(pubkey)
	if account == nil {
		d.log.Warn("account not found in cache", "pubkey", hex.EncodeToString(pubkey[:]))
		return [96]byte{}, errors.ErrPublicKeyNotFound
	}

	signature, err := account.SignGeneric(ctx, hashTreeRoot[:], domain[:])
	if err != nil {
		d.log.Warn("failed to sign voluntary exit", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}
	d.log.Debug("signed voluntary exit", "pubkey", hex.EncodeToString(pubkey[:]))
	return returnSignature(signature)
}

func (d *DirkSigner) SyncCommitteeMessageSigning(ctx context.Context, pubkey [48]byte, obj *api.SyncCommitteeMessageSigning) ([96]byte, *errors.SignerError) {
	hashTreeRoot, err := obj.SyncCommitteeMessage.HashTreeRoot()
	if err != nil {
		d.log.Warn("failed to compute hash tree root", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	// Compute the domain
	domain, err := d.calculateDomain(
		domains.DomainSyncCommittee,
		obj.ForkInfo.GenesisValidatorsRoot,
		&obj.ForkInfo.Fork,
	)
	if err != nil {
		d.log.Warn("failed to compute domain", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	account := d.getAccount(pubkey)
	if account == nil {
		d.log.Warn("account not found in cache", "pubkey", hex.EncodeToString(pubkey[:]))
		return [96]byte{}, errors.ErrPublicKeyNotFound
	}

	signature, err := account.SignGeneric(ctx, hashTreeRoot[:], domain[:])
	if err != nil {
		d.log.Warn("failed to sign sync committee message", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}
	d.log.Debug("signed sync committee message", "pubkey", hex.EncodeToString(pubkey[:]))
	return returnSignature(signature)
}

func (d *DirkSigner) SyncCommitteeSelectionProofSigning(ctx context.Context, pubkey [48]byte, obj *api.SyncCommitteeSelectionProofSigning) ([96]byte, *errors.SignerError) {
	hashTreeRoot, err := obj.SyncAggregatorSelectionData.HashTreeRoot()
	if err != nil {
		d.log.Warn("failed to compute hash tree root", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	// Compute the domain
	domain, err := d.calculateDomain(
		domains.DomainSyncCommiteeSelectionProof,
		obj.ForkInfo.GenesisValidatorsRoot,
		&obj.ForkInfo.Fork,
	)
	if err != nil {
		d.log.Warn("failed to compute domain", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	account := d.getAccount(pubkey)
	if account == nil {
		d.log.Warn("account not found in cache", "pubkey", hex.EncodeToString(pubkey[:]))
		return [96]byte{}, errors.ErrPublicKeyNotFound
	}

	signature, err := account.SignGeneric(ctx, hashTreeRoot[:], domain[:])
	if err != nil {
		d.log.Warn("failed to sign sync committee selection proof", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}
	d.log.Debug("signed sync committee selection proof", "pubkey", hex.EncodeToString(pubkey[:]))
	return returnSignature(signature)
}

func (d *DirkSigner) SyncCommitteeContributionAndProofSigning(ctx context.Context, pubkey [48]byte, obj *api.SyncCommitteeContributionAndProofSigning) ([96]byte, *errors.SignerError) {
	hashTreeRoot, err := obj.ContributionAndProof.HashTreeRoot()
	if err != nil {
		d.log.Warn("failed to compute hash tree root", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	// Compute the domain
	domain, err := d.calculateDomain(
		domains.DomainSyncContributionAndProof,
		obj.ForkInfo.GenesisValidatorsRoot,
		&obj.ForkInfo.Fork,
	)
	if err != nil {
		d.log.Warn("failed to compute domain", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	account := d.getAccount(pubkey)
	if account == nil {
		d.log.Warn("account not found in cache", "pubkey", hex.EncodeToString(pubkey[:]))
		return [96]byte{}, errors.ErrPublicKeyNotFound
	}

	signature, err := account.SignGeneric(ctx, hashTreeRoot[:], domain[:])
	if err != nil {
		d.log.Warn("failed to sign sync committee contribution and proof", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}
	d.log.Debug("signed sync committee contribution and proof", "pubkey", hex.EncodeToString(pubkey[:]))
	return returnSignature(signature)
}

func (d *DirkSigner) ValidatorRegistrationSigning(ctx context.Context, pubkey [48]byte, obj *api.ValidatorRegistrationSigning) ([96]byte, *errors.SignerError) {

	msgPubkey := obj.ValidatorRegistration.Pubkey

	if !bytes.Equal(msgPubkey[:], pubkey[:]) {
		d.log.Warn("refusing to sign validator registration with wrong validator identity",
			"msg pubkey", hex.EncodeToString(msgPubkey[:]),
			"url path pubkey", hex.EncodeToString(pubkey[:]))

		return [96]byte{}, errors.ErrBadRequest
	}

	hashTreeRoot, err := obj.ValidatorRegistration.HashTreeRoot()
	if err != nil {
		d.log.Warn("failed to compute hash tree root", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
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
		d.log.Warn("failed to compute domain", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}

	account := d.getAccount(pubkey)
	if account == nil {
		d.log.Warn("account not found in cache", "pubkey", hex.EncodeToString(pubkey[:]))
		return [96]byte{}, errors.ErrPublicKeyNotFound
	}

	signature, err := account.SignGeneric(ctx, hashTreeRoot[:], domain[:])
	if err != nil {
		d.log.Warn("failed to sign validator registration", "error", err)
		return [96]byte{}, errors.ErrInternalServerError
	}
	d.log.Debug("signed validator registration", "pubkey", hex.EncodeToString(pubkey[:]))
	return returnSignature(signature)
}
