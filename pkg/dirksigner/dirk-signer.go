package dirksigner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/OffchainLabs/prysm/v7/beacon-chain/core/signing"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/jshufro/remote-signer-dirk-interop/internal/api"
	"github.com/jshufro/remote-signer-dirk-interop/internal/domains"
	"github.com/jshufro/remote-signer-dirk-interop/internal/errors"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/dirksigner/accountcache"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/signer"
	tlsprovider "github.com/jshufro/remote-signer-dirk-interop/pkg/tls"
	"google.golang.org/grpc/credentials"

	ethpb "github.com/OffchainLabs/prysm/v7/proto/prysm/v1alpha1"
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
	return [96]byte{}, nil
}

func (d *DirkSigner) AggregateAndProofSigning(ctx context.Context, pubkey [48]byte, obj *api.AggregateAndProofSigning) ([96]byte, *errors.SignerError) {
	return [96]byte{}, nil
}

func (d *DirkSigner) AggregateAndProofSigningV2(ctx context.Context, pubkey [48]byte, obj *api.AggregateAndProofSigningV2) ([96]byte, *errors.SignerError) {
	return [96]byte{}, nil
}

func (d *DirkSigner) AttestationSigning(ctx context.Context, pubkey [48]byte, obj *api.AttestationSigning) ([96]byte, *errors.SignerError) {
	return [96]byte{}, nil
}

func (d *DirkSigner) BlockSigning(ctx context.Context, pubkey [48]byte, obj *api.BlockSigning) ([96]byte, *errors.SignerError) {
	return [96]byte{}, nil
}

func (d *DirkSigner) BeaconBlockSigning(ctx context.Context, pubkey [48]byte, obj *api.BeaconBlockSigning) ([96]byte, *errors.SignerError) {
	return [96]byte{}, nil
}

func (d *DirkSigner) DepositSigning(ctx context.Context, pubkey [48]byte, obj *api.DepositSigning) ([96]byte, *errors.SignerError) {
	return [96]byte{}, nil
}

func (d *DirkSigner) RandaoRevealSigning(ctx context.Context, pubkey [48]byte, obj *api.RandaoRevealSigning) ([96]byte, *errors.SignerError) {
	return [96]byte{}, nil
}

func (d *DirkSigner) VoluntaryExitSigning(ctx context.Context, pubkey [48]byte, obj *api.VoluntaryExitSigning) ([96]byte, *errors.SignerError) {
	return [96]byte{}, nil
}

func (d *DirkSigner) SyncCommitteeMessageSigning(ctx context.Context, pubkey [48]byte, obj *api.SyncCommitteeMessageSigning) ([96]byte, *errors.SignerError) {
	return [96]byte{}, nil
}

func (d *DirkSigner) SyncCommitteeSelectionProofSigning(ctx context.Context, pubkey [48]byte, obj *api.SyncCommitteeSelectionProofSigning) ([96]byte, *errors.SignerError) {
	return [96]byte{}, nil
}

func (d *DirkSigner) SyncCommitteeContributionAndProofSigning(ctx context.Context, pubkey [48]byte, obj *api.SyncCommitteeContributionAndProofSigning) ([96]byte, *errors.SignerError) {
	contribution := obj.ContributionAndProof.Contribution

	aggregatorIndex, err := decodeValidatorIndex(obj.ContributionAndProof.AggregatorIndex)
	if err != nil {
		d.log.Warn("failed to decode aggregator index", "error", err, "aggregator index", obj.ContributionAndProof.AggregatorIndex)
		return [96]byte{}, err
	}

	aggregationBits, err := decodeBitVector128(contribution.AggregationBits)
	if err != nil {
		d.log.Warn("failed to decode aggregation bits", "error", err, "aggregation bits", contribution.AggregationBits)
		return [96]byte{}, err
	}

	beaconBlockRoot, err := decodeRoot(contribution.BeaconBlockRoot)
	if err != nil {
		d.log.Warn("failed to decode beacon block root", "error", err, "beacon block root", contribution.BeaconBlockRoot)
		return [96]byte{}, err
	}

	contributionSignature, err := decodeSignature(contribution.Signature)
	if err != nil {
		d.log.Warn("failed to decode signature", "error", err, "signature", contribution.Signature)
		return [96]byte{}, err
	}

	slot, err := decodeSlot(contribution.Slot)
	if err != nil {
		d.log.Warn("failed to decode slot", "error", err, "slot", contribution.Slot)
		return [96]byte{}, err
	}

	subcommitteeIndex, err := decodeUint64(contribution.SubcommitteeIndex)
	if err != nil {
		d.log.Warn("failed to decode subcommittee index", "error", err, "subcommittee index", contribution.SubcommitteeIndex)
		return [96]byte{}, err
	}

	selectionProof, err := decodeSignature(obj.ContributionAndProof.SelectionProof)
	if err != nil {
		d.log.Warn("failed to decode selection proof", "error", err, "selection proof", obj.ContributionAndProof.SelectionProof)
		return [96]byte{}, err
	}

	genesisValidatorsRoot, err := decodeRoot(obj.ForkInfo.GenesisValidatorsRoot)
	if err != nil {
		d.log.Warn("failed to decode genesis validators root", "error", err, "genesis validators root", obj.ForkInfo.GenesisValidatorsRoot)
		return [96]byte{}, err
	}

	// Parse everything into ethpb.SyncCommitteeContributionAndProof
	contributionAndProof := &ethpb.ContributionAndProof{
		AggregatorIndex: aggregatorIndex,
		Contribution: &ethpb.SyncCommitteeContribution{
			AggregationBits:   aggregationBits,
			BlockRoot:         beaconBlockRoot[:],
			Signature:         contributionSignature[:],
			Slot:              slot,
			SubcommitteeIndex: subcommitteeIndex,
		},
		SelectionProof: selectionProof[:],
	}

	hashTreeRoot, nErr := contributionAndProof.HashTreeRoot()
	if nErr != nil {
		d.log.Warn("failed to compute hash tree root", "error", nErr)
		return [96]byte{}, errors.ErrInternalServerError
	}

	// Compute the domain
	domain, nErr := d.domain(domains.DomainSyncContributionAndProof, genesisValidatorsRoot[:], &obj.ForkInfo.Fork)
	if nErr != nil {
		d.log.Warn("failed to compute domain", "error", nErr)
		return [96]byte{}, errors.ErrInternalServerError
	}

	account := d.getAccount(pubkey)
	if account == nil {
		d.log.Warn("account not found in cache", "pubkey", hex.EncodeToString(pubkey[:]))
		return [96]byte{}, errors.ErrPublicKeyNotFound
	}

	signature, nErr := account.SignGeneric(ctx, hashTreeRoot[:], domain[:])
	if nErr != nil {
		d.log.Warn("failed to sign sync committee contribution and proof", "error", nErr)
		return [96]byte{}, errors.ErrInternalServerError
	}
	d.log.Debug("signed sync committee contribution and proof", "pubkey", hex.EncodeToString(pubkey[:]))
	return returnSignature(signature)
}

func (d *DirkSigner) ValidatorRegistrationSigning(ctx context.Context, pubkey [48]byte, obj *api.ValidatorRegistrationSigning) ([96]byte, *errors.SignerError) {

	feeRecipient, err := feeRecipient(obj.ValidatorRegistration.FeeRecipient)
	if err != nil {
		d.log.Warn("failed to decode fee recipient", "error", err, "fee recipient", obj.ValidatorRegistration.FeeRecipient)
		return [96]byte{}, err
	}

	gasLimit, err := decodeUint64(obj.ValidatorRegistration.GasLimit)
	if err != nil {
		d.log.Warn("failed to decode gas limit", "error", err, "gas limit", obj.ValidatorRegistration.GasLimit)
		return [96]byte{}, err
	}

	timestamp, err := decodeUint64(obj.ValidatorRegistration.Timestamp)
	if err != nil {
		d.log.Warn("failed to decode timestamp", "error", err, "timestamp", obj.ValidatorRegistration.Timestamp)
		return [96]byte{}, err
	}

	// Parse the pubkey and make sure it matches the identifier
	msgPubkey, err := decodeHex(obj.ValidatorRegistration.Pubkey)
	if err != nil {
		d.log.Warn("failed to decode pubkey", "error", err, "pubkey", obj.ValidatorRegistration.Pubkey)
		return [96]byte{}, err
	}

	if !bytes.Equal(msgPubkey, pubkey[:]) {
		d.log.Warn("refusing to sign validator registration with wrong validator identity",
			"msg pubkey", hex.EncodeToString(msgPubkey[:]),
			"url path pubkey", hex.EncodeToString(pubkey[:]))

		return [96]byte{}, errors.ErrBadRequest
	}

	// Copy fields into api.ValidatorRegistration
	validatorRegistration := &ethpb.ValidatorRegistrationV1{
		FeeRecipient: feeRecipient[:],
		GasLimit:     gasLimit,
		Timestamp:    timestamp,
		Pubkey:       pubkey[:],
	}

	hashTreeRoot, nErr := validatorRegistration.HashTreeRoot()
	if nErr != nil {
		d.log.Warn("failed to compute hash tree root", "error", nErr)
		return [96]byte{}, errors.ErrInternalServerError
	}

	// Compute the domain
	// For validator registrations, only genesis fork version is needed
	// genesis validators root must be nil
	domain, nErr := signing.ComputeDomain(
		domains.DomainApplicationBuilder,
		d.genesisForkVersion,
		nil, /* genesis validators root */
	)
	if nErr != nil {
		d.log.Warn("failed to compute domain", "error", nErr)
		return [96]byte{}, errors.ErrInternalServerError
	}

	account := d.getAccount(pubkey)
	if account == nil {
		d.log.Warn("account not found in cache", "pubkey", hex.EncodeToString(pubkey[:]))
		return [96]byte{}, errors.ErrPublicKeyNotFound
	}

	signature, nErr := account.SignGeneric(ctx, hashTreeRoot[:], domain[:])
	if nErr != nil {
		d.log.Warn("failed to sign validator registration", "error", nErr)
		return [96]byte{}, errors.ErrInternalServerError
	}
	d.log.Debug("signed validator registration", "pubkey", hex.EncodeToString(pubkey[:]),
		"fee recipient", hex.EncodeToString(feeRecipient[:]))
	return returnSignature(signature)
}
