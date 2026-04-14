package dirksigner

import (
	"fmt"
	"strconv"

	"github.com/OffchainLabs/prysm/v7/beacon-chain/core/signing"
	api "github.com/jshufro/remote-signer-dirk-interop/generated"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/domains"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/errors"
)

func (d *DirkSigner) calculateDomain(
	domainType domains.DomainType,
	forkInfo struct {
		Fork                  api.Fork `json:"fork"`
		GenesisValidatorsRoot string   `json:"genesis_validators_root"`
	},
	epoch uint64,
) ([]byte, error) {
	out, err := calculateDomainImpl(domainType, &forkInfo.Fork, forkInfo.GenesisValidatorsRoot, epoch)
	if err != nil {
		// Expected error, return it to the caller
		if _, ok := err.(errors.SignerError); ok {
			return nil, err
		}
		// Unexpected error, log and return internal server error
		d.log.Warn("failed to compute domain", "error", err)
		return nil, errors.InternalServerError()
	}
	d.log.Debug("computed domain", "domain", fmt.Sprintf("%#x", out))
	return out, nil
}

func calculateDomainImpl(
	domainType domains.DomainType,
	fork *api.Fork,
	genesisValidatorsRoot string,
	epoch uint64,
) ([]byte, error) {

	genesisValidatorsRootBytes, err := decodeHex(genesisValidatorsRoot)
	if err != nil {
		return nil, errors.BadRequest("failed to decode genesis validators root: %w", err)
	}

	forkEpoch, err := strconv.ParseUint(fork.Epoch, 10, 64)
	if err != nil {
		return nil, errors.BadRequest("failed to parse fork epoch: %w", err)
	}

	var forkVersion []byte
	if epoch < forkEpoch {
		forkVersion, err = decodeHex(fork.PreviousVersion)
		if err != nil {
			return nil, errors.BadRequest("failed to decode previous fork version: %w", err)
		}
	} else {
		forkVersion, err = decodeHex(fork.CurrentVersion)
		if err != nil {
			return nil, errors.BadRequest("failed to decode current fork version: %w", err)
		}
	}
	if len(forkVersion) != 4 {
		return nil, errors.BadRequest("fork version is not 4 bytes")
	}

	return signing.ComputeDomain(
		domainType,
		forkVersion,
		genesisValidatorsRootBytes,
	)
}
