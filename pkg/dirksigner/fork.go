package dirksigner

import (
	"fmt"
	"strconv"

	"github.com/OffchainLabs/prysm/v7/beacon-chain/core/signing"
	"github.com/jshufro/remote-signer-dirk-interop/internal/api"
	"github.com/jshufro/remote-signer-dirk-interop/internal/domains"
	"github.com/jshufro/remote-signer-dirk-interop/internal/errors"
)

func (d *DirkSigner) calculateDomain(
	domainType domains.DomainType,
	genesisValidatorsRoot string,
	epoch uint64,
	fork *api.Fork,
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

	out, nErr := signing.ComputeDomain(
		domainType,
		forkVersion,
		genesisValidatorsRootBytes,
	)
	d.log.Debug("computed domain", "domain", fmt.Sprintf("%#x", out))
	if nErr != nil {
		d.log.Warn("failed to compute domain", "error", nErr)
		return nil, errors.InternalServerError()
	}
	return out, nil
}
