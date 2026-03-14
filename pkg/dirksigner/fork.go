package dirksigner

import (
	"github.com/OffchainLabs/prysm/v7/beacon-chain/core/signing"
	"github.com/jshufro/remote-signer-dirk-interop/internal/api"
	"github.com/jshufro/remote-signer-dirk-interop/internal/domains"
	"github.com/jshufro/remote-signer-dirk-interop/internal/errors"
)

func (d *DirkSigner) calculateDomain(domainType domains.DomainType, genesisValidatorsRoot string, fork *api.Fork) ([]byte, error) {
	genesisValidatorsRootBytes, err := decodeHex(genesisValidatorsRoot)
	if err != nil {
		return nil, errors.BadRequest("failed to decode genesis validators root: %w", err)
	}

	forkVersion, err := decodeHex(fork.CurrentVersion)
	if err != nil {
		return nil, errors.BadRequest("failed to decode fork version: %w", err)
	}
	if len(forkVersion) != 4 {
		return nil, errors.BadRequest("fork version is not 4 bytes")
	}

	out, nErr := signing.ComputeDomain(
		domainType,
		forkVersion,
		genesisValidatorsRootBytes,
	)
	if nErr != nil {
		d.log.Warn("failed to compute domain", "error", nErr)
		return nil, errors.InternalServerError()
	}
	return out, nil
}
