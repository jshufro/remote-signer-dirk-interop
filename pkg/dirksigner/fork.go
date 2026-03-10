package dirksigner

import (
	"github.com/OffchainLabs/prysm/v7/beacon-chain/core/signing"
	"github.com/jshufro/remote-signer-dirk-interop/internal/api"
	"github.com/jshufro/remote-signer-dirk-interop/internal/domains"
	"github.com/jshufro/remote-signer-dirk-interop/internal/errors"
)

func (d *DirkSigner) domain(domainType domains.DomainType, genesisValidatorsRoot []byte, fork *api.Fork) ([]byte, error) {
	forkVersion, err := decodeHex(*fork.CurrentVersion)
	if err != nil {
		return nil, errors.ErrBadRequest
	}
	if len(forkVersion) != 4 {
		return nil, errors.ErrBadRequest
	}

	out, nErr := signing.ComputeDomain(
		domainType,
		forkVersion,
		genesisValidatorsRoot[:],
	)
	if nErr != nil {
		d.log.Warn("failed to compute domain", "error", nErr)
		return nil, errors.ErrInternalServerError
	}
	return out, nil
}
