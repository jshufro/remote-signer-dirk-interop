package domains

import (
	"crypto/sha256"
	"hash"
	"sync"
)

type DomainType [4]byte
type Domain [32]byte
type ForkVersion [4]byte
type Root [32]byte

var sha256Pool = sync.Pool{
	New: func() any {
		return sha256.New()
	},
}

func ComputeDomain(domainType DomainType, forkVersion [4]byte, genesisValidatorsRoot [32]byte) Domain {

	buf := [32]byte{}
	copy(buf[:4], forkVersion[:])

	// sha256(paddedForkVersion || genesisValidatorsRoot)
	hash := sha256Pool.Get().(hash.Hash)
	defer sha256Pool.Put(hash)
	hash.Write(buf[:])
	hash.Write(genesisValidatorsRoot[:])
	copy(buf[0:4], domainType[:])
	copy(buf[4:], hash.Sum(nil))
	defer hash.Reset()

	return buf
}

func DepositDomain(genesisForkVersion ForkVersion) Domain {
	return ComputeDomain(
		DomainDeposit,
		genesisForkVersion,
		Root{},
	)
}

func ValidatorRegistrationDomain(genesisForkVersion ForkVersion) Domain {
	return ComputeDomain(
		DomainApplicationBuilder,
		genesisForkVersion,
		Root{},
	)
}

var (
	// phase0
	DomainBeaconProposer    = DomainType{0x00, 0x00, 0x00, 0x00}
	DomainBeaconAttester    = DomainType{0x01, 0x00, 0x00, 0x00}
	DomainRandao            = DomainType{0x02, 0x00, 0x00, 0x00}
	DomainDeposit           = DomainType{0x03, 0x00, 0x00, 0x00}
	DomainVoluntaryExit     = DomainType{0x04, 0x00, 0x00, 0x00}
	DomainSelectionProof    = DomainType{0x05, 0x00, 0x00, 0x00}
	DomainAggregateAndProof = DomainType{0x06, 0x00, 0x00, 0x00}

	DomainApplicationMask = DomainType{0x00, 0x00, 0x00, 0x01}

	// altair
	DomainSyncCommittee              = DomainType{0x07, 0x00, 0x00, 0x00}
	DomainSyncCommiteeSelectionProof = DomainType{0x08, 0x00, 0x00, 0x00}
	DomainSyncContributionAndProof   = DomainType{0x09, 0x00, 0x00, 0x00}

	// capella
	DomainBlsToExecutionChange = DomainType{0x0A, 0x00, 0x00, 0x00}

	// non-spec domains
	// builder domain is just (0x00 | ApplicationMask)
	DomainApplicationBuilder = DomainApplicationMask
)
