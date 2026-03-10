package domains

type DomainType [4]byte

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
