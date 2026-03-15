package test

import (
	_ "embed"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/OffchainLabs/go-bitfield"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jshufro/remote-signer-dirk-interop/internal/api"
	"github.com/jshufro/remote-signer-dirk-interop/test/dirkdaemon/proc/distributedwallet"
)

var Wallet1PublicKeys = []string{
	"0xb89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b",
	"0x9977f1c8b731a8d5558146bfb86caea26434f3c5878b589bf280a42c9159e700e9df0e4086296c20b011d2e78c27d373",
	"0x9314c6de0386635e2799af798884c2ea09c63b9f079e572acc00b06a7faccce501ea4dfc0b1a23b8603680a5e3481327",
	"0xaec922bd7a9b7b1dc21993133b586b0c3041c1e2e04b513e862227b9d7aecaf9444222f7e78282a449622ffc6278915d",
	"0x872c61b4a7f8510ec809e5b023f5fdda2105d024c470ddbbeca4bc74e8280af0d178d749853e8f6a841083ac1b4db98f",
	"0x903e2989e7442ee0a8958d020507a8bd985d3974f5e8273093be00db3935f0500e141b252bd09e3728892c7a8443863c",
	"0x88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e",
	"0xa99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c",
	"0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b",
	"0x9893413c00283a3f9ed9fd9845dda1cea38228d22567f9541dccc357e54a2d6a6e204103c92564cbc05f4905ac7c493a",
	"0xa8d4c7c27795a725961317ef5953a7032ed6d83739db8b0e8a72353d1b8b4439427f7efa2c89caa03cc9f28f8cbab8ac",
	"0xa6d310dbbfab9a22450f59993f87a4ce5db6223f3b5f1f30d2c4ec718922d400e0b3c7741de8e59960f72411a0ee10a7",
	"0x81283b7a20e1ca460ebd9bbd77005d557370cabb1f9a44f530c4c4c66230f675f8df8b4c2818851aa7d77a80ca5a4a5e",
	"0x84398f539a64cbe01cfcd8c485ea51cd6657b94df93ee9b5dc61e1f18f69da6ca9d4dba63c956a81c68d5d4d4277a60f",
	"0xab0bdda0f85f842f431beaccf1250bf1fd7ba51b4100fd64364b6401fda85bb0069b3e715b58819684e7fc0b10a72a34",
	"0x876dd4705157eb66dc71bc2e07fb151ea53e1a62a0bb980a7ce72d15f58944a8a3752d754f52f4a60dbfc7b18169f268",
}

var InteropTestAccountStr = Wallet1PublicKeys[14]
var InteropTestAccount = [48]byte{}
var TestFeeRecipientStr = "0x6fdfab408c56b6105a76eff5c0435d09fc6ed7a9"
var TestFeeRecipient = [20]byte{}
var TestTimestampUnix = int64(1663224162)
var TestTimestamp time.Time

var TestRoot1Str = "0x9281f35130db9307986fb7c4fe38ca5554f725982f9ccde6a5b12d77b001bdfa"
var TestRoot1 = [32]byte{}

var TestBitVector128Str = "0x7eb8ced4cdc41f5d613bc2d084ed33b9"
var TestBitVector128 = bitfield.Bitvector128{}

var TestSignature1Str = "0x2d3acecfd98643ec07510f45984c4d9ac6e375891150e5fe32cfd8df1d4a9981a7d70d204c5830418499a4cae51282d4b9a25cb0add760d7b23bcb4f6790b9e020551e4cc40d6003610690be41600179f92035ac754eefecc3c6b4a4b57a8b13"
var TestSignature1 = [96]byte{}

var TestProof1Str = "0xab372435c0a4725fd394815a9a24849c9c25af6b4d9b6d5c43dffc9cfb124a27059d17b5b5ab716efebf8c180912fdb70451eaaff7fdf3c289cdfa025166f6acb4d8b69f4ec87aea7186ec4bf5c36dec118b9d7c26b45c9ec892235e75fd3700"
var TestProof1 = [96]byte{}

var NotFoundPubkeyStr = "0x222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"

//go:embed testdata/phase0-beacon-block.json
var phase0BeaconBlock string

//go:embed testdata/altair-beacon-block.json
var altairBeaconBlock string

//go:embed testdata/bellatrix-beacon-block.json
var bellatrixBeaconBlock string

//go:embed testdata/capella-beacon-block.json
var capellaBeaconBlock string

//go:embed testdata/deneb-beacon-block.json
var denebBeaconBlock string

//go:embed testdata/electra-beacon-block.json
var electraBeaconBlock string

//go:embed testdata/fulu-beacon-block.json
var fuluBeaconBlock string

//go:embed testdata/phase0-aggregate-and-proof.json
var phase0AggregateAndProof string

//go:embed testdata/electra-aggregate-and-proof.json
var electraAggregateAndProof string

func init() {
	interopTestAccount, err := hex.DecodeString(strings.TrimPrefix(InteropTestAccountStr, "0x"))
	if err != nil {
		panic(err)
	}
	copy(InteropTestAccount[:], interopTestAccount)
	testFeeRecipient, err := hex.DecodeString(strings.TrimPrefix(TestFeeRecipientStr, "0x"))
	if err != nil {
		panic(err)
	}
	copy(TestFeeRecipient[:], testFeeRecipient)
	TestTimestamp = time.Unix(TestTimestampUnix, 0)
	testRoot1, err := hex.DecodeString(strings.TrimPrefix(TestRoot1Str, "0x"))
	if err != nil {
		panic(err)
	}
	copy(TestRoot1[:], testRoot1)
	testBitVector128, err := hex.DecodeString(strings.TrimPrefix(TestBitVector128Str, "0x"))
	if err != nil {
		panic(err)
	}
	TestBitVector128 = bitfield.Bitvector128(testBitVector128)
	testSignature1, err := hex.DecodeString(strings.TrimPrefix(TestSignature1Str, "0x"))
	if err != nil {
		panic(err)
	}
	copy(TestSignature1[:], testSignature1)
	testProof1, err := hex.DecodeString(strings.TrimPrefix(TestProof1Str, "0x"))
	if err != nil {
		panic(err)
	}
	copy(TestProof1[:], testProof1)
}

type SigningTestCase struct {
	Pubkey             string
	SignableMsg        any
	RawBody            string
	ExpectedSignature  string
	ExpectedHttpStatus int
}

var fork = struct {
	Fork                  api.Fork `json:"fork"`
	GenesisValidatorsRoot string   `json:"genesis_validators_root"`
}{
	Fork: api.Fork{
		CurrentVersion:  "0x03000000",
		PreviousVersion: "0x02000000",
		Epoch:           "555333",
	},
	GenesisValidatorsRoot: TestRoot1Str,
}

func validatorRegistrationSigning(pubkey phase0.BLSPubKey) *api.ValidatorRegistrationSigning {
	return &api.ValidatorRegistrationSigning{
		Type: api.VALIDATORREGISTRATION,
		ValidatorRegistration: api.ValidatorRegistration{
			FeeRecipient: TestFeeRecipient,
			GasLimit:     60000000,
			Timestamp:    TestTimestamp,
			Pubkey:       pubkey,
		},
	}
}

func syncCommitteeContributionAndProofSigning() *api.SyncCommitteeContributionAndProofSigning {
	return &api.SyncCommitteeContributionAndProofSigning{
		Type: api.SYNCCOMMITTEECONTRIBUTIONANDPROOF,
		ContributionAndProof: api.ContributionAndProof{
			AggregatorIndex: 100,
			Contribution: &altair.SyncCommitteeContribution{
				Slot:              1000,
				BeaconBlockRoot:   TestRoot1,
				SubcommitteeIndex: 10,
				AggregationBits:   TestBitVector128,
				Signature:         TestSignature1,
			},
			SelectionProof: TestProof1,
		},
		ForkInfo: fork,
	}
}

func syncCommitteeSelectionProofSigning() *api.SyncCommitteeSelectionProofSigning {
	return &api.SyncCommitteeSelectionProofSigning{
		Type: api.SYNCCOMMITTEESELECTIONPROOF,
		SyncAggregatorSelectionData: api.SyncAggregatorSelectionData{
			Slot:              1000,
			SubcommitteeIndex: 10,
		},
		ForkInfo: fork,
	}
}

func syncCommitteeMessageSigning() *api.SyncCommitteeMessageSigning {
	return &api.SyncCommitteeMessageSigning{
		Type: api.SYNCCOMMITTEEMESSAGE,
		SyncCommitteeMessage: api.SyncCommitteeMessage{
			Slot:            1000,
			BeaconBlockRoot: TestRoot1,
			ValidatorIndex:  100,
			Signature:       TestSignature1,
		},
		ForkInfo: fork,
	}
}

func voluntaryExitSigning() *api.VoluntaryExitSigning {
	return &api.VoluntaryExitSigning{
		Type: api.VOLUNTARYEXIT,
		VoluntaryExit: api.VoluntaryExit{
			Epoch:          1000,
			ValidatorIndex: 100,
		},
		ForkInfo: fork,
	}
}

func randaoRevealSigning() *api.RandaoRevealSigning {
	return &api.RandaoRevealSigning{
		Type: api.RANDAOREVEAL,
		RandaoReveal: api.RandaoReveal{
			Epoch: "1000",
		},
		ForkInfo: fork,
	}
}

func depositSigning(pubkeyStr string) *api.DepositSigning {
	return &api.DepositSigning{
		Type: api.DEPOSIT,
		Deposit: struct {
			Amount                string `json:"amount,omitempty"`
			GenesisForkVersion    string `json:"genesis_fork_version,omitempty"`
			Pubkey                string `json:"pubkey,omitempty"`
			WithdrawalCredentials string `json:"withdrawal_credentials,omitempty"`
		}{
			Amount:                "32000000000",
			GenesisForkVersion:    "0x01017000",
			Pubkey:                pubkeyStr,
			WithdrawalCredentials: "0x0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
}

func attestationSigning() *api.AttestationSigning {
	return &api.AttestationSigning{
		Type: api.ATTESTATION,
		Attestation: api.AttestationData{
			Slot:            1000,
			Index:           100,
			BeaconBlockRoot: TestRoot1,
			Source: &phase0.Checkpoint{
				Epoch: 99,
				Root:  TestRoot1,
			},
			Target: &phase0.Checkpoint{
				Epoch: 100,
				Root:  TestRoot1,
			},
		},
		ForkInfo: fork,
	}
}

func aggregationSlotSigning() *api.AggregationSlotSigning {
	return &api.AggregationSlotSigning{
		Type: api.AGGREGATIONSLOT,
		AggregationSlot: struct {
			Slot string `json:"slot,omitempty"`
		}{
			Slot: "1000",
		},
		ForkInfo: fork,
	}
}

func InteropSigningTestCases() []SigningTestCase {
	pubkeyStr := InteropTestAccountStr
	pubkey := InteropTestAccount
	return []SigningTestCase{
		{
			Pubkey:             NotFoundPubkeyStr,
			SignableMsg:        &api.ValidatorRegistrationSigning{},
			ExpectedHttpStatus: http.StatusNotFound,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        validatorRegistrationSigning(pubkey),
			ExpectedSignature:  "0x98179bc50f1f7b14cd451b16ccb697cd437692d1a1a51dade6601892f4629a32468e049ea7905502c8c7b2a0f642d78d101f8369095e66a75f399d6347a3f18d86b9eac030753aeb54faf33a4997abb52610929deb81b90ff74c41c8393a9a23",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        syncCommitteeContributionAndProofSigning(),
			ExpectedSignature:  "0x83080f88390cac2e49da4897e17c52c59e761b2d63ce24cf34f24671a5fcd3ee5416dc1298e4aade7abffa453229263b19cbff8fc2b66dbba23b3ffdc5bab3b5615b75dd682c8e628c6f7897c7823daf35eaf45944947f71e35bab3cc4a6eaa6",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        syncCommitteeSelectionProofSigning(),
			ExpectedSignature:  "0x891950d5049e83c29bce012a01043642e6a9ae1e44bf7f4b42e453cfdd18959f3a822ced199b257106fed0f24509022817c355cbb165198fdd3baaf805130fa842397be1fbced4e8f3e00e3efc86d92f3fec1969f5d323a2ef97ccd0953292f5",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        syncCommitteeMessageSigning(),
			ExpectedSignature:  "0x94a419a2a09d02074682804b5a5bc5da56cfaabb9f869eacf4bb2b0ad97b830d47100913705eed967a3c390c85c4acf012e1485630fb3844880b574bd52b5b719e240fe04ebe38eefd228b56f47dcbfce3e78d6de9c9d4ed4f314c6c1e0eae1b",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        voluntaryExitSigning(),
			ExpectedSignature:  "0xb6d30c6ff0761a4b2cdf7a503bb67cf6c1d54b81829fbf3280e7fa469ceec2df90ecc0886040f6801ef6c9f0576962f30948fd21bad6db021d06458c7f6be4bdc8292692fe3b3982c5161cad06c4989793ec8741aa9615f658d2c717382bfa71",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        randaoRevealSigning(),
			ExpectedSignature:  "0xa4437051b853c1b51f383104d090842984c3b22669e99795a61faf8efdd6fab1c76d97063d55d0be609973d9492811a7139ae82fd6a06a098157c6cbb65b196a2b344e7b6a04a84bf6b8f0717b0817cd478cbb2f39ceb66a38fd4c5d29202bee",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        depositSigning(pubkeyStr),
			ExpectedSignature:  "0x939724b72c6126480aeccf793e6bc0966df7ca172fcc070a31965240bc5ea4161bcf58b46dda97c956cf9356a9120b37094ed2897604a828d23ed408c5bf643acd513b6b1dd91b8ea679a80f4be7f67d01a777cebb936dbb46e7e5bce99c6c20",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// phase0 beacon block
			Pubkey:             pubkeyStr,
			RawBody:            phase0BeaconBlock,
			ExpectedSignature:  "0x87a4926dd0f0af6a9c52c6ac3246b8d511567010765b3fabf8cfde9676b9dd74cb6ff2b3f6db210afdb4120de41330b20781d29497c36e28d926a9d82515cdf1b7a0d789d93d7c3b73f523f00d8cfcf5e84ac570ae9b35d4bd362a44b902c770",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// altair beacon block
			Pubkey:             pubkeyStr,
			RawBody:            altairBeaconBlock,
			ExpectedSignature:  "0x87368a123e543d0d2ee4882dea2cd5ffb1520861790fa540b05beb087c3f6e71c3f64862dfdf9454918d41e2ae164c160220b73cfe6709e1d6b926c0d24530a58284b6ae4ed420cbc7d1c126721c4180b50f9210ff99f17a142869b178e5e14d",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// bellatrix beacon block
			Pubkey:             pubkeyStr,
			RawBody:            bellatrixBeaconBlock,
			ExpectedSignature:  "0x87641c42e725ee35289649bf2737664e1e8e8c38f881dcc1bc5299d28f1fafd981ebe10631d482f1d51dc88bf2dcb60a04b99587ff80b4bda1c50019cba4b9b2ccbd63778a502780ccaaa8b76688a5d31b19c5f02deaf95e3e46e3b36b0d231c",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// capella beacon block
			Pubkey:             pubkeyStr,
			RawBody:            capellaBeaconBlock,
			ExpectedSignature:  "0x8e6724fcae08afcd2b21735203f58f8a4b47e241cab4f972ab5c3baa6c4caaab91d5f3e28eaaed248e0e0d775d9c9de516739a9f84362d9b846bd9636e54f3f5a5d2151caf2a87cb786c3819d333f7c0fc215168d93e1695f69df2d4f3450f5b",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// deneb beacon block
			Pubkey:             pubkeyStr,
			RawBody:            denebBeaconBlock,
			ExpectedSignature:  "0xa5822c20ecc4fd73ccb1f2e2becfa0c0e47f2e1bd1fe9b206889c966a0e49e9cebb376e1142bd9b64c23253cd09fcda01117cd5cbea6ba844f8aac8190b5963c79ea5d4edd054db418db18c1569fa6943c914b2473a05f07af3f80e81eb9c75f",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// electra beacon block
			Pubkey:             pubkeyStr,
			RawBody:            electraBeaconBlock,
			ExpectedSignature:  "0xb1a3df65bb9553348a686ac74048eee7e7eaee7e285149c8a449f416fcb8dcae668c495009f86552a9eba49e24afde2f087c80a2ccd030fd3929c68646f49f041541c0ffda32d3dbee16f478bd1cf938ee3cdb25474c2b5635ee6793e4ba77d6",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// fulu beacon block
			Pubkey:             pubkeyStr,
			RawBody:            fuluBeaconBlock,
			ExpectedSignature:  "0xb2409cb8abd33100df79cf2bc43902a35e30edea76f2a0b839ad3ebc6d9d21372ce644d6d76ada4c2efb825a91780d9813c2d19ddbd296b44fd52f441eb7488e8b222c0ee6ff9608793dc323b04bb6beb3fcdf21830b80f7b1e10518354f539d",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// attestation
			Pubkey:             pubkeyStr,
			SignableMsg:        attestationSigning(),
			ExpectedSignature:  "0x85543afe60d6b8623edc5466ef3a40bcd8a3027ef54369aa69c6222b78cf6125585c91037f85236b679b066980a3b2ca13ba2038ab24787139f89f3726f603b027139b28c2720463808096a679d8849c6f27c5b36aa15874daa87fcf6d77de25",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// aggregate and proof phase0
			Pubkey:             pubkeyStr,
			RawBody:            phase0AggregateAndProof,
			ExpectedSignature:  "0x8c8f28029e20eed22aaf4bfa2963af48373f0ce93bddf8a5dba7174054be780aaba5c8ff6530d58840618a59b5e6c24307206dbef6c70885878fb33c60fbaef1e3150f173307810040f158cd7e2d09266eec35c999006a226ab202b6d509e54c",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// aggregate and proof electra
			Pubkey:             pubkeyStr,
			RawBody:            electraAggregateAndProof,
			ExpectedSignature:  "0x90b96e7e07b815a7592c7958dd780296c11f3854a94867bf3c1ea0eec7c518e68443ceb643a63f08d419905c446de438017983727097337b271205641334664b066705eb9a4992c8bac6b59ecd07222ad48b1a4a0539ec6a6205bf0295dade2a",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// aggregation slot sligning
			Pubkey:             pubkeyStr,
			SignableMsg:        aggregationSlotSigning(),
			ExpectedSignature:  "0xb889f33d9a7bef1b93d950bf60e6f6a7582afa9787c396b329cdd36c1c0d31d91d14a1ebca7839429342a63515b557f20946df9bc32cc07353001a606bf388f6eb4e1702b69b938f7fa6bfe24584f5057ad2505cf03c1014bd09ccabab67c304",
			ExpectedHttpStatus: http.StatusOK,
		},
	}
}

func DistributedSigningTestCases() []SigningTestCase {
	pubkeyStr := distributedwallet.DistributedAccountPubkeyStr
	pubkey := distributedwallet.DistributedAccountPubkey
	return []SigningTestCase{
		{
			Pubkey:             NotFoundPubkeyStr,
			SignableMsg:        &api.ValidatorRegistrationSigning{},
			ExpectedHttpStatus: http.StatusNotFound,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        validatorRegistrationSigning(pubkey),
			ExpectedSignature:  "0x93eb9e6bfb1eddecc12e8e59252229f04f22121a71a121df15b2f8c5e7a1db382c8efdf38027a1fba39de474942f48d9068a317ed47df78c9846538116b9025195d211721e45b0cd2deb04cea27c95743fb6a650cb7d6ac79257a780ea34d259",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        syncCommitteeContributionAndProofSigning(),
			ExpectedSignature:  "0x858344f4ae00aec1b692f1d0da4c16ca31f154ba61aa91f0c1a1a65e95d18ecc525a943a6b1305e610bb330c849ea43d02c983c603eb8540220fbd8bf56a76097a12ad71e0a45ea2c7aedb2d6d9333ca44f3030b7b7e0bca44691b7ab717c31a",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        syncCommitteeSelectionProofSigning(),
			ExpectedSignature:  "0x99fecf337d970b790ba6cbcb6ac12685a081c70940ee98d9e58a276a1c7a27130942e2587eee1bf28cee06b2782422e207bcd7c26c68581f91c8b7480296d0b4a86e4a6a31b63b809ea9cdcc6386d5acb0bb98bb6da1747911b1ccd9d53bb74f",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        syncCommitteeMessageSigning(),
			ExpectedSignature:  "0x8957ad63251fe542e02d228a588b7ccfdeff7be7b933f1b191ff039baf10a99247984a31c459edd04d2f821e192f538c136fc579841694f32006339d543fc292a820ce8d4de687161d84ee9d32c589b059820972bf91b34219e7f7e63e6dcc83",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        voluntaryExitSigning(),
			ExpectedSignature:  "0x88faac0bfbcf4c0916ad6be44ae820d8d255e334fd296f7348ce78745e66fa5bae41a9e4475e9e7bfc74a2d5d3e7308d145e00b3a24fa602ba5fdbebb36de632594314babea2919dff48ddcb21fa797b7efefd389acd4ccb43483ca4c401eb14",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        randaoRevealSigning(),
			ExpectedSignature:  "0x91a352f1689dba1154ba79910568787a135178b83c112cdb0775128f3c020d32202b8deafa1fe67616e1bcbb84a450f707f4207757bb5d6dc523445a4edf3a39d0a223dfefd607c06b5f231dde958b487cf3b203fd5b12c014e0daee062688b3",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        depositSigning(pubkeyStr),
			ExpectedSignature:  "0x8d24184efeddf504c43524b94fbdaf0ea2889ac287fcdfa02ce77b3e590f6a8ebb9488e763dafde06fc2f6a2575375f4005fcc3b976e7a259472adab22372b385621a68f9ec3f80ec0d6cca5ba2a22b3a8415ef38a2cb586849dcf571fa2c253",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// phase0 beacon block
			Pubkey:             pubkeyStr,
			RawBody:            phase0BeaconBlock,
			ExpectedSignature:  "0xa5072f5035079b11faf86021202ff216cb0c75cb0a9657e133cc4d3fc66707fb6e02590be545af81fdb5672b3b16d9d10eab564961b74e5d54add66ebe7de5eb81093d5f597445fb5c14ef5362549f063f9b0a0abd20fbf07b862e5233e605c2",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// altair beacon block
			Pubkey:             pubkeyStr,
			RawBody:            altairBeaconBlock,
			ExpectedSignature:  "0x981420fe0087df6ae30dab4ade0269a3c1ca513a5c9e8aa51e5beddc2b90731b5632f56f2403a2596a062ca02cb22c3c067ae818eaac82a8c61c36dbf77cad0f50887bec05bf5a2974107266b0c4263b4ca7d10a27b556758a015f074ac0b530",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// bellatrix beacon block
			Pubkey:             pubkeyStr,
			RawBody:            bellatrixBeaconBlock,
			ExpectedSignature:  "0x83839c77840daaf9ed70b1c89c46202b94fc8e0826a01003488199e6df7d4345c70cf370426c18921680dd07e7997ecf159d892b14431e677fb0e06c635774a5e34f9c4ee539d2bc3546d963c05cd74a868586229188d60847a98dfba6dd0bc2",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// capella beacon block
			Pubkey:             pubkeyStr,
			RawBody:            capellaBeaconBlock,
			ExpectedSignature:  "0x811a3c98a83c799aa011faeef09c2be15014f3d489ef131b6bcbac531c234199c5f8c70d05ed53f2ed7aceb2a659f58a0694ad99eaa6b333f92d29e88de8a8e75b50b348656a90659b26d4e836397c575e9b5964b7b36a55e87d824a853c2284",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// deneb beacon block
			Pubkey:             pubkeyStr,
			RawBody:            denebBeaconBlock,
			ExpectedSignature:  "0xad724c0cff44374a7c7e5ad804218e6371be5cb75d33424cfd61b9261988c9459e55ba1a90423efa9065e517a4dfbf11150a6eb6279579b20753a3fa133742ca446e80e13807ff020cef55b8e97b5b6d12bca7f480e1bd5c19c5c702c6248573",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// electra beacon block
			Pubkey:             pubkeyStr,
			RawBody:            electraBeaconBlock,
			ExpectedSignature:  "0x9378e76689bcd578ce92f0a6505ec3a5734d7e770434fef1becdf206f1e4a75ad2bb9110c70c8c0fcfe68c07f8200a17126242899b0df5393dbb0d50e12b11ffd87e689e159fe2ed1bfd03d0ecf1c7352eec067e712f950d556eb6ee8236a4d1",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// fulu beacon block
			Pubkey:             pubkeyStr,
			RawBody:            fuluBeaconBlock,
			ExpectedSignature:  "0xa57125b94aeb4020a20fc7d3a1018a1782a4608b5549a761427daacabd2ccc85584377f566e087384560c4b89c4cbe350b809ccae4ee5201ac34c241a9ffcb4c2af5bef37537584b81c22cc3dc3c825e72c83033e0e842f0746b16e4df3550c9",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// attestation
			Pubkey:             pubkeyStr,
			SignableMsg:        attestationSigning(),
			ExpectedSignature:  "0x8ea44d899dcba6be17174867906f30c114fa43e93d559731357f445f4c735a99ea84cedd6da591c42f04fdf726a6d29c00c04aa8d8f7d7cb4a80acb5d0c6528ef56fc7687d0ec8f83d6a788d3116d20dbe52f952ea3988819c42186de41553df",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// aggregate and proof phase0
			Pubkey:             pubkeyStr,
			RawBody:            phase0AggregateAndProof,
			ExpectedSignature:  "0x948374e0d1cee36e83a9a9605994b250686748fe2280be4b5808fe1451a76bc2c97ce7aca81490499b487de921f87e820fa8dced7ad65ef847d61b42ac2c38f0742e3e93ad4d551a9209ee549279745b4d8692d4798c181880df746f5be9b6b3",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// aggregate and proof electra
			Pubkey:             pubkeyStr,
			RawBody:            electraAggregateAndProof,
			ExpectedSignature:  "0x99dcab3d9f2bdcdf5d55087ca029992d0e6e604c116a6284c7a61caa072d94dffc950251e2688623e3a911a24cbb27fc1214a89eb7fa9d081cea7d19c5b2b33f21539b3687ea6fb58e25292174b8a914e8a6d8eb9cdcbed5972c6f39e1907c65",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// aggregation slot sligning
			Pubkey:             pubkeyStr,
			SignableMsg:        aggregationSlotSigning(),
			ExpectedSignature:  "0x957a9432ec632e1bbb4af8a047fa65b01bf29bf330af7f2a368c22130df2436c728ea5bce776fd62df276a9a04106015019dff6026e7a6abcfe2f53828c5c6c14c9864b814b1790317160f3141a79a8ce408205f1e008a9ced84f9f421de2cac",
			ExpectedHttpStatus: http.StatusOK,
		},
	}
}
