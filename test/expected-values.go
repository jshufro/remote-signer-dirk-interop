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
	api "github.com/jshufro/remote-signer-dirk-interop/generated"
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

var MainnetGenesisValidatorsRootStr = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
var MainnetGenesisValidatorsRoot = [32]byte{}

var TestBitVector128Str = "0x7eb8ced4cdc41f5d613bc2d084ed33b9"
var TestBitVector128 = bitfield.Bitvector128{}

var TestSignature1Str = "0x2d3acecfd98643ec07510f45984c4d9ac6e375891150e5fe32cfd8df1d4a9981a7d70d204c5830418499a4cae51282d4b9a25cb0add760d7b23bcb4f6790b9e020551e4cc40d6003610690be41600179f92035ac754eefecc3c6b4a4b57a8b13"
var TestSignature1 = [96]byte{}

var TestProof1Str = "0xab372435c0a4725fd394815a9a24849c9c25af6b4d9b6d5c43dffc9cfb124a27059d17b5b5ab716efebf8c180912fdb70451eaaff7fdf3c289cdfa025166f6acb4d8b69f4ec87aea7186ec4bf5c36dec118b9d7c26b45c9ec892235e75fd3700"
var TestProof1 = [96]byte{}

var NotFoundPubkeyStr = "0x222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"
var NotFoundPubkey = [48]byte{}

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
	notFoundPubkey, err := hex.DecodeString(strings.TrimPrefix(NotFoundPubkeyStr, "0x"))
	if err != nil {
		panic(err)
	}
	copy(NotFoundPubkey[:], notFoundPubkey)
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
	mainnetGenesisValidatorsRoot, err := hex.DecodeString(strings.TrimPrefix(MainnetGenesisValidatorsRootStr, "0x"))
	if err != nil {
		panic(err)
	}
	copy(MainnetGenesisValidatorsRoot[:], mainnetGenesisValidatorsRoot)
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

// fork uses mainnet Capella fork and mainnet genesis validators root so that
// domain computation matches web3signer (mainnet) for signables that use fork_info.
var fork = struct {
	Fork                  api.Fork `json:"fork"`
	GenesisValidatorsRoot string   `json:"genesis_validators_root"`
}{
	Fork: api.Fork{
		CurrentVersion:  "0x03000000", // Capella
		PreviousVersion: "0x02000000", // Bellatrix
		Epoch:           "194048",     // mainnet Capella fork epoch
	},
	GenesisValidatorsRoot: MainnetGenesisValidatorsRootStr,
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
				Slot:              6209536,
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
			Slot:              6209536,
			SubcommitteeIndex: 10,
		},
		ForkInfo: fork,
	}
}

func syncCommitteeMessageSigning() *api.SyncCommitteeMessageSigning {
	return &api.SyncCommitteeMessageSigning{
		Type: api.SYNCCOMMITTEEMESSAGE,
		SyncCommitteeMessage: api.SyncCommitteeMessage{
			Slot:            "6209536",
			BeaconBlockRoot: TestRoot1Str,
		},
		ForkInfo: fork,
	}
}

func voluntaryExitSigning() *api.VoluntaryExitSigning {
	out := &api.VoluntaryExitSigning{
		Type: api.VOLUNTARYEXIT,
		VoluntaryExit: api.VoluntaryExit{
			Epoch:          194048, // mainnet Capella range so fork version matches
			ValidatorIndex: 100,
		},
		ForkInfo: fork,
	}
	out.ForkInfo.GenesisValidatorsRoot = MainnetGenesisValidatorsRootStr
	return out
}

func randaoRevealSigning() *api.RandaoRevealSigning {
	return &api.RandaoRevealSigning{
		Type: api.RANDAOREVEAL,
		RandaoReveal: api.RandaoReveal{
			Epoch: "194048", // mainnet Capella range so fork version matches
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
			Slot: "6209536", // mainnet Capella range (epoch 194048) so fork version matches
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
			SignableMsg:        validatorRegistrationSigning(NotFoundPubkey),
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
			ExpectedSignature:  "0xb9757d0c6603caa1cecee5989b512b7b041ea4db2271db0fabf9a8ea66854770042c9a856545bb3dd0209a52ded71b40010716229873e9fdfa8aaab6687e675b7dfd61be96681c64ee69928c5b30386b5b996f4728e72d04e5e22a7ff9d184f5",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        syncCommitteeSelectionProofSigning(),
			ExpectedSignature:  "0x81147f3d1d7c31e515ae530baf06c119dec25ac1639b36ea955e61c7495f63b8984208a3fc6bcb45595891fcc2643fe00f5331e16e0bf40f3d9c982ef9234f38f25b403f052c68ade44ecf4802f773e67e055514605e87addb7acb3cc3e0465b",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        syncCommitteeMessageSigning(),
			ExpectedSignature:  "0x877b83c3cf856d09961bc76f99433777ba089c8cd0e15260122ed69e5a16889301c778c2a35a713ab64b5b376b31656d09167c821b18d35bb6354b8d2c3f5bae4938fff5dab815e41c0efc5c6aed4f9479a114fe554ce3c99dd5f981e5c11f2c",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        voluntaryExitSigning(),
			ExpectedSignature:  "0x8b2a6084c9e6df8fdbd21a30e3955de6e7ccc3169091ac6b777b5f5e715d07bd5b04ef9f9369c3b2c99631fac10980d0027c710335069946fe3546bb4f3f8493f8cba601fa2b37e44442c6cce660b9f18e0232fccf50faec61f7bae3f1d90bc4",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        randaoRevealSigning(),
			ExpectedSignature:  "0xa2520fc4f502e00abd0e479982fed20f7996dad57f860705226f33dfd6f962a22ad4efdc9e47394c77b49f0e330c98f702129dcf14fd429ea7d6ae96ff28a94fb00a52c95d44fc0f79349735de7513dc5b67f73554dd7835007269ed2f61d0c2",
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
			ExpectedSignature:  "0xb979fac150bf45f6281aaeab1b66b494142553293c5092d500be7ae719d3c0953f32f63357581178a249e4b71c5c2320083ee0a626944dc3ffb00647d8eb3cc7fffe1f06e7088e5cf0b109b37f1e3b6a9a687fc7ae1f240f116df0e96e58899e",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// altair beacon block
			Pubkey:             pubkeyStr,
			RawBody:            altairBeaconBlock,
			ExpectedSignature:  "0x935c179624592b6d979b72729e27875c00b6a5c11ed6ab36ea2d14b5824ddcfe7882e5fb963ad64ccc4e44b314186e16013101aa658b83e095d509e570167a3246f0ceca1a52e8fe73f70cbcbad47f2ab9978da38036a2ed56cdfd112351363e",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// bellatrix beacon block
			Pubkey:             pubkeyStr,
			RawBody:            bellatrixBeaconBlock,
			ExpectedSignature:  "0xa9fefea4805372183eb447765e44be3b23fe84d996a6db0fbcc737026085792cf38f50012d8109a81547bfb4d5e7ae8c0fb36f6dfa80d4ed8aa23c5cc7c6bb982d42a6f91933de9f806a6c8547fe8e6a2097d3a2802add75037015aa71abe5f9",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// capella beacon block
			Pubkey:             pubkeyStr,
			RawBody:            capellaBeaconBlock,
			ExpectedSignature:  "0x8c5a55ffcf3b74d4e324fb0796aef6ce1c76117d553a9d801625be9d5e04b89228856346224de3202df99506e01a888807259c809d9a12b5538a3a2d88cd5094e84c4290d90f9de3f5942b07be806d888a1f092a5041bb7ace3a556f02b6f48d",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// deneb beacon block
			Pubkey:             pubkeyStr,
			RawBody:            denebBeaconBlock,
			ExpectedSignature:  "0x85f364382ea6557b93740087b0675601f243a89f12425b260c8f7fb44cbcd1ea7617e7ae038fa3ed4e70c5429a03e10b042e67d80d48a92a494ab6d6a2c2a615813f290383d517b977342210df1cdd74bbdcd9f196361246d539b65e85123cc1",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// electra beacon block
			Pubkey:             pubkeyStr,
			RawBody:            electraBeaconBlock,
			ExpectedSignature:  "0xa2e52c083264d78fa3f44eccb8afcbf04e4faa4988b3c6b79a601a37325fa4dd59162219b647e5c75a4bd4ab60c9194800fe118d865526a26cbfa8dbdf2d75b67422fafc8eaccdd0d133d82ef1f890139896425559df3067f29cf823db6d6521",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// fulu beacon block
			Pubkey:             pubkeyStr,
			RawBody:            fuluBeaconBlock,
			ExpectedSignature:  "0xa71cd31506ec597e896e6f6205b56cc39f73626a72473411d58cdc326e33e5ef979c42f37427b686e513c4adafce4f9018310e9adcb56fe261f1f873caf8740f86abaf9bc248e867d4f1469aa7f537aaecced2eda9317ff486c3b1d851a1ff76",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// attestation
			Pubkey:             pubkeyStr,
			SignableMsg:        attestationSigning(),
			ExpectedSignature:  "0x8c82eb0da26fedec4af953bc45b946221efa7136e524a8dd19c897a4afc31c9b55850877e4b40b2ac2f9f57351091464041fe10f7a035aa139da23f3ce6c6199fdee500a87cc94b8e9573e1ef5c39bef8b08354c05ac2dcfeb5c9156a564e3a2",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// aggregate and proof phase0
			Pubkey:             pubkeyStr,
			RawBody:            phase0AggregateAndProof,
			ExpectedSignature:  "0x8134241fda2ff80eb134ea045ee1870f3b5530ac4535b11e5938a0ba7ee83e40194222c656c55c44903dfe9d4cf6f26a09107875d3926be025a0e7681ad39eabff57bbb9c8332a29aff70bdb0b666f2d13b9be95be75ff649c7ba5fa583af401",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// aggregate and proof electra
			Pubkey:             pubkeyStr,
			RawBody:            electraAggregateAndProof,
			ExpectedSignature:  "0xab0c958b1f660008bf6983361318b59e21f7f45ae90a0f4ee9365721af9bd11badf8c6e61cb15c70c1a4efb3f0202d1100eb45c400b243bde7e1921dac1d3dad39e8525ae93be258ce2ae363782b6333be763e28b3fe1b03ad2afdf5e525d226",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// aggregation slot sligning
			Pubkey:             pubkeyStr,
			SignableMsg:        aggregationSlotSigning(),
			ExpectedSignature:  "0x812659f12a1b664e286768e147595f69272a4777ca1cd7c8799fe944b763621ec5807af899a01b3b6b34d10f05c5fe581228f7d1121b1f89581e7afc2044c35e0d444d2913ce3c81d46a8075d3c85122ee61c506f271655425a7e7a04a94b7fd",
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
			ExpectedSignature:  "0x8cf76a418d7055dcf8f6f09cfff89874fe902cc892ef5830a15eb950caaaf90cf840847b8390f0ff353eb628b037a4f60915bde4e9ef6074d63c02eea3623dd3618007d2d08ded7cccfcaa47c2bba9f918c3a532cf576331fa45fba4f6505cbc",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        syncCommitteeSelectionProofSigning(),
			ExpectedSignature:  "0xac91522e2c8c03b19ddad1e2527a252432e8a0fcb6f89417d88130bf181b7b5dc8f5a5d1cfd6af9cdaaf0c2d5c1f77ef0b4db1f33ab9c7e8629f8d4914462f157216519f3094497bd1757a20463946fac669f9b2abe3d88ee2c3cc41d2ff2cd3",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        syncCommitteeMessageSigning(),
			ExpectedSignature:  "0x83194fea25b7b8f7a0b171e9b742de995fb548faaeb555eca490d83c0afd00dc72f5b860da1cdc6572cfe0c8aae142170147d45e3b33c92e886093ad577cb417ead78b80238a12ec089755abfc45dfe4e4fdedd4ac198eed9c7fd421c41c04f8",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        voluntaryExitSigning(),
			ExpectedSignature:  "0xacf2e0824145978a4d2a2df750e687c4c72545cd3032d6a5b767e503d6155a524e432b83a3eb29598cdb16c776f94f51002cd9c4c3da6708b8ccc520e73a2c63ff8ae6d63d3e52be1c1cc01e7967f6a150c27c103630b96322cc3b44e4a6bf09",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			Pubkey:             pubkeyStr,
			SignableMsg:        randaoRevealSigning(),
			ExpectedSignature:  "0xac8002757d5a67a07c6dbf38719c6e6d6e6a24f6a7af0f7e2eb3809bd0191ba936e5ed86a17b08d9394aa06b2fb246540ccee61b92cf3e108723a081a2ea60ef61391ef9a7ff91e18def616edfd13910d0f6099b987bf1e8e4a423a0259a41f5",
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
			ExpectedSignature:  "0x868e55433fcbd96ac4f0a97fab33db37d34faf416bac89a875a8670b337437907dd482b8ed7a481055761fcfe4b8c4f408b403d5a2c3ba9067e4b26382c354a8469bbbd0f55cc3146d071f5cfe85c1b68d06ed8899bbc216ecbd09a6e8a8e708",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// altair beacon block
			Pubkey:             pubkeyStr,
			RawBody:            altairBeaconBlock,
			ExpectedSignature:  "0x82ca261a0f20ab58322be37db1611a1cf2d0c70eec717db12f2464d44d2330f20545c089e1b9a6fe2cacff6ac3bc94670a7721c55a576fcdbef35de50cfa4f085824be096d3b1cdcce30ecf6a495cb5a84a8d70c93b4c3793c54a05f984f5c35",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// bellatrix beacon block
			Pubkey:             pubkeyStr,
			RawBody:            bellatrixBeaconBlock,
			ExpectedSignature:  "0xaea74b501ebf70502a7c2f874600be83c0a53d53952378c46d5ce1d7c608583ae75015274a524ef87eeb4906f2d322ab0a5e762c5116735ebd0c4b0d091526f8f2818f20b538b285172aa2e09652b5ec279459ec49aca1d1e60ae0bcb94fe086",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// capella beacon block
			Pubkey:             pubkeyStr,
			RawBody:            capellaBeaconBlock,
			ExpectedSignature:  "0xa58cf94f0ca7ac0292588170936d99cc4e196667a2336a7c6635df9bc21dcd5fda83f82e3e62f8935831172b52396b33179dcfa0e090329722d88100e7661ff36b9f37f255214fe93ed04edb64fd2052590850d8b8c0c43fe6327fb9c0ed4be2",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// deneb beacon block
			Pubkey:             pubkeyStr,
			RawBody:            denebBeaconBlock,
			ExpectedSignature:  "0xa4e52ae82d9967ad996492868a5c428b57ed570d8ca63e0e1b75932ff12a0218e373f444f2bf7b4ef8af918a29179310003a39e8825f4d474676066dbf28bb51a705b08de0b474e0a9b890f51f34c2a9be15906506c72b4fc3e32988a09db798",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// electra beacon block
			Pubkey:             pubkeyStr,
			RawBody:            electraBeaconBlock,
			ExpectedSignature:  "0xa86fff10554e8c9fd486e40edcf18267070a3610534d2ae520eedc3aadaa532c96996567af264b47d79a80fa794ab0d403df8acf541162e6cc688957382e397b2a969c630dcaaa7359390980efed4f40b194bd7752b1c3c105686139bdae1e7a",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// fulu beacon block
			Pubkey:             pubkeyStr,
			RawBody:            fuluBeaconBlock,
			ExpectedSignature:  "0xa800a7442003edda849180b824285c88a40d657658c7db633588b436321c11d762f8c7113f3231e16e8c13d22e4f6c2c05e5a3b3677ff44bd8bbf7dcfa399e2fdc9346df2fcaca1c2bdf70642f2782aca7b078f0aad1ff465585c1afeff4b56a",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// attestation
			Pubkey:             pubkeyStr,
			SignableMsg:        attestationSigning(),
			ExpectedSignature:  "0x88293faf70da73e4059637906e2baa95d279b30ef1fa857d7dd28c66ed6210f4c7862fe97a097d5aadfa459d88ef0d950651c017a28cd9128b3cce907aa73eb2d05c26ce12ea320a673925efe0efd22bc8760d2c11005a51d91e772211aa320c",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// aggregate and proof phase0
			Pubkey:             pubkeyStr,
			RawBody:            phase0AggregateAndProof,
			ExpectedSignature:  "0x82a49a8b6912e8336cd43ef09f2f2902348cad0642a70923cb73482da85f1e7b3e56b99af2c18300725481c45fba9923055fb3463a0ded750a68a17e2dc0a6ada131caa434bb2112733158c71425fd6bef614a092a3945f34a73b55857e764a5",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// aggregate and proof electra
			Pubkey:             pubkeyStr,
			RawBody:            electraAggregateAndProof,
			ExpectedSignature:  "0xb31b20a8c870bed23ae3cf0ba09b15ae0d66cd6b95174c5f32bfb033d1b8ce79f422da642d6023122c4b2949434ee5c20a97d6fe96fe51534ca4aa1c1d024d28048150409a4fd17764e0c75e06c5851bb24a3c454dd6f0e8b922c351c3d861b2",
			ExpectedHttpStatus: http.StatusOK,
		},
		{
			// aggregation slot sligning
			Pubkey:             pubkeyStr,
			SignableMsg:        aggregationSlotSigning(),
			ExpectedSignature:  "0x8cce53bbd1d0bf982c1fe15575b2bb77237be3e6488ea9ebc1be7b40f3521f8a3228a8d60192a53e1b74787e9cccbea304af936809e962bb3fc756ec04e691e41b3e279895a5282186b16de0a5a8973ea99d056df20ab11c41bcd83777611ef5",
			ExpectedHttpStatus: http.StatusOK,
		},
	}
}
