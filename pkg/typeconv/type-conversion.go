package typeconv

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/jshufro/remote-signer-dirk-interop/generated/api"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/domains"
	e2t "github.com/wealdtech/go-eth2-types/v2"
)

func DecodeGwei(hexStr string) (phase0.Gwei, error) {
	amount, err := strconv.ParseUint(hexStr, 10, 64)
	if err != nil {
		return 0, err
	}
	return phase0.Gwei(amount), nil
}

func DecodeBLSPubKey(hexStr string) (phase0.BLSPubKey, error) {
	bytes, err := DecodeHexWithLength(hexStr, 48)
	if err != nil {
		return phase0.BLSPubKey{}, err
	}
	return phase0.BLSPubKey(bytes), nil
}

func DecodeForkVersion(hexStr string) (domains.ForkVersion, error) {
	bytes, err := DecodeHexWithLength(hexStr, 4)
	if err != nil {
		return domains.ForkVersion{}, err
	}
	return domains.ForkVersion(bytes), nil
}

func DecodeHexWithLength(hexStr string, length int) ([]byte, error) {
	bytes, err := DecodeHex(hexStr)
	if err != nil {
		return nil, err
	}
	if len(bytes) != length {
		return nil, fmt.Errorf("hex string is %d bytes, expected %d bytes", len(bytes), length)
	}
	return bytes, nil
}

func DecodeHex(hexStr string) ([]byte, error) {
	bytes, err := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}
	return bytes, nil
}

func EncodeHex(bytes []byte) string {
	return "0x" + hex.EncodeToString(bytes)
}

func Uint64ToHashTreeRoot(u uint64) [32]byte {
	hashTreeRoot := [32]byte{}
	binary.LittleEndian.PutUint64(hashTreeRoot[:], u)
	return hashTreeRoot
}

func SignatureToBytes(signature e2t.Signature) ([96]byte, error) {
	b := signature.Marshal()
	if len(b) != 96 {
		return [96]byte{}, fmt.Errorf("signature is %d bytes, expected 96 bytes", len(b))
	}
	var out [96]byte
	copy(out[:], b)
	return out, nil
}

func DepositSigningToHashRoot(deposit *api.DepositSigning) (ssz.HashRoot, error) {

	amount, err := DecodeGwei(deposit.Deposit.Amount)
	if err != nil {
		return nil, fmt.Errorf("failed to parse amount: %w", err)
	}

	pubkey, err := DecodeBLSPubKey(deposit.Deposit.Pubkey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode pubkey: %w", err)
	}

	withdrawalCredentials, err := DecodeHexWithLength(deposit.Deposit.WithdrawalCredentials, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to decode withdrawal credentials: %w", err)
	}

	return &phase0.DepositMessage{
		Amount:                amount,
		PublicKey:             pubkey,
		WithdrawalCredentials: withdrawalCredentials,
	}, nil
}
