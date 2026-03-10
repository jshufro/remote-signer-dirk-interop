package dirksigner

import (
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/jshufro/remote-signer-dirk-interop/internal/errors"
	e2types "github.com/wealdtech/go-eth2-types/v2"
)

func decodeHex(hexStr string) ([]byte, *errors.SignerError) {
	bytes, err := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
	if err != nil {
		return nil, errors.ErrBadRequest
	}
	return bytes, nil
}

func decodeUint64(uint64Str string) (uint64, *errors.SignerError) {
	u64, err := strconv.ParseUint(uint64Str, 10, 64)
	if err != nil {
		return 0, errors.ErrBadRequest
	}
	return u64, nil
}

func feeRecipient(feeRecipient string) (bellatrix.ExecutionAddress, *errors.SignerError) {
	out := bellatrix.ExecutionAddress{}
	bytes, err := decodeHex(feeRecipient)
	if err != nil {
		return bellatrix.ExecutionAddress{}, err
	}
	if len(bytes) != 20 {
		return bellatrix.ExecutionAddress{}, errors.ErrBadRequest
	}
	copy(out[:], bytes)
	return out, nil
}

func returnSignature(signature e2types.Signature) ([96]byte, *errors.SignerError) {
	b := signature.Marshal()
	if len(b) != 96 {
		return [96]byte{}, errors.ErrInternalServerError
	}
	return [96]byte(b), nil
}
