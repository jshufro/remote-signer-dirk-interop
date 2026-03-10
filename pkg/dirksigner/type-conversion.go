package dirksigner

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/OffchainLabs/go-bitfield"
	"github.com/OffchainLabs/prysm/v7/consensus-types/primitives"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/jshufro/remote-signer-dirk-interop/internal/errors"
	"github.com/rs/zerolog"
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

func decodeValidatorIndex(validatorIndex string) (primitives.ValidatorIndex, *errors.SignerError) {
	u64, err := strconv.ParseUint(validatorIndex, 10, 64)
	if err != nil {
		return 0, errors.ErrBadRequest
	}
	return primitives.ValidatorIndex(u64), nil
}

func decodeBitVector128(bitVector128 string) (bitfield.Bitvector128, *errors.SignerError) {
	bytes, err := decodeHex(bitVector128)
	if err != nil {
		return bitfield.Bitvector128{}, err
	}
	if len(bytes) != 16 {
		return bitfield.Bitvector128{}, errors.ErrBadRequest
	}
	return bitfield.Bitvector128(bytes), nil
}

func decodeRoot(root string) ([32]byte, *errors.SignerError) {
	bytes, err := decodeHex(root)
	if err != nil {
		return [32]byte{}, err
	}
	if len(bytes) != 32 {
		return [32]byte{}, errors.ErrBadRequest
	}
	return [32]byte(bytes), nil
}

func decodeSignature(signature string) ([96]byte, *errors.SignerError) {
	bytes, err := decodeHex(signature)
	if err != nil {
		return [96]byte{}, err
	}
	if len(bytes) != 96 {
		return [96]byte{}, errors.ErrBadRequest
	}
	return [96]byte(bytes), nil
}

func decodeSlot(slot string) (primitives.Slot, *errors.SignerError) {
	u64, err := decodeUint64(slot)
	if err != nil {
		return primitives.Slot(0), err
	}
	return primitives.Slot(u64), nil
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

func slogLevelToZerologLevel(level slog.Level) zerolog.Level {
	switch level {
	case slog.LevelDebug:
		return zerolog.DebugLevel
	case slog.LevelInfo:
		return zerolog.InfoLevel
	case slog.LevelWarn:
		return zerolog.WarnLevel
	case slog.LevelError:
		return zerolog.ErrorLevel
	}
	fmt.Fprintf(os.Stderr, "invalid zerolog level %d, defaulting to trace\n", level)
	return zerolog.TraceLevel
}
