package typeconv

import (
	"encoding/hex"
	"strings"

	"github.com/jshufro/remote-signer-dirk-interop/pkg/errors"
)

func DecodeHex(hexStr string) ([]byte, error) {
	bytes, err := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
	if err != nil {
		return nil, errors.BadRequest("failed to decode hex: %w", err)
	}
	return bytes, nil
}

func EncodeHex(bytes []byte) string {
	return "0x" + hex.EncodeToString(bytes)
}
