package dirksigner

import (
	"encoding/hex"
	"strings"

	"github.com/jshufro/remote-signer-dirk-interop/internal/errors"
)

func decodeHex(hexStr string) ([]byte, error) {
	bytes, err := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
	if err != nil {
		return nil, errors.BadRequest("failed to decode hex: %w", err)
	}
	return bytes, nil
}
