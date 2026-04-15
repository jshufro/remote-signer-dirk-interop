package typeconv

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jshufro/remote-signer-dirk-interop/pkg/errors"

	e2t "github.com/wealdtech/go-eth2-types/v2"
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
