package dirksigner

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"

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
