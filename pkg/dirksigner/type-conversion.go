package dirksigner

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/jshufro/remote-signer-dirk-interop/internal/errors"
	"github.com/rs/zerolog"
)

func decodeHex(hexStr string) ([]byte, error) {
	bytes, err := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
	if err != nil {
		return nil, errors.BadRequest("failed to decode hex: %w", err)
	}
	return bytes, nil
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
