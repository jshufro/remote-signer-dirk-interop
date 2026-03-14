package dirk

import (
	"log/slog"
	"testing"

	"github.com/rs/zerolog"
)

func TestSlogLevelToZerologLevel(t *testing.T) {
	tests := []struct {
		slogLevel    slog.Level
		zerologLevel zerolog.Level
	}{
		{slog.LevelDebug, zerolog.DebugLevel},
		{slog.LevelInfo, zerolog.InfoLevel},
		{slog.LevelWarn, zerolog.WarnLevel},
		{slog.LevelError, zerolog.ErrorLevel},
	}
	for _, test := range tests {
		zerologLevel := slogLevelToZerologLevel(test.slogLevel)
		if zerologLevel != test.zerologLevel {
			t.Fatalf("expected %d, got %d", test.zerologLevel, zerologLevel)
		}
	}

	zerologLevel := slogLevelToZerologLevel(slog.Level(100))
	if zerologLevel != zerolog.TraceLevel {
		t.Fatalf("expected %d, got %d", zerolog.TraceLevel, zerologLevel)
	}
}
