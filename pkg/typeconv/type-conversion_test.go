package typeconv

import (
	"testing"
)

func TestHexRoundTrip(t *testing.T) {
	hex := "0x0000000000000000000000000000000000000000000000000000000000000000"
	decoded, err := DecodeHex(hex)
	if err != nil {
		t.Fatalf("failed to decode hex: %v", err)
	}
	reencoded := EncodeHex(decoded)
	if reencoded != hex {
		t.Fatalf("expected %s, got %s", hex, reencoded)
	}
}
