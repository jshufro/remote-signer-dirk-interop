package config

import "testing"

func TestGenesisForkVersionValidNetworks(t *testing.T) {
	tests := []struct {
		name    string
		network string
	}{
		{"mainnet", "mainnet"},
		{"holesky", "holesky"},
		{"hoodi", "hoodi"},
		{"sepolia", "sepolia"},
		{"custom_hex", "0x01020304"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Network: tt.network}
			v, err := cfg.GenesisForkVersion()
			if err != nil {
				t.Fatalf("GenesisForkVersion(%q) error = %v", tt.network, err)
			}
			if len(v) != 4 {
				t.Fatalf("GenesisForkVersion(%q) len = %d, want 4", tt.network, len(v))
			}
		})
	}
}

func TestGenesisForkVersionInvalidNetwork(t *testing.T) {
	cfg := &Config{Network: "not-a-network"}
	if _, err := cfg.GenesisForkVersion(); err == nil {
		t.Fatalf("expected error for invalid network, got nil")
	}
}

