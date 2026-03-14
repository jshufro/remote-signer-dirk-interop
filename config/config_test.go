package config

import (
	_ "embed"
	"strings"
	"testing"

	"github.com/spf13/afero"
)

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
			err := cfg.setGenesisForkVersion()
			if err != nil {
				t.Fatalf("GenesisForkVersion(%q) error = %v", tt.network, err)
			}
			if len(cfg.GenesisForkVersion()) != 4 {
				t.Fatalf("GenesisForkVersion(%q) len = %d, want 4", tt.network, len(cfg.GenesisForkVersion()))
			}
		})
	}
}

func TestGenesisForkVersionInvalidNetwork(t *testing.T) {
	cfg := &Config{Network: "not-a-network"}
	if err := cfg.setGenesisForkVersion(); err == nil {
		t.Fatalf("expected error for invalid network, got nil")
	}

	cfg = &Config{Network: "0xbuti'mnothex"}
	if err := cfg.setGenesisForkVersion(); err == nil {
		t.Fatalf("expected error for invalid network, got nil")
	}

	cfg = &Config{Network: "0x00"}
	if err := cfg.setGenesisForkVersion(); err == nil {
		t.Fatalf("expected error for invalid network, got nil")
	}
}

//go:embed test/valid_config.yaml
var validConfig string

func TestLoadConfig(t *testing.T) {
	// Create a mock fs
	fs := afero.NewMemMapFs()

	// Create a mock config file
	configFile := "test.yaml"

	// Write the mock config file to the mock fs
	f, err := fs.Create(configFile)
	if err != nil {
		t.Fatalf("Create(%q) error = %v", configFile, err)
	}
	_, err = f.WriteString(validConfig)
	if err != nil {
		t.Fatalf("WriteString(%q) error = %v", validConfig, err)
	}
	_ = f.Close()

	// Load the valid config
	cfg, err := Load(configFile, fs)
	if err != nil {
		t.Fatalf("Load(%q) error = %v", configFile, err)
	}

	err = cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	// Load a path that doesn't exist and expect an error
	_, err = Load("does-not-exist.yaml", fs)
	if err == nil {
		t.Fatalf("expected error for non-existent config file, got nil")
	}

	// Load _no_ path and expect an error
	_, err = Load("", fs)
	if err == nil {
		t.Fatalf("expected error for no config file, got nil")
	}
}

func TestRequiredFields(t *testing.T) {
	cfg := &Config{}
	v := newViper(nil)
	err := cfg.Populate(v)
	if err != nil {
		t.Fatalf("Populate(%v) error = %v", v, err)
	}

	err = cfg.Validate()
	if err == nil {
		t.Fatalf("expected error for missing required fields, got nil")
	}
	if !strings.Contains(err.Error(), "at least one dirk endpoint is required") {
		t.Fatalf("expected error for missing required fields, got %v", err)
	}

	// Add dirks
	cfg.Dirk.Endpoints = []string{"dirk.example.com:9091"}
	err = cfg.Validate()
	if err == nil {
		t.Fatalf("expected error for missing required fields, got nil")
	}
	if !strings.Contains(err.Error(), "dirk wallet name must not be empty") {
		t.Fatalf("expected error for missing required fields, got %v", err)
	}

	// Add wallet
	cfg.Dirk.Wallet = "wallet-name"
	err = cfg.Validate()
	if err == nil {
		t.Fatalf("expected error for missing required fields, got nil")
	}
	if !strings.Contains(err.Error(), "ssl.cert and ssl.privkey must be set") {
		t.Fatalf("expected error for missing required fields, got %v", err)
	}

	// Add cert and privkey
	cfg.SSL.Cert = "/path/to/server.crt"
	cfg.SSL.PrivKey = "/path/to/server.key"
	err = cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	// Mangle genesis fork version to ensure it causes an error in Validate()
	cfg.Network = "not valid"
	err = cfg.Validate()
	if err == nil {
		t.Fatalf("expected error for invalid network, got nil")
	}
	if !strings.Contains(err.Error(), "invalid network") {
		t.Fatalf("expected error for invalid network, got %v", err)
	}
}

func TestPopulateNilConfig(t *testing.T) {
	var cfg *Config
	v := newViper(nil)
	err := cfg.Populate(v)
	if err == nil {
		t.Fatalf("expected error for nil config, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshaling config") {
		t.Fatalf("expected error for nil config, got %v", err)
	}
}
