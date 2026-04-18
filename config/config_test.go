package config

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func testCertKeyPaths(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	var certBuf bytes.Buffer
	if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}
	var keyBuf bytes.Buffer
	if err := pem.Encode(&keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, certBuf.Bytes(), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyBuf.Bytes(), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// testRootCAPath writes a self-signed CA certificate PEM and returns its path.
func testRootCAPath(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}
	p := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write root CA: %v", err)
	}
	return p
}

func TestLoadConfigWithRootCA(t *testing.T) {
	fs := afero.NewMemMapFs()
	configFile := "test.yaml"

	certPath, keyPath := testCertKeyPaths(t)
	rootPath := testRootCAPath(t)
	yamlBody := strings.ReplaceAll(validConfig, "/path/to/server.crt", certPath)
	yamlBody = strings.ReplaceAll(yamlBody, "/path/to/server.key", keyPath)
	yamlBody = strings.Replace(yamlBody,
		"  privkey: \""+keyPath+"\"",
		"  privkey: \""+keyPath+"\"\n  root_ca: \""+rootPath+"\"",
		1)

	f, err := fs.Create(configFile)
	if err != nil {
		t.Fatalf("Create(%q) error = %v", configFile, err)
	}
	if _, err := f.WriteString(yamlBody); err != nil {
		t.Fatalf("WriteString error = %v", err)
	}
	_ = f.Close()

	cfg, err := Load(configFile, fs)
	if err != nil {
		t.Fatalf("Load(%q) with root_ca error = %v", configFile, err)
	}
	if cfg.SSL.CertPool == nil {
		t.Fatal("expected non-nil CertPool after loading root_ca")
	}
}

func TestLoadConfig(t *testing.T) {
	// Create a mock fs
	fs := afero.NewMemMapFs()

	// Create a mock config file
	configFile := "test.yaml"

	certPath, keyPath := testCertKeyPaths(t)
	yamlBody := strings.ReplaceAll(validConfig, "/path/to/server.crt", certPath)
	yamlBody = strings.ReplaceAll(yamlBody, "/path/to/server.key", keyPath)

	// Write the mock config file to the mock fs
	f, err := fs.Create(configFile)
	if err != nil {
		t.Fatalf("Create(%q) error = %v", configFile, err)
	}
	_, err = f.WriteString(yamlBody)
	if err != nil {
		t.Fatalf("WriteString error = %v", err)
	}
	_ = f.Close()

	// Load the valid config
	cfg, err := Load(configFile, fs)
	if err != nil {
		t.Fatalf("Load(%q) error = %v", configFile, err)
	}

	err = cfg.validate()
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
	err := cfg.populate(v)
	if err != nil {
		t.Fatalf("Populate(%v) error = %v", v, err)
	}

	err = cfg.validate()
	if err == nil {
		t.Fatalf("expected error for missing required fields, got nil")
	}
	if !strings.Contains(err.Error(), "at least one dirk endpoint is required") {
		t.Fatalf("expected error for missing required fields, got %v", err)
	}

	// Add dirks
	cfg.Dirk.Endpoints = []string{"dirk.example.com:9091"}
	err = cfg.validate()
	if err == nil {
		t.Fatalf("expected error for missing required fields, got nil")
	}
	if !strings.Contains(err.Error(), "dirk wallet name must not be empty") {
		t.Fatalf("expected error for missing required fields, got %v", err)
	}

	// Add wallet
	cfg.Dirk.Wallet = "wallet-name"
	err = cfg.validate()
	if err == nil {
		t.Fatalf("expected error for missing required fields, got nil")
	}
	if !strings.Contains(err.Error(), "ssl.cert and ssl.privkey must be set") {
		t.Fatalf("expected error for missing required fields, got %v", err)
	}

	// Add cert and privkey
	cfg.SSL.Cert = "/path/to/server.crt"
	cfg.SSL.PrivKey = "/path/to/server.key"
	err = cfg.validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	// Mangle genesis fork version to ensure it causes an error in Validate()
	cfg.Network = "not valid"
	err = cfg.validate()
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
	err := cfg.populate(v)
	if err == nil {
		t.Fatalf("expected error for nil config, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshaling config") {
		t.Fatalf("expected error for nil config, got %v", err)
	}
}

func TestPopulateUnmarshalError(t *testing.T) {
	cfg := &Config{}
	v := newViper(nil)
	v.Set("listen_port", "not-a-u16")
	err := cfg.populate(v)
	if err == nil {
		t.Fatal("expected unmarshal error, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshaling config") {
		t.Fatalf("expected unmarshaling config wrapper, got %v", err)
	}
	if errors.Unwrap(err) == nil {
		t.Fatalf("expected wrapped decode error, got %v", err)
	}
}
