package config

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds application configuration.
type Config struct {
	LogLevel  string `mapstructure:"log_level"`
	LogFormat string `mapstructure:"log_format"`

	ListenAddress string `mapstructure:"listen_address"`
	ListenPort    uint16 `mapstructure:"listen_port"`
	Dirk          struct {
		Timeout   time.Duration `mapstructure:"timeout"`
		Endpoints []string      `mapstructure:"endpoints"`
		Wallet    string        `mapstructure:"wallet"`
	} `mapstructure:"dirk"`

	// TLS: required for serving and/or connecting to Dirk
	SSL struct {
		Cert             string        `mapstructure:"cert"`
		PrivKey          string        `mapstructure:"privkey"`
		RootCA           string        `mapstructure:"root_ca"` // optional
		RefreshThreshold time.Duration `mapstructure:"refresh_threshold"`
		RefreshRetry     time.Duration `mapstructure:"refresh_retry"`
	}

	// Network is either mainnet or hoodi
	Network string `mapstructure:"network"`
}

// Load reads configuration from file and environment into cfg.
// Config file is optional; env vars use prefix REMOTE_SIGNER_.
func Load(cfgFile string) (*Config, error) {
	v := viper.New()

	v.SetEnvPrefix("REMOTE_SIGNER")
	v.AutomaticEnv()

	// Defaults
	v.SetDefault("listen_address", "0.0.0.0")
	v.SetDefault("listen_port", 9090)
	v.SetDefault("network", "mainnet")

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

// Validate performs basic validation of the configuration and returns an error
// if any required fields are missing or invalid.
func (c *Config) Validate() error {
	if c.ListenAddress == "" {
		return fmt.Errorf("listen_address must not be empty")
	}
	if len(c.Dirk.Endpoints) == 0 {
		return fmt.Errorf("at least one dirk endpoint is required")
	}
	if c.Dirk.Wallet == "" {
		return fmt.Errorf("dirk wallet name must not be empty")
	}
	if c.SSL.Cert == "" || c.SSL.PrivKey == "" {
		return fmt.Errorf("ssl.cert and ssl.privkey must be set")
	}
	if _, err := c.GenesisForkVersion(); err != nil {
		return err
	}
	return nil
}

// GenesisForkVersion returns the configured genesis fork version as 4 bytes.
// It returns an error if the network value is invalid.
func (c *Config) GenesisForkVersion() ([]byte, error) {
	switch c.Network {
	case "mainnet":
		return []byte{0x00, 0x00, 0x00, 0x00}, nil
	case "holesky":
		return []byte{0x01, 0x01, 0x70, 0x00}, nil
	case "hoodi":
		return []byte{0x10, 0x00, 0x09, 0x10}, nil
	case "sepolia":
		return []byte{0x90, 0x00, 0x00, 0x69}, nil
	default:
		if trimmed, found := strings.CutPrefix(c.Network, "0x"); found {
			hexBytes, err := hex.DecodeString(trimmed)
			if err != nil {
				return nil, fmt.Errorf("invalid genesis fork version %q: %w", c.Network, err)
			}
			if len(hexBytes) != 4 {
				return nil, fmt.Errorf("invalid genesis fork version length %q: got %d, want 4", c.Network, len(hexBytes))
			}
			return hexBytes, nil
		}
		return nil, fmt.Errorf("invalid network %q", c.Network)
	}
}

// GetGenesisForkVersion is kept for backwards compatibility. New code should
// prefer GenesisForkVersion, which returns an error instead of panicking.
func (c *Config) GetGenesisForkVersion() []byte {
	v, err := c.GenesisForkVersion()
	if err != nil {
		panic(err)
	}
	return v
}
