package config

import (
	"fmt"
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

	_ = cfg.GetGenesisForkVersion()

	return &cfg, nil
}

func (c *Config) GetGenesisForkVersion() []byte {
	switch c.Network {
	case "mainnet":
		return []byte{0x00, 0x00, 0x00, 0x00}
	case "hoodi":
		return []byte{0x10, 0x00, 0x09, 0x10}
	default:
		panic("invalid network")
	}
}
