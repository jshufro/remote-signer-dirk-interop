package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// Config holds application configuration.
type Config struct {
	ListenAddress string   `mapstructure:"listen_address"`
	ListenPort    uint16   `mapstructure:"listen_port"`
	DirkEndpoints []string `mapstructure:"dirk_endpoints"`

	// TLS: required for serving and/or connecting to Dirk
	SSLCert    string `mapstructure:"ssl_cert"`
	SSLPrivKey string `mapstructure:"ssl_privkey"`
	RootCA     string `mapstructure:"root_ca"` // optional
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

	return &cfg, nil
}
