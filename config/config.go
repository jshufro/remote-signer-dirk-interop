package config

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/afero"
	"github.com/spf13/viper"

	tlsprovider "github.com/jshufro/remote-signer-dirk-interop/pkg/tls"
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

		CertPool    *x509.CertPool          `mapstructure:"-"`
		TLSProvider tlsprovider.TLSProvider `mapstructure:"-"`
	}

	OTLP struct {
		TraceRecipient            string `mapstructure:"trace_recipient"`
		Secure                    bool   `mapstructure:"secure"`
		HostnameOverride          string `mapstructure:"hostname_override"`
		ServiceInstanceIDOverride string `mapstructure:"service_instance_id_override"`
	} `mapstructure:"otlp"`

	Metrics struct {
		ListenAddress string `mapstructure:"listen_address"`
		ListenPort    uint16 `mapstructure:"listen_port"`
	} `mapstructure:"metrics"`

	// Network is either mainnet or hoodi
	Network            string `mapstructure:"network"`
	genesisForkVersion []byte

	Log            *slog.Logger
	ParsedLogLevel slog.Level
}

func (c *Config) populate(v *viper.Viper) error {
	if c == nil {
		return fmt.Errorf("unmarshaling config: nil config")
	}
	err := v.Unmarshal(c)
	if err != nil {
		return fmt.Errorf("unmarshaling config: %w", err)
	}

	c.SSL.CertPool, err = x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("failed to get system cert pool: %w", err)
	}

	if c.SSL.RootCA != "" {
		rootCABytes, err := os.ReadFile(c.SSL.RootCA)
		if err != nil {
			return fmt.Errorf("failed to read root CA: %w", err)
		}
		c.SSL.CertPool.AppendCertsFromPEM(rootCABytes)
	}

	c.ParsedLogLevel = parseLogLevel(c.LogLevel)
	if c.LogFormat == "json" {
		c.Log = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: c.ParsedLogLevel,
		}))
	} else {
		c.Log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: c.ParsedLogLevel,
		}))
	}

	return nil
}

func (c *Config) initClientTLS() error {
	tlsProvider := tlsprovider.NewTLSProvider(c.SSL.Cert, c.SSL.PrivKey)
	tlsProvider.SetThreshold(c.SSL.RefreshThreshold)
	tlsProvider.SetRetry(c.SSL.RefreshRetry)
	tlsProvider.SetLogger(c.Log)

	if err := tlsProvider.LoadCertificate(); err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}
	c.SSL.TLSProvider = tlsProvider
	return nil
}

func newViper(fs afero.Fs) *viper.Viper {
	v := viper.New()
	if fs != nil {
		v.SetFs(fs)
	}

	v.SetEnvPrefix("REMOTE_SIGNER")
	v.AutomaticEnv()

	// Defaults
	v.SetDefault("listen_address", "0.0.0.0")
	v.SetDefault("listen_port", 9090)
	v.SetDefault("network", "mainnet")
	v.SetDefault("otlp.secure", true)
	return v

}

// Load reads configuration from file and environment into cfg.
// Config file is optional; env vars use prefix REMOTE_SIGNER_.
func Load(cfgFile string, fs afero.Fs) (*Config, error) {
	v := newViper(fs)
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}

	cfg := &Config{}
	if err := cfg.populate(v); err != nil {
		return nil, fmt.Errorf("populating config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	if err := cfg.initClientTLS(); err != nil {
		return nil, fmt.Errorf("loading tls credentials: %w", err)
	}

	return cfg, nil
}

// Validate performs basic validation of the configuration and returns an error
// if any required fields are missing or invalid.
func (c *Config) validate() error {
	if len(c.Dirk.Endpoints) == 0 {
		return fmt.Errorf("at least one dirk endpoint is required")
	}
	if c.Dirk.Wallet == "" {
		return fmt.Errorf("dirk wallet name must not be empty")
	}
	if c.SSL.Cert == "" || c.SSL.PrivKey == "" {
		return fmt.Errorf("ssl.cert and ssl.privkey must be set")
	}
	if err := c.setGenesisForkVersion(); err != nil {
		return err
	}
	return nil
}

// GenesisForkVersion returns the configured genesis fork version as 4 bytes.
// It returns an error if the network value is invalid.
func (c *Config) setGenesisForkVersion() error {
	switch c.Network {
	case "mainnet":
		c.genesisForkVersion = []byte{0x00, 0x00, 0x00, 0x00}
		return nil
	case "holesky":
		c.genesisForkVersion = []byte{0x01, 0x01, 0x70, 0x00}
		return nil
	case "hoodi":
		c.genesisForkVersion = []byte{0x10, 0x00, 0x09, 0x10}
		return nil
	case "sepolia":
		c.genesisForkVersion = []byte{0x90, 0x00, 0x00, 0x69}
		return nil
	default:
		if trimmed, found := strings.CutPrefix(c.Network, "0x"); found {
			hexBytes, err := hex.DecodeString(trimmed)
			if err != nil {
				return fmt.Errorf("invalid genesis fork version %q: %w", c.Network, err)
			}
			if len(hexBytes) != 4 {
				return fmt.Errorf("invalid genesis fork version length %q: got %d, want 4", c.Network, len(hexBytes))
			}
			c.genesisForkVersion = hexBytes
			return nil
		}
		return fmt.Errorf("invalid network %q", c.Network)
	}
}

func (c *Config) GenesisForkVersion() []byte {
	return c.genesisForkVersion
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	fmt.Fprintf(os.Stderr, "invalid log level %s, defaulting to info\n", level)
	return slog.LevelInfo
}
