package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jshufro/remote-signer-dirk-interop/config"
	"github.com/jshufro/remote-signer-dirk-interop/generated/api"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/dirksigner"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/domains"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/service"
	tlsprovider "github.com/jshufro/remote-signer-dirk-interop/pkg/tls"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	e2wd "github.com/wealdtech/go-eth2-wallet-dirk"
)

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

func startDirkSigner(ctx context.Context, cfg *config.Config, log *slog.Logger) (*dirksigner.DirkSigner, error) {
	var err error

	// Read CA into memory
	var rootCA *x509.CertPool
	if cfg.SSL.RootCA != "" {
		rootCABytes, err := os.ReadFile(cfg.SSL.RootCA)
		if err != nil {
			return nil, fmt.Errorf("failed to read root CA: %w", err)
		}
		rootCA = x509.NewCertPool()
		rootCA.AppendCertsFromPEM(rootCABytes)
	} else {
		rootCA, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to get system cert pool: %w", err)
		}
	}

	tlsProvider := tlsprovider.NewTLSProvider(cfg.SSL.Cert, cfg.SSL.PrivKey)
	tlsProvider.SetThreshold(cfg.SSL.RefreshThreshold)
	tlsProvider.SetRetry(cfg.SSL.RefreshRetry)
	tlsProvider.SetLogger(log)
	// Load the certificate synchronously to make sure
	// it's valid on startup.
	if err := tlsProvider.LoadCertificate(); err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	dirkEndpoints := make([]*e2wd.Endpoint, len(cfg.Dirk.Endpoints))
	for i, endpoint := range cfg.Dirk.Endpoints {
		host, portStr, err := net.SplitHostPort(endpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to split host port: %w", err)
		}
		port, err := strconv.ParseUint(portStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to convert port to int: %w", err)
		}
		dirkEndpoints[i] = e2wd.NewEndpoint(host, uint32(port))
	}

	dirkSigner := &dirksigner.DirkSigner{
		GenesisForkVersion: domains.ForkVersion(cfg.GenesisForkVersion()),
		RootCA:             rootCA,
	}

	dirkSigner.SetLogger(log)
	ctx, cancel := context.WithTimeout(ctx, cfg.Dirk.Timeout)
	defer cancel()

	err = dirkSigner.Open(ctx, cfg.Dirk.Wallet, dirkEndpoints, tlsProvider, parseLogLevel(cfg.LogLevel))
	if err != nil {
		return nil, fmt.Errorf("failed to open dirk signer: %w", err)
	}

	return dirkSigner, nil
}

func startHttp(ctx context.Context, service api.ServerInterface, cfg *config.Config, log *slog.Logger) error {

	log.Info("listening",
		"address", cfg.ListenAddress,
		"port", cfg.ListenPort,
		"dirk_endpoints", cfg.Dirk.Endpoints,
		"dirk_wallet", cfg.Dirk.Wallet)
	_ = context.AfterFunc(ctx, func() {
		log.Info("received signal, shutting down")
	})

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.ListenPort))
	if err != nil {
		log.Error("failed to listen", "error", err)
		os.Exit(1)
	}
	defer func() {
		_ = listener.Close()
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		n, err := w.Write([]byte("{\"status\":\"UP\",\"outcome\":\"UP\",\"checks\":[]}"))
		if err != nil {
			log.Error("failed to write healthcheck response", "error", err, "bytes_written", n)
		}
	})

	var metricsServer *http.Server
	var metricsListener net.Listener
	if cfg.Metrics.ListenPort == cfg.ListenPort && cfg.Metrics.ListenAddress == cfg.ListenAddress {
		mux.Handle("/metrics", promhttp.Handler())
	} else if cfg.Metrics.ListenPort != 0 {
		metricsListener, err = net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.Metrics.ListenAddress, cfg.Metrics.ListenPort))
		if err != nil {
			log.Error("failed to listen for metrics", "error", err)
			os.Exit(1)
		}
		defer func() {
			_ = metricsListener.Close()
		}()
		serveMux := http.NewServeMux()
		serveMux.Handle("/metrics", promhttp.Handler())
		metricsServer = &http.Server{
			Handler: serveMux,
		}
	}

	server := http.Server{
		Handler: api.HandlerWithOptions(service, api.StdHTTPServerOptions{
			BaseRouter: mux,
		}),
	}

	_ = context.AfterFunc(ctx, func() {
		err := server.Shutdown(context.Background())
		if err != nil {
			log.Error("failed to shutdown server", "error", err)
		}

		if metricsServer != nil {
			err = metricsServer.Shutdown(context.Background())
			if err != nil {
				log.Error("failed to shutdown metrics server", "error", err)
			}
		}
	})

	if metricsServer != nil {
		go func() {
			err = metricsServer.Serve(metricsListener)
			if err != http.ErrServerClosed && err != nil {
				log.Error("failed to serve metrics", "error", err)
				os.Exit(1)
			}
			if err == http.ErrServerClosed {
				log.Info("metrics server closed")
			}
		}()
	}

	err = server.Serve(listener)
	if err == http.ErrServerClosed {
		log.Info("server closed")
		return nil
	}
	if err != nil {
		log.Error("failed to serve", "error", err)
		return fmt.Errorf("failed to serve: %w", err)
	}
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfgPath := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	if *cfgPath == "" {
		fmt.Fprintf(os.Stderr, "config file is required\n")
		fmt.Fprintln(os.Stderr)
		flag.Usage()
		os.Exit(1)
	}

	cfg, err := config.Load(*cfgPath, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	var log *slog.Logger
	logLevel := parseLogLevel(cfg.LogLevel)
	if cfg.LogFormat == "json" {
		log = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: logLevel,
		}))
	} else {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: logLevel,
		}))
	}

	dirkSigner, err := startDirkSigner(ctx, cfg, log)
	if err != nil {
		log.Error("failed to start dirk signer", "error", err)
		os.Exit(1)
	}

	service, err := service.NewService(dirkSigner)
	if err != nil {
		log.Error("failed to create service", "error", err)
		os.Exit(1)
	}

	service.SetLogger(log)
	service.SetTimeout(cfg.Dirk.Timeout)

	prometheus.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "remote_signer_dirk_interop_up",
		Help: "Indicates if the remote signer dirk interop is up",
	}, func() float64 {
		return 1
	}))

	startTimeGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "remote_signer_dirk_interop_start_time",
		Help: "Indicates the start time of the remote signer dirk interop",
	})
	startTimeGauge.Set(float64(time.Now().Unix()))
	prometheus.MustRegister(startTimeGauge)

	err = startHttp(ctx, service, cfg, log)
	if err != nil {
		log.Error("failed to start http", "error", err)
		os.Exit(1)
	}
}
