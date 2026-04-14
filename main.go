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

	"github.com/jshufro/remote-signer-dirk-interop/config"
	api "github.com/jshufro/remote-signer-dirk-interop/generated"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/dirksigner"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/service"
	tlsprovider "github.com/jshufro/remote-signer-dirk-interop/pkg/tls"
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

func main() {
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

	log.Info("listening",
		"address", cfg.ListenAddress,
		"port", cfg.ListenPort,
		"dirk_endpoints", cfg.Dirk.Endpoints,
		"dirk_wallet", cfg.Dirk.Wallet)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.ListenPort))
	if err != nil {
		log.Error("failed to listen", "error", err)
		os.Exit(1)
	}
	defer func() {
		_ = listener.Close()
	}()

	// Read CA into memory
	var rootCABytes []byte
	var rootCA *x509.CertPool
	if cfg.SSL.RootCA != "" {
		rootCABytes, err = os.ReadFile(cfg.SSL.RootCA)
		if err != nil {
			log.Error("failed to read root CA", "error", err)
			os.Exit(1)
		}
		rootCA = x509.NewCertPool()
		rootCA.AppendCertsFromPEM(rootCABytes)
	} else {
		rootCA, err = x509.SystemCertPool()
		if err != nil {
			log.Error("failed to get system cert pool", "error", err)
			os.Exit(1)
		}
	}

	tlsProvider := tlsprovider.NewTLSProvider(cfg.SSL.Cert, cfg.SSL.PrivKey)
	tlsProvider.SetThreshold(cfg.SSL.RefreshThreshold)
	tlsProvider.SetRetry(cfg.SSL.RefreshRetry)
	tlsProvider.SetLogger(log)
	// Load the certificate synchronously to make sure
	// it's valid on startup.
	if err := tlsProvider.LoadCertificate(); err != nil {
		log.Error("failed to load certificate", "error", err)
		os.Exit(1)
	}

	dirkEndpoints := make([]*e2wd.Endpoint, len(cfg.Dirk.Endpoints))
	for i, endpoint := range cfg.Dirk.Endpoints {
		host, portStr, err := net.SplitHostPort(endpoint)
		if err != nil {
			log.Error("failed to split host port", "error", err)
			os.Exit(1)
		}
		port, err := strconv.ParseUint(portStr, 10, 32)
		if err != nil {
			log.Error("failed to convert port to int", "error", err)
			os.Exit(1)
		}
		dirkEndpoints[i] = e2wd.NewEndpoint(host, uint32(port))
	}

	dirkSigner := dirksigner.NewDirkSigner(
		cfg.GenesisForkVersion(),
		dirkEndpoints,
		cfg.Dirk.Wallet,
		rootCA,
		tlsProvider,
		log,
	)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Dirk.Timeout)
	defer cancel()
	err = dirkSigner.Open(ctx, logLevel)
	if err != nil {
		log.Error("failed to open dirk signer", "error", err)
		os.Exit(1)
	}

	service, err := service.NewService(dirkSigner)
	if err != nil {
		log.Error("failed to create service", "error", err)
		os.Exit(1)
	}

	service.SetLogger(log)
	service.SetTimeout(cfg.Dirk.Timeout)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		n, err := w.Write([]byte("{\"status\":\"UP\",\"outcome\":\"UP\",\"checks\":[]}"))
		if err != nil {
			log.Error("failed to write healthcheck response", "error", err, "bytes_written", n)
		}
	})

	server := http.Server{
		Handler: api.HandlerWithOptions(service, api.StdHTTPServerOptions{
			BaseRouter: mux,
		}),
	}

	// Trap sigterm to gracefully shutdown the server
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChan
		log.Info("received signal, shutting down")
		err := server.Shutdown(context.Background())
		if err != nil {
			log.Error("failed to shutdown server", "error", err)
		}

		// Restore sigterm handler
		signal.Reset(os.Interrupt, syscall.SIGTERM)
	}()

	err = server.Serve(listener)
	if err == http.ErrServerClosed {
		log.Info("server closed")
		return
	}
	if err != nil {
		log.Error("failed to serve", "error", err)
		os.Exit(1)
	}
}
