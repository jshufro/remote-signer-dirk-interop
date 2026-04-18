package main

import (
	"context"
	"crypto/tls"
	_ "embed"
	"flag"
	"fmt"
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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	e2wd "github.com/wealdtech/go-eth2-wallet-dirk"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"google.golang.org/grpc/credentials"
)

func startDirkSigner(ctx context.Context, cfg *config.Config) (*dirksigner.DirkSigner, error) {
	var err error

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
		RootCA:             cfg.SSL.CertPool,
	}

	dirkSigner.SetLogger(cfg.Log)
	ctx, cancel := context.WithTimeout(ctx, cfg.Dirk.Timeout)
	defer cancel()

	err = dirkSigner.Open(ctx, cfg.Dirk.Wallet, dirkEndpoints, cfg.SSL.TLSProvider, cfg.ParsedLogLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to open dirk signer: %w", err)
	}

	return dirkSigner, nil
}

func startHttp(ctx context.Context, service api.ServerInterface, cfg *config.Config) error {

	cfg.Log.Info("listening",
		"address", cfg.ListenAddress,
		"port", cfg.ListenPort,
		"dirk_endpoints", cfg.Dirk.Endpoints,
		"dirk_wallet", cfg.Dirk.Wallet)
	_ = context.AfterFunc(ctx, func() {
		cfg.Log.Info("received signal, shutting down")
	})

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.ListenPort))
	if err != nil {
		cfg.Log.Error("failed to listen", "error", err)
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
			cfg.Log.Error("failed to write healthcheck response", "error", err, "bytes_written", n)
		}
	})

	var metricsServer *http.Server
	var metricsListener net.Listener
	if cfg.Metrics.ListenPort == cfg.ListenPort && cfg.Metrics.ListenAddress == cfg.ListenAddress {
		mux.Handle("/metrics", promhttp.Handler())
	} else if cfg.Metrics.ListenPort != 0 {
		metricsListener, err = net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.Metrics.ListenAddress, cfg.Metrics.ListenPort))
		if err != nil {
			cfg.Log.Error("failed to listen for metrics", "error", err)
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
			cfg.Log.Error("failed to shutdown server", "error", err)
		}

		if metricsServer != nil {
			err = metricsServer.Shutdown(context.Background())
			if err != nil {
				cfg.Log.Error("failed to shutdown metrics server", "error", err)
			}
		}
	})

	if metricsServer != nil {
		go func() {
			err = metricsServer.Serve(metricsListener)
			if err != http.ErrServerClosed && err != nil {
				cfg.Log.Error("failed to serve metrics", "error", err)
				os.Exit(1)
			}
			if err == http.ErrServerClosed {
				cfg.Log.Info("metrics server closed")
			}
		}()
	}

	err = server.Serve(listener)
	if err == http.ErrServerClosed {
		cfg.Log.Info("server closed")
		return nil
	}
	if err != nil {
		cfg.Log.Error("failed to serve", "error", err)
		return fmt.Errorf("failed to serve: %w", err)
	}
	return nil
}

//go:embed version.txt
var version string

func startTracing(ctx context.Context, cfg *config.Config) error {
	if cfg.OTLP.TraceRecipient == "" {
		return nil
	}
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(cfg.OTLP.TraceRecipient),
	}
	if cfg.OTLP.Secure {
		tlsConfig := &tls.Config{
			GetClientCertificate: cfg.SSL.TLSProvider.GetClientCertificate,
			RootCAs:              cfg.SSL.CertPool,
		}
		credentials := credentials.NewTLS(tlsConfig)
		opts = append(opts, otlptracegrpc.WithTLSCredentials(credentials))
	} else {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	client := otlptracegrpc.NewClient(opts...)
	exporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create otlp trace exporter: %w", err)
	}

	var hostname string
	if cfg.OTLP.HostnameOverride != "" {
		hostname = cfg.OTLP.HostnameOverride
	} else {
		hostname, err = os.Hostname()
		if err != nil {
			cfg.Log.Error("failed to get hostname", "error", err)
			hostname = "unknown"
		}
	}

	var serviceInstanceID string
	if cfg.OTLP.ServiceInstanceIDOverride != "" {
		serviceInstanceID = cfg.OTLP.ServiceInstanceIDOverride
	} else {
		serviceInstanceID = hostname
	}

	rs := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String("remote-signer-dirk-interop"),
		semconv.HostNameKey.String(hostname),
		semconv.ServiceInstanceIDKey.String(serviceInstanceID),
		semconv.ServiceVersionKey.String(version),
	)

	tp := trace.NewTracerProvider(trace.WithBatcher(exporter), trace.WithResource(rs))

	// Set as the global default trace provider
	otel.SetTracerProvider(tp)

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	context.AfterFunc(ctx, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := tp.Shutdown(ctx)
		if err != nil {
			cfg.Log.Error("failed to shutdown tracing", "error", err)
		}
		cfg.Log.Debug("tracing shutdown completed")
	})

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

	err = startTracing(ctx, cfg)
	if err != nil {
		cfg.Log.Error("failed to start tracing", "error", err)
		os.Exit(1)
	}

	dirkSigner, err := startDirkSigner(ctx, cfg)
	if err != nil {
		cfg.Log.Error("failed to start dirk signer", "error", err)
		os.Exit(1)
	}

	service, err := service.NewService(dirkSigner)
	if err != nil {
		cfg.Log.Error("failed to create service", "error", err)
		os.Exit(1)
	}

	service.SetLogger(cfg.Log)
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

	err = startHttp(ctx, service, cfg)
	if err != nil {
		cfg.Log.Error("failed to start http", "error", err)
		os.Exit(1)
	}
}
