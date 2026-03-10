package tls

import (
	"crypto/tls"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type TLSProvider struct {
	threshold time.Duration
	retry     time.Duration
	certPath  string
	keyPath   string

	cachedCert *tls.Certificate
	lastLoaded atomic.Pointer[time.Time]
	mu         sync.RWMutex

	log *slog.Logger
}

func NewTLSProvider(certPath, keyPath string) *TLSProvider {
	return &TLSProvider{
		threshold: 24 * time.Hour,   // By default, refresh certificate when 24h remain
		retry:     10 * time.Minute, // By default, retry every 10 minutes until the cert is fresh
		certPath:  certPath,
		keyPath:   keyPath,
		log:       slog.Default(),
	}
}

func (t *TLSProvider) SetLogger(log *slog.Logger) {
	t.log = log
}

func (t *TLSProvider) SetThreshold(threshold time.Duration) {
	t.threshold = threshold
}

func (t *TLSProvider) SetRetry(retry time.Duration) {
	t.retry = retry
}

func (t *TLSProvider) LoadCertificate() error {
	return t.loadCertificate()
}

func (t *TLSProvider) GetCertificate() (*tls.Certificate, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.cachedCert != nil {
		// Check the expiry
		timeLeft := time.Until(t.cachedCert.Leaf.NotAfter)

		// If we're below the threshold, attempt to refresh the certificates from disk
		// but do so asynchronously
		lastLoadedPtr := t.lastLoaded.Load()
		if timeLeft < t.threshold && lastLoadedPtr != nil && time.Since(*lastLoadedPtr) > t.retry {
			go func() {
				err := t.loadCertificate()
				if err != nil {
					t.log.Error("failed to load certificate", "error", err)
				}
			}()
		}

		return t.cachedCert, nil
	}

	// We don't have a cached certificate, so we need to load one from disk synchronously
	err := t.loadCertificate()
	if err != nil {
		return nil, err
	}

	return t.cachedCert, nil
}

func (t *TLSProvider) loadCertificate() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.log.Info("loading certificate", "cert_path", t.certPath, "key_path", t.keyPath)

	cert, err := os.ReadFile(t.certPath)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(t.keyPath)
	if err != nil {
		return err
	}

	certPair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return err
	}

	now := time.Now()
	t.lastLoaded.Store(&now)
	t.cachedCert = &certPair

	return nil
}
