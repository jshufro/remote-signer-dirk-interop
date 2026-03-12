package tls

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"os"
	"sync"
	"time"
)

type TLSProvider interface {
	GetCertificate() (*tls.Certificate, error)
}

type tlsProvider struct {
	threshold time.Duration
	retry     time.Duration
	certPath  string
	keyPath   string

	cachedCert *tls.Certificate
	lastLoaded time.Time
	mu         sync.RWMutex

	log *slog.Logger
}

// type assertion
var _ TLSProvider = (*tlsProvider)(nil)

func NewTLSProvider(certPath, keyPath string) *tlsProvider {
	return &tlsProvider{
		threshold: 24 * time.Hour,   // By default, refresh certificate when 24h remain
		retry:     10 * time.Minute, // By default, retry every 10 minutes until the cert is fresh
		certPath:  certPath,
		keyPath:   keyPath,
		log:       slog.Default(),
	}
}

func (t *tlsProvider) SetLogger(log *slog.Logger) {
	t.log = log
}

func (t *tlsProvider) SetThreshold(threshold time.Duration) {
	t.threshold = threshold
}

func (t *tlsProvider) SetRetry(retry time.Duration) {
	t.retry = retry
}

func (t *tlsProvider) LoadCertificate() error {
	return t.loadCertificate()
}

func (t *tlsProvider) GetCertificate() (*tls.Certificate, error) {
	t.mu.RLock()
	cert := t.cachedCert
	if cert != nil {
		// If we're below the threshold, attempt to refresh the certificates from disk asynchronously.
		// Only use Leaf for expiry if it was set (loadCertificateUnlocked sets it).
		if cert.Leaf != nil {
			timeLeft := time.Until(cert.Leaf.NotAfter)
			lastLoaded := t.lastLoaded
			if timeLeft < t.threshold && !lastLoaded.IsZero() && time.Since(lastLoaded) > t.retry {
				go func() {
					err := t.loadCertificate()
					if err != nil {
						t.log.Error("failed to refresh certificate", "error", err)
					}
				}()
			}
		}
		t.mu.RUnlock()
		return cert, nil
	}
	t.mu.RUnlock()

	// No cached cert: take write lock, double-check, and load.
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cachedCert != nil {
		return t.cachedCert, nil
	}
	if err := t.loadCertificateUnlocked(); err != nil {
		return nil, err
	}
	return t.cachedCert, nil
}

// loadCertificate holds the write lock and loads the certificate from disk.
func (t *tlsProvider) loadCertificate() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.loadCertificateUnlocked()
}

// loadCertificateUnlocked loads the certificate from disk and updates cachedCert and lastLoaded.
// Caller must hold t.mu write lock.
func (t *tlsProvider) loadCertificateUnlocked() error {
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
	// Set Leaf so GetCertificate can safely use NotAfter for refresh threshold.
	certPair.Leaf, err = x509.ParseCertificate(certPair.Certificate[0])
	if err != nil {
		return err
	}

	t.lastLoaded = time.Now()
	t.cachedCert = &certPair

	return nil
}
