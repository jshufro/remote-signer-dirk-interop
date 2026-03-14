package tls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestCertFiles creates a temporary self-signed certificate and key on disk
// and returns their file paths.
func newTestCertFiles(t *testing.T, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	var certBuf bytes.Buffer
	if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("failed to encode certificate: %v", err)
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	var keyBuf bytes.Buffer
	if err := pem.Encode(&keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("failed to encode private key: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	if err := os.WriteFile(certPath, certBuf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, keyBuf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	return certPath, keyPath
}

func TestNewTLSProviderDefaults(t *testing.T) {
	certPath, keyPath := "cert.pem", "key.pem"

	p := NewTLSProvider(certPath, keyPath)
	if p.certPath != certPath {
		t.Fatalf("expected certPath %q, got %q", certPath, p.certPath)
	}
	if p.keyPath != keyPath {
		t.Fatalf("expected keyPath %q, got %q", keyPath, p.keyPath)
	}
	if p.threshold != 24*time.Hour {
		t.Fatalf("expected default threshold 24h, got %v", p.threshold)
	}
	if p.retry != 10*time.Minute {
		t.Fatalf("expected default retry 10m, got %v", p.retry)
	}
	if p.log == nil {
		t.Fatalf("expected non-nil logger")
	}
}

func TestTLSProviderSetters(t *testing.T) {
	p := NewTLSProvider("cert.pem", "key.pem")

	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	p.SetLogger(logger)
	if p.log != logger {
		t.Fatalf("expected logger to be set")
	}

	p.SetThreshold(5 * time.Minute)
	if p.threshold != 5*time.Minute {
		t.Fatalf("expected threshold 5m, got %v", p.threshold)
	}

	p.SetRetry(30 * time.Second)
	if p.retry != 30*time.Second {
		t.Fatalf("expected retry 30s, got %v", p.retry)
	}
}

func TestLoadCertificateSuccessAndGetCertificateCaches(t *testing.T) {
	// Certificate valid for a while so that reload threshold is not triggered.
	certPath, keyPath := newTestCertFiles(t, time.Now().Add(2*time.Hour))

	p := NewTLSProvider(certPath, keyPath)

	// Initial explicit load.
	if err := p.LoadCertificate(); err != nil {
		t.Fatalf("LoadCertificate failed: %v", err)
	}

	p.mu.RLock()
	firstCert := p.cachedCert
	firstLoaded := p.lastLoaded
	p.mu.RUnlock()

	if firstCert == nil {
		t.Fatalf("expected cachedCert to be set after LoadCertificate")
	}
	if firstCert.Leaf == nil {
		t.Fatalf("expected Leaf to be set on cached certificate")
	}
	if firstLoaded.IsZero() {
		t.Fatalf("expected lastLoaded to be set")
	}

	// GetCertificate should return the same cached cert without reloading.
	got, err := p.GetCertificate()
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if got != firstCert {
		t.Fatalf("expected GetCertificate to return cached cert pointer")
	}
}

func TestLoadCertificateMissingFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "missing-cert.pem")
	keyPath := filepath.Join(dir, "missing-key.pem")

	p := NewTLSProvider(certPath, keyPath)

	// Missing cert file.
	if err := p.LoadCertificate(); err == nil {
		t.Fatalf("expected error when cert file is missing")
	}

	// Present cert, missing key.
	if err := os.WriteFile(certPath, []byte("dummy cert"), 0o600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := p.LoadCertificate(); err == nil {
		t.Fatalf("expected error when key file is missing")
	}
}

func TestLoadCertificateBadKeyPair(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	// Write something that cannot form a valid key pair.
	if err := os.WriteFile(certPath, []byte("not a cert"), 0o600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	p := NewTLSProvider(certPath, keyPath)
	if err := p.LoadCertificate(); err == nil {
		t.Fatalf("expected error from invalid key pair")
	}
}

func TestLoadCertificateBadLeafCertificate(t *testing.T) {
	// Valid key but a PEM-encoded block that X509KeyPair accepts,
	// while x509.ParseCertificate fails when parsing Certificate[0].
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	// Garbage bytes with CERTIFICATE type; X509KeyPair only decodes PEM, it doesn't parse.
	var certBuf bytes.Buffer
	if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}); err != nil {
		t.Fatalf("failed to encode garbage certificate: %v", err)
	}
	if err := os.WriteFile(certPath, certBuf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}

	// Valid private key.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	var keyBuf bytes.Buffer
	if err := pem.Encode(&keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		t.Fatalf("failed to encode private key: %v", err)
	}
	if err := os.WriteFile(keyPath, keyBuf.Bytes(), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	p := NewTLSProvider(certPath, keyPath)
	if err := p.LoadCertificate(); err == nil {
		t.Fatalf("expected error from invalid leaf certificate")
	}
}

func TestGetCertificateConcurrentLoadWhenEmpty(t *testing.T) {
	// Use a real cert; GetCertificate should lazily load it when cache is empty.
	certPath, keyPath := newTestCertFiles(t, time.Now().Add(2*time.Hour))

	p := NewTLSProvider(certPath, keyPath)

	got, err := p.GetCertificate()
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if got == nil {
		t.Fatalf("expected non-nil certificate")
	}

	// Subsequent call should still return a valid cert without error.
	got2, err := p.GetCertificate()
	if err != nil {
		t.Fatalf("GetCertificate (second) failed: %v", err)
	}
	if !tlsCertEqual(got, got2) {
		t.Fatalf("expected same certificate contents on subsequent GetCertificate")
	}
}

// tlsCertEqual checks that two *tls.Certificate have the same raw certificate bytes.
func tlsCertEqual(a, b *tls.Certificate) bool {
	if a == nil || b == nil {
		return a == b
	}
	if len(a.Certificate) != len(b.Certificate) {
		return false
	}
	for i := range a.Certificate {
		if !bytes.Equal(a.Certificate[i], b.Certificate[i]) {
			return false
		}
	}
	return true
}

func TestGetCertificateTriggersAsyncReloadWhenExpiringSoon(t *testing.T) {
	// Cert initially valid long enough; we'll later adjust Leaf.NotAfter and lastLoaded
	// to simulate an about-to-expire certificate that should trigger reload.
	certPath, keyPath := newTestCertFiles(t, time.Now().Add(2*time.Hour))

	p := NewTLSProvider(certPath, keyPath)
	// Use aggressive thresholds so test runs quickly.
	p.SetThreshold(1 * time.Hour)
	p.SetRetry(0)

	if err := p.LoadCertificate(); err != nil {
		t.Fatalf("initial LoadCertificate failed: %v", err)
	}

	// Capture initial lastLoaded.
	p.mu.RLock()
	initialLoaded := p.lastLoaded
	p.mu.RUnlock()

	// Simulate certificate expiring soon and last load sufficiently in the past.
	p.mu.Lock()
	if p.cachedCert == nil || p.cachedCert.Leaf == nil {
		p.mu.Unlock()
		t.Fatalf("expected cached certificate with Leaf set")
	}
	p.cachedCert.Leaf.NotAfter = time.Now().Add(30 * time.Minute)      // less than threshold
	p.lastLoaded = time.Now().Add(-2 * time.Hour)                      // older than retry
	cachedBefore := p.cachedCert                                       // keep pointer for sanity
	p.mu.Unlock()

	// Call GetCertificate, which should return the cached cert and start a
	// background reload because of the threshold logic.
	got, err := p.GetCertificate()
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if got != cachedBefore {
		t.Fatalf("expected GetCertificate to return cached cert")
	}

	// Wait briefly for the goroutine to run reload.
	deadline := time.Now().Add(2 * time.Second)
	for {
		time.Sleep(10 * time.Millisecond)

		p.mu.RLock()
		newLoaded := p.lastLoaded
		p.mu.RUnlock()

		if newLoaded.After(initialLoaded) {
			// Reload occurred.
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected async reload to update lastLoaded; still %v", newLoaded)
		}
	}
}

