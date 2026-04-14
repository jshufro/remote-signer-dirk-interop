package test

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/attestantio/dirk/testing/logger"
	"github.com/herumi/bls-eth-go-binary/bls"
	api "github.com/jshufro/remote-signer-dirk-interop/generated"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/dirksigner"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/service"
	tlstest "github.com/jshufro/remote-signer-dirk-interop/pkg/tls/test"
	"github.com/jshufro/remote-signer-dirk-interop/test/client"
	"github.com/jshufro/remote-signer-dirk-interop/test/dirkdaemon"
	"github.com/jshufro/remote-signer-dirk-interop/test/dirkdaemon/proc/distributedwallet"
	"github.com/neilotoole/slogt"
	e2wd "github.com/wealdtech/go-eth2-wallet-dirk"
)

func init() {
	err := bls.Init(bls.BLS12_381)
	if err != nil {
		panic(err)
	}
}

func emitDirkLogs(t *testing.T, tmpdir string, logCaptureMap map[int]*logger.LogCapture) {
	for id, logCapture := range logCaptureMap {
		logfile := filepath.Join(tmpdir, fmt.Sprintf("signer-test%02d/dirk.log", id))
		fd, err := os.OpenFile(logfile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("Could not open log file: %v", err)
		}
		defer func() { _ = fd.Close() }()

		for _, entry := range logCapture.Entries() {
			_, err := fd.WriteString(entry["message"].(string))
			if err != nil {
				t.Fatalf("Could not write log to file: %v", err)
			}
			for key, value := range entry {
				if key == "message" {
					continue
				}
				_, err := fmt.Fprintf(fd, " '%s'='%v'", key, value)
				if err != nil {
					t.Fatalf("Could not write log to file: %v", err)
				}
			}
			_, err = fd.WriteString("\n")
			if err != nil {
				t.Fatalf("Could not write log to file: %v", err)
			}
		}
	}
}

func startDaemons(t *testing.T, ids ...dirkdaemon.ID) []*e2wd.Endpoint {
	ctx := t.Context()
	tmpdir, err := os.MkdirTemp("", t.Name())
	if err != nil {
		t.Fatalf("Could not create temp dir for logs and wallets: %v", err)
	}
	peerMap, logCaptureMap, err := dirkdaemon.StartDaemons(ctx, tmpdir, ids...)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Log("test failed, leaving logs and wallets in place for debugging")
			t.Log("tmpdir", tmpdir)
			emitDirkLogs(t, tmpdir, logCaptureMap)
			return
		}
		_ = os.RemoveAll(tmpdir)
	})
	endpoints := make([]*e2wd.Endpoint, 0, len(peerMap))
	for _, peer := range peerMap {
		host, portStr, err := net.SplitHostPort(peer)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		port, err := strconv.ParseUint(portStr, 10, 32)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		endpoints = append(endpoints, e2wd.NewEndpoint(host, uint32(port)))
	}
	return endpoints
}

func newDirkSigner(t *testing.T, walletName string, endpoints []*e2wd.Endpoint, logger *slog.Logger) (*dirksigner.DirkSigner, error) {
	ctx := t.Context()
	dirkSigner := dirksigner.NewDirkSigner(
		[]byte{0x00, 0x00, 0x00, 0x00},
		endpoints,
		walletName,
		tlstest.CAPool(),
		tlstest.NewMockTLSProvider(tlstest.ClientTest01),
		logger,
	)

	err := dirkSigner.Open(ctx, slog.LevelDebug)
	if err != nil {
		return nil, fmt.Errorf("failed to open dirk signer: %w", err)
	}

	return dirkSigner, nil
}

func startService(t *testing.T, walletName string, endpoints []*e2wd.Endpoint, logger *slog.Logger) *client.ClientWithResponses {
	dirkSigner, err := newDirkSigner(t, walletName, endpoints, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	service, err := service.NewService(dirkSigner)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	service.SetLogger(logger)

	// create the http test server
	server := httptest.NewServer(api.Handler(service))

	client, err := client.NewClientWithResponses(server.URL)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	return client
}

func TestDirkInteropSignerOperations(t *testing.T) {
	// Create the dirk daemons
	endpoints := startDaemons(t, dirkdaemon.ID1)
	logger := slogt.New(t, slogt.Text())
	c := startService(t, "Wallet 1", endpoints, logger)

	// Get the public keys
	ctx := t.Context()
	publicKeysResp, err := c.PUBLICKEYLISTWithResponse(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if publicKeysResp.StatusCode() != http.StatusOK {
		t.Fatalf("expected status code %d, got %d", http.StatusOK, publicKeysResp.StatusCode())
	}
	if publicKeysResp.JSON200 == nil {
		t.Fatalf("expected public keys, got none")
	}
	publicKeys := *publicKeysResp.JSON200
	if len(publicKeys) == 0 {
		t.Fatalf("expected public keys, got none")
	}

	// Check that the public keys match expected values
	expectedPublicKeys := Wallet1PublicKeys
	if len(publicKeys) != len(expectedPublicKeys) {
		t.Fatalf("expected %d public keys, got %d", len(expectedPublicKeys), len(publicKeys))
	}
	slices.Sort(publicKeys)
	slices.Sort(expectedPublicKeys)
	if !slices.Equal(publicKeys, expectedPublicKeys) {
		t.Fatalf("public keys do not match expected values")
	}

	if !slices.Contains(expectedPublicKeys, InteropTestAccountStr) {
		t.Fatalf("interop test account not found in public keys")
	}

	// Test signing
	for _, testCase := range InteropSigningTestCases() {
		buffer := bytes.NewBuffer(nil)
		if testCase.RawBody != "" {
			buffer.WriteString(testCase.RawBody)
		} else {
			marshaller := json.NewEncoder(buffer)
			err := marshaller.Encode(testCase.SignableMsg)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		}
		identifier := testCase.Pubkey
		if testing.Verbose() {
			t.Logf("signing request: %s", buffer.String())
		}
		resp, err := c.SIGNWithBodyWithResponse(
			ctx,
			identifier,
			"application/json",
			buffer,
		)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if resp.StatusCode() != testCase.ExpectedHttpStatus {
			t.Fatalf("expected status code %d, got %d", testCase.ExpectedHttpStatus, resp.StatusCode())
		}
		if testCase.ExpectedHttpStatus == http.StatusOK {
			if resp.JSON200 == nil {
				t.Fatalf("expected signature, got none")
			}
			if !strings.EqualFold(resp.JSON200.Signature, testCase.ExpectedSignature) {
				t.Fatalf("expected signature %v, got %v", testCase.ExpectedSignature, resp.JSON200.Signature)
			}
		}
	}
}

func TestDirkDistributedSignerOperations(t *testing.T) {
	// Create the dirk daemons
	endpoints := startDaemons(t)
	logger := slogt.New(t, slogt.Text())
	c := startService(t, "Wallet 3", endpoints, logger)

	// Get the public keys
	ctx := t.Context()
	publicKeysResp, err := c.PUBLICKEYLISTWithResponse(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if publicKeysResp.StatusCode() != http.StatusOK {
		t.Fatalf("expected status code %d, got %d", http.StatusOK, publicKeysResp.StatusCode())
	}
	if publicKeysResp.JSON200 == nil {
		t.Fatalf("expected public keys, got none")
	}
	publicKeys := *publicKeysResp.JSON200
	if len(publicKeys) == 0 {
		t.Fatalf("expected public keys, got none")
	}
	pubkey := publicKeys[0]
	if pubkey != distributedwallet.DistributedAccountPubkeyStr {
		t.Fatalf("expected public key %s, got %s", InteropTestAccountStr, pubkey)
	}

	// Test signing
	for _, testCase := range DistributedSigningTestCases() {
		buffer := bytes.NewBuffer(nil)
		if testCase.RawBody != "" {
			buffer.WriteString(testCase.RawBody)
		} else {
			marshaller := json.NewEncoder(buffer)
			err := marshaller.Encode(testCase.SignableMsg)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		}
		identifier := testCase.Pubkey
		if testing.Verbose() {
			t.Logf("signing request: %s", buffer.String())
		}
		resp, err := c.SIGNWithBodyWithResponse(
			ctx,
			identifier,
			"application/json",
			buffer,
		)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if resp.StatusCode() != testCase.ExpectedHttpStatus {
			t.Fatalf("expected status code %d, got %d", testCase.ExpectedHttpStatus, resp.StatusCode())
		}
		if testCase.ExpectedHttpStatus == http.StatusOK {
			if resp.JSON200 == nil {
				t.Fatalf("expected signature, got none")
			}
			if !strings.EqualFold(resp.JSON200.Signature, testCase.ExpectedSignature) {
				t.Fatalf("expected signature %v, got %v", testCase.ExpectedSignature, resp.JSON200.Signature)
			}
		}
	}
}
