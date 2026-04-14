package dirksigner

import (
	"bytes"
	"strings"
	"testing"

	api "github.com/jshufro/remote-signer-dirk-interop/generated"
	"github.com/jshufro/remote-signer-dirk-interop/pkg/domains"
)

func domain(domain domains.DomainType, genesisValidatorsRoot string, epoch uint64, fork *api.Fork) ([]byte, error) {
	return calculateDomainImpl(domain, fork, genesisValidatorsRoot, epoch)
}

func TestCalculateDomain(t *testing.T) {
	d, err := domain(domains.DomainAggregateAndProof, "0x0000000000000000000000000000000000000000000000000000000000000000", 100, &api.Fork{
		CurrentVersion:  "0x00000000",
		PreviousVersion: "0x00000000",
		Epoch:           "100",
	})
	if err != nil {
		t.Fatalf("failed to calculate domain: %v", err)
	}
	expectedDomain := "06000000f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9"
	expectedDomainBytes, err := decodeHex(expectedDomain)
	if err != nil {
		t.Fatalf("failed to decode expected domain: %v", err)
	}
	if !bytes.Equal(d, expectedDomainBytes) {
		t.Fatalf("domain is not correct: %x", d)
	}

	// Invalid genesis validator root should produce an error
	_, err = domain(domains.DomainAggregateAndProof, "0xgg", 100, &api.Fork{
		CurrentVersion:  "0x00000000",
		PreviousVersion: "0x00000000",
		Epoch:           "100",
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	_, err = domain(domains.DomainAggregateAndProof, "0x12", 100, &api.Fork{
		CurrentVersion:  "0x00000000",
		PreviousVersion: "0x00000000",
		Epoch:           "100",
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	// Invalid current version should produce an error
	_, err = domain(domains.DomainAggregateAndProof, "0x0000000000000000000000000000000000000000000000000000000000000000", 100, &api.Fork{
		CurrentVersion:  "0x1234567890",
		PreviousVersion: "0x00000000",
		Epoch:           "100",
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "fork version is not 4 bytes") {
		t.Fatalf("error is not correct: %v", err)
	}
	_, err = domain(domains.DomainAggregateAndProof, "0x0000000000000000000000000000000000000000000000000000000000000000", 100, &api.Fork{
		CurrentVersion:  "0xgg",
		PreviousVersion: "0x00000000",
		Epoch:           "100",
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	// Invalid epoch should produce an error
	_, err = domain(domains.DomainAggregateAndProof, "0x0000000000000000000000000000000000000000000000000000000000000000", 100, &api.Fork{
		CurrentVersion:  "0x00000000",
		PreviousVersion: "0x00000000",
		Epoch:           "not-a-number",
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse fork epoch") {
		t.Fatalf("error is not correct: %v", err)
	}

	// Invalid previous version should produce an error
	_, err = domain(domains.DomainAggregateAndProof, "0x0000000000000000000000000000000000000000000000000000000000000000", 10, &api.Fork{
		CurrentVersion:  "0x00000000",
		PreviousVersion: "0xgg",
		Epoch:           "100",
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode previous fork version") {
		t.Fatalf("error is not correct: %v", err)
	}
}
