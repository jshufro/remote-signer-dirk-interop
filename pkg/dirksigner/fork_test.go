package dirksigner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jshufro/remote-signer-dirk-interop/internal/api"
	"github.com/jshufro/remote-signer-dirk-interop/internal/domains"
	"github.com/neilotoole/slogt"
)

func TestCalculateDomain(t *testing.T) {
	dirk := DirkSigner{
		log: slogt.New(t),
	}
	domain, err := dirk.calculateDomain(domains.DomainAggregateAndProof, "0x0000000000000000000000000000000000000000000000000000000000000000", 100, &api.Fork{
		CurrentVersion:  "0x00000000",
		PreviousVersion: "0x00000000",
	})
	if err != nil {
		t.Fatalf("failed to calculate domain: %v", err)
	}
	expectedDomain := "06000000f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9"
	expectedDomainBytes, err := decodeHex(expectedDomain)
	if err != nil {
		t.Fatalf("failed to decode expected domain: %v", err)
	}
	if !bytes.Equal(domain, expectedDomainBytes) {
		t.Fatalf("domain is not correct: %x", domain)
	}

	// Invalid genesis validator root should produce an error
	_, err = dirk.calculateDomain(domains.DomainAggregateAndProof, "0xgg", 100, &api.Fork{
		CurrentVersion:  "0x00000000",
		PreviousVersion: "0x00000000",
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	_, err = dirk.calculateDomain(domains.DomainAggregateAndProof, "0x12", 100, &api.Fork{
		CurrentVersion:  "0x00000000",
		PreviousVersion: "0x00000000",
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	// Invalid current version should produce an error
	_, err = dirk.calculateDomain(domains.DomainAggregateAndProof, "0x0000000000000000000000000000000000000000000000000000000000000000", 100, &api.Fork{
		CurrentVersion:  "0x1234567890",
		PreviousVersion: "0x00000000",
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "fork version is not 4 bytes") {
		t.Fatalf("error is not correct: %v", err)
	}
	_, err = dirk.calculateDomain(domains.DomainAggregateAndProof, "0x0000000000000000000000000000000000000000000000000000000000000000", 100, &api.Fork{
		CurrentVersion:  "0xgg",
		PreviousVersion: "0x00000000",
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}
