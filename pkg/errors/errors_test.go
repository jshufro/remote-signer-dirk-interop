package errors

import (
	"testing"
)

func TestErrors(t *testing.T) {
	err := InternalServerError()
	if err.Error() != "internal_server_error" {
		t.Fatalf("expected error for missing required fields, got %v", err)
	}
	msg := "this is an error message"
	err = PublicKeyNotFound("%s", msg)
	if err.Error() != "public_key_not_found: this is an error message" {
		t.Fatalf("expected error for missing required fields, got %v", err)
	}
	err = BadRequest("%s", msg)
	if err.Error() != "bad_request: this is an error message" {
		t.Fatalf("expected error for missing required fields, got %v", err)
	}
	err = SlashingProtectionTriggered("%s", msg)
	if err.Error() != "slashing_protection_triggered: this is an error message" {
		t.Fatalf("expected error for missing required fields, got %v", err)
	}
}
