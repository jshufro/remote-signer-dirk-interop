package typeconv

import (
	"strings"
	"testing"

	"github.com/jshufro/remote-signer-dirk-interop/generated/api"
)

func TestHexRoundTrip(t *testing.T) {
	hex := "0x5555555555555555555555000000000000000000000000333333333333333333"
	decoded, err := DecodeHex(hex)
	if err != nil {
		t.Fatalf("failed to decode hex: %v", err)
	}
	reencoded := EncodeHex(decoded)
	if reencoded != hex {
		t.Fatalf("expected %s, got %s", hex, reencoded)
	}
}

func TestDecodeGweiError(t *testing.T) {
	_, err := DecodeGwei("invalid")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid syntax") {
		t.Fatalf("expected error `invalid syntax`, got `%v`", err)
	}
}

func TestDecodeBLSPubKeyError(t *testing.T) {
	_, err := DecodeBLSPubKey("invalid")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid byte") {
		t.Fatalf("expected error `invalid byte`, got `%v`", err)
	}
}

var validPubkeyStr = "0x1111111111111100000000000000aaaaaaaaaaa000000000000000ffffffffffaaaaaaa000000000000000ffffffffff"
var validWithdrawalCredentialsStr = "0x0200000000000000000000000000000000000000000033333333333333333333"
var validAmountStr = "1000000000"

func TestDepositSigningToHashRootError(t *testing.T) {
	_, err := DepositSigningToHashRoot(&api.DepositSigning{
		Deposit: struct {
			Amount                string `json:"amount,omitempty"`
			GenesisForkVersion    string `json:"genesis_fork_version,omitempty"`
			Pubkey                string `json:"pubkey,omitempty"`
			WithdrawalCredentials string `json:"withdrawal_credentials,omitempty"`
		}{
			Amount:                "invalid",
			Pubkey:                validPubkeyStr,
			WithdrawalCredentials: validWithdrawalCredentialsStr,
		},
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse amount") {
		t.Fatalf("expected error `failed to parse amount`, got `%v`", err)
	}

	_, err = DepositSigningToHashRoot(&api.DepositSigning{
		Deposit: struct {
			Amount                string `json:"amount,omitempty"`
			GenesisForkVersion    string `json:"genesis_fork_version,omitempty"`
			Pubkey                string `json:"pubkey,omitempty"`
			WithdrawalCredentials string `json:"withdrawal_credentials,omitempty"`
		}{
			Amount:                validAmountStr,
			Pubkey:                "0x04",
			WithdrawalCredentials: validWithdrawalCredentialsStr,
		},
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode pubkey: hex string is 1 bytes, expected 48 bytes") {
		t.Fatalf("expected error `failed to decode pubkey: hex string is 1 bytes, expected 48 bytes`, got `%v`", err)
	}

	_, err = DepositSigningToHashRoot(&api.DepositSigning{
		Deposit: struct {
			Amount                string `json:"amount,omitempty"`
			GenesisForkVersion    string `json:"genesis_fork_version,omitempty"`
			Pubkey                string `json:"pubkey,omitempty"`
			WithdrawalCredentials string `json:"withdrawal_credentials,omitempty"`
		}{
			Amount:                validAmountStr,
			Pubkey:                validPubkeyStr,
			WithdrawalCredentials: "0066",
		},
	})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode withdrawal credentials: hex string is 2 bytes, expected 32 bytes") {
		t.Fatalf("expected error `failed to decode withdrawal credentials: hex string is 2 bytes, expected 32 bytes`, got `%v`", err)
	}
}
