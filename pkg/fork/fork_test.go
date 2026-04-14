package fork

import (
	"reflect"
	"strings"
	"testing"
)

func TestForkInfoRoundTrip(t *testing.T) {
	forkInfo := &ForkInfo{
		Fork: Fork{
			CurrentVersion:  []byte{0x00, 0x00, 0x00, 0x20},
			PreviousVersion: []byte{0x00, 0x00, 0x00, 0x10},
			Epoch:           100,
		},
		GenesisValidatorsRoot: []byte{0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09},
	}
	marshalled, err := forkInfo.MarshalJSON()
	if err != nil {
		t.Fatalf("failed to marshal fork info: %v", err)
	}
	unmarshalled := &ForkInfo{}
	err = unmarshalled.UnmarshalJSON(marshalled)
	if err != nil {
		t.Fatalf("failed to unmarshal fork info: %v", err)
	}
	if !reflect.DeepEqual(forkInfo, unmarshalled) {
		t.Fatalf("fork info is not equal: %v", unmarshalled)
	}
}

func TestForkInvalidJSON(t *testing.T) {
	type testCase struct {
		name          string
		json          string
		expectedError string
	}
	tests := []testCase{
		{
			name: "invalid json",
			json: `invalid json{
				"fork": {
					"current_version": "0x00000020",
					"previous_version": "0x00000010",
					"epoch": "100"
				},
				"genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
			}`,
			expectedError: "invalid character",
		},
		{
			name: "invalid current version",
			json: `{
				"fork": {
					"current_version": "bad current version",
					"previous_version": "0x00000010",
					"epoch": "100"
				},
				"genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
			}`,
			expectedError: "failed to decode current_version",
		},
		{
			name: "invalid current version length",
			json: `{
				"fork": {
					"current_version": "0x0000002000",
					"previous_version": "0x00000010",
					"epoch": "100"
				},
				"genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
			}`,
			expectedError: "current_version is not 4 bytes",
		},
		{
			name: "invalid previous version",
			json: `{
				"fork": {
					"current_version": "0x00000020",
					"previous_version": "bad previous version",
					"epoch": "100"
				},
				"genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
			}`,
			expectedError: "failed to decode previous_version",
		},
		{
			name: "invalid previous version length",
			json: `{
				"fork": {
					"current_version": "0x00000020",
					"previous_version": "0x0000001000",
					"epoch": "100"
				},
				"genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
			}`,
			expectedError: "previous_version is not 4 bytes",
		},
		{
			name: "invalid epoch",
			json: `{
				"fork": {
					"current_version": "0x00000020",
					"previous_version": "0x00000010",
					"epoch": "bad epoch"
				},
				"genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
			}`,
			expectedError: "failed to parse fork epoch",
		},
		{
			name: "invalid genesis validators root",
			json: `{
				"fork": {
					"current_version": "0x00000020",
					"previous_version": "0x00000010",
					"epoch": "100"
				},
				"genesis_validators_root": "bad genesis validators root"
			}`,
			expectedError: "failed to decode genesis_validators_root",
		},
		{
			name: "invalid genesis validators root length",
			json: `{
				"fork": {
					"current_version": "0x00000020",
					"previous_version": "0x00000010",
					"epoch": "100"
				},
				"genesis_validators_root": "0x0000"
			}`,
			expectedError: "genesis_validators_root is not 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forkInfo := &ForkInfo{}
			err := forkInfo.UnmarshalJSON([]byte(tt.json))
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.expectedError) {
				t.Fatalf("expected error `%s`, got `%v`", tt.expectedError, err)
			}
		})
	}
}
