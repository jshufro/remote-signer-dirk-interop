package web3signerparity

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jshufro/remote-signer-dirk-interop/test"
	"github.com/jshufro/remote-signer-dirk-interop/test/client"
)

func TestParitySigning(t *testing.T) {
	testCases := test.InteropSigningTestCases()

	url := "http://localhost:9000"
	client, err := client.NewClientWithResponses(url,
		client.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
			req.Header.Set("Accept", "application/json")
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	for _, testCase := range testCases {
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
		bodyBytes := buffer.Bytes()
		identifier := testCase.Pubkey
		if testing.Verbose() {
			t.Logf("signing request: %s", buffer.String())
		}
		resp, err := client.SIGNWithBodyWithResponse(
			t.Context(),
			identifier,
			"application/json",
			bytes.NewReader(bodyBytes),
		)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if resp.StatusCode() != testCase.ExpectedHttpStatus {
			t.Fatalf("expected status code %d, got %d", testCase.ExpectedHttpStatus, resp.StatusCode())
		}
		if testCase.ExpectedHttpStatus == http.StatusOK {
			t.Logf("response: %+v", string(resp.Body))
			if resp.JSON200 == nil {
				t.Fatalf("expected signature, got none")
			}
			gotSig := resp.JSON200.Signature
			expSig := testCase.ExpectedSignature
			match := strings.EqualFold(gotSig, expSig)
			if !match {
				t.Fatalf("expected signature %v, got %v", expSig, resp.JSON200.Signature)
			}
		}
	}
}
