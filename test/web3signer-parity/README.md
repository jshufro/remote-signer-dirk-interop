# Web3Signer parity test

This test compares signing responses from Consensys Web3Signer (mainnet) against expected signatures.

**Why a separate expected file?** The shared `test.InteropSigningTestCases()` expected values use a custom fork/genesis. Web3Signer is configured with `eth2.network: "mainnet"`, so signing domains differ and signatures do not match. This package uses `expected_signatures.json` (generated from Web3Signer) when present.

**Generate or update expected signatures:**

1. Start Web3Signer (e.g. `make` in this directory) so it listens on port 9000.
2. From the repo root, run:
   ```bash
   UPDATE_PARITY_EXPECTED=1 go test -v ./test/web3signer-parity/... -run TestSigning
   ```
3. This writes `test/web3signer-parity/expected_signatures.json`. Re-run the test without the env var to verify.
