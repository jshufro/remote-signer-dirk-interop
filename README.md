[![Go Reference](https://pkg.go.dev/badge/github.com/jshufro/remote-signer-dirk-interop.svg)](https://pkg.go.dev/github.com/jshufro/remote-signer-dirk-interop) [![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0) [![Go generate & lint](https://github.com/jshufro/remote-signer-dirk-interop/actions/workflows/generate-check.yml/badge.svg)](https://github.com/jshufro/remote-signer-dirk-interop/actions/workflows/generate-check.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/jshufro/remote-signer-dirk-interop)](https://goreportcard.com/report/github.com/jshufro/remote-signer-dirk-interop)
### remote-signer-dirk-interop

`remote-signer-dirk-interop` is a small HTTP service that implements the [Ethereum remote-signer API](https://github.com/ethereum/remote-signing-api) and forwards all signing requests to a [Dirk](http://github.com/attestantio/dirk) signer or signing cluster.

---

### Configuration

An example configuration file is provided in [config.example.yaml](config.example.yaml)

---

### Why?

Dirk is a powerful distributed signer, but its bespoke gRPC API is only supported natively by [Vouch](https://github.com/attestantio/vouch).
This project lets you use Dirk with any Validator Client that supports the remote-signer API, e.g., [Vero](https://github.com/serenita-org/vero)

---

### Testing

To run the main test suite locally:

```bash
make test
```

To generate a coverage report:
```bash
make coverage
```

For Web3Signer parity tests, `cd test/web3signer-parity` and run `make ci`.

---

### License

This project is licensed under [AGPLv3](LICENSE.md).

### Copyright

remote-signer-dirk-interop
Copyright (C) 2026  Jacob Shufro

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
