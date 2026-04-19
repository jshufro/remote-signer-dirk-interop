[![Go Reference](https://pkg.go.dev/badge/github.com/jshufro/remote-signer-dirk-interop.svg)](https://pkg.go.dev/github.com/jshufro/remote-signer-dirk-interop) [![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0) [![Go generate & lint](https://github.com/jshufro/remote-signer-dirk-interop/actions/workflows/generate-check.yml/badge.svg)](https://github.com/jshufro/remote-signer-dirk-interop/actions/workflows/generate-check.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/jshufro/remote-signer-dirk-interop)](https://goreportcard.com/report/github.com/jshufro/remote-signer-dirk-interop)
### remote-signer-dirk-interop

`remote-signer-dirk-interop` is a small HTTP service that implements the [Ethereum remote-signer API](https://github.com/ethereum/remote-signing-api) and forwards all signing requests to a [Dirk](https://github.com/attestantio/dirk) signer or signing cluster.

This project has not been audited (and it will not be audited).
Use it at your own risk.

---

### Configuration

An example configuration file is provided in [config.example.yaml](config.example.yaml)

Run the program with `./remote-signer-dirk-interop -config path/to/config.yaml`.

**Note:** The TLS/SSL configuration for this application only secures its communications with Dirk.
**You are responsible for securing communication between the VC and the `listen_port` for this application.**

An example docker-compose.yaml:
```yaml
services:
  remote-signer-dirk-interop:
    image: ghcr.io/jshufro/remote-signer-dirk-interop:latest
    command: ["-config", "/etc/remote-signer/config.yaml"]
    ports:
      - "127.0.0.1:9090:9090"
      - "127.0.0.1:9091:9091"
    volumes:
      - ./certs:/certs:ro
    configs:
      - source: remote_signer_config
        target: /etc/remote-signer/config.yaml

configs:
  remote_signer_config:
    content: |
      log_level: info
      log_format: json
      listen_address: "0.0.0.0"
      listen_port: 9090
      metrics:
        listen_address: "0.0.0.0"
        listen_port: 9091
      dirk:
        timeout: 4s
        endpoints:
          - "dirk1.example.invalid:9091"
          - "dirk2.example.invalid:9091"
          - "dirk3.example.invalid:9091"
        wallet: "example-wallet"
      ssl:
        refresh_threshold: 24h
        refresh_retry: 10m
        cert: "/certs/server.crt"
        privkey: "/certs/server.key"
        root_ca: "/certs/ca.crt"
      network: "mainnet"
```

---

### Why?

Dirk is a powerful distributed signer, but its bespoke gRPC API is only supported natively by [Vouch](https://github.com/attestantio/vouch).
This project lets you use Dirk with any Validator Client that supports the remote-signer API, e.g., [Vero](https://github.com/serenita-org/vero)

You may want to use this project if:
1. You want to use a specific Validator Client with Dirk signers (other than Vouch).
2. You want to use both Vero and Vouch with Dirk (with an appropriate Vouch multiinstance configuration).

You should not use this project if:
1. You simply want to use Vouch and Dirk.
2. You want full DVT.
3. You want to use Vero, but are happy with [Web3Signer](https://docs.web3signer.consensys.io/) instead of Dirk.

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

This project is released under [AGPL-3.0](https://www.gnu.org/licenses/agpl-3.0.en.html).
Unlike the GPL alone, AGPL can apply when people **use the program over a network**, not only when you ship binaries.
Read [LICENSE.md](LICENSE.md) for the exact conditions, especially if you fork, patch, or embed the service in a product you operate for others.


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
