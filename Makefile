OAPI_CODEGEN = go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest

.PHONY: build
build: generate
	go build -o remote-signer-dirk-interop .

.PHONY: generate
generate: $(shell find remote-signing-api/signing/ -type f)
	go generate ./...

.PHONY: test
test:
	go test ./...

.PHONY: coverage.out
coverage.out:
	go test ./... -coverprofile=coverage.out -covermode=atomic

.PHONY: coverage
coverage: coverage.out
	go tool cover -html=coverage.out
