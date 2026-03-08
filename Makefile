OAPI_CODEGEN = go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest

.PHONY: generate
generate: $(shell find remote-signing-api/signing/ -type f)
	mkdir -p internal/api
	$(OAPI_CODEGEN) -config oapi-codegen.yaml --import-mapping ../schemas.yaml:remote-signing-api/schemas.yaml remote-signing-api/remote-signing-oapi.yaml
