package main

//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.6.0 -config oapi-codegen/oapi-schemas.yaml remote-signing-api/signing/schemas.yaml
//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.6.0 -config oapi-codegen/oapi-codegen.yaml remote-signing-api/remote-signing-oapi.yaml
//go:generate go run ./signablegen remote-signing-api/signing/paths/sign.yaml generated generated/sign.gen.go api generated/api/signables-replacements.gen.go
