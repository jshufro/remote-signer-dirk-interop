package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed mappings.yaml
var yamlFile []byte

type Import struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

type Mappings struct {
	Imports         []Import          `yaml:"imports"`
	Types           map[string]string `yaml:"types"`
	DeprecatedTypes []string          `yaml:"deprecated-types"`
}

func (i Import) String() string {
	if i.Name == "" {
		return fmt.Sprintf("\t\"%s\"\n", i.Path)
	}
	return fmt.Sprintf("\t%s \"%s\"\n", i.Name, i.Path)
}

var mappings Mappings

func main() {
	if len(os.Args) != 6 {
		log.Fatalf("usage: %s <sign.yaml> <pkgname> <dst.go> <replacements-pkgname> <replacements-dst.go>", os.Args[0])
	}

	// parse mappings.yaml
	if err := yaml.Unmarshal(yamlFile, &mappings); err != nil {
		log.Fatalf("parsing mappings.yaml: %v", err)
	}

	// schemasPath is currently unused but kept for the intended interface.
	// It can be used in the future to validate that referenced schemas exist.
	signPath := os.Args[1]
	pkgname := os.Args[2]
	dst := os.Args[3]
	replacementsPkgname := os.Args[4]
	replacementsDst := os.Args[5]

	data, err := os.ReadFile(signPath)
	if err != nil {
		log.Fatalf("reading sign.yaml: %v", err)
	}

	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		log.Fatalf("parsing sign.yaml: %v", err)
	}

	schema, err := extractSchema(root)
	if err != nil {
		log.Fatalf("extracting schema from sign.yaml: %v", err)
	}

	discriminatorMapping, err := extractDiscriminatorMapping(schema)
	if err != nil {
		log.Fatalf("extracting discriminator mapping from sign.yaml: %v", err)
	}

	oneOf, err := extractOneOf(schema)
	if err != nil {
		log.Fatalf("extracting oneOf from sign.yaml: %v", err)
	}

	schemaNames := schemaNamesFromRefs(oneOf)
	if len(schemaNames) == 0 {
		log.Fatalf("no schemas found under post.requestBody.content.application/json.schema.oneOf")
	}

	discriminatorsToTypes, err := discriminatorMappingToTypes(discriminatorMapping)
	if err != nil {
		log.Fatalf("extracting discriminator mapping to types: %v", err)
	}
	if len(discriminatorsToTypes) == 0 {
		log.Fatalf("no discriminator mapping found")
	}

	if len(discriminatorsToTypes) != len(schemaNames) {
		log.Fatalf("number of discriminator mappings does not match number of schemas")
	}

	if err := emitGo(pkgname, schemaNames, discriminatorsToTypes, dst, replacementsPkgname, replacementsDst); err != nil {
		log.Fatalf("emitting Go: %v", err)
	}
}

func extractSchema(root map[string]any) (map[string]any, error) {
	post, ok := root["post"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing or invalid 'post' object")
	}

	requestBody, ok := post["requestBody"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing or invalid 'post.requestBody'")
	}

	content, ok := requestBody["content"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing or invalid 'post.requestBody.content'")
	}

	appJSON, ok := content["application/json"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing or invalid 'post.requestBody.content.application/json'")
	}

	schema, ok := appJSON["schema"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing or invalid '...application/json.schema'")
	}
	return schema, nil
}

func extractDiscriminatorMapping(schema map[string]any) (map[string]any, error) {
	rawDiscriminator, ok := schema["discriminator"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing or invalid '...schema.discriminator'")
	}

	discriminatorMapping, ok := rawDiscriminator["mapping"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing or invalid '...schema.discriminator.mapping'")
	}

	return discriminatorMapping, nil
}

func extractOneOf(schema map[string]any) ([]any, error) {

	rawOneOf, ok := schema["oneOf"].([]any)
	if !ok {
		return nil, fmt.Errorf("missing or invalid '...schema.oneOf'")
	}

	return rawOneOf, nil
}

func refToName(ref string) string {
	lastSlash := strings.LastIndex(ref, "/")
	if lastSlash == -1 || lastSlash+1 >= len(ref) {
		return ""
	}
	return ref[lastSlash+1:]
}

func schemaNamesFromRefs(oneOf []any) []string {
	seen := make(map[string]struct{})
	var out []string

	for _, item := range oneOf {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ref, ok := m["$ref"].(string)
		if !ok || ref == "" {
			continue
		}

		name := refToName(ref)
		if name == "" {
			continue
		}

		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}

	return out
}

func discriminatorMappingToTypes(discriminatorMapping map[string]any) (map[string]string, error) {
	types := make(map[string]string)
	for discriminator, schema := range discriminatorMapping {
		schemaStr, ok := schema.(string)
		if !ok {
			return nil, fmt.Errorf("invalid schema type: %T", schema)
		}

		types[discriminator] = refToName(schemaStr)
	}
	return types, nil
}

type panicWriter struct {
	bytes.Buffer
}

func (w *panicWriter) Write(s string) {
	if _, err := w.WriteString(s); err != nil {
		panic(fmt.Errorf("writing generated buffer: %w", err))
	}
}

func (w *panicWriter) Writef(format string, args ...any) {
	if _, err := fmt.Fprintf(&w.Buffer, format, args...); err != nil {
		panic(fmt.Errorf("writing generated buffer: %w", err))
	}
}

func emitGo(pkgname string, schemaNames []string, discriminatorsToTypes map[string]string, dst string, replacementsPkgname string, replacementsDst string) error {
	var buf panicWriter

	slices.SortFunc(mappings.Imports, func(a, b Import) int {
		return strings.Compare(a.Path, b.Path)
	})

	customImports := make([]string, 0, len(mappings.Imports))
	for _, importItem := range mappings.Imports {
		customImports = append(customImports, importItem.String())
	}

	skipTypes := make(map[string]any)
	for _, typeItem := range mappings.DeprecatedTypes {
		skipTypes[typeItem] = struct{}{}
	}

	write := buf.Write
	writef := buf.Writef

	write("// Code generated by signablegen; DO NOT EDIT.\n\n")
	writef("package %s\n\n", pkgname)

	write("import (\n")
	write("\t\"context\"\n")
	write("\t\"fmt\"\n")
	write("\n")
	write("\t\"github.com/jshufro/remote-signer-dirk-interop/pkg/errors\"\n")
	write("\t\"github.com/jshufro/remote-signer-dirk-interop/pkg/fork\"\n")
	write("\n")
	writef("\t\"github.com/jshufro/remote-signer-dirk-interop/%s/%s\"\n", pkgname, replacementsPkgname)
	write(")\n")
	write("\n")
	write("// Signer combines all signable request types from the remote signing API.\n")
	write("type Signer[AccountType any] interface {\n")
	for _, name := range schemaNames {
		if _, ok := skipTypes[name]; ok {
			continue
		}
		writef("\t%s(context.Context, AccountType, *%s.%s, *fork.ForkInfo) ([96]byte, error)\n", name, replacementsPkgname, name)
	}
	write("}\n")
	write("\n")
	write("// StringToSignableType converts a discriminator string to a signable type.\n")
	write("func StringToSignableType(discriminator string) (any, error) {\n")
	write("\tswitch discriminator {\n")
	discriminators := make([]string, 0, len(discriminatorsToTypes))
	for discriminator := range discriminatorsToTypes {
		discriminators = append(discriminators, discriminator)
	}
	sort.Strings(discriminators)

	for _, discriminator := range discriminators {
		name := discriminatorsToTypes[discriminator]
		if _, ok := skipTypes[name]; ok {
			continue
		}
		writef("\tcase %q:\n", discriminator)
		writef("\t\treturn &%s.%s{}, nil\n", replacementsPkgname, name)
	}

	write("\tdefault:\n")
	write("\t\treturn nil, fmt.Errorf(\"unknown discriminator value: %s\", discriminator)\n")
	write("\t}\n")
	write("}\n")
	write("\n")
	write("// Sign calls the appropriate sign method based on the type of the signable.\n")
	write("func Sign[AccountType any](ctx context.Context, signer Signer[AccountType], account AccountType, signable any, forkInfo *fork.ForkInfo) ([96]byte, error) {\n")
	write("\tswitch signable := signable.(type) {\n")

	for _, name := range schemaNames {
		if _, ok := skipTypes[name]; ok {
			continue
		}
		writef("\tcase *%s.%s:\n", replacementsPkgname, name)
		writef("\t\treturn signer.%s(ctx, account, signable, forkInfo)\n", name)
	}

	write("\tdefault:\n")
	write("\t\treturn [96]byte{}, errors.InternalServerError()\n")
	write("\t}\n")
	write("}\n")

	f, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("creating %s: %w", dst, err)
	}

	if _, err := io.Copy(f, &buf); err != nil {
		return fmt.Errorf("writing %s: %w", dst, err)
	}

	err = f.Close()
	if err != nil {
		return fmt.Errorf("closing %s: %w", dst, err)
	}

	write("// Code generated by signablegen; DO NOT EDIT.\n\n")
	writef("package %s\n\n", replacementsPkgname)

	write("import (\n")
	for _, importItem := range customImports {
		write(importItem)
	}
	write(")\n")
	write("\n")
	aliases := []string{}
	for from, to := range mappings.Types {
		aliases = append(aliases, fmt.Sprintf("type %s = %s\n", from, to))
	}
	slices.Sort(aliases)
	for _, alias := range aliases {
		write(alias)
	}

	f, err = os.Create(replacementsDst)
	if err != nil {
		return fmt.Errorf("creating %s: %w", replacementsDst, err)
	}

	if _, err := io.Copy(f, &buf); err != nil {
		return fmt.Errorf("writing %s: %w", replacementsDst, err)
	}
	err = f.Close()
	if err != nil {
		return fmt.Errorf("closing %s: %w", replacementsDst, err)
	}

	return nil
}
