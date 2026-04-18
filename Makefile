OAPI_CODEGEN = go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest

GOENV_GOCACHE = $(shell go env GOCACHE)
GOENV_GOMODCACHE = $(shell go env GOMODCACHE)

PKG = $(subst /,\/,$(shell go list))

TEST_SKIP = -test.skip=TestParitySigning

VERBOSE ?= false
ifeq ($(VERBOSE), true)
	_GO_TEST_FLAGS = $(GO_TEST_FLAGS) -test.v $(TEST_SKIP)
else
	_GO_TEST_FLAGS = $(GO_TEST_FLAGS) $(TEST_SKIP)
endif

DOCKER_TEST_CMD = docker run --rm \
	-v $(PWD):/app\
	-v $(GOENV_GOCACHE):/home/user/.cache/go-build \
	-v $(GOENV_GOMODCACHE):/home/user/.go-mod-cache \
	-v /tmp:/tmp \
	-u $(shell id -u):$(shell id -g) \
	-e GOCACHE=/home/user/.cache/go-build \
	-e GOMODCACHE=/home/user/.go-mod-cache \
	-w /app \
	--add-host=signer-test01:0.0.0.0 \
	--add-host=signer-test02:0.0.0.0 \
	--add-host=signer-test03:0.0.0.0 \
	--add-host=signer-test04:0.0.0.0 \
	--add-host=signer-test05:0.0.0.0 \
	remote-signer-dirk-interop-dependencies go test $(_GO_TEST_FLAGS) ./...

.PHONY: build
build: generate
	go build -o remote-signer-dirk-interop .

.PHONY: generate
generate: $(shell find remote-signing-api/signing/ -type f)
	go generate ./...

.PHONY: remote-signer-dirk-interop-dependencies
remote-signer-dirk-interop-dependencies: generate
	docker build --target dependencies -t remote-signer-dirk-interop-dependencies .

.PHONY: test
test: remote-signer-dirk-interop-dependencies
	$(DOCKER_TEST_CMD)

.PHONY: coverage.out
coverage.out: remote-signer-dirk-interop-dependencies
	$(DOCKER_TEST_CMD) -coverpkg=./... -coverprofile=coverage.out
	sed -i '/\.gen\.go/d' coverage.out
	sed -i '/$(PKG)\/test/d' coverage.out
	sed -i '/$(PKG)\/pkg\/tls\/test/d' coverage.out
	sed -i '/$(PKG)\/main.go/d' coverage.out
	sed -i '/$(PKG)\/signablegen/d' coverage.out

.PHONY: coverage
coverage: coverage.out
	go tool cover -html=coverage.out

.PHONY: clean
clean:
	docker rmi remote-signer-dirk-interop-dependencies
	rm -f remote-signer-dirk-interop
	rm -f coverage.out

.PHONY: release
release: version.txt
	docker build . -t ghcr.io/jshufro/remote-signer-dirk-interop:$(shell cat version.txt)
	docker push ghcr.io/jshufro/remote-signer-dirk-interop:$(shell cat version.txt)

.PHONY: release-latest
release-latest:
	docker tag ghcr.io/jshufro/remote-signer-dirk-interop:$(shell cat version.txt) ghcr.io/jshufro/remote-signer-dirk-interop:latest
	docker push ghcr.io/jshufro/remote-signer-dirk-interop:latest
