# proxykit — one entry point for humans, CI and coding agents.
#   make check   run before finishing ANY change (see AGENTS.md)
GO ?= go
FUZZ_TIME ?= 10s
GOLANGCI_LINT_VERSION ?= v2.15.0
GOLANGCI_LINT ?= $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

# Every GOOS/GOARCH proxykit must build for. Each platform_<os>.go needs at
# least one entry here; the last ones exercise platform_unsupported.go.
LIB_PKGS ?= . ./relay ./gateway
CROSS_TARGETS ?= \
	darwin/amd64 darwin/arm64 ios/arm64 \
	linux/amd64 linux/arm64 linux/386 android/arm64 \
	windows/amd64 windows/arm64 windows/386 \
	freebsd/amd64 openbsd/amd64 netbsd/amd64 js/wasm wasip1/wasm

.PHONY: check fmt fmt-check vet lint cross test race coverage fuzz build

check: fmt-check vet lint cross race

fmt:
	gofmt -w .

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed (run make fmt):"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

lint:
	$(GOLANGCI_LINT) run ./...

# Compiles every platform file under its own build tag: a missing
# platformBackend method fails here, not on a user's machine.
cross:
	@set -e; for t in $(CROSS_TARGETS); do \
		echo "build $$t"; \
		GOOS=$${t%/*} GOARCH=$${t#*/} CGO_ENABLED=0 $(GO) build $(LIB_PKGS); \
	done

test:
	$(GO) test -timeout 60s ./...

race:
	$(GO) test -race -timeout 60s ./...

coverage:
	$(GO) test -race -coverpkg=.,./relay,./gateway -coverprofile=coverage.out -timeout 60s ./...
	$(GO) tool cover -func=coverage.out

fuzz:
	$(GO) test . -run='^$$' -fuzz='^FuzzParse$$' -fuzztime=$(FUZZ_TIME)
	$(GO) test . -run='^$$' -fuzz='^FuzzParseWithLayout$$' -fuzztime=$(FUZZ_TIME)

build:
	$(GO) build ./...
