GO ?= go
FUZZ_TIME ?= 10s

.PHONY: fmt vet test race coverage fuzz build check

fmt:
	gofmt -w .

vet:
	$(GO) vet ./...

test:
	$(GO) test -timeout 60s ./...

race:
	$(GO) test -race -timeout 60s ./...

coverage:
	$(GO) test -race -coverpkg=.,./relay -coverprofile=coverage.out -timeout 60s ./...
	$(GO) tool cover -func=coverage.out

fuzz:
	$(GO) test . -run='^$$' -fuzz='^FuzzParse$$' -fuzztime=$(FUZZ_TIME)
	$(GO) test . -run='^$$' -fuzz='^FuzzParseWithLayout$$' -fuzztime=$(FUZZ_TIME)

build:
	$(GO) build ./...

check: vet race
