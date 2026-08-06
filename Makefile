# Klarion — build/test/release automation.
#
# Version metadata is injected into the main package at link time. We prefer
# `git describe` but fall back to sane defaults so the Makefile also works from
# a source tarball with no .git directory (guarded with `2>/dev/null || echo`).

BINARY      := klarion
PKG         := ./cmd/klarion
INSTALL_DIR ?= $(shell go env GOBIN)
ifeq ($(INSTALL_DIR),)
INSTALL_DIR := $(shell go env GOPATH)/bin
endif

# Guarded git introspection — never fail outside a repo.
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# -s -w strips debug info for smaller binaries; -X injects build metadata into
# the frozen main.version/commit/date vars (see cmd/klarion/root.go).
LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

GO      ?= go
GOFILES := $(shell find . -type f -name '*.go' -not -path './vendor/*')

.PHONY: all build install test lint fmt vet tidy clean snapshot testdata scan-self help

all: build

## build: compile the klarion binary with version metadata.
build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) $(PKG)

## install: install klarion into $(INSTALL_DIR).
install:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(INSTALL_DIR)/$(BINARY) $(PKG)

## test: run the full test suite with the race detector and coverage.
test:
	$(GO) test ./... -race -cover

## lint: verify formatting and run go vet.
lint:
	@unformatted=$$(gofmt -l $(GOFILES)); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needs to be run on:"; echo "$$unformatted"; exit 1; \
	fi
	$(GO) vet ./...

## fmt: format all Go sources in place.
fmt:
	gofmt -w $(GOFILES)

## vet: run go vet only.
vet:
	$(GO) vet ./...

## tidy: reconcile go.mod/go.sum.
tidy:
	$(GO) mod tidy

## clean: remove build artifacts.
clean:
	rm -f $(BINARY)
	rm -rf dist/
	$(GO) clean

## snapshot: build a local, unpublished release with goreleaser.
snapshot:
	goreleaser release --snapshot --clean

## testdata: generate the demo fixture (testdata/leaky.env), which is not committed.
testdata:
	./testdata/gen-leaky-env.sh

## scan-self: build klarion and scan this repository (dogfooding).
scan-self: build
	./$(BINARY) scan .

## help: list available targets.
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
