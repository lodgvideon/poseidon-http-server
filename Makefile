.PHONY: build lint test test-race bench bench-gate coverage coverage-gate tidy loadtest

COVERAGE_MIN ?= 80
GO ?= go
GOLANGCI_LINT ?= golangci-lint

# Version metadata injected into the binary via -ldflags.
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/poseidon-server ./cmd/poseidon-server

tidy:
	$(GO) mod tidy

lint:
	$(GO) vet ./...
	$(GOLANGCI_LINT) run

test:
	$(GO) test -count=1 ./...

test-race:
	$(GO) test -race -count=1 ./...

coverage:
	$(GO) test -race -count=1 -coverprofile=cover.out ./...
	$(GO) tool cover -func=cover.out

coverage-gate:
	$(GO) test -race -count=1 -coverprofile=cover.out ./...
	./scripts/coverage-gate.sh $(COVERAGE_MIN)

bench:
	$(GO) test -bench=. -benchmem -benchtime=2s -count=10 -run=^$$ ./...

bench-gate:
	./scripts/bench-gate.sh

# loadtest — manual load/soak harness (see loadtest/README.md). Selected via
# LOADTEST={h2load|ghz|k6} (default h2load). Requires a running server and the
# corresponding tool (h2load/ghz/k6). Guarded: no-ops with an install hint when
# the tool is absent, so `make loadtest` never hard-fails in tool-less CI.
LOADTEST ?= h2load
loadtest:
	@case "$(LOADTEST)" in \
	  h2load) \
	    if command -v h2load >/dev/null 2>&1; then \
	      bash loadtest/h2load.sh; \
	    else \
	      echo "loadtest: h2load not installed — skipping (install nghttp2-client; see loadtest/README.md)"; \
	    fi ;; \
	  ghz) \
	    if command -v ghz >/dev/null 2>&1; then \
	      bash loadtest/ghz.sh; \
	    else \
	      echo "loadtest: ghz not installed — skipping (go install github.com/bojand/ghz/cmd/ghz@latest; see loadtest/README.md)"; \
	    fi ;; \
	  k6) \
	    if command -v k6 >/dev/null 2>&1; then \
	      k6 run loadtest/k6_http2.js; \
	    else \
	      echo "loadtest: k6 not installed — skipping (brew install k6; see loadtest/README.md)"; \
	    fi ;; \
	  *) \
	    echo "loadtest: unknown LOADTEST='$(LOADTEST)' (want h2load|ghz|k6)"; exit 2 ;; \
	esac
