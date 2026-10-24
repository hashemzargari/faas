.PHONY: all build test race vet lint fmt e2e compat chaos bench dev image clean

SHELL := /bin/bash
GOENV := source scripts/env.sh &&

all: build test

build:
	$(GOENV) go build -trimpath -o bin/ ./cmd/...

test:
	$(GOENV) go test -count=1 ./internal/... ./pkg/...

race:
	$(GOENV) go test -race -count=1 ./internal/... ./pkg/...

vet:
	$(GOENV) go vet ./...

fmt:
	$(GOENV) gofmt -l -w .

e2e: build
	$(GOENV) go test -count=1 -tags=e2e ./test/e2e/...

compat: build
	$(GOENV) go test -count=1 -tags=compat ./test/compat/...

chaos: build
	$(GOENV) go test -count=1 -tags=chaos ./test/chaos/...

bench:
	$(GOENV) go test -run=^$$ -bench=. -benchmem ./internal/ec/ ./internal/gateway/offloader/

dev: build
	$(GOENV) go run ./cmd/fass-all --dev

image:
	docker build -f deploy/docker/Dockerfile -t fass:dev .

clean:
	rm -rf bin .gocache
