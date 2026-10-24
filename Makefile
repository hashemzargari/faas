.PHONY: all build test race vet lint fmt e2e compat chaos bench dev dev-up dev-down dev-logs image clean cli console deploy-lint

SHELL := /bin/bash
GOENV := source scripts/env.sh &&

all: build test

build:
	$(GOENV) go build -trimpath -o bin/ ./cmd/...

test:
	$(GOENV) go test -count=1 ./cmd/... ./internal/... ./pkg/...

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

# Third-party client matrix against a live cluster. `compat-clients` is
# plaintext dev; `compat-clients-tls` runs the same 16 checks with mTLS on the
# shard transport (throwaway CA minted into a temp dir, never in the repo).
compat-clients: build
	bash scripts/compat.sh

compat-clients-tls: build
	COMPAT_TLS=1 bash scripts/compat.sh

chaos: build
	$(GOENV) go test -count=1 -tags=chaos ./test/chaos/...

bench:
	$(GOENV) go test -run=^$$ -bench=. -benchmem ./internal/ec/ ./internal/gateway/offloader/

# Docker dev cluster (deploy/docker/compose.dev.yml): builds the image, boots
# the coordinator + 12 per-disk agents + gateway, runs the end-to-end smoke
# check (12 ACTIVE + a real S3 PUT/GET), then tears everything down including
# volumes. Requires Docker Engine + Compose v2. No-container alternative:
# ./scripts/smoke-cluster.sh
COMPOSE_DEV := docker compose -f deploy/docker/compose.dev.yml

dev:
	@set -euo pipefail; \
	trap '$(COMPOSE_DEV) down -v --remove-orphans >/dev/null 2>&1 || true' EXIT; \
	$(COMPOSE_DEV) up -d --build; \
	$(COMPOSE_DEV) run --rm smoke; \
	echo "make dev: 12-agent dev cluster smoke check passed"

dev-up:
	$(COMPOSE_DEV) up -d --build

dev-down:
	$(COMPOSE_DEV) down -v --remove-orphans

dev-logs:
	$(COMPOSE_DEV) logs -f --tail=100

# Operator surface. `make build` also produces bin/fass-cli and bin/fass-console
# (named after their directories); these targets install the operator-facing
# names: bin/fass and bin/fass-console.
cli:
	$(GOENV) go build -trimpath -o bin/fass ./cmd/fass-cli

console:
	$(GOENV) go build -trimpath -o bin/fass-console ./cmd/fass-console

# Lint the deployment artifacts. Optional tooling is skipped cleanly: this is a
# convenience gate, not a reason for CI to fail on a host without Helm.
deploy-lint:
	@set -euo pipefail; \
	if command -v helm >/dev/null 2>&1; then \
		echo "deploy-lint: helm $$(helm version --short)"; \
		helm lint deploy/helm/fass; \
		for v in deploy/helm/fass/values-*.yaml; do \
			echo "deploy-lint: helm template -f $$v"; \
			helm template fass deploy/helm/fass -f "$$v" >/dev/null; \
		done; \
	else \
		echo "deploy-lint: helm not found — skipping Helm lint/template"; \
	fi; \
	if command -v systemd-analyze >/dev/null 2>&1; then \
		echo "deploy-lint: systemd-analyze verify"; \
		out=$$(mktemp); \
		if systemd-analyze verify deploy/systemd/*.service 2>"$$out"; then \
			cat "$$out"; echo "deploy-lint: systemd units ok"; \
		else \
			if grep -v 'is not executable' "$$out" | grep -q .; then \
				cat "$$out" >&2; rm -f "$$out"; exit 1; \
			fi; \
			echo "deploy-lint: systemd units syntactically ok (binaries not installed on this host)"; \
		fi; \
		rm -f "$$out"; \
	else \
		echo "deploy-lint: systemd-analyze not found — skipping unit verification"; \
	fi

image:
	docker build -f deploy/docker/Dockerfile -t fass:dev .

clean:
	rm -rf bin .gocache
