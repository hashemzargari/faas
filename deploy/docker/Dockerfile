# Multi-stage build for every FASS binary.
#
# Dependencies are vendored, so the build needs no network and is reproducible.
# CGO is disabled: the whole tree is pure Go (no SQLite cgo driver by design,
# see docs/06 §2.0 decision D-C).

FROM golang:1.24-alpine AS build
WORKDIR /src

# Cache the dependency layer separately from the source.
COPY go.mod go.sum ./
COPY vendor/ ./vendor/
RUN go mod verify

COPY . .
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0 GOFLAGS=-mod=vendor
RUN for cmd in fass-gateway fass-coordinator fass-agent fass-console fass-cli fass-bridge fass-operator fass-all; do \
      [ -d "cmd/$cmd" ] && ls cmd/$cmd/*.go >/dev/null 2>&1 && \
        CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
          -o /out/$cmd ./cmd/$cmd || echo "skip $cmd"; \
    done

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /usr/local/bin/
USER nonroot:nonroot
EXPOSE 7000 8080 7100 9090
ENTRYPOINT ["/usr/local/bin/fass-all"]
