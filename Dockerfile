# Multi-stage build for statedrift.
# Final image is ~8 MB on top of distroless/static (~2 MB CA certs +
# /etc/passwd). Stdlib-only Go binary, fully static (CGO_ENABLED=0).
#
# Build:
#   docker build -t statedrift:dev .
#   # or, with version metadata matching the Makefile:
#   docker build \
#     --build-arg VERSION=$(git describe --tags --always 2>/dev/null || echo dev) \
#     --build-arg COMMIT=$(git rev-parse --short HEAD) \
#     --build-arg BUILDDATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
#     -t statedrift:dev .
#
# Run (snapshot the container itself — works out of the box):
#   docker run --rm statedrift:dev version
#
# Note: snapshotting the *host* /proc and /sys from inside this container
# requires a --host-root flag that doesn't exist yet (planned post-v0.3).
# Until then, use the bare binary on the host for host snapshots, or run
# the container with --pid=host --net=host -v /proc:/host/proc:ro and a
# wrapper that nsenters into the host.

# ---- builder ----
FROM golang:1.22-alpine AS builder

ARG VERSION=dev
ARG BUILDDATE=unknown
ARG LICENSE_SECRET=statedrift-pro-license-v1:replace-before-release

WORKDIR /src

COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

ENV CGO_ENABLED=0 GOOS=linux

RUN go build \
    -ldflags="-s -w \
      -X 'github.com/statedrift/statedrift/internal/collector.Version=${VERSION}' \
      -X 'github.com/statedrift/statedrift/internal/collector.BuildDate=${BUILDDATE}' \
      -X 'github.com/statedrift/statedrift/internal/license.licenseSecret=${LICENSE_SECRET}'" \
    -o /out/statedrift ./cmd/statedrift

# ---- final ----
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/statedrift /statedrift

ENTRYPOINT ["/statedrift"]
