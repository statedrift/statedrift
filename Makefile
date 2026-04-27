.PHONY: build build-all clean test vet install release docker \
        test-docker test-docker-v02 test-docker-all test-integration

BINARY  := statedrift
VERSION := 0.2.0
COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILDDATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
# LICENSE_SECRET must be set in the environment for production builds.
# Dev/CI builds use the placeholder (licenses signed with it only work against
# binaries built with the same placeholder key).
# Example: LICENSE_SECRET=my-real-key make build
LICENSE_SECRET ?= PLACEHOLDER_DEV_BUILD_DO_NOT_SHIP

LDFLAGS := -s -w \
	-X 'github.com/statedrift/statedrift/internal/collector.Version=$(VERSION)' \
	-X 'github.com/statedrift/statedrift/internal/collector.BuildDate=$(BUILDDATE)' \
	-X 'github.com/statedrift/statedrift/internal/license.licenseSecret=$(LICENSE_SECRET)'

DIST := dist

# Build a static binary for the current platform.
build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/statedrift

# Build for multiple platforms.
build-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY)-linux-amd64 ./cmd/statedrift
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY)-linux-arm64 ./cmd/statedrift

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf bin/ $(DIST)/

# Install to /usr/local/bin (run with sudo).
install: build
	cp bin/$(BINARY) /usr/local/bin/$(BINARY)
	chmod 755 /usr/local/bin/$(BINARY)
	@echo "Installed $(BINARY) to /usr/local/bin/"
	@echo "Run 'sudo statedrift init' to get started."

# Cross-compile, package, and checksum for release.
# Produces:
#   dist/statedrift-VERSION-linux-amd64.tar.gz
#   dist/statedrift-VERSION-linux-arm64.tar.gz
#   dist/sha256sums.txt
release: clean
	mkdir -p $(DIST)

	# amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-ldflags="$(LDFLAGS)" \
		-o $(DIST)/$(BINARY) ./cmd/statedrift
	cp README.md LICENSE $(DIST)/
	tar -czf $(DIST)/$(BINARY)-$(VERSION)-linux-amd64.tar.gz \
		-C $(DIST) $(BINARY) README.md LICENSE
	rm $(DIST)/$(BINARY) $(DIST)/README.md $(DIST)/LICENSE

	# arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
		-ldflags="$(LDFLAGS)" \
		-o $(DIST)/$(BINARY) ./cmd/statedrift
	cp README.md LICENSE $(DIST)/
	tar -czf $(DIST)/$(BINARY)-$(VERSION)-linux-arm64.tar.gz \
		-C $(DIST) $(BINARY) README.md LICENSE
	rm $(DIST)/$(BINARY) $(DIST)/README.md $(DIST)/LICENSE

	# checksums
	cd $(DIST) && sha256sum $(BINARY)-$(VERSION)-*.tar.gz > sha256sums.txt

	# Extract just this version's section from CHANGELOG.md so
	# `gh release create --notes-file dist/release-notes-$(VERSION).md`
	# doesn't dump the whole changelog into the GitHub release page.
	awk '/^## \[$(VERSION)\]/{flag=1; print; next} /^## \[/{flag=0} flag' \
		CHANGELOG.md > $(DIST)/release-notes-$(VERSION).md

	@echo ""
	@echo "Release artifacts in $(DIST)/:"
	@ls -lh $(DIST)/

# Build the distribution container image. Mirrors `make build`'s LDFLAGS
# via Dockerfile build args so the image binary reports the same version
# string as the host binary.
docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILDDATE=$(BUILDDATE) \
		--build-arg LICENSE_SECRET=$(LICENSE_SECRET) \
		-t statedrift:$(VERSION) \
		-t statedrift:latest \
		.

# ── Docker integration tests ──────────────────────────────────────────────────

# Original integration tests (pre-v0.2).
test-docker: build
	@echo "--- test: no-systemd container"
	bash tests/test_no_systemd.sh
	@echo "--- test: verify.sh (host)"
	bash tests/test_verify.sh
	@echo "--- test: verify.sh Ubuntu 24.04"
	bash tests/test_verify_ubuntu2404.sh
	@echo ""
	@echo "All pre-v0.2 Docker tests passed."

# v0.2 Docker integration tests.
# Covers: optional collectors, analyze command, Rocky Linux 9 (rpm), arm64.
# arm64 requires: make build-all + QEMU (docker run --privileged --rm tonistiigi/binfmt --install arm64)
test-docker-v02: build
	@echo "--- test: v0.2 collectors + analyze (Ubuntu 22.04)"
	bash tests/test_v02_collectors.sh
	@echo "--- test: v0.2 Rocky Linux 9 (rpm)"
	bash tests/test_v02_rocky9.sh
	@echo ""
	@echo "All v0.2 Docker tests passed."
	@echo "NOTE: arm64 test requires 'make build-all' and QEMU — run separately:"
	@echo "      bash tests/test_v02_arm64.sh"

# Run all Docker tests (pre-v0.2 + v0.2).
test-docker-all: build
	$(MAKE) test-docker
	$(MAKE) test-docker-v02

# Run arm64 test only (requires make build-all and QEMU configured).
test-arm64: build-all
	bash tests/test_v02_arm64.sh

# Run unit tests + all Docker tests (full CI equivalent).
test-integration: test test-docker-all
