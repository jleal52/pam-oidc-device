# pam-oidc-device build entry points.
#
# The PAM module (cmd/pam_oidc_device) is a cgo package behind the "pam"
# build tag because it needs <security/pam_modules.h> (libpam0g-dev). Plain
# `go test ./...`, `go vet ./...` and `golangci-lint run ./...` therefore
# never touch it; `make so` builds it natively when the headers are present
# and inside Docker otherwise. `make lint-pam` / `make vet-pam` type-check
# the cgo package (they need the headers, so they also fall back to Docker).

GO          ?= go
GOFLAGS_SO  ?= -trimpath -buildvcs=false -ldflags='-s -w'
PAM_TAGS    ?= pam
BUILD_DIR   ?= build
SO          ?= $(BUILD_DIR)/pam_oidc_device.so
PAM_HEADER  ?= /usr/include/security/pam_modules.h
DOCKER_IMG  ?= golang:1.26-bookworm
GOMOD_CACHE ?= pam-oidc-device-gomod
GOBUILD_CACHE ?= pam-oidc-device-gocache

# Runs a shell command in a throwaway container with libpam0g-dev and the
# repository mounted at /src. Module and build caches persist in named
# volumes so reruns are fast; the build output is chowned back to the
# invoking user because the container runs as root to install packages.
define docker_run
docker run --rm \
	-v "$(CURDIR)":/src -w /src \
	-v $(GOMOD_CACHE):/go/pkg/mod \
	-v $(GOBUILD_CACHE):/tmp/gocache \
	-e GOFLAGS=-buildvcs=false -e GOCACHE=/tmp/gocache \
	-e HOST_UID=$(shell id -u) -e HOST_GID=$(shell id -g) \
	$(DOCKER_IMG) sh -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends libpam0g-dev >/dev/null && $(1); rc=$$?; chown -R "$$HOST_UID:$$HOST_GID" $(BUILD_DIR) 2>/dev/null; exit $$rc'
endef

.PHONY: test lint vet so so-native check-so vet-pam package integration mock-provider clean

test:
	$(GO) test ./...

lint:
	golangci-lint run ./...

vet:
	$(GO) vet ./...

# Type-checks the cgo package; needs the PAM headers.
vet-pam:
	@if [ -f $(PAM_HEADER) ]; then \
		$(GO) vet -tags $(PAM_TAGS) ./cmd/...; \
	else \
		$(call docker_run,go vet -tags $(PAM_TAGS) ./cmd/...); \
	fi

so-native:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 $(GO) build -buildmode=c-shared -tags $(PAM_TAGS) $(GOFLAGS_SO) -o $(SO) ./cmd/pam_oidc_device

so:
	@if [ -f $(PAM_HEADER) ]; then \
		$(MAKE) so-native; \
	else \
		echo "$(PAM_HEADER) not found, building in Docker ($(DOCKER_IMG))"; \
		$(call docker_run,make so-native); \
	fi

# Verifies that the three PAM entry points are exported (prints them).
CHECK_SO_CMD = nm -D $(SO) | grep -E " T pam_sm_(authenticate|setcred|acct_mgmt)$$" | awk "{print} END {if (NR != 3) {print \"check-so: expected 3 pam_sm_* symbols, found \" NR; exit 1}}"
check-so:
	@if command -v nm >/dev/null 2>&1; then \
		$(CHECK_SO_CMD); \
	else \
		$(call docker_run,$(CHECK_SO_CMD)); \
	fi

# Builds dist/pam-oidc-device_<version>_<arch>.{deb,rpm} with nfpm, run from
# its Docker image so that nothing is added to go.mod or the host. The deb
# puts the module under the multiarch directory of ARCH, the rpm under
# /usr/lib64/security. `so` builds for the host architecture, so the package
# refuses to wrap a module whose ELF machine does not match ARCH.
VERSION   ?= 0.0.0-dev
ARCH      ?= amd64
DIST_DIR  ?= dist
NFPM_IMG  ?= goreleaser/nfpm:v2.47.0
MULTIARCH_amd64 = x86_64-linux-gnu
MULTIARCH_arm64 = aarch64-linux-gnu
MULTIARCH ?= $(MULTIARCH_$(ARCH))
ELF_MACHINE_amd64 = 3e00
ELF_MACHINE_arm64 = b700

define nfpm_run
docker run --rm \
	-v "$(CURDIR)":/src -w /src \
	--user "$(shell id -u):$(shell id -g)" \
	-e VERSION="$(VERSION)" -e ARCH="$(ARCH)" -e MULTIARCH="$(MULTIARCH)" \
	$(NFPM_IMG) package -f packaging/nfpm.yaml -p $(1) -t $(DIST_DIR)/
endef

package: so
	@test -n "$(MULTIARCH)" || { echo "package: unsupported ARCH=$(ARCH) (amd64 or arm64)" >&2; exit 1; }
	@m="$$(od -An -tx1 -j18 -N2 $(SO) | tr -d ' \n')"; \
	test "$$m" = "$(ELF_MACHINE_$(ARCH))" || { echo "package: $(SO) is not a $(ARCH) binary (ELF e_machine $$m)" >&2; exit 1; }
	mkdir -p $(DIST_DIR)
	$(call nfpm_run,deb)
	$(call nfpm_run,rpm)

# Builds the module (Docker if needed) and the static mock provider, then runs
# the pamtester scenarios in a stock Debian container (test/integration/run.sh).
IT_IMG ?= pam-oidc-device-it
mock-provider:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags='-s -w' -o $(BUILD_DIR)/mock-provider ./cmd/mock-provider

integration: so mock-provider
	docker build -q -f test/integration/Dockerfile -t $(IT_IMG) .
	docker run --rm $(IT_IMG)

clean:
	rm -rf $(BUILD_DIR)
