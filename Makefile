# oidc-ssh build entry points.
#
# The PAM module (pam/pam_oidc_ssh.c) is plain C and needs
# <security/pam_modules.h> (libpam0g-dev) plus a C compiler; the helper it
# execs (cmd/oidc-ssh-helper) is a static Go binary. `make so` builds
# the module natively when the headers are present and inside Docker
# otherwise; `go test ./...` never needs the headers.

GO             ?= go
GOFLAGS_COMMON ?= -trimpath -buildvcs=false
GOFLAGS_BIN    ?= $(GOFLAGS_COMMON) -ldflags='-s -w'
# oidc-ssh additionally reports its version to the provider at enrolment.
GOFLAGS_SSH    ?= $(GOFLAGS_COMMON) -ldflags='-s -w -X github.com/jleal52/oidc-ssh/internal/sshcmd.Version=$(VERSION)'
CC          ?= cc
CFLAGS_SO   ?= -O2 -Wall -Wextra -Werror -fPIC -shared -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now
BUILD_DIR   ?= build
SO          ?= $(BUILD_DIR)/pam_oidc_ssh.so
HELPER      ?= $(BUILD_DIR)/oidc-ssh-helper
OIDC_SSH    ?= $(BUILD_DIR)/oidc-ssh
PAM_HEADER  ?= /usr/include/security/pam_modules.h
DOCKER_IMG  ?= golang:1.26-bookworm
GOMOD_CACHE ?= oidc-ssh-gomod
GOBUILD_CACHE ?= oidc-ssh-gocache

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

.PHONY: test lint vet so so-native so-docker check-glibc helper oidc-ssh check-so package integration integration-sshd mock-provider clean

test:
	$(GO) test ./...

lint:
	golangci-lint run ./...

vet:
	$(GO) vet ./...

so-native:
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS_SO) -o $(SO) pam/pam_oidc_ssh.c -lpam

# Static helper binary exec'ed by the module for every login.
helper:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS_BIN) -o $(HELPER) ./cmd/oidc-ssh-helper

# Static oidc-ssh binary: enrolment, AuthorizedKeysCommand and status.
oidc-ssh:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS_SSH) -o $(OIDC_SSH) ./cmd/oidc-ssh

so:
	@if [ -f $(PAM_HEADER) ]; then \
		$(MAKE) so-native; \
	else \
		echo "$(PAM_HEADER) not found, building in Docker ($(DOCKER_IMG))"; \
		$(call docker_run,make so-native); \
	fi

# Release build of the module: always inside Debian 12 so the object links
# against glibc 2.36 symbols and loads on every supported distribution.
# `check-glibc` enforces that ceiling on whatever is in build/.
C_BUILD_IMG   ?= debian:bookworm-slim
GLIBC_CEILING ?= 2.36
so-docker:
	mkdir -p $(BUILD_DIR)
	docker run --rm -v "$(CURDIR)":/src -w /src -e HOST_UID=$(shell id -u) -e HOST_GID=$(shell id -g) $(C_BUILD_IMG) \
		sh -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends gcc libc6-dev libpam0g-dev make >/dev/null && make so-native; rc=$$?; chown -R "$$HOST_UID:$$HOST_GID" $(BUILD_DIR) 2>/dev/null; exit $$rc'

check-glibc:
	@max=$$(objdump -T $(SO) | grep -oE 'GLIBC_[0-9.]+' | sed 's/GLIBC_//' | sort -uV | tail -1); \
	echo "highest glibc symbol version required: $$max (ceiling $(GLIBC_CEILING))"; \
	test "$$(printf '%s\n%s\n' "$$max" "$(GLIBC_CEILING)" | sort -V | tail -1)" = "$(GLIBC_CEILING)"

# Verifies that the three PAM entry points are exported (prints them).
CHECK_SO_CMD = nm -D $(SO) | grep -E " T pam_sm_(authenticate|setcred|acct_mgmt)$$" | awk "{print} END {if (NR != 3) {print \"check-so: expected 3 pam_sm_* symbols, found \" NR; exit 1}}"
check-so:
	@if command -v nm >/dev/null 2>&1; then \
		$(CHECK_SO_CMD); \
	else \
		$(call docker_run,$(CHECK_SO_CMD)); \
	fi

# Builds dist/oidc-ssh_<version>_<arch>.{deb,rpm} with nfpm, run from
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

# `so` is phony, so this rebuilds the module natively even when the caller
# already produced it with so-docker. That is fine as long as the ceiling
# still holds, which is why check-glibc runs HERE and not only before: the
# release workflow checks the Debian-built artefact and then packages
# whatever this rule leaves behind. Verifying the one that ships is the only
# check that means anything.
package: so helper oidc-ssh check-glibc
	@test -n "$(MULTIARCH)" || { echo "package: unsupported ARCH=$(ARCH) (amd64 or arm64)" >&2; exit 1; }
	@m="$$(od -An -tx1 -j18 -N2 $(SO) | tr -d ' \n')"; \
	test "$$m" = "$(ELF_MACHINE_$(ARCH))" || { echo "package: $(SO) is not a $(ARCH) binary (ELF e_machine $$m)" >&2; exit 1; }
	mkdir -p $(DIST_DIR)
	$(call nfpm_run,deb)
	$(call nfpm_run,rpm)

# Builds the module (Docker if needed) and the static mock provider, then runs
# the pamtester scenarios in a stock Debian container (test/integration/run.sh).
IT_IMG ?= oidc-ssh-it
mock-provider:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS_BIN) -o $(BUILD_DIR)/mock-provider ./cmd/mock-provider

integration: so helper mock-provider
	docker build -q -f test/integration/Dockerfile -t $(IT_IMG) .
	docker run --rm $(IT_IMG)

# Everything that only a real OpenSSH server can exercise: the device flow
# through its fork model, host enrolment, AuthorizedKeysCommand, the
# last-known-good cache when the provider is broken, and the key options
# sshd is allowed to apply.
IT_SSHD_IMG ?= oidc-ssh-sshd
integration-sshd: so helper oidc-ssh mock-provider
	docker build -q -f test/integration/Dockerfile.sshd -t $(IT_SSHD_IMG) .
	docker run --rm $(IT_SSHD_IMG)

clean:
	rm -rf $(BUILD_DIR)
