# Integration test image: a stock Debian PAM stack, pamtester, the module
# built by `make so` and the mock provider built by `make integration`.
# Build from the repository root:
#   docker build -f test/integration/Dockerfile -t pam-oidc-device-it .
FROM debian:bookworm-slim

RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends libpam0g pamtester ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m systems

# Install the module next to the stock ones so PAM finds it by bare name.
# The multiarch directory is derived from where libpam-modules put
# pam_permit.so (dpkg-architecture would need dpkg-dev).
COPY build/pam_oidc_device.so /tmp/pam_oidc_device.so
RUN dir="$(dirname "$(find /usr/lib -name pam_permit.so -print -quit)")" \
    && test -n "$dir" \
    && install -m 0644 /tmp/pam_oidc_device.so "$dir/pam_oidc_device.so" \
    && rm /tmp/pam_oidc_device.so

COPY test/integration/pam.d-test        /etc/pam.d/oidc-test
COPY test/integration/pam.d-test-ignore /etc/pam.d/oidc-test-ignore
COPY test/integration/pam.d-test-acct   /etc/pam.d/oidc-test-acct
COPY test/integration/pam.d-test-default /etc/pam.d/oidc-test-default
COPY test/integration/config.yaml       /etc/pam_oidc_device.yaml
# Only at the 0.2 path, never at the legacy one: that is what makes the
# default-config scenario fail if the module stops honouring the search.
COPY test/integration/config.yaml       /etc/oidc-ssh/config.yaml
COPY build/pam-oidc-device-helper /usr/libexec/pam-oidc-device/pam-oidc-device-helper
COPY build/mock-provider                /usr/local/bin/mock-provider
COPY test/integration/run.sh            /run.sh

ENTRYPOINT ["/run.sh"]
