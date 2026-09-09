#!/bin/sh
# Post-install script for pam-oidc-device (deb and rpm). It only prints the
# manual steps: the module is inert until it is referenced from /etc/pam.d.
# Skipped on upgrades (deb: configure with a previous version; rpm: $1 > 1).
set -e

case "$1" in
    configure)
        [ -z "$2" ] || exit 0
        ;;
    [0-9]*)
        [ "$1" -le 1 ] || exit 0
        ;;
esac

module=$(find /usr/lib /usr/lib64 -name pam_oidc_device.so -print -quit 2>/dev/null || true)
[ -n "$module" ] || module=pam_oidc_device.so

cat <<MSG

pam-oidc-device installed: $module

1. Configuration (see the annotated example):
     install -m 0644 /usr/share/doc/pam-oidc-device/config.example.yaml \\
         /etc/security/pam_oidc_device.yaml
   then set issuer, client_id and the users -> group mapping.

2. PAM: add the module to the service that should use it, for example in
   /etc/pam.d/sshd before the other auth lines:
     auth  [success=done ignore=ignore default=die]  pam_oidc_device.so
   (unmapped users fall through to the next module; "required" instead
   would deny them). The module needs no line in the account stack.

3. sshd (/etc/ssh/sshd_config):
     KbdInteractiveAuthentication yes
     Match User systems,ops
         AuthenticationMethods keyboard-interactive
   and, because a login can take up to timeout + 4 x http_timeout
   (340s with the default configuration) while sshd's default
   LoginGraceTime is 120s:
     LoginGraceTime 400
   Then: sshd -t && systemctl reload sshd

Audit lines go to syslog (authpriv) tagged pam_oidc_device.

MSG
exit 0
