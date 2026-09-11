#!/bin/sh
# Post-install script for oidc-ssh (deb and rpm). It only prints the
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

module=$(find /usr/lib /usr/lib64 -name pam_oidc_ssh.so -print -quit 2>/dev/null || true)
[ -n "$module" ] || module=pam_oidc_ssh.so

cat <<MSG

oidc-ssh installed: $module

1. Configuration (see the annotated example):
     install -m 0640 -g oidc-ssh \\
         /usr/share/doc/oidc-ssh/config.example.yaml \\
         /etc/oidc-ssh/config.yaml
   then set issuer, client_id and the users -> group mapping.

2. PAM: add the module to the service that should use it, for example in
   /etc/pam.d/sshd before the other auth lines:
     auth  [success=done ignore=ignore default=die]  pam_oidc_ssh.so
   (unmapped users fall through to the next module; "required" instead
   would deny them). The module needs no line in the account stack.

3. sshd (/etc/ssh/sshd_config), device flow only:
     KbdInteractiveAuthentication yes
     Match User systems,ops
         AuthenticationMethods keyboard-interactive
   and, because a login can take up to timeout + 4 x http_timeout
   (340s with the default configuration) while sshd's default
   LoginGraceTime is 120s:
     LoginGraceTime 400
   Then: sshd -t && systemctl reload sshd

4. Optional: key-based login, which is far quicker than approving a
   browser prompt on every connection. Enrol the host first:
     oidc-ssh enroll --issuer https://idp.example.com --client-id ssh-pam \\
         --name \$(hostname -s) --group servers --account systems
   It prints a URL and a code; somebody allowed to enrol hosts approves
   them, and the host identity is written to /etc/oidc-ssh. Then:
     AuthorizedKeysCommand /usr/libexec/oidc-ssh/oidc-ssh \\
         authorized-keys %u %f
     AuthorizedKeysCommandUser oidc-ssh
     PermitUserEnvironment OIDC_USER,OIDC_SUB
     Match User systems,ops
         AuthenticationMethods publickey keyboard-interactive:pam
         PubkeyAuthentication yes
         AuthorizedKeysFile none
   Mind the separator: a SPACE lists alternatives (a key is enough, and
   without one you fall back to the device flow), while a COMMA requires
   both, which is how you turn the browser approval into a second factor.
   "oidc-ssh status" reports what the host knows and whether it reaches
   the provider.

Audit lines go to syslog (authpriv), tagged pam_oidc_ssh for the PAM
module and oidc-ssh for the authorized-keys command.

MSG
exit 0
