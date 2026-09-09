#!/bin/sh
# Pre-install script for pam-oidc-device (deb and rpm).
#
# Creates the unprivileged system account that sshd runs
# AuthorizedKeysCommand as. It has to exist before the package lays down
# /etc/oidc-ssh and /var/cache/oidc-ssh, which are owned by its group.
#
# Idempotent: re-running it on an upgrade, or on a host where an
# administrator created the account by hand, changes nothing.
set -e

user=oidc-ssh
group=oidc-ssh

if ! getent group "$group" >/dev/null 2>&1; then
    if command -v groupadd >/dev/null 2>&1; then
        groupadd --system "$group"
    elif command -v addgroup >/dev/null 2>&1; then
        addgroup --system "$group"
    fi
fi

if ! getent passwd "$user" >/dev/null 2>&1; then
    # No shell, no home, no login: this account exists to read a key file
    # and make one HTTPS request. If it is ever the entry point of an
    # attack, there should be nothing behind it.
    if command -v useradd >/dev/null 2>&1; then
        useradd --system --gid "$group" --no-create-home \
            --home-dir /nonexistent --shell /usr/sbin/nologin \
            --comment "OIDC SSH authorized-keys helper" "$user"
    elif command -v adduser >/dev/null 2>&1; then
        adduser --system --ingroup "$group" --no-create-home \
            --home /nonexistent --shell /usr/sbin/nologin "$user"
    fi
fi

exit 0
