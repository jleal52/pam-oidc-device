#!/usr/bin/env bash
# Real sshd scenarios: the OpenSSH server forks a privilege-separated child
# per connection and runs pam_authenticate there, which is exactly the
# process model pamtester cannot reproduce; and it is the only thing that
# runs AuthorizedKeysCommand, applies the key options it prints and enforces
# PermitUserEnvironment. Each scenario drives the OpenSSH client against it
# and checks the outcome, the session environment and the audit line.
#
# The audit lines are read from syslog (busybox syslogd, started below),
# because that is where both the PAM helper and oidc-ssh write them: the
# login path has no other channel, sshd's stdout belongs to the protocol and
# the AuthorizedKeysCommand's stdout is parsed as keys.
#
# Nothing here waits for a fixed amount of time: every wait is a condition
# polled until it holds or a deadline passes, and every failure names what
# was expected and dumps the logs that explain it.
set -euo pipefail

LISTEN=127.0.0.1:8089
PORT=${LISTEN##*:}
WORK=$(mktemp -d)
KEYS=$WORK/keys
MOCK_PID=""
SYSLOGD_PID=""
SSHD_LOG=$WORK/sshd.log
SYSLOG=/var/log/oidc-ssh.log

OIDC_SSH=/usr/libexec/oidc-ssh/oidc-ssh
CONFIG=/etc/oidc-ssh/config.yaml
HOST_KEY=/etc/oidc-ssh/host.key
CACHE=/var/cache/oidc-ssh

cleanup() {
    stop_mock
    [ -z "$SYSLOGD_PID" ] || kill "$SYSLOGD_PID" 2>/dev/null || true
    pkill -x sshd 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "FAIL $1" >&2
    shift
    for f in "$@"; do
        echo "--- $f" >&2
        cat "$f" >&2 || true
    done
    exit 1
}

# wait_for <seconds> <command...>: run the command until it succeeds or the
# deadline passes. Returns non-zero on timeout so the caller can say what it
# was waiting for.
wait_for() {
    local limit=$1
    shift
    local deadline=$((SECONDS + limit))
    until "$@"; do
        [ "$SECONDS" -lt "$deadline" ] || return 1
        sleep 0.1
    done
}

port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

start_mock() {
    : >"$WORK/mock.err"
    mock-provider --listen "$LISTEN" "$@" >"$WORK/mock.out" 2>"$WORK/mock.err" &
    MOCK_PID=$!
    wait_for 10 port_open "$PORT" \
        || fail "mock-provider did not start listening on $LISTEN" "$WORK/mock.out" "$WORK/mock.err"
}

stop_mock() {
    if [ -n "$MOCK_PID" ]; then
        kill "$MOCK_PID" 2>/dev/null || true
        wait "$MOCK_PID" 2>/dev/null || true
        MOCK_PID=""
    fi
}

# The audit assertions look only at the lines a scenario produced, so that a
# match left behind by an earlier scenario can never make a later one pass.
syslog_mark() { wc -l <"$SYSLOG" | tr -d " "; }
syslog_since() { tail -n "+$(($1 + 1))" "$SYSLOG"; }
syslog_matches() { syslog_since "$1" | grep -qE -- "$2"; }

# expect_syslog <scenario> <mark> <extended regexp>
expect_syslog() {
    wait_for 10 syslog_matches "$2" "$3" || {
        syslog_since "$2" >"$WORK/syslog.tail"
        fail "$1: no audit line matching /$3/ since the scenario started" "$WORK/syslog.tail" "$SSHD_LOG" "$WORK/mock.err"
    }
}

# expect_no_syslog <scenario> <mark> <extended regexp>
expect_no_syslog() {
    if syslog_matches "$2" "$3"; then
        syslog_since "$2" >"$WORK/syslog.tail"
        fail "$1: unexpected audit line matching /$3/" "$WORK/syslog.tail" "$SSHD_LOG"
    fi
}

# --- syslog, keys and the servers ------------------------------------------

: >"$SYSLOG"
busybox syslogd -n -O "$SYSLOG" &
SYSLOGD_PID=$!
wait_for 10 test -S /dev/log || fail "syslogd did not create /dev/log"

mkdir -p "$KEYS"
ssh-keygen -q -t ed25519 -N '' -C 'authorized' -f "$KEYS/test.key"
ssh-keygen -q -t ed25519 -N '' -C 'not authorized' -f "$KEYS/other.key"
FINGERPRINT=$(ssh-keygen -lf "$KEYS/test.key.pub" | awk '{print $2}')

# What the provider serves for each account. `systems` gets the well-formed
# line a provider is expected to return; `ops` gets the same key with an
# extra environment= option that sshd must refuse to apply.
printf 'environment="OIDC_USER=alice@example.com" %s\n' "$(cat "$KEYS/test.key.pub")" >"$KEYS/systems.keys"
printf 'environment="LD_PRELOAD=/tmp/not-really-there.so",environment="OIDC_USER=alice@example.com" %s\n' \
    "$(cat "$KEYS/test.key.pub")" >"$KEYS/ops.keys"
MOCK_KEYS=(--ssh-keys "systems=$KEYS/systems.keys" --ssh-keys "ops=$KEYS/ops.keys")

# sshd -D in the background, logging to stderr → file. Its own log is the
# one that explains a refused authentication attempt.
/usr/sbin/sshd -D -e >"$SSHD_LOG" 2>&1 &
wait_for 10 port_open 2222 || fail "sshd did not start" "$SSHD_LOG"

SSH_COMMON=(-p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
            -o IdentitiesOnly=yes -o ConnectTimeout=10 -o LogLevel=ERROR)
# sshpass gives ssh a pty and answers the "Press Enter after approving"
# prompt (matched with -P) with an empty line, like a person would.
SSHPASS=(sshpass -v -P "Press Enter" -p "")
# Device flow only: no key is offered at all.
SSH_KBD=("${SSHPASS[@]}" ssh "${SSH_COMMON[@]}"
         -o PreferredAuthentications=keyboard-interactive -o PubkeyAuthentication=no
         -o NumberOfPasswordPrompts=1)
# Key only: no fallback, so a refused key is a refused login.
SSH_KEY=(ssh "${SSH_COMMON[@]}" -o PreferredAuthentications=publickey
         -o PubkeyAuthentication=yes -o BatchMode=yes)
# Key first, device flow second: what a real client does.
SSH_BOTH=("${SSHPASS[@]}" ssh "${SSH_COMMON[@]}"
          -o PreferredAuthentications=publickey,keyboard-interactive
          -o PubkeyAuthentication=yes -o NumberOfPasswordPrompts=1)

# --- device flow, before this host is enrolled -----------------------------

echo "== approved: env exported, sudo keeps it"
mark=$(syslog_mark)
start_mock --outcome approved --pending 1 --username alice@example.com --groups ssh:admin
set +e
out=$("${SSH_KBD[@]}" systems@127.0.0.1 'echo "OIDC_USER=$OIDC_USER OIDC_SUB=$OIDC_SUB"; sudo -n env | grep ^OIDC_USER= | sed s/^/sudo:/' 2>"$WORK/ssh.err")
rc=$?
set -e
stop_mock
[ "$rc" -eq 0 ] || fail "approved: ssh exit $rc" "$WORK/ssh.err" "$SSHD_LOG"
grep -q 'OIDC_USER=alice@example.com OIDC_SUB=user-1' <<<"$out" || fail "approved: env missing: $out" "$SSHD_LOG"
grep -q '^sudo:OIDC_USER=alice@example.com' <<<"$out" || fail "approved: sudo dropped OIDC_USER: $out"
# sshpass owns the pty, so the client-side text is not observable here, but
# with -v it reports when it matched the prompt: proof that sshd relayed the
# "Press Enter" prompt (and the URL that precedes it) to the client.
grep -q 'detected prompt' "$WORK/ssh.err" || fail "approved: prompt not relayed to the client" "$WORK/ssh.err" "$SSHD_LOG"
expect_syslog approved "$mark" 'result=success reason=- '
echo "PASS approved"

echo "== denied"
mark=$(syslog_mark)
start_mock --outcome denied --pending 0
set +e
"${SSH_KBD[@]}" systems@127.0.0.1 true 2>"$WORK/ssh.err"; rc=$?
set -e
stop_mock
[ "$rc" -ne 0 ] || fail "denied: ssh succeeded"
expect_syslog denied "$mark" 'result=denied reason=denied'
echo "PASS denied"

echo "== wrong group"
mark=$(syslog_mark)
start_mock --outcome approved --pending 0 --groups ssh:ops
set +e
"${SSH_KBD[@]}" systems@127.0.0.1 true 2>"$WORK/ssh.err"; rc=$?
set -e
stop_mock
[ "$rc" -ne 0 ] || fail "wrong-group: ssh succeeded"
expect_syslog wrong-group "$mark" 'result=denied reason=missing_group'
echo "PASS wrong-group"

echo "== provider down"
mark=$(syslog_mark)
set +e
"${SSH_KBD[@]}" systems@127.0.0.1 true 2>"$WORK/ssh.err"; rc=$?
set -e
[ "$rc" -ne 0 ] || fail "provider-down: ssh succeeded"
expect_syslog provider-down "$mark" 'result=error reason=provider_unavailable'
echo "PASS provider-down"

# --- enrolment and key-based login -----------------------------------------

# One provider process serves the rest of the run, because enrolment lives in
# its memory: restarting it would forget this host. The scenario that needs a
# broken provider replaces it on purpose, and its failure mode (a 500 before
# the request is even authenticated) does not depend on knowing the host.
echo "== enroll: non-interactive, writes the identity and the configuration"
start_mock --outcome approved --pending 0 --groups ssh:admin "${MOCK_KEYS[@]}"
set +e
"$OIDC_SSH" enroll --name it-host --group test-hosts --account systems --account ops \
    >"$WORK/enroll.out" 2>"$WORK/enroll.err"
rc=$?
set -e
[ "$rc" -eq 0 ] || fail "enroll: exit $rc" "$WORK/enroll.out" "$WORK/enroll.err" "$WORK/mock.err"
[ -f "$HOST_KEY" ] || fail "enroll: $HOST_KEY was not created" "$WORK/enroll.out"
grep -q '^host_id:' "$CONFIG" || fail "enroll: no host_id in $CONFIG" "$CONFIG" "$WORK/enroll.out"
grep -q '^api_base:' "$CONFIG" || fail "enroll: no api_base in $CONFIG" "$CONFIG" "$WORK/enroll.out"
grep -q 'POST /api/ssh/hosts/enroll' "$WORK/mock.err" || fail "enroll: the provider was never asked" "$WORK/mock.err"
grep -q 'Host enrolled as "it-host"' "$WORK/enroll.out" || fail "enroll: unexpected report" "$WORK/enroll.out"
# The one question a broken key login always raises: can the unprivileged
# AuthorizedKeysCommand user read what enrolment left behind? status fails
# on any file it cannot read, so this is the permission check.
set +e
runuser -u oidc-ssh -- "$OIDC_SSH" status >"$WORK/status.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 0 ] || fail "enroll: \"status\" as the oidc-ssh user exited $rc" "$WORK/status.out"
echo "PASS enroll"

echo "== key login: AuthorizedKeysCommand, OIDC_USER in the session and under sudo"
mark=$(syslog_mark)
set +e
out=$("${SSH_KEY[@]}" -i "$KEYS/test.key" systems@127.0.0.1 \
    'echo "OIDC_USER=$OIDC_USER"; sudo -n env | grep ^OIDC_USER= | sed s/^/sudo:/' 2>"$WORK/ssh.err")
rc=$?
set -e
[ "$rc" -eq 0 ] || fail "key-login: ssh exit $rc" "$WORK/ssh.err" "$SSHD_LOG" "$WORK/mock.err"
grep -q '^OIDC_USER=alice@example.com' <<<"$out" || fail "key-login: OIDC_USER not in the session: $out" "$SSHD_LOG"
grep -q '^sudo:OIDC_USER=alice@example.com' <<<"$out" || fail "key-login: sudo dropped OIDC_USER: $out"
grep -q 'GET /api/ssh/authorized-keys' "$WORK/mock.err" || fail "key-login: the provider was never asked" "$WORK/mock.err"
expect_syslog key-login "$mark" "account=systems .*result=ok lines=1"
# sshd expands %f into the fingerprint of the key the client offered, and
# the query is scoped to it; a fixed-string match because a base64
# fingerprint is not a regular expression.
syslog_since "$mark" | grep -qF "fingerprint=$FINGERPRINT" \
    || fail "key-login: the audit line does not carry $FINGERPRINT" "$SYSLOG"
# The answer is now the last known good one for this account and key.
[ -n "$(ls -A "$CACHE/systems" 2>/dev/null)" ] \
    || fail "key-login: nothing was cached under $CACHE/systems" "$WORK/status.out"
echo "PASS key-login"

echo "== unauthorized key: refused, and the device flow still lets you in"
mark=$(syslog_mark)
set +e
"${SSH_KEY[@]}" -i "$KEYS/other.key" systems@127.0.0.1 true 2>"$WORK/ssh.err"; rc=$?
set -e
[ "$rc" -ne 0 ] || fail "unauthorized-key: ssh succeeded with a key the provider does not know" "$SSHD_LOG"
expect_syslog unauthorized-key "$mark" "account=systems .*result=empty lines=0"
mark=$(syslog_mark)
set +e
out=$("${SSH_BOTH[@]}" -i "$KEYS/other.key" systems@127.0.0.1 'echo "OIDC_USER=$OIDC_USER"' 2>"$WORK/ssh.err")
rc=$?
set -e
[ "$rc" -eq 0 ] || fail "keyboard-interactive-fallback: ssh exit $rc" "$WORK/ssh.err" "$SSHD_LOG" "$WORK/mock.err"
grep -q '^OIDC_USER=alice@example.com' <<<"$out" || fail "keyboard-interactive-fallback: OIDC_USER not in the session: $out"
expect_syslog keyboard-interactive-fallback "$mark" 'result=success reason=- '
echo "PASS unauthorized-key + keyboard-interactive-fallback"

echo "== PermitUserEnvironment: sshd drops the environment option it was not told to accept"
mark=$(syslog_mark)
set +e
out=$("${SSH_KEY[@]}" -i "$KEYS/test.key" ops@127.0.0.1 \
    'echo "LD_PRELOAD=[${LD_PRELOAD-unset}] OIDC_USER=[${OIDC_USER-unset}]"' 2>"$WORK/ssh.err")
rc=$?
set -e
[ "$rc" -eq 0 ] || fail "user-environment: ssh exit $rc" "$WORK/ssh.err" "$SSHD_LOG" "$WORK/mock.err"
# OIDC_USER proves the environment= options on the line were processed at
# all, so the LD_PRELOAD assertion below cannot pass by accident.
grep -q 'OIDC_USER=\[alice@example.com\]' <<<"$out" \
    || fail "user-environment: the allowed environment option was not applied: $out" "$SSHD_LOG"
grep -q 'LD_PRELOAD=\[unset\]' <<<"$out" \
    || fail "user-environment: sshd let LD_PRELOAD through: $out" "$SSHD_LOG"
expect_syslog user-environment "$mark" "account=ops .*result=ok lines=1"
echo "PASS user-environment"

echo "== provider 500: a warm cache still lets the key in, a cold one does not"
stop_mock
start_mock --outcome approved --pending 0 --keys-outcome 500 "${MOCK_KEYS[@]}"
mark=$(syslog_mark)
set +e
out=$("${SSH_KEY[@]}" -i "$KEYS/test.key" systems@127.0.0.1 'echo "OIDC_USER=$OIDC_USER"' 2>"$WORK/ssh.err")
rc=$?
set -e
[ "$rc" -eq 0 ] || fail "cache-warm: ssh exit $rc with a cached answer available" "$WORK/ssh.err" "$SSHD_LOG" "$WORK/mock.err"
grep -q '^OIDC_USER=alice@example.com' <<<"$out" || fail "cache-warm: the cached line lost its options: $out"
expect_syslog cache-warm "$mark" "account=systems .*result=cache lines=1 .*source=cache age="
echo "PASS cache-warm"

rm -rf "${CACHE:?}/systems"
mark=$(syslog_mark)
set +e
"${SSH_KEY[@]}" -i "$KEYS/test.key" systems@127.0.0.1 true 2>"$WORK/ssh.err"; rc=$?
set -e
[ "$rc" -ne 0 ] || fail "cache-cold: ssh succeeded with no provider and no cache" "$SSHD_LOG"
expect_syslog cache-cold "$mark" "account=systems .*result=error lines=0"
expect_no_syslog cache-cold "$mark" 'result=(ok|cache)'
echo "PASS cache-cold"

echo "== sshd still alive after every scenario (no runtime crash)"
port_open 2222 || fail "sshd died" "$SSHD_LOG"
grep -qiE 'panic|fatal error|SIGSEGV' "$SSHD_LOG" && fail "sshd log has a crash" "$SSHD_LOG"
echo "PASS sshd-alive"
echo "ALL PASS"
