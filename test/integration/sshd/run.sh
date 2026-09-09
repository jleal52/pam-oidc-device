#!/usr/bin/env bash
# Real sshd scenarios: the OpenSSH server forks a privilege-separated child
# per connection and runs pam_authenticate there, which is exactly the process
# model pamtester cannot reproduce. Each scenario starts the mock provider,
# connects with the OpenSSH client using keyboard-interactive only, and checks
# the outcome, the session environment and the audit line.
set -euo pipefail

LISTEN=127.0.0.1:8089
PORT=${LISTEN##*:}
WORK=$(mktemp -d)
MOCK_PID=""
SSHD_LOG=$WORK/sshd.log

cleanup() { stop_mock; pkill -x sshd 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

fail() { echo "FAIL $1" >&2; shift; for f in "$@"; do echo "--- $f" >&2; cat "$f" >&2 || true; done; exit 1; }

start_mock() {
    mock-provider --listen "$LISTEN" "$@" >"$WORK/mock.out" 2>"$WORK/mock.err" &
    MOCK_PID=$!
    for _ in $(seq 1 50); do
        (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && return 0
        sleep 0.1
    done
    fail "mock-provider did not start" "$WORK/mock.out" "$WORK/mock.err"
}
stop_mock() { if [ -n "$MOCK_PID" ]; then kill "$MOCK_PID" 2>/dev/null || true; wait "$MOCK_PID" 2>/dev/null || true; MOCK_PID=""; fi; }

# sshd -D in the background, logging to stderr → file (no syslogd here; the
# module's audit line also lands on stderr through the same channel).
/usr/sbin/sshd -D -e >"$SSHD_LOG" 2>&1 &
for _ in $(seq 1 50); do
    (exec 3<>"/dev/tcp/127.0.0.1/2222") 2>/dev/null && break
    sleep 0.1
done

# sshpass gives ssh a pty and answers the "Press Enter after approving"
# prompt (matched with -P) with an empty line, like a person would.
SSH=(sshpass -v -P "Press Enter" -p "" ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
     -o PreferredAuthentications=keyboard-interactive -o PubkeyAuthentication=no
     -o NumberOfPasswordPrompts=1 -o ConnectTimeout=10 -o LogLevel=ERROR)

echo "== approved: env exported, sudo keeps it"
start_mock --outcome approved --pending 1 --username alice@example.com --groups ssh:admin
set +e
out=$("${SSH[@]}" systems@127.0.0.1 'echo "OIDC_USER=$OIDC_USER OIDC_SUB=$OIDC_SUB"; sudo -n env | grep ^OIDC_USER= | sed s/^/sudo:/' 2>"$WORK/ssh.err")
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
grep -q 'result=success reason=- ' "$SSHD_LOG" || fail "approved: audit line missing" "$SSHD_LOG"
echo "PASS approved"

echo "== denied"
start_mock --outcome denied --pending 0
set +e
"${SSH[@]}" systems@127.0.0.1 true 2>"$WORK/ssh.err"; rc=$?
set -e
stop_mock
[ "$rc" -ne 0 ] || fail "denied: ssh succeeded"
grep -q 'result=denied reason=denied' "$SSHD_LOG" || fail "denied: audit line missing" "$SSHD_LOG"
echo "PASS denied"

echo "== wrong group"
start_mock --outcome approved --pending 0 --groups ssh:ops
set +e
"${SSH[@]}" systems@127.0.0.1 true 2>"$WORK/ssh.err"; rc=$?
set -e
stop_mock
[ "$rc" -ne 0 ] || fail "wrong-group: ssh succeeded"
grep -q 'result=denied reason=missing_group' "$SSHD_LOG" || fail "wrong-group: audit line missing" "$SSHD_LOG"
echo "PASS wrong-group"

echo "== provider down"
set +e
"${SSH[@]}" systems@127.0.0.1 true 2>"$WORK/ssh.err"; rc=$?
set -e
[ "$rc" -ne 0 ] || fail "provider-down: ssh succeeded"
grep -q 'result=error reason=provider_unavailable' "$SSHD_LOG" || fail "provider-down: audit line missing" "$SSHD_LOG"
echo "PASS provider-down"

echo "== sshd still alive after four logins (no runtime crash)"
(exec 3<>"/dev/tcp/127.0.0.1/2222") 2>/dev/null || fail "sshd died" "$SSHD_LOG"
grep -qiE 'panic|fatal error|SIGSEGV' "$SSHD_LOG" && fail "sshd log has a crash" "$SSHD_LOG"
echo "PASS sshd-alive"
echo "ALL PASS"
