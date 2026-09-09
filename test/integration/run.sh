#!/usr/bin/env bash
# pamtester scenarios against the mock provider. Runs inside the image
# built from test/integration/Dockerfile; prints "PASS <scenario>" per
# scenario and exits non-zero on the first failure.
#
# There is no syslogd in the container, so the module falls back to writing
# its audit line to stderr; pamtester's stderr is captured to assert on it.
# pamtester prints PAM_TEXT_INFO messages to stdout.
set -euo pipefail

LISTEN=127.0.0.1:8089
PORT=${LISTEN##*:}
WORK=$(mktemp -d)
MOCK_PID=""

cleanup() {
    stop_mock
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

start_mock() {
    : >"$WORK/mock.err"
    mock-provider --listen "$LISTEN" "$@" >"$WORK/mock.out" 2>"$WORK/mock.err" &
    MOCK_PID=$!
    for _ in $(seq 1 50); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    fail "mock-provider did not start listening on $LISTEN" "$WORK/mock.out" "$WORK/mock.err"
}

stop_mock() {
    if [[ -n "$MOCK_PID" ]]; then
        kill "$MOCK_PID" 2>/dev/null || true
        wait "$MOCK_PID" 2>/dev/null || true
        MOCK_PID=""
    fi
}

port_is_free() {
    ! (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null
}

# run_pamtester <service> <user>: runs pamtester and stores the exit code in
# RC, stdout in $WORK/out and stderr in $WORK/err.
run_pamtester() {
    set +e
    pamtester "$1" "$2" authenticate >"$WORK/out" 2>"$WORK/err"
    RC=$?
    set -e
}

# expect <scenario> <file> <pattern>: the file must contain the pattern.
expect() {
    grep -qF -- "$3" "$2" || fail "$1: expected '$3' in $(basename "$2")" "$WORK/out" "$WORK/err" "$WORK/mock.err"
}

# expect_absent <scenario> <file> <pattern>: the file must not contain it.
expect_absent() {
    ! grep -qF -- "$3" "$2" || fail "$1: did not expect '$3' in $(basename "$2")" "$WORK/out" "$WORK/err" "$WORK/mock.err"
}

echo "== module: $(find /usr/lib -name pam_oidc_device.so -print -quit)"
echo "== pamtester: $(pamtester 2>&1 | head -1 || true)"

# (a) approved login as a mapped user with the right group
scenario=approved
start_mock --outcome approved --pending 1 --groups ssh:admin
run_pamtester oidc-test systems
[[ $RC -eq 0 ]] || fail "$scenario: exit $RC, want 0" "$WORK/out" "$WORK/err" "$WORK/mock.err"
expect "$scenario" "$WORK/out" "Open the following URL"
expect "$scenario" "$WORK/out" "Code:"
expect "$scenario" "$WORK/err" "result=success"
expect "$scenario" "$WORK/err" "user=alice@example.com"
expect "$scenario" "$WORK/mock.err" "POST /device_authorization"
expect "$scenario" "$WORK/mock.err" "POST /token"
stop_mock
echo "PASS $scenario"

# (b) the user rejects the request at the provider
scenario=denied
start_mock --outcome denied
run_pamtester oidc-test systems
[[ $RC -ne 0 ]] || fail "$scenario: exit 0, want failure" "$WORK/out" "$WORK/err" "$WORK/mock.err"
expect "$scenario" "$WORK/out" "Login denied"
expect "$scenario" "$WORK/err" "result=denied"
expect "$scenario" "$WORK/err" "reason=denied"
stop_mock
echo "PASS $scenario"

# (c) approved at the provider, but without the group mapped to "systems"
scenario=wrong-group
start_mock --outcome approved --groups ssh:ops
run_pamtester oidc-test systems
[[ $RC -ne 0 ]] || fail "$scenario: exit 0, want failure" "$WORK/out" "$WORK/err" "$WORK/mock.err"
expect "$scenario" "$WORK/out" "Not allowed to log in as systems"
expect "$scenario" "$WORK/err" "result=denied"
expect "$scenario" "$WORK/err" "reason=missing_group"
stop_mock
echo "PASS $scenario"

# (d) unmapped user with the fall-through stack: PAM_IGNORE lets
# pam_permit decide, and the provider is never contacted
scenario=unmapped-ignore
start_mock --outcome approved
run_pamtester oidc-test-ignore root
[[ $RC -eq 0 ]] || fail "$scenario: exit $RC, want 0 (pam_permit)" "$WORK/out" "$WORK/err" "$WORK/mock.err"
expect_absent "$scenario" "$WORK/out" "Open the following URL"
expect_absent "$scenario" "$WORK/mock.err" "POST /device_authorization"
expect_absent "$scenario" "$WORK/mock.err" "GET /.well-known/openid-configuration"
stop_mock
echo "PASS $scenario"

# (d') unmapped user with "required": PAM_IGNORE alone leaves the stack
# without a verdict, so pam_authenticate fails
scenario=unmapped-required
start_mock --outcome approved
run_pamtester oidc-test root
[[ $RC -ne 0 ]] || fail "$scenario: exit 0, want failure (no verdict)" "$WORK/out" "$WORK/err" "$WORK/mock.err"
expect "$scenario" "$WORK/err" "result=ignore"
expect "$scenario" "$WORK/err" "reason=not_mapped"
expect_absent "$scenario" "$WORK/mock.err" "POST /device_authorization"
stop_mock
echo "PASS $scenario"

# (f) account stack with only this module: pam_sm_acct_mgmt returns
# PAM_IGNORE, so there is no verdict and pam_acct_mgmt must fail. The
# provider is never involved in the account phase.
scenario=acct-mgmt-ignore
set +e
pamtester oidc-test-acct systems acct_mgmt >"$WORK/out" 2>"$WORK/err"
RC=$?
set -e
[[ $RC -ne 0 ]] || fail "$scenario: exit 0, want failure (no verdict)" "$WORK/out" "$WORK/err"
echo "PASS $scenario"

# (e) provider down: nothing listens on the issuer port
scenario=provider-down
port_is_free || fail "$scenario: port $PORT still busy"
start=$SECONDS
run_pamtester oidc-test systems
elapsed=$((SECONDS - start))
[[ $RC -ne 0 ]] || fail "$scenario: exit 0, want failure" "$WORK/out" "$WORK/err"
[[ $elapsed -le 15 ]] || fail "$scenario: took ${elapsed}s, want <= 15s" "$WORK/out" "$WORK/err"
expect "$scenario" "$WORK/out" "Identity provider unavailable"
expect "$scenario" "$WORK/err" "result=error"
expect "$scenario" "$WORK/err" "reason=provider_unavailable"
echo "PASS $scenario (${elapsed}s)"

echo "ALL PASS"
