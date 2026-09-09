package pammap_test

import (
	"testing"

	"github.com/jleal52/pam-oidc-device/internal/auth"
	"github.com/jleal52/pam-oidc-device/internal/pamlog"
	"github.com/jleal52/pam-oidc-device/internal/pammap"
)

func TestConstantsMatchLinuxPAM(t *testing.T) {
	// Values from <security/_pam_types.h>; the cgo build also asserts them.
	if pammap.PAMSuccess != 0 || pammap.PAMAuthErr != 7 || pammap.PAMAuthinfoUnavail != 9 ||
		pammap.PAMUserUnknown != 10 || pammap.PAMIgnore != 25 {
		t.Fatalf("PAM constants drifted: success=%d auth_err=%d authinfo_unavail=%d user_unknown=%d ignore=%d",
			pammap.PAMSuccess, pammap.PAMAuthErr, pammap.PAMAuthinfoUnavail, pammap.PAMUserUnknown, pammap.PAMIgnore)
	}
}

func TestToPAM(t *testing.T) {
	tests := []struct {
		code auth.Code
		want int
	}{
		{auth.Success, pammap.PAMSuccess},
		{auth.Ignore, pammap.PAMIgnore},
		{auth.AuthErr, pammap.PAMAuthErr},
		{auth.AuthInfoUnavail, pammap.PAMAuthinfoUnavail},
		{auth.Unknown, pammap.PAMAuthinfoUnavail},
		{auth.Code(42), pammap.PAMAuthinfoUnavail},
		{auth.Code(-1), pammap.PAMAuthinfoUnavail},
	}
	for _, tc := range tests {
		if got := pammap.ToPAM(tc.code); got != tc.want {
			t.Errorf("ToPAM(%v) = %d, want %d", tc.code, got, tc.want)
		}
	}
}

func TestOnlySuccessGrants(t *testing.T) {
	for c := auth.Code(-5); c < 50; c++ {
		if got := pammap.ToPAM(c); got == pammap.PAMSuccess && c != auth.Success {
			t.Fatalf("ToPAM(%d) returned PAM_SUCCESS for a non-Success code", int(c))
		}
	}
}

func TestResult(t *testing.T) {
	tests := []struct {
		code auth.Code
		want string
	}{
		{auth.Success, pamlog.ResultSuccess},
		{auth.Ignore, pamlog.ResultIgnore},
		{auth.AuthErr, pamlog.ResultDenied},
		{auth.AuthInfoUnavail, pamlog.ResultError},
		{auth.Unknown, pamlog.ResultError},
		{auth.Code(42), pamlog.ResultError},
	}
	for _, tc := range tests {
		if got := pammap.Result(tc.code); got != tc.want {
			t.Errorf("Result(%v) = %q, want %q", tc.code, got, tc.want)
		}
	}
}
