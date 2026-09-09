// Package pammap translates the outcome of an authentication attempt into
// PAM return codes and log labels.
//
// It deliberately does not import the PAM headers so that the mapping can be
// tested without cgo. The numeric values mirror Linux-PAM's
// <security/_pam_types.h>; they are part of the PAM ABI and have not changed
// since Linux-PAM 0.x, but the cgo module asserts them against the real
// header at build time all the same.
package pammap

import (
	"github.com/jleal52/pam-oidc-device/internal/auth"
	"github.com/jleal52/pam-oidc-device/internal/pamlog"
)

// PAM return codes, as defined in <security/_pam_types.h>. Verified against
// libpam0g-dev 1.5.2-6+deb12u2 (Debian bookworm, the image used by make so):
//
//	#define PAM_SUCCESS 0            /* Successful function return */
//	#define PAM_AUTH_ERR 7           /* Authentication failure */
//	#define PAM_AUTHINFO_UNAVAIL 9   /* Underlying authentication service ... */
//	#define PAM_USER_UNKNOWN 10      /* User not known to the underlying ... */
//	#define PAM_IGNORE 25            /* Ignore underlying account module */
//
// cmd/pam_oidc_device/pam_shim.h carries _Static_asserts with the same
// values, so a header that disagrees fails the cgo build.
const (
	// PAMSuccess is PAM_SUCCESS: successful function return.
	PAMSuccess = 0
	// PAMAuthErr is PAM_AUTH_ERR: authentication failure.
	PAMAuthErr = 7
	// PAMAuthinfoUnavail is PAM_AUTHINFO_UNAVAIL: cannot access the
	// authentication information (network or hardware failure).
	PAMAuthinfoUnavail = 9
	// PAMUserUnknown is PAM_USER_UNKNOWN: user not known to the module.
	PAMUserUnknown = 10
	// PAMIgnore is PAM_IGNORE: ignore this module regardless of the control
	// flag in the stack.
	PAMIgnore = 25
)

// ToPAM returns the PAM return code for an authentication outcome. Anything
// that is not an explicit Success, Ignore or AuthErr fails closed as
// PAM_AUTHINFO_UNAVAIL: it never grants access and tells the PAM stack that
// the module could not decide.
func ToPAM(c auth.Code) int {
	switch c {
	case auth.Success:
		return PAMSuccess
	case auth.Ignore:
		return PAMIgnore
	case auth.AuthErr:
		return PAMAuthErr
	default:
		return PAMAuthinfoUnavail
	}
}

// Result returns the result= label logged for an outcome: success, ignore,
// denied for AuthErr and error for everything else.
func Result(c auth.Code) string {
	switch c {
	case auth.Success:
		return pamlog.ResultSuccess
	case auth.Ignore:
		return pamlog.ResultIgnore
	case auth.AuthErr:
		return pamlog.ResultDenied
	default:
		return pamlog.ResultError
	}
}
