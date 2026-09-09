package auth

import "time"

// SetNow replaces the clock used to compute the device code lifetime.
func SetNow(a *Authenticator, now func() time.Time) {
	a.now = now
}
