// Package pamlog builds the single audit line the PAM module writes to
// syslog for every authentication attempt.
//
// It has no PAM or syslog dependency so that the sanitisation and the field
// order can be unit-tested without cgo. Values are sanitised before they
// reach the line: syslog consumers split on whitespace and newlines, and a
// crafted claim value or provider error must not be able to forge fields.
package pamlog

import (
	"strings"
	"unicode"
)

// Limits applied to values by Attempt.Line.
const (
	// MaxValueLen bounds every field except err.
	MaxValueLen = 200
	// MaxErrLen bounds the err field, which carries wrapped error chains.
	MaxErrLen = 300
)

// Results carried in the result= field.
const (
	ResultSuccess = "success"
	ResultDenied  = "denied"
	ResultIgnore  = "ignore"
	ResultError   = "error"
)

// Level is the syslog severity of a line, kept independent from log/syslog
// so the mapping can be tested anywhere.
type Level int

// Levels, from least to most severe.
const (
	LevelDebug Level = iota
	LevelInfo
	LevelNotice
	LevelErr
)

// String returns the lower-case syslog name of the level.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelNotice:
		return "notice"
	case LevelErr:
		return "err"
	default:
		return "err"
	}
}

// LevelFor returns the severity at which a result is logged: success at
// info, denied at notice, ignore at debug and everything else at err.
func LevelFor(result string) Level {
	switch result {
	case ResultSuccess:
		return LevelInfo
	case ResultDenied:
		return LevelNotice
	case ResultIgnore:
		return LevelDebug
	default:
		return LevelErr
	}
}

// Attempt describes one authentication attempt.
type Attempt struct {
	// User is the identity provider user name (username claim).
	User string
	// Subject is the token subject.
	Subject string
	// LocalUser is the account requested from PAM.
	LocalUser string
	// RHost is PAM_RHOST, the client address as seen by the application.
	RHost string
	// Host is the local hostname.
	Host string
	// Result is one of the Result* constants.
	Result string
	// Reason is the machine-readable cause, empty on success.
	Reason string
	// Err is the underlying error, nil unless something failed.
	Err error
}

// Line renders the attempt as a single "key=value" line with a fixed key
// order: user, sub, local_user, rhost, host, result, reason, err. Every
// value is sanitised; empty values are rendered as "-" so the line always
// has the same number of fields.
func (a Attempt) Line() string {
	errText := ""
	if a.Err != nil {
		errText = a.Err.Error()
	}
	fields := [...]struct{ key, value string }{
		{"user", Sanitize(a.User, MaxValueLen)},
		{"sub", Sanitize(a.Subject, MaxValueLen)},
		{"local_user", Sanitize(a.LocalUser, MaxValueLen)},
		{"rhost", Sanitize(a.RHost, MaxValueLen)},
		{"host", Sanitize(a.Host, MaxValueLen)},
		{"result", Sanitize(a.Result, MaxValueLen)},
		{"reason", Sanitize(a.Reason, MaxValueLen)},
		{"err", Sanitize(errText, MaxErrLen)},
	}
	var b strings.Builder
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(f.key)
		b.WriteByte('=')
		if f.value == "" {
			b.WriteByte('-')
		} else {
			b.WriteString(f.value)
		}
	}
	return b.String()
}

// Sanitize makes s safe to embed as a value in a key=value log line: runs
// of whitespace and control characters (including newlines and NUL) are
// collapsed to a single underscore, invalid UTF-8 is dropped, surrounding
// whitespace is removed and the result is truncated to limit runes with a
// trailing "..." marker when it was cut. A limit <= 0 disables truncation.
func Sanitize(s string, limit int) string {
	var b strings.Builder
	b.Grow(len(s))
	pendingSep := false
	for _, r := range strings.ToValidUTF8(s, "") {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == unicode.ReplacementChar {
			pendingSep = b.Len() > 0
			continue
		}
		if pendingSep {
			b.WriteByte('_')
			pendingSep = false
		}
		b.WriteRune(r)
	}
	out := b.String()
	if limit > 0 {
		if runes := []rune(out); len(runes) > limit {
			out = string(runes[:limit]) + "..."
		}
	}
	return out
}
