package pamlog_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/jleal52/oidc-ssh/internal/pamlog"
)

func TestSanitize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"plain", "alice@example.com", 200, "alice@example.com"},
		{"empty", "", 200, ""},
		{"only whitespace", " \t\n ", 200, ""},
		{"trims surrounding whitespace", "  alice  ", 200, "alice"},
		{"collapses whitespace runs", "a  b\t\tc", 200, "a_b_c"},
		{"newline cannot forge a field", "alice\nresult=success", 200, "alice_result=success"},
		{"carriage return and NUL", "a\r\x00b", 200, "a_b"},
		{"other control characters", "a\x1b[31mb\x7f", 200, "a_[31mb"},
		{"invalid utf-8 dropped", "a\xffb", 200, "ab"},
		{"replacement char treated as separator", "a�b", 200, "a_b"},
		{"unicode kept", "josé.müller", 200, "josé.müller"},
		{"truncates with marker", strings.Repeat("x", 10), 5, "xxxxx..."},
		{"exact length not truncated", strings.Repeat("x", 5), 5, "xxxxx"},
		{"truncation counts runes", strings.Repeat("é", 6), 4, "éééé..."},
		{"max zero disables truncation", strings.Repeat("x", 500), 0, strings.Repeat("x", 500)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pamlog.Sanitize(tc.in, tc.max); got != tc.want {
				t.Fatalf("Sanitize(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
			}
		})
	}
}

func TestSanitizeNeverContainsWhitespace(t *testing.T) {
	inputs := []string{"a b", "a\tb", "a\nb", "\n\n", "a b", "a b", " x "}
	for _, in := range inputs {
		out := pamlog.Sanitize(in, 200)
		if strings.ContainsFunc(out, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' }) {
			t.Fatalf("Sanitize(%q) = %q still contains whitespace", in, out)
		}
	}
}

func TestLineOrderAndPlaceholders(t *testing.T) {
	a := pamlog.Attempt{
		User:      "alice@example.com",
		Subject:   "sub-123",
		LocalUser: "deploy",
		RHost:     "203.0.113.5",
		Host:      "bastion",
		Result:    pamlog.ResultSuccess,
	}
	want := "user=alice@example.com sub=sub-123 local_user=deploy rhost=203.0.113.5 host=bastion result=success reason=- err=-"
	if got := a.Line(); got != want {
		t.Fatalf("Line() = %q\nwant %q", got, want)
	}
}

func TestLineIsDeterministicAndFixedWidth(t *testing.T) {
	a := pamlog.Attempt{Result: pamlog.ResultError, Reason: "provider_unavailable", Err: errors.New("dial tcp: timeout")}
	first := a.Line()
	for i := 0; i < 5; i++ {
		if got := a.Line(); got != first {
			t.Fatalf("Line() changed between calls: %q vs %q", first, got)
		}
	}
	fields := strings.Fields(first)
	if len(fields) != 8 {
		t.Fatalf("expected 8 fields, got %d: %q", len(fields), first)
	}
	keys := []string{"user", "sub", "local_user", "rhost", "host", "result", "reason", "err"}
	for i, k := range keys {
		if !strings.HasPrefix(fields[i], k+"=") {
			t.Fatalf("field %d = %q, want prefix %q", i, fields[i], k+"=")
		}
	}
	if fields[7] != "err=dial_tcp:_timeout" {
		t.Fatalf("err field = %q", fields[7])
	}
}

func TestLineSanitisesEveryValue(t *testing.T) {
	a := pamlog.Attempt{
		User:      "evil\nresult=success",
		Subject:   "s\tub",
		LocalUser: "loc al",
		RHost:     "h\x00ost",
		Host:      "bas\rtion",
		Result:    "den ied",
		Reason:    "rea\nson",
		Err:       errors.New("multi\nline\nerror"),
	}
	line := a.Line()
	if strings.Count(line, "\n") != 0 || strings.Count(line, "\t") != 0 {
		t.Fatalf("line contains newlines or tabs: %q", line)
	}
	if got := len(strings.Fields(line)); got != 8 {
		t.Fatalf("expected 8 fields after sanitising, got %d: %q", got, line)
	}
}

func TestLineTruncation(t *testing.T) {
	a := pamlog.Attempt{
		User: strings.Repeat("u", pamlog.MaxValueLen+50),
		Err:  errors.New(strings.Repeat("e", pamlog.MaxErrLen+50)),
	}
	fields := strings.Fields(a.Line())
	wantUser := "user=" + strings.Repeat("u", pamlog.MaxValueLen) + "..."
	if fields[0] != wantUser {
		t.Fatalf("user field not truncated to %d: len %d", pamlog.MaxValueLen, len(fields[0]))
	}
	wantErr := "err=" + strings.Repeat("e", pamlog.MaxErrLen) + "..."
	if fields[7] != wantErr {
		t.Fatalf("err field not truncated to %d: len %d", pamlog.MaxErrLen, len(fields[7]))
	}
}

func TestLevelFor(t *testing.T) {
	tests := map[string]pamlog.Level{
		pamlog.ResultSuccess: pamlog.LevelInfo,
		pamlog.ResultDenied:  pamlog.LevelNotice,
		pamlog.ResultIgnore:  pamlog.LevelDebug,
		pamlog.ResultError:   pamlog.LevelErr,
		"whatever":           pamlog.LevelErr,
		"":                   pamlog.LevelErr,
	}
	for result, want := range tests {
		if got := pamlog.LevelFor(result); got != want {
			t.Errorf("LevelFor(%q) = %v, want %v", result, got, want)
		}
	}
}

func TestLevelString(t *testing.T) {
	tests := map[pamlog.Level]string{
		pamlog.LevelDebug:  "debug",
		pamlog.LevelInfo:   "info",
		pamlog.LevelNotice: "notice",
		pamlog.LevelErr:    "err",
		pamlog.Level(99):   "err",
	}
	for l, want := range tests {
		if got := l.String(); got != want {
			t.Errorf("Level(%d).String() = %q, want %q", int(l), got, want)
		}
	}
}

func TestValidEnvValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", true},
		{"email", "alice@example.com", true},
		{"subject", "auth0|5f1e2d3c4b5a69788796a5b4", true},
		{"unicode", "josé.müller", true},
		{"space allowed", "Alice Example", true},
		{"newline", "alice\nresult=success", false},
		{"carriage return", "alice\r", false},
		{"escape", "alice\x1b[31m", false},
		{"nul", "alice\x00root", false},
		{"tab", "a\tb", false},
		{"delete", "a\x7fb", false},
		{"c1 control", "a\u0085b", false},
		{"invalid utf-8", "a\xffb", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pamlog.ValidEnvValue(tc.in); got != tc.want {
				t.Fatalf("ValidEnvValue(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizePrompt(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "Open the following URL", "Open the following URL"},
		{"empty", "", ""},
		{"keeps newline and tab", "line1\n\tline2\n", "line1\n\tline2\n"},
		{"strips escape sequence", "https://example.com/\x1b[2J\x1b[Hverify", "https://example.com/[2J[Hverify"},
		{"strips carriage return", "Code: ABCD\rXXXX", "Code: ABCDXXXX"},
		{"strips nul and delete", "a\x00b\x7fc", "abc"},
		{"strips c1 controls", "ab\u0085c", "abc"},
		{"drops invalid utf-8", "a\xffb", "ab"},
		{"unicode kept", "josé.müller → ok", "josé.müller → ok"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pamlog.SanitizePrompt(tc.in); got != tc.want {
				t.Fatalf("SanitizePrompt(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizePromptAgreesWithValidEnvValue(t *testing.T) {
	// Whatever SanitizePrompt lets through must be either \n, \t or a
	// character ValidEnvValue would also accept: the two helpers share one
	// notion of "control character".
	in := "a\x00b\x1bc\rd\ne\tf\x7fg\xffhi"
	out := pamlog.SanitizePrompt(in)
	stripped := strings.NewReplacer("\n", "", "\t", "").Replace(out)
	if !pamlog.ValidEnvValue(stripped) {
		t.Fatalf("SanitizePrompt(%q) = %q, which ValidEnvValue rejects after removing \\n and \\t", in, out)
	}
}
