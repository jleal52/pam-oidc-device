package oidc

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestClampInterval(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want int64 }{
		{-1, 5},
		{0, 5},
		{1, 1},
		{5, 5},
		{60, 60},
		{61, 60},
		{3600, 60},
	}
	for _, tc := range cases {
		if got := clampInterval(tc.in); got != tc.want {
			t.Errorf("clampInterval(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestCheckEndpointsHTTPS(t *testing.T) {
	t.Parallel()
	https := discoveredEndpoints{
		DeviceAuthorizationEndpoint: "https://idp.example/device",
		TokenEndpoint:               "https://idp.example/token",
		JWKSURI:                     "https://idp.example/jwks",
	}
	cases := []struct {
		name    string
		meta    discoveredEndpoints
		allow   bool
		wantErr string // substring of the error, empty means no error
	}{
		{name: "all https", meta: https},
		{name: "http device endpoint", meta: func() discoveredEndpoints {
			m := https
			m.DeviceAuthorizationEndpoint = "http://idp.example/device"
			return m
		}(), wantErr: "device_authorization_endpoint"},
		{name: "http token endpoint", meta: func() discoveredEndpoints {
			m := https
			m.TokenEndpoint = "http://idp.example/token"
			return m
		}(), wantErr: "token_endpoint"},
		{name: "http jwks_uri", meta: func() discoveredEndpoints {
			m := https
			m.JWKSURI = "http://idp.example/jwks"
			return m
		}(), wantErr: "jwks_uri"},
		{name: "missing token endpoint", meta: func() discoveredEndpoints {
			m := https
			m.TokenEndpoint = ""
			return m
		}(), wantErr: "token_endpoint"},
		{name: "missing jwks_uri", meta: func() discoveredEndpoints {
			m := https
			m.JWKSURI = ""
			return m
		}(), wantErr: "jwks_uri"},
		{name: "scheme is case-insensitive", meta: func() discoveredEndpoints {
			m := https
			m.TokenEndpoint = "HTTPS://idp.example/token"
			return m
		}()},
		{name: "insecure allowed skips the check", meta: discoveredEndpoints{
			DeviceAuthorizationEndpoint: "http://idp.example/device",
			TokenEndpoint:               "http://idp.example/token",
			JWKSURI:                     "http://idp.example/jwks",
		}, allow: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkEndpointsHTTPS(tc.meta, tc.allow)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error mentioning %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), "https") {
				t.Fatalf("error %q should mention %q and https", err, tc.wantErr)
			}
		})
	}
}

func TestSanitizeProviderText(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{name: "empty", in: "", max: 10, want: ""},
		{name: "plain", in: "access denied", max: 100, want: "access denied"},
		{name: "collapses whitespace", in: "  a \n\n b\t\r\n c  ", max: 100, want: "a b c"},
		{name: "strips control characters", in: "a\x1bb\x00c\x7fd", max: 100, want: "a b c d"},
		// The ESC byte is what makes a terminal escape act; the printable
		// remainder of the sequence is harmless and is kept.
		{name: "defuses terminal escapes", in: "\x1b[31mred\x1b[0m", max: 100, want: "[31mred [0m"},
		{name: "truncates", in: "abcdefghij", max: 5, want: "abcde..."},
		{name: "truncates by rune", in: "ááááá", max: 3, want: "ááá..."},
		{name: "exact length is not truncated", in: "abcde", max: 5, want: "abcde"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := sanitizeProviderText(tc.in, tc.max); got != tc.want {
				t.Errorf("sanitizeProviderText(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
			}
		})
	}
}

func TestWrapProviderErrorNeverIncludesBody(t *testing.T) {
	t.Parallel()
	re := &oauth2.RetrieveError{
		Response:         &http.Response{StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway"},
		Body:             []byte("<html>SECRET-BODY</html>"),
		ErrorCode:        "",
		ErrorDescription: "",
	}
	err := wrapProviderError("token request", re)
	msg := err.Error()
	if strings.Contains(msg, "SECRET-BODY") {
		t.Fatalf("error leaks the raw body: %q", msg)
	}
	if !strings.Contains(msg, "502") {
		t.Errorf("error should mention the status code: %q", msg)
	}
	var got *oauth2.RetrieveError
	if !errors.As(err, &got) {
		t.Error("the original *oauth2.RetrieveError should remain in the chain")
	}

	plain := errors.New("dial tcp: connection refused")
	if err := wrapProviderError("token request", plain); !errors.Is(err, plain) {
		t.Errorf("non-provider errors should be wrapped, got %v", err)
	}
}
