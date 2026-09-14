package cli

import (
	"errors"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/endpoint"
)

func TestResolveTarget(t *testing.T) {
	existing := map[string]bool{
		"leaf.pem":        true,
		"example.com":     true, // an existing file named like a host is still a file
		"example.com:443": true, // and so is one named like host:port
		`C:\certs\a.pem`:  true,
	}
	exists := func(p string) bool { return existing[p] }

	for _, tc := range []struct {
		arg  string
		want targetKind
	}{
		{"-", targetStdin},
		{"leaf.pem", targetFile},
		{"example.com", targetFile},
		{"example.com:443", targetFile},
		{`C:\certs\a.pem`, targetFile},
		{`D:\missing\cert.pem`, targetFile},
		{"c:/missing/cert.pem", targetFile},
		{"C:443", targetFile},
		{`\\server\share\cert.pem`, targetFile},
		{"a:b", targetFile},
		{"missing.pem", targetFile},
		{"missing.crt", targetFile},
		{"certs/missing", targetFile},
		{"./api.example.com", targetFile},
		{"./api.example.com:443", targetFile},
		{"cert", targetFile},
		{"[notes]", targetFile},
		{"192.0.2.10", targetFile},
		{"server:443", targetFile}, // a single-label host is not endpoint-shaped
		{"api.example.com:443", targetEndpoint},
		{"localhost:8443", targetEndpoint},
		{"[2001:db8::1]:443", targetEndpoint},
		{"https://api.example.com", targetEndpoint},
		{"tls://api.example.com:8443", targetEndpoint},
		{"api.example.org", targetEndpoint},
	} {
		if got := resolveTarget(tc.arg, exists); got != tc.want {
			t.Errorf("resolveTarget(%q) = %s, want %s", tc.arg, got, tc.want)
		}
	}
}

// Endpoint-shaped arguments resolve as endpoints whatever their port, so a
// malformed one is a usage error from endpoint parsing, never a missing file.
func TestEndpointShapedTargets(t *testing.T) {
	none := func(string) bool { return false }
	for _, tc := range []struct {
		arg   string
		valid bool
	}{
		{"example.com:443", true},
		{"example.com:1", true},
		{"example.com:65535", true},
		{"example.com:0", false},
		{"example.com:65536", false},
		{"example.com:-1", false},
		{"example.com:abc", false},
		{"example.com:", false},
		{"localhost:0", false},
		{"192.0.2.10:443", true},
		{"192.0.2.10:99999", false},
		{"[2001:db8::1]:443", true},
		{"[2001:db8::1]", true},
		{"[2001:db8::1]:0", false},
		{"[2001:db8::1]:abc", false},
		{"[2001:db8::1", false},
		{"[2001:db8::1]443", false},
		{"2001:db8::1", false},
		{"2001:db8::1:443", false},
		{"fe80::1%eth0:443", false},
		{"tls://example.com:443", true},
		{"tls://example.com:1", true},
		{"tls://example.com:65535", true},
		{"tls://example.com:0", false},
		{"tls://example.com:65536", false},
		{"tls://example.com:-1", false},
		{"tls://example.com:abc", false},
		{"tls://[2001:db8::1]:443", true},
		{"tls://2001:db8::1:443", false},
		{"https://example.com", false},
	} {
		if got := resolveTarget(tc.arg, none); got != targetEndpoint {
			t.Errorf("resolveTarget(%q) = %s, want endpoint", tc.arg, got)
			continue
		}
		_, err := endpoint.Parse(tc.arg)
		if tc.valid != (err == nil) {
			t.Errorf("endpoint.Parse(%q) error %v, want valid=%v", tc.arg, err, tc.valid)
		}
		if err != nil && !errors.Is(err, endpoint.ErrInvalid) {
			t.Errorf("endpoint.Parse(%q) error %v is not ErrInvalid", tc.arg, err)
		}
	}
}
