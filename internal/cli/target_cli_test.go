package cli_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Malformed endpoint-shaped arguments are usage errors (exit 2) that name the
// endpoint problem. They never become "file not found" and never dial: run's
// dialer fails the test if called.
func TestMalformedEndpointsAreUsageErrors(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, tc := range []struct{ arg, mention string }{
		{"example.com:0", "port"},
		{"example.com:65536", "port"},
		{"example.com:-1", "port"},
		{"example.com:abc", "port"},
		{"example.com:", "port"},
		{"192.0.2.10:99999", "port"},
		{"tls://example.com:0", "port"},
		{"tls://example.com:65536", "port"},
		{"tls://example.com:-1", "port"},
		{"tls://example.com:abc", "port"},
		{"[2001:db8::1]:0", "port"},
		{"[2001:db8::1", "]"},
		{"[2001:db8::1]443", "]"},
		{"2001:db8::1", "[address]:port"},
		{"2001:db8::1:443", "[address]:port"},
		{"tls://2001:db8::1:443", "[address]:port"},
		{"https://example.com", "unsupported scheme"},
		{"https://example.com:443", "unsupported scheme"},
	} {
		code, out, stderr := run(t, nil, "inspect", tc.arg)
		if code != 2 || out != "" {
			t.Errorf("inspect %q: exit %d, stdout %q; want exit 2 and no output", tc.arg, code, out)
		}
		lower := strings.ToLower(stderr)
		if !strings.Contains(stderr, "invalid endpoint") || !strings.Contains(stderr, tc.mention) ||
			strings.Contains(lower, "no such file") || strings.Contains(lower, "cannot find") {
			t.Errorf("inspect %q: stderr %q, want an invalid endpoint error mentioning %q", tc.arg, stderr, tc.mention)
		}
	}
}

// An existing file whose name contains a colon is still a file, where the
// platform allows such names.
func TestExistingColonFileWinsOverEndpoint(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file names cannot contain ':'")
	}
	leaf, err := os.ReadFile(filepath.Join("..", "..", "testdata", "certs", "leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	for _, name := range []string{"example.com:443", "example.com:65536"} {
		if err := os.WriteFile(name, leaf, 0o644); err != nil {
			t.Fatal(err)
		}
		code, out, stderr := run(t, nil, "inspect", "--output", "json", name)
		if code != 0 || stderr != "" || !strings.Contains(out, `"kind": "file"`) || !strings.Contains(out, `"probe": null`) {
			t.Errorf("inspect %q: exit %d, stderr %q; want the file inspected", name, code, stderr)
		}
	}
}
