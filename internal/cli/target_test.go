package cli

import "testing"

func TestResolveTarget(t *testing.T) {
	existing := map[string]bool{
		"leaf.pem":       true,
		"example.com":    true, // an existing file named like a host is still a file
		`C:\certs\a.pem`: true,
	}
	exists := func(p string) bool { return existing[p] }

	for _, tc := range []struct {
		arg  string
		want targetKind
	}{
		{"-", targetStdin},
		{"leaf.pem", targetFile},
		{"example.com", targetFile},
		{`C:\certs\a.pem`, targetFile},
		{`D:\missing\cert.pem`, targetFile},
		{"c:/missing/cert.pem", targetFile},
		{`\\server\share\cert.pem`, targetFile},
		{"a:b", targetFile},
		{"missing.pem", targetFile},
		{"missing.crt", targetFile},
		{"certs/missing", targetFile},
		{"./api.example.com", targetFile},
		{"cert", targetFile},
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
