package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/cli"
)

var vectorDir = filepath.Join("internal", "fingerprint", "testdata", "vectors")

func TestMatchGoldens(t *testing.T) {
	chdirRoot(t)
	for _, tc := range []struct {
		name, cert, key string
		code            int
	}{
		{"match-ecdsa", "ecdsa-p256/cert.pem", "ecdsa-p256/key.pem", cli.ExitOK},
		{"match-rsa-pkcs8", "rsa-2048/cert.pem", "rsa-2048/pkcs8.pem", cli.ExitOK},
		{"match-mismatch", "rsa-2048/cert.pem", "ecdsa-p256/pkcs8.pem", cli.ExitFindings},
	} {
		cert := filepath.Join(vectorDir, filepath.FromSlash(tc.cert))
		key := filepath.Join(vectorDir, filepath.FromSlash(tc.key))
		for _, format := range []string{"text", "json"} {
			code, stdout, stderr := run(t, nil, "match", cert, key, "--output", format)
			if code != tc.code {
				t.Errorf("%s %s: exit %d, want %d; stderr %s", tc.name, format, code, tc.code, stderr)
			}
			ext := ".txt"
			if format == "json" {
				ext = ".json"
			}
			golden(t, tc.name+ext, filepath.ToSlash(stdout))
		}
	}
}

// In a bundle, the answer names the entry whose key matches.
func TestMatchBundleNamesTheEntry(t *testing.T) {
	chdirRoot(t)
	var bundle []byte
	for _, v := range []string{"rsa-2048", "ecdsa-p256", "ed25519"} {
		data, err := os.ReadFile(filepath.Join(vectorDir, v, "cert.pem"))
		if err != nil {
			t.Fatal(err)
		}
		bundle = append(bundle, data...)
	}
	path := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := run(t, nil, "match", path, filepath.Join(vectorDir, "ecdsa-p256", "pkcs8.pem"), "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("exit %d", code)
	}
	var doc struct {
		Schema       string `json:"schema"`
		Matched      *int   `json:"matched"`
		Certificates []struct {
			State string `json:"state"`
		} `json:"certificates"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != "trustsmith.match/v1" || doc.Matched == nil || *doc.Matched != 1 || len(doc.Certificates) != 3 ||
		doc.Certificates[0].State != "does_not_match" || doc.Certificates[1].State != "matches" || doc.Certificates[2].State != "does_not_match" {
		t.Errorf("unexpected result:\n%s", stdout)
	}
}

// Nothing derived from the private value reaches the output: only the public
// identity, which the certificate already publishes.
func TestMatchPrintsNoPrivateMaterial(t *testing.T) {
	chdirRoot(t)
	keyPath := filepath.Join(vectorDir, "ecdsa-p256", "key.pem")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Join(strings.Split(strings.TrimSpace(string(keyPEM)), "\n")[1:3], "")
	for _, format := range []string{"text", "json"} {
		_, stdout, _ := run(t, nil, "match", filepath.Join(vectorDir, "ecdsa-p256", "cert.pem"), keyPath, "-o", format)
		if strings.Contains(stdout, body[:16]) {
			t.Errorf("%s output contains key material", format)
		}
	}
}

func TestMatchErrors(t *testing.T) {
	chdirRoot(t)
	tmp := t.TempDir()
	encrypted := filepath.Join(tmp, "enc.pem")
	if err := os.WriteFile(encrypted, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMAA=\n-----END ENCRYPTED PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(vectorDir, "ecdsa-p256", "cert.pem")
	key := filepath.Join(vectorDir, "ecdsa-p256", "key.pem")
	for name, tc := range map[string]struct {
		args []string
		code int
		want string
	}{
		"one argument":  {[]string{"match", cert}, cli.ExitUsage, "certificate file and a private key file"},
		"bad output":    {[]string{"match", cert, key, "-o", "yaml"}, cli.ExitUsage, "invalid --output"},
		"encrypted key": {[]string{"match", cert, encrypted}, cli.ExitError, "encrypted"},
		"key as cert":   {[]string{"match", key, key}, cli.ExitError, "no certificate found"},
		"cert as key":   {[]string{"match", cert, cert}, cli.ExitError, "no private key found"},
		"missing file":  {[]string{"match", filepath.Join(tmp, "none.pem"), key}, cli.ExitError, "none.pem"},
	} {
		code, _, stderr := run(t, nil, tc.args...)
		if code != tc.code || !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: exit %d, stderr %q; want exit %d containing %q", name, code, stderr, tc.code, tc.want)
		}
	}
}
