package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/cli"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
)

// Goldens live next to this package; tests run from the repository root so
// the paths inside the output are short and platform-neutral.
var goldenDir = filepath.Join("internal", "cli", "testdata", "golden")

func chdirRoot(t *testing.T) {
	t.Helper()
	t.Chdir(filepath.Join("..", ".."))
}

func run(t *testing.T, stdin []byte, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := cli.Run(args, bytes.NewReader(stdin), &out, &errOut, cli.Env{
		Now:     func() time.Time { return testpki.Now },
		Version: "v0.0.0-test",
		// Tests never use the network: endpoint tests pass their own dialer.
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			t.Errorf("unexpected network dial to %s", address)
			return nil, errors.New("tests do not use the network")
		},
	})
	return code, out.String(), errOut.String()
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	// The Go release that performed trust validation is part of the output.
	// Goldens record a placeholder so they do not change with every toolchain
	// update; TestTrustJSONContract checks the real value.
	got = strings.ReplaceAll(got, runtime.Version(), "GO_VERSION")
	path := filepath.Join(goldenDir, name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden %s (run with UPDATE_GOLDEN=1): %v", path, err)
	}
	if normalized := strings.ReplaceAll(string(want), "\r\n", "\n"); normalized != got {
		t.Errorf("output differs from %s (run with UPDATE_GOLDEN=1 to accept)\n--- got ---\n%s", path, got)
	}
}

func corpusNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("testdata", "certs"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.Name() != "README.md" {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatal("empty corpus")
	}
	return names
}

func TestGoldens(t *testing.T) {
	chdirRoot(t)
	for _, name := range corpusNames(t) {
		path := "testdata/certs/" + name
		t.Run(name, func(t *testing.T) {
			_, text, stderr := run(t, nil, "inspect", "--fail-on", "never", path)
			if stderr != "" {
				t.Errorf("unexpected stderr: %s", stderr)
			}
			golden(t, name+".txt", text)

			_, js, _ := run(t, nil, "inspect", "--fail-on", "never", "--output", "json", path)
			if !json.Valid([]byte(js)) {
				t.Fatalf("invalid JSON:\n%s", js)
			}
			golden(t, name+".json", js)
		})
	}
	for _, name := range []string{"leaf.pem", "bundle-with-bad-block.pem", "noncanonical-rsa-key.pem", "x25519-key.pem"} {
		t.Run(name+" advanced", func(t *testing.T) {
			_, text, _ := run(t, nil, "inspect", "--fail-on", "never", "--advanced", "testdata/certs/"+name)
			golden(t, name+".advanced.txt", text)
		})
	}
}

type jsonResult struct {
	Schema string `json:"schema"`
	Input  struct {
		Kind    string `json:"kind"`
		Locator string `json:"locator"`
		Format  string `json:"format"`
	} `json:"input"`
	Artifacts []struct {
		Entry        int                `json:"entry"`
		Type         string             `json:"type"`
		Fingerprints map[string]*string `json:"fingerprints"`
	} `json:"artifacts"`
	Findings []struct {
		Code     string `json:"code"`
		Severity string `json:"severity"`
		Entry    *int   `json:"entry"`
		Title    string `json:"title"`
	} `json:"findings"`
}

func decodeJSON(t *testing.T, s string) jsonResult {
	t.Helper()
	var r jsonResult
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		t.Fatalf("%v\n%s", err, s)
	}
	return r
}

func TestJSONContract(t *testing.T) {
	chdirRoot(t)
	_, out, _ := run(t, nil, "inspect", "--output", "json", "--fail-on", "never", "testdata/certs/bundle-with-bad-block.pem")
	r := decodeJSON(t, out)
	if r.Schema != "trustsmith.inspect/v1" {
		t.Errorf("schema %q", r.Schema)
	}
	if len(r.Artifacts) != 3 || r.Artifacts[1].Type != "malformed" {
		t.Fatalf("artifacts %+v", r.Artifacts)
	}
	fp := r.Artifacts[0].Fingerprints
	for _, scheme := range []string{"x509-cert-sha256", "x509-spki-sha256", "x509-spki-encoded-sha256"} {
		if fp[scheme] == nil || len(*fp[scheme]) != 64 {
			t.Errorf("fingerprint %s: %v", scheme, fp[scheme])
		}
	}
	if len(r.Findings) != 1 || r.Findings[0].Code != "input.malformed_pem" || r.Findings[0].Entry == nil || *r.Findings[0].Entry != 1 || r.Findings[0].Title == "" {
		t.Errorf("findings %+v", r.Findings)
	}

	_, out, _ = run(t, nil, "inspect", "--output", "json", "--fail-on", "never", "testdata/certs/x25519-key.pem")
	if fp := decodeJSON(t, out).Artifacts[0].Fingerprints; fp["x509-spki-sha256"] != nil {
		t.Error("a key without an ADR-0002 identity must have a null x509-spki-sha256, never a substitute")
	}

	_, out, _ = run(t, nil, "inspect", "--output", "json", "--fail-on", "never", "testdata/certs/empty.pem")
	if r := decodeJSON(t, out); len(r.Findings) != 1 || r.Findings[0].Entry != nil || r.Artifacts == nil {
		t.Errorf("whole-input finding must have a null entry and artifacts an empty array: %s", out)
	}
}

func TestExitCodes(t *testing.T) {
	chdirRoot(t)
	for _, tc := range []struct {
		name   string
		args   []string
		code   int
		stderr string
	}{
		{"valid certificate", []string{"inspect", "testdata/certs/leaf.pem"}, 0, ""},
		{"critical finding", []string{"inspect", "testdata/certs/expired.pem"}, 3, ""},
		{"critical finding, fail-on never", []string{"inspect", "--fail-on", "never", "testdata/certs/expired.pem"}, 0, ""},
		{"warning below default threshold", []string{"inspect", "testdata/certs/expiring-warning.pem"}, 0, ""},
		{"warning at warning threshold", []string{"inspect", "--fail-on", "warning", "testdata/certs/expiring-warning.pem"}, 3, ""},
		{"info at info threshold", []string{"inspect", "--fail-on", "info", "testdata/certs/text-around.pem"}, 3, ""},
		{"json does not change exit code", []string{"inspect", "--output", "json", "testdata/certs/expired.pem"}, 3, ""},
		{"missing file", []string{"inspect", "testdata/certs/does-not-exist.pem"}, 1, "does-not-exist.pem"},
		{"directory", []string{"inspect", "testdata/certs"}, 1, "directory"},
		{"no argument", []string{"inspect"}, 2, "usage"},
		{"two arguments", []string{"inspect", "a.pem", "b.pem"}, 2, "usage"},
		{"bad output", []string{"inspect", "--output", "yaml", "testdata/certs/leaf.pem"}, 2, "--output"},
		{"bad fail-on", []string{"inspect", "--fail-on", "error", "testdata/certs/leaf.pem"}, 2, "--fail-on"},
		{"unknown flag", []string{"inspect", "--nope", "testdata/certs/leaf.pem"}, 2, "nope"},
		{"unknown command", []string{"frobnicate"}, 2, "frobnicate"},
		{"https is not an endpoint scheme", []string{"inspect", "https://api.example.com"}, 2, "unsupported scheme"},
		{"endpoint with a path", []string{"inspect", "tls://api.example.com/index.html"}, 2, "path"},
		{"endpoint with user information", []string{"inspect", "tls://user@api.example.com:443"}, 2, "user information"},
		{"endpoint port out of range", []string{"inspect", "tls://api.example.com:65536"}, 2, "port"},
		{"unknown probe policy", []string{"inspect", "--probe-policy", "legacy", "api.example.com:443"}, 2, "--probe-policy"},
		{"probe policy for a file", []string{"inspect", "--probe-policy", "modern", "testdata/certs/leaf.pem"}, 2, "--probe-policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := run(t, nil, tc.args...)
			if code != tc.code {
				t.Errorf("exit %d, want %d (stderr: %s)", code, tc.code, stderr)
			}
			if tc.stderr == "" && stderr != "" {
				t.Errorf("unexpected stderr: %s", stderr)
			}
			if tc.stderr != "" && !strings.Contains(strings.ToLower(stderr), strings.ToLower(tc.stderr)) {
				t.Errorf("stderr %q does not mention %q", stderr, tc.stderr)
			}
		})
	}
}

func TestStdin(t *testing.T) {
	chdirRoot(t)
	data, err := os.ReadFile(filepath.Join("testdata", "certs", "bundle.pem"))
	if err != nil {
		t.Fatal(err)
	}
	code, fromStdin, _ := run(t, data, "inspect", "--output", "json", "-")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	_, fromFile, _ := run(t, nil, "inspect", "--output", "json", "testdata/certs/bundle.pem")

	s, f := decodeJSON(t, fromStdin), decodeJSON(t, fromFile)
	if s.Input.Kind != "stdin" || s.Input.Locator != "-" {
		t.Errorf("input %+v", s.Input)
	}
	if len(s.Artifacts) != len(f.Artifacts) {
		t.Fatalf("artifact count %d vs %d", len(s.Artifacts), len(f.Artifacts))
	}
	for i := range s.Artifacts {
		if *s.Artifacts[i].Fingerprints["x509-cert-sha256"] != *f.Artifacts[i].Fingerprints["x509-cert-sha256"] {
			t.Errorf("artifact %d differs between stdin and file", i)
		}
	}
}

func TestHostileInputNeverPanics(t *testing.T) {
	chdirRoot(t)
	dir := t.TempDir()
	garbage := [][]byte{
		{0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
		[]byte("-----BEGIN CERTIFICATE-----\n" + strings.Repeat("A", 5000) + "\n-----END CERTIFICATE-----\n"),
		bytes.Repeat([]byte("-----BEGIN CERTIFICATE-----\n"), 200),
		{0xef, 0xbb, 0xbf, 0x30, 0x00},
	}
	var paths []string
	for i, g := range garbage {
		p := filepath.Join(dir, "garbage"+string(rune('a'+i)))
		if err := os.WriteFile(p, g, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	for _, name := range corpusNames(t) {
		paths = append(paths, filepath.Join("testdata", "certs", name))
	}
	for _, p := range paths {
		for _, output := range []string{"text", "json"} {
			code, _, stderr := run(t, nil, "inspect", "--advanced", "--output", output, p)
			if code != 0 && code != 3 {
				t.Errorf("%s (%s): exit %d: %s", p, output, code, stderr)
			}
		}
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := run(t, nil, "version")
	if code != 0 || !strings.Contains(out, "v0.0.0-test") {
		t.Errorf("exit %d output %q", code, out)
	}
}
