package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/cli"
)

func TestScanGoldens(t *testing.T) {
	chdirRoot(t)
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"scan-certs.txt", []string{"scan", "testdata/certs", "--fail-on", "never"}},
		{"scan-certs.json", []string{"scan", "testdata/certs", "--fail-on", "never", "-o", "json"}},
		{"scan-certs-expiring.txt", []string{"scan", "testdata/certs", "--fail-on", "never", "--expiring-within", "30"}},
	} {
		code, stdout, stderr := run(t, nil, tc.args...)
		if code != cli.ExitOK {
			t.Fatalf("%s: exit %d: %s", tc.name, code, stderr)
		}
		golden(t, tc.name, filepath.ToSlash(stdout))
	}
}

func TestScanExitCodes(t *testing.T) {
	chdirRoot(t)
	if code, _, _ := run(t, nil, "scan", "testdata/certs"); code != cli.ExitFindings {
		t.Errorf("scan of a corpus with expired certificates: exit %d, want %d", code, cli.ExitFindings)
	}
	if code, _, _ := run(t, nil, "scan", "testdata/certs/leaf.pem", "--fail-on", "warning"); code != cli.ExitOK {
		t.Errorf("scan of one valid file: exit %d", code)
	}
	for name, tc := range map[string]struct {
		args []string
		code int
	}{
		"missing":       {[]string{"scan", "testdata/does-not-exist"}, cli.ExitError},
		"no argument":   {[]string{"scan"}, cli.ExitUsage},
		"bad output":    {[]string{"scan", "testdata/certs", "-o", "csv"}, cli.ExitUsage},
		"bad fail-on":   {[]string{"scan", "testdata/certs", "--fail-on", "sometimes"}, cli.ExitUsage},
		"negative days": {[]string{"scan", "testdata/certs", "--expiring-within", "-1"}, cli.ExitUsage},
	} {
		if code, _, _ := run(t, nil, tc.args...); code != tc.code {
			t.Errorf("%s: exit %d, want %d", name, code, tc.code)
		}
	}
}

// Only certificate files are listed; keys and other files are passed over
// without being decoded, and links are never followed.
func TestScanSelectsFilesAndSkipsLinks(t *testing.T) {
	chdirRoot(t)
	leaf, err := os.ReadFile("testdata/certs/leaf.pem")
	if err != nil {
		t.Fatal(err)
	}
	der, err := os.ReadFile("testdata/certs/leaf.der")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := map[string][]byte{
		"etc/nginx/site.conf.pem-copy": leaf, // armour is enough, whatever the name
		"etc/ssl/server.crt":           der,  // DER needs a certificate extension
		"etc/ssl/server.bin":           der,  // ...so this one is passed over
		"etc/ssl/server.key":           []byte("-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----\n"),
		"README":                       []byte("not a certificate"),
	}
	for name, data := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	links := 0
	if runtime.GOOS != "windows" {
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "secret.pem"), leaf, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, "link-to-outside")); err != nil {
			t.Fatal(err)
		}
		links = 1
	}
	code, stdout, stderr := run(t, nil, "scan", dir, "-o", "json", "--fail-on", "never")
	if code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var doc struct {
		Overview struct {
			FilesExamined    int `json:"files_examined"`
			CertificateFiles int `json:"certificate_files"`
			SkippedSymlinks  int `json:"skipped_symlinks"`
		} `json:"overview"`
		Certificates []struct {
			File string `json:"file"`
		} `json:"certificates"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Overview.FilesExamined != len(files) || doc.Overview.CertificateFiles != 2 || doc.Overview.SkippedSymlinks != links {
		t.Errorf("overview %+v", doc.Overview)
	}
	for _, c := range doc.Certificates {
		if strings.Contains(c.File, "link-to-outside") || strings.HasSuffix(c.File, ".bin") {
			t.Errorf("listed %s", c.File)
		}
	}
}
