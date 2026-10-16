package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/cli"
)

// The local CA end to end, through the CLI: create a CA, issue from it, and
// inspect the result against it with every check inspect offers.
func TestCAInitIssueInspect(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "ca")
	out := filepath.Join(tmp, "app")

	code, stdout, stderr := run(t, nil, "ca", "init", "--dir", dir, "--name", "Example Local CA", "--permit-dns", "example.internal", "--permit-ip", "10.0.0.0/8")
	if code != cli.ExitOK {
		t.Fatalf("ca init: exit %d: %s", code, stderr)
	}
	for _, want := range []string{"Created a local CA in " + dir, "CN=Example Local CA", "example.internal, 10.0.0.0/8 (critical name constraints)", "keep it secret"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("ca init output lacks %q:\n%s", want, stdout)
		}
	}

	code, stdout, stderr = run(t, nil, "ca", "issue", "--ca-dir", dir, "--dns", "app.example.internal", "--ip", "10.1.2.3", "--out", out)
	if code != cli.ExitOK {
		t.Fatalf("ca issue: exit %d: %s", code, stderr)
	}
	for _, want := range []string{"Issued a TLS server certificate for app.example.internal, 10.1.2.3", out + ".pem", out + ".key", "Proven before writing"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("ca issue output lacks %q:\n%s", want, stdout)
		}
	}

	for _, host := range []string{"app.example.internal", "10.1.2.3"} {
		code, stdout, _ = run(t, nil, "inspect", out+".pem", "--roots", filepath.Join(dir, "ca.pem"), "--purpose", "tls-server", "--hostname", host, "--fail-on", "info")
		if code != cli.ExitOK {
			t.Errorf("inspect --hostname %s of the issued certificate: exit %d\n%s", host, code, stdout)
		}
	}
}

func TestCAErrors(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "ca")
	if code, _, stderr := run(t, nil, "ca", "init", "--dir", dir, "--permit-dns", "example.internal"); code != cli.ExitOK {
		t.Fatalf("ca init: %s", stderr)
	}
	for name, tc := range map[string]struct {
		args []string
		code int
		want string
	}{
		"init twice":     {[]string{"ca", "init", "--dir", dir}, cli.ExitError, "never overwrites"},
		"bad key type":   {[]string{"ca", "init", "--dir", filepath.Join(tmp, "x"), "--key-type", "dsa"}, cli.ExitUsage, "invalid --key-type"},
		"bad permit-ip":  {[]string{"ca", "init", "--dir", filepath.Join(tmp, "x"), "--permit-ip", "10.0.0.1"}, cli.ExitUsage, "invalid --permit-ip"},
		"no names":       {[]string{"ca", "issue", "--ca-dir", dir}, cli.ExitUsage, "at least one --dns or --ip"},
		"bad use":        {[]string{"ca", "issue", "--ca-dir", dir, "--dns", "a.example.internal", "--use", "email"}, cli.ExitUsage, "invalid --use"},
		"bad ip":         {[]string{"ca", "issue", "--ca-dir", dir, "--ip", "300.1.1.1"}, cli.ExitUsage, "invalid --ip"},
		"outside":        {[]string{"ca", "issue", "--ca-dir", dir, "--dns", "example.com", "--out", filepath.Join(tmp, "o")}, cli.ExitError, "outside the CA's permitted names"},
		"too long":       {[]string{"ca", "issue", "--ca-dir", dir, "--dns", "a.example.internal", "--days", "500", "--out", filepath.Join(tmp, "o")}, cli.ExitError, "at most 397 days"},
		"missing CA":     {[]string{"ca", "issue", "--ca-dir", filepath.Join(tmp, "none"), "--dns", "a.example.internal", "--out", filepath.Join(tmp, "o")}, cli.ExitError, "trustsmith ca init"},
		"positional arg": {[]string{"ca", "init", "extra"}, cli.ExitUsage, "unknown command"},
	} {
		code, _, stderr := run(t, nil, tc.args...)
		if code != tc.code || !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: exit %d, stderr %q; want exit %d containing %q", name, code, stderr, tc.code, tc.want)
		}
	}
	if entries, _ := os.ReadDir(tmp); len(entries) != 1 {
		t.Errorf("refused commands wrote files: %v", entries)
	}
}

func TestCAIssueDefaultOut(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	if code, _, stderr := run(t, nil, "ca", "init"); code != cli.ExitOK {
		t.Fatal(stderr)
	}
	if code, _, stderr := run(t, nil, "ca", "issue", "--dns", "*.svc.example.internal", "--use", "both"); code != cli.ExitOK {
		t.Fatal(stderr)
	}
	for _, f := range []string{"trustsmith-ca/ca.pem", "trustsmith-ca/ca.key", "_wildcard.svc.example.internal.pem", "_wildcard.svc.example.internal.key"} {
		if _, err := os.Stat(f); err != nil {
			t.Error(err)
		}
	}
}
