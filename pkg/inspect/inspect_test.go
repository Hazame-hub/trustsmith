package inspect_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/testpki"
	"github.com/Hazame-hub/trustsmith/pkg/inspect"
)

// The library returns the CLI's document byte for byte: the golden file is
// the one internal/cli records for `trustsmith inspect -o json` of leaf.pem.
func TestTargetMatchesTheCLIGolden(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	got, err := inspect.Target("testdata/certs/leaf.pem", inspect.Options{Now: func() time.Time { return testpki.Now }})
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("internal/cli/testdata/golden/leaf.pem.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("inspect.Target output differs from the CLI golden leaf.pem.json")
	}
}

// Hostname and Purpose are the CLI's --hostname and --purpose: the document
// is the golden internal/cli records for `inspect leaf.pem --purpose
// tls-client --hostname www.example.test`, which matches the name and fails
// the purpose.
func TestTargetHostnameAndPurposeMatchTheCLIGolden(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	got, err := inspect.Target("testdata/certs/leaf.pem", inspect.Options{
		Now:      func() time.Time { return testpki.Now },
		Hostname: "www.example.test",
		Purpose:  "tls-client",
	})
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("internal/cli/testdata/golden/hostname-match-purpose-mismatch.json")
	if err != nil {
		t.Fatal(err)
	}
	// Goldens record the Go release that matched the name as a placeholder.
	got = bytes.ReplaceAll(got, []byte(runtime.Version()), []byte("GO_VERSION"))
	if !bytes.Equal(got, want) {
		t.Errorf("inspect.Target output differs from the CLI golden hostname-match-purpose-mismatch.json")
	}
}

func TestTargetRefusesABadOption(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	if _, err := inspect.Target("testdata/certs/leaf.pem", inspect.Options{Purpose: "nonsense"}); err == nil {
		t.Error("purpose nonsense: no error")
	}
	if _, err := inspect.Target("testdata/certs/leaf.pem", inspect.Options{Hostname: "https://www.example.test/"}); err == nil {
		t.Error("a URL as host name: no error")
	}
}

func TestTargetErrors(t *testing.T) {
	_, err := inspect.Target(filepath.Join(t.TempDir(), "missing.pem"), inspect.Options{})
	if err == nil {
		t.Fatal("inspection of a missing file: no error")
	}
}
