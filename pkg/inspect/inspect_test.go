package inspect_test

import (
	"bytes"
	"os"
	"path/filepath"
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

func TestTargetErrors(t *testing.T) {
	_, err := inspect.Target(filepath.Join(t.TempDir(), "missing.pem"), inspect.Options{})
	if err == nil {
		t.Fatal("inspection of a missing file: no error")
	}
}
