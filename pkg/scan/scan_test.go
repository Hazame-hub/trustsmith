package scan_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/testpki"
	"github.com/Hazame-hub/trustsmith/pkg/scan"
)

// The library returns the CLI's document byte for byte: the golden file is
// the one internal/cli records for `trustsmith scan testdata/certs -o json`.
func TestDirectoryMatchesTheCLIGolden(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	got, err := scan.Directory("testdata/certs", scan.Options{Now: func() time.Time { return testpki.Now }})
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("internal/cli/testdata/golden/scan-certs.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("scan.Directory output differs from the CLI golden scan-certs.json")
	}
	var doc struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(got, &doc); err != nil || doc.Schema != scan.Schema {
		t.Errorf("schema %q (%v), want %q", doc.Schema, err, scan.Schema)
	}
}

func TestDirectoryErrors(t *testing.T) {
	_, err := scan.Directory(filepath.Join(t.TempDir(), "missing"), scan.Options{})
	if err == nil {
		t.Fatal("scan of a missing path: no error")
	}
}

// A path that looks like a flag is still a path.
func TestDirectoryTakesDashPathsLiterally(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("--help", 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := scan.Directory("--help", scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`"path": "--help"`)) {
		t.Errorf("document does not name the --help directory:\n%s", got)
	}
}
