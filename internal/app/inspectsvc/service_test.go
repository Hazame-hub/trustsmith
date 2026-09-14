package inspectsvc_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/artifact"
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
)

var corpus = filepath.Join("..", "..", "..", "testdata", "certs")

func service() *inspectsvc.Service {
	return inspectsvc.New(func() time.Time { return testpki.Now })
}

type expectation struct {
	types    []inspectsvc.ArtifactType
	findings []string // "entry:code:severity", entry -1 for the whole input
}

const (
	cert        = inspectsvc.TypeCertificate
	unparseable = inspectsvc.TypeUnparseableCertificate
	unsupported = inspectsvc.TypeUnsupported
	malformed   = inspectsvc.TypeMalformed
)

// corpusExpectations is the reviewed meaning of every committed fixture at the
// test clock (2026-09-14T12:00:00Z). A fixture added without an expectation
// fails TestCorpus.
var corpusExpectations = map[string]expectation{
	"root-ca.pem":                 {types: []inspectsvc.ArtifactType{cert}},
	"leaf.pem":                    {types: []inspectsvc.ArtifactType{cert}},
	"leaf.der":                    {types: []inspectsvc.ArtifactType{cert}},
	"bundle.pem":                  {types: []inspectsvc.ArtifactType{cert, cert, cert}},
	"client.pem":                  {types: []inspectsvc.ArtifactType{cert}},
	"bundle-with-bad-block.pem":   {types: []inspectsvc.ArtifactType{cert, malformed, cert}, findings: []string{"1:input.malformed_pem:critical"}},
	"bundle-with-private-key.pem": {types: []inspectsvc.ArtifactType{cert, unsupported}, findings: []string{"1:input.unsupported_format:warning"}},
	"private-key-only.pem":        {types: []inspectsvc.ArtifactType{unsupported}, findings: []string{"-1:input.no_certificates:critical", "0:input.unsupported_format:warning"}},
	"text-around.pem":             {types: []inspectsvc.ArtifactType{cert}, findings: []string{"-1:input.trailing_data:info", "-1:input.trailing_data:info"}},
	"trailing-data.der":           {types: []inspectsvc.ArtifactType{cert}, findings: []string{"-1:input.trailing_data:warning"}},
	"malformed.pem":               {types: []inspectsvc.ArtifactType{malformed}, findings: []string{"-1:input.no_certificates:critical", "0:input.malformed_pem:critical"}},
	"empty.pem":                   {findings: []string{"-1:input.empty:critical"}},
	"not-a-certificate.txt":       {findings: []string{"-1:input.unsupported_format:critical"}},
	"expired.pem":                 {types: []inspectsvc.ArtifactType{cert}, findings: []string{"0:cert.expired:critical"}},
	"not-yet-valid.pem":           {types: []inspectsvc.ArtifactType{cert}, findings: []string{"0:cert.not_yet_valid:critical"}},
	"expiring-warning.pem":        {types: []inspectsvc.ArtifactType{cert}, findings: []string{"0:cert.expiring_soon:warning"}},
	"expiring-critical.pem":       {types: []inspectsvc.ArtifactType{cert}, findings: []string{"0:cert.expiring_soon:critical"}},
	"self-signed-leaf.pem":        {types: []inspectsvc.ArtifactType{cert}, findings: []string{"0:cert.self_signed_leaf:warning"}},
	"cn-only.pem":                 {types: []inspectsvc.ArtifactType{cert}, findings: []string{"0:name.cn_only_no_san:warning"}},
	"rsa-1024.pem":                {types: []inspectsvc.ArtifactType{cert}, findings: []string{"0:key.rsa_under_2048:critical"}},
	"sha1.pem":                    {types: []inspectsvc.ArtifactType{cert}, findings: []string{"0:sig.sha1:critical"}},
	"md5.pem":                     {types: []inspectsvc.ArtifactType{cert}, findings: []string{"0:sig.md5:critical"}},
	"noncanonical-rsa-key.pem":    {types: []inspectsvc.ArtifactType{unparseable}, findings: []string{"0:input.unparseable_certificate:critical", "0:key.noncanonical_spki:warning"}},
	"x25519-key.pem":              {types: []inspectsvc.ArtifactType{cert}, findings: []string{"0:key.unsupported_for_identity:info"}},
}

func corpusFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(corpus)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && e.Name() != "README.md" {
			names = append(names, e.Name())
		}
	}
	return names
}

func findingKeys(fs []findings.Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, strings.Join([]string{itoa(f.Entry), string(f.Code), string(f.Severity)}, ":"))
	}
	return out
}

func itoa(i int) string {
	if i < 0 {
		return "-" + string(rune('0'-i))
	}
	return string(rune('0' + i))
}

func TestCorpus(t *testing.T) {
	names := corpusFiles(t)
	if len(names) != len(corpusExpectations) {
		t.Errorf("corpus has %d files, expectations cover %d", len(names), len(corpusExpectations))
	}
	svc := service()
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			want, ok := corpusExpectations[name]
			if !ok {
				t.Fatalf("no expectation for fixture %s", name)
			}
			res, err := svc.InspectFile(filepath.Join(corpus, name))
			if err != nil {
				t.Fatalf("InspectFile: %v", err)
			}

			var types []inspectsvc.ArtifactType
			for i, a := range res.Artifacts {
				if a.Entry != i {
					t.Errorf("artifact %d has entry %d", i, a.Entry)
				}
				types = append(types, a.Type)
				if (a.Type == cert) != (a.Certificate != nil && a.Summary != nil) {
					t.Errorf("artifact %d: facts and summary must exist exactly for parsed certificates", i)
				}
				if (a.Type == unparseable) != (a.Unparseable != nil) {
					t.Errorf("artifact %d: unparseable facts mismatch", i)
				}
			}
			if !slices.Equal(types, want.types) {
				t.Errorf("artifact types %v, want %v", types, want.types)
			}
			wantFindings := want.findings
			if wantFindings == nil {
				wantFindings = []string{}
			}
			if got := findingKeys(res.Findings); !slices.Equal(got, wantFindings) {
				t.Errorf("findings %v, want %v", got, wantFindings)
			}
			for _, f := range res.Findings {
				if _, ok := findings.Describe(f.Code); !ok {
					t.Errorf("uncatalogued code %s", f.Code)
				}
			}
			if res.InternalErrors != 0 {
				t.Errorf("recovered %d internal errors", res.InternalErrors)
			}

			again, err := svc.InspectFile(filepath.Join(corpus, name))
			if err != nil || !reflect.DeepEqual(res, again) {
				t.Error("inspection is not deterministic")
			}
		})
	}
}

func TestResultMetadata(t *testing.T) {
	path := filepath.Join(corpus, "bundle-with-bad-block.pem")
	res, err := service().InspectFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if res.Source.Kind != inspectsvc.SourceFile || res.Source.Locator != path || res.Size != len(data) {
		t.Errorf("source %+v size %d", res.Source, res.Size)
	}
	if res.Format != artifact.FormatPEM || !res.InspectedAt.Equal(testpki.Now) {
		t.Errorf("format %s inspected at %s", res.Format, res.InspectedAt)
	}
	if res.Highest != findings.SeverityCritical {
		t.Errorf("highest severity %s", res.Highest)
	}

	clean, err := service().InspectFile(filepath.Join(corpus, "leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if clean.Highest != "" || len(clean.Findings) != 0 {
		t.Errorf("clean certificate: highest %q findings %v", clean.Highest, clean.Findings)
	}
}

// TestFindingsOrder: whole-input findings first, then by entry, then by
// descending severity, then by code.
func TestFindingsOrder(t *testing.T) {
	res, err := service().InspectBytes(inspectsvc.Source{Kind: inspectsvc.SourceStdin, Locator: "-"},
		append([]byte("leading text\n"), mustRead(t, "rsa-1024.pem")...))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-1:input.trailing_data:info", "0:key.rsa_under_2048:critical"}
	if got := findingKeys(res.Findings); !slices.Equal(got, want) {
		t.Errorf("order %v, want %v", got, want)
	}
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(corpus, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReaderMatchesFile(t *testing.T) {
	path := filepath.Join(corpus, "bundle.pem")
	fromFile, err := service().InspectFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fromStdin, err := service().InspectReader(inspectsvc.Source{Kind: inspectsvc.SourceStdin, Locator: "-"}, bytes.NewReader(mustRead(t, "bundle.pem")))
	if err != nil {
		t.Fatal(err)
	}
	if fromStdin.Source.Kind != inspectsvc.SourceStdin {
		t.Errorf("source %+v", fromStdin.Source)
	}
	fromStdin.Source = fromFile.Source
	if !reflect.DeepEqual(fromFile, fromStdin) {
		t.Error("stdin and file inspection of the same bytes differ")
	}
}

func TestClockIsInjected(t *testing.T) {
	later := inspectsvc.New(func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) })
	res, err := later.InspectFile(filepath.Join(corpus, "leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if got := findingKeys(res.Findings); !slices.Equal(got, []string{"0:cert.expired:critical"}) {
		t.Errorf("findings %v", got)
	}
}

func TestInspectFileErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := service().InspectFile(filepath.Join(dir, "missing.pem")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	if _, err := service().InspectFile(dir); err == nil {
		t.Error("a directory must be rejected")
	}
	big := filepath.Join(dir, "big.pem")
	if err := os.WriteFile(big, make([]byte, artifact.MaxInputBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service().InspectFile(big); !errors.Is(err, artifact.ErrTooLarge) {
		t.Errorf("oversized file: %v", err)
	}
	if _, err := service().InspectReader(inspectsvc.Source{Kind: inspectsvc.SourceStdin, Locator: "-"},
		bytes.NewReader(make([]byte, artifact.MaxInputBytes+1))); !errors.Is(err, artifact.ErrTooLarge) {
		t.Errorf("oversized stdin: %v", err)
	}
}

// FuzzInspectBytes drives the whole pipeline. Besides not panicking, it fails
// if the service had to recover from a panic internally, so a recovered bug
// cannot hide from fuzzing.
func FuzzInspectBytes(f *testing.F) {
	entries, err := os.ReadDir(corpus)
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range entries {
		if b, err := os.ReadFile(filepath.Join(corpus, e.Name())); err == nil && e.Name() != "README.md" {
			f.Add(b)
		}
	}
	svc := service()
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := svc.InspectBytes(inspectsvc.Source{Kind: inspectsvc.SourceStdin, Locator: "-"}, data)
		if err != nil {
			if !errors.Is(err, artifact.ErrTooLarge) && !errors.Is(err, artifact.ErrTooManyBlocks) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		if res.InternalErrors != 0 {
			t.Fatalf("pipeline recovered from %d panics", res.InternalErrors)
		}
		for _, f := range res.Findings {
			if _, ok := findings.Describe(f.Code); !ok {
				t.Fatalf("uncatalogued code %s", f.Code)
			}
		}
	})
}
