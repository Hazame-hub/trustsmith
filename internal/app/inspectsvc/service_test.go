package inspectsvc_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
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
	types         []inspectsvc.ArtifactType
	findings      []string // "entry:code:severity", entry -1 for the whole input
	relationships []string // "[child entries]->[candidate entries]:state"
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
	"bundle.pem":                  {types: []inspectsvc.ArtifactType{cert, cert, cert}, relationships: []string{"[0]->[1]:verified", "[1]->[2]:verified"}},
	"client.pem":                  {types: []inspectsvc.ArtifactType{cert}},
	"bundle-with-bad-block.pem":   {types: []inspectsvc.ArtifactType{cert, malformed, cert}, findings: []string{"1:input.malformed_pem:critical"}, relationships: []string{"[0]->[2]:verified"}},
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

	// Issuer relationships inside one input.
	"bundle-reversed.pem":               {types: []inspectsvc.ArtifactType{cert, cert, cert}, relationships: []string{"[1]->[0]:verified", "[2]->[1]:verified"}},
	"bundle-duplicate.pem":              {types: []inspectsvc.ArtifactType{cert, cert, cert}, relationships: []string{"[0 2]->[1]:verified"}},
	"issuer-name-match-wrong-key.pem":   {types: []inspectsvc.ArtifactType{cert, cert}, relationships: []string{"[0]->[1]:invalid"}},
	"issuer-key-id-match-wrong-key.pem": {types: []inspectsvc.ArtifactType{cert, cert}, relationships: []string{"[0]->[1]:invalid"}},
	"sha1-with-issuer.pem":              {types: []inspectsvc.ArtifactType{cert, cert}, findings: []string{"0:sig.sha1:critical"}, relationships: []string{"[0]->[1]:verified"}},
	"md5-with-issuer.pem":               {types: []inspectsvc.ArtifactType{cert, cert}, findings: []string{"0:sig.md5:critical", "0:issuer.candidate_unverifiable:info"}, relationships: []string{"[0]->[1]:unverifiable"}},
	"self-issued-not-self-signed.pem":   {types: []inspectsvc.ArtifactType{cert}},
	"reissued-intermediates.pem":        {types: []inspectsvc.ArtifactType{cert, cert, cert}, relationships: []string{"[0]->[1]:verified", "[0]->[2]:verified"}},
}

// relationshipKeys renders relationships as "[child entries]->[candidate entries]:state".
func relationshipKeys(res inspectsvc.Result) []string {
	join := func(v []int) string {
		parts := make([]string, len(v))
		for i, n := range v {
			parts[i] = strconv.Itoa(n)
		}
		return "[" + strings.Join(parts, " ") + "]"
	}
	out := []string{}
	for _, r := range res.Relationships {
		out = append(out, join(r.ChildEntries)+"->"+join(r.CandidateEntries)+":"+string(r.State))
	}
	return out
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
		out = append(out, strings.Join([]string{strconv.Itoa(f.Entry), string(f.Code), string(f.Severity)}, ":"))
	}
	return out
}

// TestPEMAndDERShareIdentity proves, end to end, that the same certificate in
// PEM and DER form yields the same fingerprints and the same interpretation.
func TestPEMAndDERShareIdentity(t *testing.T) {
	svc := service()
	fromPEM, err := svc.InspectFile(filepath.Join(corpus, "leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}
	fromDER, err := svc.InspectFile(filepath.Join(corpus, "leaf.der"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fromPEM.Artifacts) != 1 || len(fromDER.Artifacts) != 1 {
		t.Fatalf("want one artifact each, got %d and %d", len(fromPEM.Artifacts), len(fromDER.Artifacts))
	}
	p, d := fromPEM.Artifacts[0], fromDER.Artifacts[0]
	if p.Certificate == nil || d.Certificate == nil {
		t.Fatal("both inputs must parse as certificates")
	}
	if p.Certificate.Fingerprint != d.Certificate.Fingerprint {
		t.Errorf("x509-cert-sha256 differs: %s vs %s", p.Certificate.Fingerprint, d.Certificate.Fingerprint)
	}
	if p.Certificate.KeyID != d.Certificate.KeyID || p.Certificate.EncodedSPKI != d.Certificate.EncodedSPKI {
		t.Error("key fingerprints differ between PEM and DER")
	}
	if !reflect.DeepEqual(p.Summary, d.Summary) || !reflect.DeepEqual(fromPEM.Findings, fromDER.Findings) {
		t.Error("interpretation differs between PEM and DER")
	}
	if fromPEM.Format != artifact.FormatPEM || fromDER.Format != artifact.FormatDER {
		t.Errorf("formats %s / %s", fromPEM.Format, fromDER.Format)
	}
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
			wantRelationships := want.relationships
			if wantRelationships == nil {
				wantRelationships = []string{}
			}
			if got := relationshipKeys(res); !slices.Equal(got, wantRelationships) {
				t.Errorf("relationships %v, want %v", got, wantRelationships)
			}
			for _, f := range res.Findings {
				if _, ok := findings.Describe(f.Code); !ok {
					t.Errorf("uncatalogued code %s", f.Code)
				}
			}
			if res.RecoveredPanics != 0 {
				t.Errorf("recovered %d internal errors", res.RecoveredPanics)
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
		if res.RecoveredPanics != 0 {
			t.Fatalf("pipeline recovered from %d panics", res.RecoveredPanics)
		}
		for _, f := range res.Findings {
			if _, ok := findings.Describe(f.Code); !ok {
				t.Fatalf("uncatalogued code %s", f.Code)
			}
		}
	})
}
