package findings_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/findings"
)

// declaredCodes returns every constant of type Code declared in codes.go, by
// reading the source. That way a constant that is emitted but has no catalog
// entry cannot hide from the tests.
func declaredCodes(t *testing.T) map[string]findings.Code {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "codes.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]findings.Code{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Code" {
				t.Fatalf("codes.go: constant %s must be declared with explicit type Code", vs.Names[0].Name)
			}
			for i, name := range vs.Names {
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("codes.go: %s must be a string literal", name.Name)
				}
				out[name.Name] = findings.Code(strings.Trim(lit.Value, `"`))
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("codes.go declares no codes")
	}
	return out
}

var codeFormat = regexp.MustCompile(`^[a-z]+\.[a-z0-9]+(_[a-z0-9]+)*$`)

func TestEveryDeclaredCodeIsCatalogued(t *testing.T) {
	seen := map[findings.Code]string{}
	for name, code := range declaredCodes(t) {
		if prev, dup := seen[code]; dup {
			t.Errorf("%s and %s share code %q", prev, name, code)
		}
		seen[code] = name
		if !codeFormat.MatchString(string(code)) {
			t.Errorf("%s = %q is not a dotted lowercase code", name, code)
		}
		d, ok := findings.Describe(code)
		if !ok {
			t.Errorf("%s (%q) has no catalog entry", name, code)
			continue
		}
		if d.Title == "" || d.Explanation == "" {
			t.Errorf("%q: title and explanation are required", code)
		}
		for _, a := range d.Remediation {
			if a.Code == "" || a.Text == "" {
				t.Errorf("%q: remediation actions need a code and text", code)
			}
		}
	}
	if len(findings.Codes()) != len(seen) {
		t.Errorf("catalog has %d codes, codes.go declares %d — the catalog has orphans", len(findings.Codes()), len(seen))
	}
}

func TestCodesAreSorted(t *testing.T) {
	codes := findings.Codes()
	if !slices.IsSorted(codes) {
		t.Errorf("Codes() must be sorted: %v", codes)
	}
}

// TestStableCodesGolden makes finding codes an append-only contract. New
// codes are recorded with UPDATE_GOLDEN=1; a removed or renamed code fails
// even then, because scripts and future exports depend on the names.
func TestStableCodesGolden(t *testing.T) {
	path := filepath.Join("testdata", "codes.golden")
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var golden []string
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			golden = append(golden, line)
		}
	}
	current := map[string]bool{}
	var currentList []string
	for _, c := range findings.Codes() {
		current[string(c)] = true
		currentList = append(currentList, string(c))
	}
	for _, g := range golden {
		if !current[g] {
			t.Errorf("finding code %q was removed or renamed; codes are a stable contract. "+
				"Removing one is an intentional compatibility change: edit %s by hand and record it in docs/adr/0003-findings.md", g, path)
		}
	}
	if t.Failed() {
		return
	}
	if slices.Equal(golden, currentList) {
		return
	}
	if os.Getenv("UPDATE_GOLDEN") != "1" {
		t.Fatalf("new finding codes are not recorded in %s; run with UPDATE_GOLDEN=1", path)
	}
	content := "# Stable finding codes (append-only; see docs/adr/0003-findings.md).\n" + strings.Join(currentList, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSeverity(t *testing.T) {
	order := []findings.Severity{findings.SeverityInfo, findings.SeverityWarning, findings.SeverityCritical}
	for i, a := range order {
		for j, b := range order {
			if got, want := a.AtLeast(b), i >= j; got != want {
				t.Errorf("%s.AtLeast(%s) = %v, want %v", a, b, got, want)
			}
		}
		parsed, err := findings.ParseSeverity(string(a))
		if err != nil || parsed != a {
			t.Errorf("ParseSeverity(%q) = %q, %v", a, parsed, err)
		}
	}
	for _, bad := range []string{"", "error", "CRITICAL", "never"} {
		if _, err := findings.ParseSeverity(bad); err == nil {
			t.Errorf("ParseSeverity(%q) must fail", bad)
		}
	}
}

func TestUnknownCodeIsNotDescribed(t *testing.T) {
	if _, ok := findings.Describe("no.such_code"); ok {
		t.Error("Describe must report unknown codes")
	}
}
