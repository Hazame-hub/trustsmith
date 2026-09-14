package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// explicitTrustPackage is the only package allowed to use the standard
// verifier, and only with trust anchors the user supplied explicitly
// (ADR-0006). Anywhere else, a VerifyOptions.Roots would turn certificates
// into trust anchors implicitly.
const explicitTrustPackage = "internal/trustverify/"

// verifierIdents may appear only in explicitTrustPackage.
var verifierIdents = map[string]bool{"VerifyOptions": true, "CertPool": true, "NewCertPool": true}

// systemTrustIdents are forbidden everywhere, tests included: Trustsmith never
// consults the system or platform trust store in this version.
var systemTrustIdents = map[string]bool{"SystemCertPool": true, "SetFallbackRoots": true}

// requiredVerifyOptions must be set explicitly at every Verify call site, so
// no Go default (system roots, server-auth key usage, system clock) applies.
var requiredVerifyOptions = []string{"Roots", "Intermediates", "CurrentTime", "KeyUsages", "MaxConstraintComparisions"}

type goFile struct {
	rel     string // slash-separated, relative to the repository root
	fset    *token.FileSet
	file    *ast.File
	imports map[string]string // local name -> import path
	test    bool
}

func goFiles(t *testing.T) []goFile {
	t.Helper()
	var files []goFile
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == "testdata" {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			gf := goFile{rel: filepath.ToSlash(rel), fset: fset, file: file, imports: map[string]string{}, test: strings.HasSuffix(path, "_test.go")}
			for _, imp := range file.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				name := p[strings.LastIndex(p, "/")+1:]
				if imp.Name != nil {
					name = imp.Name.Name
				}
				gf.imports[name] = p
			}
			files = append(files, gf)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return files
}

// x509Selector reports the identifier name when e is <crypto/x509>.<name>.
func (f goFile) x509Selector(e ast.Expr) (string, bool) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || f.imports[id.Name] != "crypto/x509" {
		return "", false
	}
	return sel.Sel.Name, true
}

// isMethodVerify reports a call of a method named Verify (not a package
// function such as ed25519.Verify).
func (f goFile) isMethodVerify(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Verify" {
		return false
	}
	if id, ok := sel.X.(*ast.Ident); ok {
		if _, isPackage := f.imports[id.Name]; isPackage {
			return false
		}
	}
	return true
}

func TestSystemTrustIsNeverUsed(t *testing.T) {
	for _, f := range goFiles(t) {
		ast.Inspect(f.file, func(n ast.Node) bool {
			if e, ok := n.(ast.Expr); ok {
				if name, ok := f.x509Selector(e); ok && systemTrustIdents[name] {
					t.Errorf("%s: x509.%s consults the system trust store", f.fset.Position(n.Pos()), name)
				}
			}
			return true
		})
	}
}

func TestStandardVerifierOnlyInExplicitTrustPackage(t *testing.T) {
	verifyCalls := 0
	for _, f := range goFiles(t) {
		inTrust := strings.HasPrefix(f.rel, explicitTrustPackage)
		checkedLiterals := map[*ast.CompositeLit]bool{}
		ast.Inspect(f.file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				if !f.isMethodVerify(n) {
					return true
				}
				if !inTrust {
					t.Errorf("%s: a Verify call outside %s; certificates are validated only against explicitly supplied anchors, in one package", f.fset.Position(n.Pos()), explicitTrustPackage)
					return true
				}
				if f.test {
					return true // tests may build controls, e.g. Go's default key usage
				}
				verifyCalls++
				lit := verifyOptionsLiteral(f, n)
				if lit == nil {
					t.Errorf("%s: Verify must be called with an x509.VerifyOptions literal built at the call site", f.fset.Position(n.Pos()))
					return true
				}
				checkedLiterals[lit] = true
				checkVerifyOptions(t, f, lit)
			case *ast.SelectorExpr:
				if name, ok := f.x509Selector(n); ok && verifierIdents[name] && !inTrust {
					t.Errorf("%s: x509.%s outside %s", f.fset.Position(n.Pos()), name, explicitTrustPackage)
				}
			}
			return true
		})
		if inTrust && !f.test {
			ast.Inspect(f.file, func(n ast.Node) bool {
				if lit, ok := n.(*ast.CompositeLit); ok {
					if name, ok := f.x509Selector(lit.Type); ok && name == "VerifyOptions" && !checkedLiterals[lit] {
						t.Errorf("%s: an x509.VerifyOptions literal not passed directly to Verify", f.fset.Position(lit.Pos()))
					}
				}
				return true
			})
		}
	}
	if verifyCalls == 0 {
		t.Errorf("no Verify call found in %s; this test would check nothing", explicitTrustPackage)
	}
}

func verifyOptionsLiteral(f goFile, call *ast.CallExpr) *ast.CompositeLit {
	if len(call.Args) != 1 {
		return nil
	}
	lit, ok := call.Args[0].(*ast.CompositeLit)
	if !ok {
		return nil
	}
	if name, ok := f.x509Selector(lit.Type); !ok || name != "VerifyOptions" {
		return nil
	}
	return lit
}

func checkVerifyOptions(t *testing.T, f goFile, lit *ast.CompositeLit) {
	t.Helper()
	set := map[string]ast.Expr{}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			t.Errorf("%s: VerifyOptions must use keyed fields", f.fset.Position(elt.Pos()))
			continue
		}
		if key, ok := kv.Key.(*ast.Ident); ok {
			set[key.Name] = kv.Value
		}
	}
	for _, name := range requiredVerifyOptions {
		v, ok := set[name]
		switch {
		case !ok:
			t.Errorf("%s: VerifyOptions.%s must be set explicitly", f.fset.Position(lit.Pos()), name)
		case isNil(v):
			t.Errorf("%s: VerifyOptions.%s must not be nil (nil Roots means the system trust store, nil KeyUsages means server authentication)", f.fset.Position(v.Pos()), name)
		}
	}
	for _, forbidden := range []string{"DNSName"} {
		if _, ok := set[forbidden]; ok {
			t.Errorf("%s: VerifyOptions.%s is not used by generic inspection", f.fset.Position(lit.Pos()), forbidden)
		}
	}
	if !slices.Contains(requiredVerifyOptions, "Roots") {
		t.Fatal("Roots must stay required")
	}
}

func isNil(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "nil"
}
