package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenX509 are crypto/x509 identifiers that declare certificates trusted
// or consult system trust. Supplying included certificates as
// VerifyOptions.Roots would make them trust anchors; trust anchors are a later,
// explicit decision and must not enter through the standard verifier.
var forbiddenX509 = map[string]bool{
	"VerifyOptions":  true,
	"CertPool":       true,
	"NewCertPool":    true,
	"SystemCertPool": true,
}

func TestNoImplicitTrustThroughTheStandardVerifier(t *testing.T) {
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == "testdata" {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			x509Name := ""
			for _, imp := range file.Imports {
				if strings.Trim(imp.Path.Value, `"`) == "crypto/x509" {
					x509Name = "x509"
					if imp.Name != nil {
						x509Name = imp.Name.Name
					}
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.SelectorExpr:
					if id, ok := n.X.(*ast.Ident); ok && x509Name != "" && id.Name == x509Name && forbiddenX509[n.Sel.Name] {
						t.Errorf("%s: x509.%s would bring trust anchors in implicitly", fset.Position(n.Pos()), n.Sel.Name)
					}
				case *ast.CallExpr:
					if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Verify" {
						t.Errorf("%s: a Verify call is not allowed in production code; signatures are checked with sigcheck, and trust is never implied", fset.Position(n.Pos()))
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
