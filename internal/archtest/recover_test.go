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

// recoverBoundaries are the only files allowed to call recover(): the
// standard-library X.509 parser boundary and the signature-verification
// engine boundary, both of which process attacker-controlled bytes. A panic
// anywhere else — interpretation, relationship resolution, rendering,
// application logic — is a Trustsmith bug and must not be converted into a
// finding about the input.
var recoverBoundaries = map[string]bool{
	"internal/x509facts/x509facts.go": true,
	"internal/sigcheck/sigcheck.go":   true,
}

func TestRecoverOnlyAtUntrustedInputBoundaries(t *testing.T) {
	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "recover" {
				if !recoverBoundaries[rel] {
					t.Errorf("%s: recover() outside the untrusted-input boundaries", fset.Position(call.Pos()))
				}
				found[rel] = true
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for f := range recoverBoundaries {
		if !found[f] {
			t.Errorf("%s no longer recovers; update recoverBoundaries", f)
		}
	}
}
