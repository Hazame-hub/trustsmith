package archtest

import (
	"go/ast"
	"slices"
	"strings"
	"testing"
)

// issuancePackage is the only production package that creates certificates
// or generates and encodes private keys (ADR-0012). Tests and the test
// certificate builder may too.
const issuancePackage = "internal/issuance/"

// keyStorePackage is the only production package that writes CA and issued
// keys to disk (ADR-0012).
const keyStorePackage = "internal/app/casvc/"

// issuanceIdents are crypto identifiers confined to issuancePackage.
var issuanceIdents = map[string]map[string]bool{
	"crypto/x509":    {"CreateCertificate": true, "MarshalPKCS8PrivateKey": true, "MarshalECPrivateKey": true, "MarshalPKCS1PrivateKey": true},
	"crypto/ecdsa":   {"GenerateKey": true},
	"crypto/rsa":     {"GenerateKey": true},
	"crypto/ed25519": {"GenerateKey": true},
}

func TestIssuanceOnlyInIssuancePackage(t *testing.T) {
	for _, f := range goFiles(t) {
		if f.test || strings.HasPrefix(f.rel, issuancePackage) || strings.HasPrefix(f.rel, "internal/testpki/") {
			continue
		}
		ast.Inspect(f.file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if issuanceIdents[f.imports[id.Name]][sel.Sel.Name] {
				t.Errorf("%s: %s.%s outside %s; certificates and keys are created in one package", f.fset.Position(n.Pos()), id.Name, sel.Sel.Name, issuancePackage)
			}
			return true
		})
	}
}

// The issuance package is pure apart from the IP address types of package
// net: no filesystem, processes, network I/O or interface layer.
func TestIssuanceStaysPure(t *testing.T) {
	p := modulePackages(t)[module+"/internal/issuance"]
	if p.ImportPath == "" {
		t.Fatal("internal/issuance no longer exists; update archtest")
	}
	for _, imp := range p.Imports {
		if imp != "net" && slices.Contains(forbiddenDirectImports, imp) {
			t.Errorf("internal/issuance imports %s; it takes keys, times and randomness as inputs", imp)
		}
		if strings.HasPrefix(imp, module+"/") {
			t.Errorf("internal/issuance imports %s; it depends on no other Trustsmith package", imp)
		}
	}
}

// Only the key store opens files for writing in production code, so a
// private key can reach disk in one audited place.
func TestOnlyKeyStoreWritesFiles(t *testing.T) {
	writers := map[string]bool{"OpenFile": true, "WriteFile": true, "Create": true}
	for _, f := range goFiles(t) {
		if f.test || strings.HasPrefix(f.rel, keyStorePackage) || strings.HasPrefix(f.rel, "internal/testpki/") {
			continue
		}
		ast.Inspect(f.file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && f.imports[id.Name] == "os" && writers[sel.Sel.Name] {
				t.Errorf("%s: os.%s outside %s; only the key store writes files", f.fset.Position(n.Pos()), sel.Sel.Name, keyStorePackage)
			}
			return true
		})
	}
}
