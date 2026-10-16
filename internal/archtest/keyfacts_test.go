package archtest

import (
	"go/ast"
	"strings"
	"testing"
)

// privateKeyParsers decode private keys. Production code may call them only
// in keyfacts, which reduces a key to its public identity for `match`
// (ADR-0013), and in issuance, which loads the local CA's own key (ADR-0012).
var privateKeyParsers = map[string]bool{"ParsePKCS8PrivateKey": true, "ParsePKCS1PrivateKey": true, "ParseECPrivateKey": true}

var privateKeyPackages = []string{"internal/keyfacts/", "internal/issuance/", "internal/testpki/"}

func TestPrivateKeysDecodedOnlyWhereDocumented(t *testing.T) {
	for _, f := range goFiles(t) {
		if f.test {
			continue
		}
		allowed := false
		for _, p := range privateKeyPackages {
			allowed = allowed || strings.HasPrefix(f.rel, p)
		}
		if allowed {
			continue
		}
		ast.Inspect(f.file, func(n ast.Node) bool {
			if e, ok := n.(ast.Expr); ok {
				if name, ok := f.x509Selector(e); ok && privateKeyParsers[name] {
					t.Errorf("%s: x509.%s outside the packages that may decode private keys", f.fset.Position(n.Pos()), name)
				}
			}
			return true
		})
	}
}
