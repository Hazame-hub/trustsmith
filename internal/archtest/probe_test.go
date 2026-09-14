package archtest

import (
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// probePackage is the only package that opens network connections and
// speaks TLS. It acquires certificates for diagnostics; every certificate
// decision is made elsewhere (ADR-0009).
const probePackage = "internal/probe/"

// requiredTLSConfig must be set explicitly in the probe's client
// configuration, so no crypto/tls default decides what a probe offers.
var requiredTLSConfig = []string{
	"ServerName", "InsecureSkipVerify", "MinVersion", "MaxVersion", "CipherSuites", "CurvePreferences",
	"Renegotiation", "ClientSessionCache", "SessionTicketsDisabled", "NextProtos", "Time", "GetClientCertificate",
}

// forbiddenTLSConfig must never be set by the probe: the handshake neither
// validates trust nor host names, uses no roots, and logs no secrets.
var forbiddenTLSConfig = []string{"RootCAs", "VerifyPeerCertificate", "VerifyConnection", "KeyLogWriter", "Certificates", "GetCertificate"}

func (f goFile) selector(e ast.Expr, importPath string) (string, bool) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || f.imports[id.Name] != importPath {
		return "", false
	}
	return sel.Sel.Name, true
}

func TestTLSOnlyInProbePackage(t *testing.T) {
	for _, f := range goFiles(t) {
		if f.test || strings.HasPrefix(f.rel, probePackage) {
			continue
		}
		for _, imp := range f.imports {
			if imp == "crypto/tls" {
				t.Errorf("%s imports crypto/tls; TLS connections belong to %s", f.rel, probePackage)
			}
		}
	}
}

// TestInsecureSkipVerifyOnlyInProbe: skipping verification is confined to the
// diagnostic acquisition package, tests included.
func TestInsecureSkipVerifyOnlyInProbe(t *testing.T) {
	found := 0
	for _, f := range goFiles(t) {
		ast.Inspect(f.file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || id.Name != "InsecureSkipVerify" {
				return true
			}
			if !strings.HasPrefix(f.rel, probePackage) {
				t.Errorf("%s: InsecureSkipVerify outside %s", f.fset.Position(id.Pos()), probePackage)
			} else if !f.test {
				found++
			}
			return true
		})
	}
	if found == 0 {
		t.Error("no InsecureSkipVerify found in the probe package; this test would check nothing")
	}
}

// TestProbeClientConfig checks the single tls.Config literal of the probe.
func TestProbeClientConfig(t *testing.T) {
	literals := 0
	for _, f := range goFiles(t) {
		if f.test || !strings.HasPrefix(f.rel, probePackage) {
			continue
		}
		ast.Inspect(f.file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if name, ok := f.selector(lit.Type, "crypto/tls"); !ok || name != "Config" {
				return true
			}
			literals++
			set := map[string]ast.Expr{}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					t.Errorf("%s: tls.Config must use keyed fields", f.fset.Position(elt.Pos()))
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok {
					set[key.Name] = kv.Value
				}
			}
			for _, name := range requiredTLSConfig {
				if _, ok := set[name]; !ok {
					t.Errorf("%s: tls.Config.%s must be set explicitly", f.fset.Position(lit.Pos()), name)
				}
			}
			for _, name := range forbiddenTLSConfig {
				if _, ok := set[name]; ok {
					t.Errorf("%s: tls.Config.%s must not be set by the probe", f.fset.Position(lit.Pos()), name)
				}
			}
			if v, ok := set["InsecureSkipVerify"].(*ast.Ident); !ok || v.Name != "true" {
				t.Errorf("%s: InsecureSkipVerify must be the literal true: acquisition never verifies", f.fset.Position(lit.Pos()))
			}
			return true
		})
	}
	if literals != 1 {
		t.Errorf("the probe must build exactly one tls.Config literal, found %d", literals)
	}
}

// TestProbeDependsOnNoOtherTrustsmithPackage keeps acquisition separate from
// every evaluation layer: composition happens in the application service.
func TestProbeDependsOnNoOtherTrustsmithPackage(t *testing.T) {
	p, ok := modulePackages(t)[module+"/internal/probe"]
	if !ok {
		t.Fatal("internal/probe not found")
	}
	for _, dep := range p.Deps {
		if strings.HasPrefix(dep, module+"/") {
			t.Errorf("internal/probe depends on %s", dep)
		}
	}
}

// TestNetworkDialOnlyInProbe: no other production code opens connections.
func TestNetworkDialOnlyInProbe(t *testing.T) {
	dialers := map[string]bool{"Dial": true, "DialTimeout": true, "Dialer": true, "DialTCP": true, "DialIP": true, "DialUDP": true, "Listen": true, "ListenTCP": true, "ListenPacket": true}
	for _, f := range goFiles(t) {
		if f.test || strings.HasPrefix(f.rel, probePackage) {
			continue
		}
		ast.Inspect(f.file, func(n ast.Node) bool {
			if e, ok := n.(ast.Expr); ok {
				if name, ok := f.selector(e, "net"); ok && dialers[name] {
					t.Errorf("%s: net.%s outside %s", f.fset.Position(n.Pos()), name, probePackage)
				}
			}
			return true
		})
	}
}

// TestNoHTTP: Trustsmith speaks no application protocol, in code or tests.
func TestNoHTTP(t *testing.T) {
	for _, f := range goFiles(t) {
		for _, imp := range f.imports {
			if imp == "net/http" || strings.HasPrefix(imp, "net/http/") {
				t.Errorf("%s imports %s", f.rel, imp)
			}
		}
	}
	for name, p := range modulePackages(t) {
		if slices.Contains(p.Deps, "net/http") {
			t.Errorf("%s depends on net/http", name)
		}
	}
}

// TestNoGODEBUG: no behaviour is changed through GODEBUG, neither by a go.mod
// godebug block, a //go:debug directive nor a GODEBUG setting in code.
func TestNoGODEBUG(t *testing.T) {
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(mod), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "godebug") {
			t.Errorf("go.mod has a godebug directive: %s", line)
		}
	}
	for _, f := range goFiles(t) {
		for _, group := range f.file.Comments {
			for _, c := range group.List {
				if strings.HasPrefix(c.Text, "//go:debug") {
					t.Errorf("%s: %s", f.fset.Position(c.Pos()), c.Text)
				}
			}
		}
		ast.Inspect(f.file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING || f.rel == "internal/archtest/probe_test.go" {
				return true
			}
			if s, err := strconv.Unquote(lit.Value); err == nil && strings.Contains(s, "GODEBUG") {
				t.Errorf("%s: a GODEBUG string literal", f.fset.Position(lit.Pos()))
			}
			return true
		})
	}
}
