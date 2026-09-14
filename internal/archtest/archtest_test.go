package archtest

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const module = "github.com/Hazame-hub/trustsmith"

var root = filepath.Join("..", "..")

// domain packages describe and interpret certificates. They take bytes and
// times as inputs and must not reach the filesystem, network, processes,
// databases or any interface layer.
var domain = []string{
	module + "/internal/fingerprint",
	module + "/internal/artifact",
	module + "/internal/x509facts",
	module + "/internal/findings",
	module + "/internal/interpret",
	module + "/internal/sigcheck",
	module + "/internal/issuerlinks",
	module + "/internal/chainpath",
	module + "/internal/trustverify",
	module + "/internal/purpose",
}

// forbiddenDirectImports are standard-library packages domain code must not
// import itself (crypto/x509 may use some of them internally; that is fine).
var forbiddenDirectImports = []string{"os", "os/exec", "net", "net/http", "database/sql", "syscall", "io/fs"}

// allowedModules is every third-party module the build may compile. Adding a
// module is a deliberate, reviewed change: it is how SQLite, UI frameworks or
// other out-of-scope dependencies are kept from leaking into a slice.
var allowedModules = []string{
	"golang.org/x/crypto",
	"github.com/spf13/cobra",
	"github.com/spf13/pflag",
	"github.com/inconshreveable/mousetrap",
}

type pkg struct {
	ImportPath string
	Standard   bool
	Imports    []string
	Deps       []string
	Module     *struct{ Path string }
}

func goList(t *testing.T, args ...string) []pkg {
	t.Helper()
	return goListFor(t, "", args...)
}

// goListFor runs go list for a target operating system ("" means the host).
func goListFor(t *testing.T, goos string, args ...string) []pkg {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list", "-json"}, args...)...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if goos != "" {
		cmd.Env = append(cmd.Env, "GOOS="+goos)
	}
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("go list: %v\n%s", err, exitErr.Stderr)
		}
		t.Fatalf("go list: %v", err)
	}
	var pkgs []pkg
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for {
		var p pkg
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func modulePackages(t *testing.T) map[string]pkg {
	t.Helper()
	out := map[string]pkg{}
	for _, p := range goList(t, "./...") {
		out[p.ImportPath] = p
	}
	for _, d := range domain {
		if _, ok := out[d]; !ok {
			t.Fatalf("domain package %s no longer exists; update archtest", d)
		}
	}
	return out
}

func TestDomainPackagesStayPure(t *testing.T) {
	pkgs := modulePackages(t)
	for _, name := range domain {
		p := pkgs[name]
		for _, imp := range p.Imports {
			if slices.Contains(forbiddenDirectImports, imp) {
				t.Errorf("%s imports %s; domain code takes bytes and times as inputs", name, imp)
			}
		}
		for _, dep := range p.Deps {
			switch {
			case dep == "github.com/spf13/cobra",
				strings.HasPrefix(dep, module+"/internal/cli"),
				strings.HasPrefix(dep, module+"/internal/app/"),
				strings.HasPrefix(dep, module+"/internal/testpki"),
				strings.HasPrefix(dep, module+"/cmd/"):
				t.Errorf("%s depends on %s", name, dep)
			}
		}
	}
}

func TestApplicationServicesDoNotDependOnInterfaces(t *testing.T) {
	for name, p := range modulePackages(t) {
		if !strings.HasPrefix(name, module+"/internal/app/") {
			continue
		}
		for _, dep := range p.Deps {
			if dep == "github.com/spf13/cobra" || strings.HasPrefix(dep, module+"/internal/cli") || strings.HasPrefix(dep, module+"/cmd/") {
				t.Errorf("%s depends on %s", name, dep)
			}
		}
	}
}

func TestProductionCodeDoesNotUseTestPKI(t *testing.T) {
	for name, p := range modulePackages(t) {
		if strings.HasPrefix(name, module+"/internal/testpki") || name == module+"/internal/archtest" {
			continue
		}
		if slices.ContainsFunc(p.Deps, func(d string) bool { return strings.HasPrefix(d, module+"/internal/testpki") }) {
			t.Errorf("%s depends on internal/testpki", name)
		}
	}
}

// releasePlatforms are the operating systems Trustsmith is built for. Module
// usage is collected across all of them: some dependencies are compiled only
// on one platform (cobra uses mousetrap on Windows only), so checking just the
// host would wrongly report them as unused elsewhere.
var releasePlatforms = []string{"linux", "darwin", "windows"}

func TestThirdPartyModulesAreAllowListed(t *testing.T) {
	seen := map[string]bool{}
	for _, goos := range releasePlatforms {
		for _, p := range goListFor(t, goos, "-deps", "./...") {
			if p.Standard || p.Module == nil || p.Module.Path == module {
				continue
			}
			seen[p.Module.Path] = true
		}
	}
	for m := range seen {
		if !slices.Contains(allowedModules, m) {
			t.Errorf("module %s is compiled into the build but not allow-listed", m)
		}
	}
	for _, m := range allowedModules {
		if !seen[m] {
			t.Errorf("allow-listed module %s is no longer used; remove it from the list", m)
		}
	}
}

// TestOnlyCmdReadsTheClock enforces clock injection: nothing under internal/
// may refer to time.Now.
func TestOnlyCmdReadsTheClock(t *testing.T) {
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		timeName := ""
		for _, imp := range file.Imports {
			if strings.Trim(imp.Path.Value, `"`) == "time" {
				timeName = "time"
				if imp.Name != nil {
					timeName = imp.Name.Name
				}
			}
		}
		if timeName == "" {
			return nil
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == timeName && sel.Sel.Name == "Now" {
					t.Errorf("%s refers to time.Now; take the time as an input (only cmd/ wires the real clock)", path)
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
