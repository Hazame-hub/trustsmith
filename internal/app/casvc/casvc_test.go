package casvc_test

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/app/casvc"
	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/issuance"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
)

func service() *casvc.Service {
	return casvc.New(func() time.Time { return testpki.Now }, rand.Reader)
}

func initCA(t *testing.T, mutate func(*casvc.InitRequest)) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ca")
	r := casvc.InitRequest{Dir: dir, CommonName: "Test Local CA", KeyType: issuance.KeyECDSAP256, Validity: issuance.DefaultRootValidity}
	if mutate != nil {
		mutate(&r)
	}
	if _, err := service().Init(r); err != nil {
		t.Fatal(err)
	}
	return dir
}

func issueRequest(dir string, out string) casvc.IssueRequest {
	return casvc.IssueRequest{Dir: dir, Out: out, DNSNames: []string{"app.example.internal"},
		IPs: []netip.Addr{netip.MustParseAddr("10.1.2.3")}, Server: true,
		KeyType: issuance.KeyECDSAP256, Validity: issuance.DefaultLeafValidity}
}

func TestInitWritesAPrivateCADirectory(t *testing.T) {
	dir := initCA(t, nil)
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions only")
	}
	for path, want := range map[string]os.FileMode{
		dir:                                0o700 | os.ModeDir,
		filepath.Join(dir, casvc.KeyFile):  0o600,
		filepath.Join(dir, casvc.CertFile): 0o644,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode() != want {
			t.Errorf("%s: mode %v, want %v", path, info.Mode(), want)
		}
	}
}

func TestInitNeverReplacesACA(t *testing.T) {
	dir := initCA(t, nil)
	before, _ := os.ReadFile(filepath.Join(dir, casvc.KeyFile))
	_, err := service().Init(casvc.InitRequest{Dir: dir, CommonName: "Other", KeyType: issuance.KeyECDSAP256, Validity: issuance.DefaultRootValidity})
	if !errors.Is(err, casvc.ErrExists) {
		t.Fatalf("err %v, want ErrExists", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, casvc.KeyFile))
	if string(before) != string(after) {
		t.Error("the CA key changed")
	}
}

func TestIssueProvesBeforeWriting(t *testing.T) {
	dir := initCA(t, nil)
	out := filepath.Join(t.TempDir(), "app")
	res, err := service().Issue(issueRequest(dir, out))
	if err != nil {
		t.Fatal(err)
	}
	if res.CertPath != out+".pem" || res.KeyPath != out+".key" {
		t.Errorf("paths %s %s", res.CertPath, res.KeyPath)
	}
	if got := res.Proof.Trust.Targets[0].Result.State; got != "verified" {
		t.Errorf("proof trust state %s", got)
	}

	// An independent inspection of the written file agrees.
	roots, err := inspectsvc.LoadRoots([]string{filepath.Join(dir, casvc.CertFile)})
	if err != nil {
		t.Fatal(err)
	}
	insp, err := inspectsvc.New(func() time.Time { return testpki.Now }, inspectsvc.WithRoots(roots)).InspectFile(res.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	if insp.Highest != "" {
		t.Errorf("inspection of the issued certificate has findings: %+v", insp.Findings)
	}
	key, err := os.ReadFile(res.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := issuance.DecodePrivateKey(key)
	if err != nil || !issuance.KeyMatches(res.Certificate, signer) {
		t.Errorf("the written key does not belong to the certificate: %v", err)
	}
}

func TestIssueRefusesAndWritesNothing(t *testing.T) {
	dir := initCA(t, func(r *casvc.InitRequest) { r.PermittedDNS = []string{"example.internal"} })
	outDir := t.TempDir()
	for name, mutate := range map[string]func(*casvc.IssueRequest){
		"outside constraints": func(r *casvc.IssueRequest) { r.DNSNames = []string{"example.com"} },
		"ip not permitted":    func(r *casvc.IssueRequest) {}, // the CA permits no IP range at all
		"no CA":               func(r *casvc.IssueRequest) { r.Dir = filepath.Join(outDir, "missing") },
	} {
		r := issueRequest(dir, filepath.Join(outDir, "out"))
		mutate(&r)
		if _, err := service().Issue(r); err == nil {
			t.Errorf("%s: issued", name)
		}
		entries, _ := os.ReadDir(outDir)
		if len(entries) != 0 {
			t.Fatalf("%s: wrote %v", name, entries)
		}
	}
}

func TestIssueNeverReplacesFiles(t *testing.T) {
	dir := initCA(t, nil)
	out := filepath.Join(t.TempDir(), "app")
	if err := os.WriteFile(out+".key", []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service().Issue(issueRequest(dir, out)); !errors.Is(err, casvc.ErrExists) {
		t.Fatalf("err %v, want ErrExists", err)
	}
	if data, _ := os.ReadFile(out + ".key"); string(data) != "existing" {
		t.Error("the existing key was replaced")
	}
	if _, err := os.Stat(out + ".pem"); !errors.Is(err, os.ErrNotExist) {
		t.Error("a certificate was written next to a key it does not belong to")
	}
}

func TestIssueRefusesAMismatchedCAKey(t *testing.T) {
	a, b := initCA(t, nil), initCA(t, nil)
	keyB, err := os.ReadFile(filepath.Join(b, casvc.KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(a, casvc.KeyFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a, casvc.KeyFile), keyB, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service().Issue(issueRequest(a, filepath.Join(t.TempDir(), "app"))); err == nil {
		t.Fatal("issued with a CA key that does not belong to the CA certificate")
	}
}

func TestIssueWildcardAndClient(t *testing.T) {
	dir := initCA(t, nil)
	r := issueRequest(dir, filepath.Join(t.TempDir(), "wild"))
	r.DNSNames = []string{"*.svc.example.internal"}
	r.Client = true
	if _, err := service().Issue(r); err != nil {
		t.Fatal(err)
	}
}

// A certificate outside the CA's constraints, signed anyway as a stolen CA
// key could, fails validation: the constraint protects relying parties, not
// only this tool's own refusal. A DNS-only CA covers no IP address.
func TestConstraintsHoldAgainstAStolenKey(t *testing.T) {
	dir := initCA(t, func(r *casvc.InitRequest) { r.PermittedDNS = []string{"example.internal"} })
	caPEM, _ := os.ReadFile(filepath.Join(dir, casvc.CertFile))
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := os.ReadFile(filepath.Join(dir, casvc.KeyFile))
	caKey, err := issuance.DecodePrivateKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := inspectsvc.LoadRoots([]string{filepath.Join(dir, casvc.CertFile)})
	if err != nil {
		t.Fatal(err)
	}
	for name, tmpl := range map[string]*x509.Certificate{
		"other domain": {DNSNames: []string{"bank.example.com"}},
		"ip address":   {IPAddresses: []net.IP{net.ParseIP("10.1.2.3")}},
	} {
		tmpl.SerialNumber = big.NewInt(1)
		tmpl.NotBefore, tmpl.NotAfter = testpki.Now.Add(-time.Hour), testpki.Now.Add(time.Hour)
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, caKey.Public(), caKey)
		if err != nil {
			t.Fatal(err)
		}
		res, err := inspectsvc.New(func() time.Time { return testpki.Now }, inspectsvc.WithRoots(roots)).
			InspectBytes(inspectsvc.Source{Kind: inspectsvc.SourceFile, Locator: name}, issuance.EncodeCertificate(der))
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Trust.Targets[0].Result.State; got == "verified" {
			t.Errorf("%s: a certificate outside the name constraints validated", name)
		}
	}
}
