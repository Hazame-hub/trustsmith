package casvc_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/app/casvc"
	"github.com/Hazame-hub/trustsmith/internal/issuance"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
)

func csrPEM(t *testing.T, tmpl testpki.RequestTemplate, key crypto.Signer) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: testpki.Request(t, tmpl, key)})
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signRequest(dir, out string, csr []byte) casvc.SignRequest {
	return casvc.SignRequest{Dir: dir, Out: out, CSR: csr, Server: true, Validity: issuance.DefaultLeafValidity}
}

// The key never leaves the requester: the certificate carries the request's
// public key, only the certificate is written, and it is proven like an
// issued one.
func TestSignCertifiesTheRequestersKeyAndWritesOnlyTheCertificate(t *testing.T) {
	dir := initCA(t, func(r *casvc.InitRequest) {
		r.PermittedDNS = []string{"example.internal"}
		r.PermittedIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	})
	key := ecKey(t)
	csr := csrPEM(t, testpki.RequestTemplate{CommonName: "ignored", DNSNames: []string{"app.example.internal"}, IPAddresses: []string{"10.1.2.3"}}, key)
	out := filepath.Join(t.TempDir(), "app")

	res, err := service().Sign(signRequest(dir, out, csr))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Certificate.PublicKey.(*ecdsa.PublicKey).Equal(key.Public()) {
		t.Error("the certificate does not carry the request's key")
	}
	if got := res.Certificate.DNSNames; len(got) != 1 || got[0] != "app.example.internal" {
		t.Errorf("DNS names %v, want the request's", got)
	}
	if len(res.IPs) != 1 || res.IPs[0] != netip.MustParseAddr("10.1.2.3") {
		t.Errorf("IPs %v, want the request's", res.IPs)
	}
	if res.Certificate.Subject.CommonName == "ignored" {
		t.Error("the request's subject was copied; the CA decides what it certifies")
	}
	if _, err := os.Stat(out + ".key"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a key file was written: %v", err)
	}
	if _, err := os.Stat(out + ".pem"); err != nil {
		t.Error(err)
	}
}

func TestSignNamesOverrideTheRequest(t *testing.T) {
	dir := initCA(t, nil)
	csr := csrPEM(t, testpki.RequestTemplate{DNSNames: []string{"asked.example.internal"}}, ecKey(t))
	r := signRequest(dir, filepath.Join(t.TempDir(), "o"), csr)
	r.DNSNames = []string{"given.example.internal"}
	res, err := service().Sign(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Certificate.DNSNames; len(got) != 1 || got[0] != "given.example.internal" {
		t.Errorf("DNS names %v, want only the given name", got)
	}
}

// Requests the CA refuses, each before anything is written.
func TestSignRefusesAndWritesNothing(t *testing.T) {
	dir := initCA(t, func(r *casvc.InitRequest) { r.PermittedDNS = []string{"example.internal"} })
	good := testpki.Request(t, testpki.RequestTemplate{DNSNames: []string{"app.example.internal"}}, ecKey(t))
	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // the point of the test
	if err != nil {
		t.Fatal(err)
	}
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		csr  []byte
		want string
	}{
		"bad signature": {testpki.CorruptSignature(good), "does not verify"},
		"weak rsa":      {testpki.Request(t, testpki.RequestTemplate{DNSNames: []string{"a.example.internal"}}, weakRSA), "too short"},
		"p-224":         {testpki.Request(t, testpki.RequestTemplate{DNSNames: []string{"a.example.internal"}}, p224), "not accepted"},
		"outside":       {testpki.Request(t, testpki.RequestTemplate{DNSNames: []string{"bank.example.com"}}, ecKey(t)), "outside the CA's permitted names"},
		"no names":      {testpki.Request(t, testpki.RequestTemplate{CommonName: "app.example.internal"}, ecKey(t)), ""},
		"not a request": {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}), "expected a certificate signing request"},
		"two blocks":    {append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: good}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: good})...), "more than one"},
		"garbage":       {[]byte("hello"), "not a certificate signing request"},
	} {
		out := filepath.Join(t.TempDir(), "o")
		_, err := service().Sign(signRequest(dir, out, tc.csr))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want one containing %q", name, err, tc.want)
		}
		if _, statErr := os.Stat(out + ".pem"); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("%s: a certificate was written", name)
		}
	}
}

// RSA, Ed25519, DER and the legacy PEM label are all accepted; RSA gets
// keyEncipherment as an issued RSA certificate would.
func TestSignAcceptsEveryAcceptedKeyAndEncoding(t *testing.T) {
	dir := initCA(t, nil)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := testpki.RequestTemplate{DNSNames: []string{"app.example.internal"}}
	for name, csr := range map[string][]byte{
		"rsa":        csrPEM(t, tmpl, rsaKey),
		"ed25519":    csrPEM(t, tmpl, edKey),
		"der":        testpki.Request(t, tmpl, ecKey(t)),
		"legacy pem": pem.EncodeToMemory(&pem.Block{Type: "NEW CERTIFICATE REQUEST", Bytes: testpki.Request(t, tmpl, ecKey(t))}),
	} {
		res, err := service().Sign(signRequest(dir, filepath.Join(t.TempDir(), "o"), csr))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if name == "rsa" && res.Certificate.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
			t.Error("rsa: no keyEncipherment")
		}
	}
}

// Extensions the request asks for are not copied: a request for a CA
// certificate gets an end-entity certificate.
func TestSignIgnoresRequestedExtensions(t *testing.T) {
	dir := initCA(t, nil)
	bc, err := asn1.Marshal(struct {
		IsCA bool `asn1:"optional"`
	}{true})
	if err != nil {
		t.Fatal(err)
	}
	csr := testpki.Request(t, testpki.RequestTemplate{DNSNames: []string{"app.example.internal"},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: bc}}}, ecKey(t))
	res, err := service().Sign(signRequest(dir, filepath.Join(t.TempDir(), "o"), csr))
	if err != nil {
		t.Fatal(err)
	}
	if res.Certificate.IsCA {
		t.Error("a requested CA bit was copied")
	}
}

func TestSignNeverReplacesACertificate(t *testing.T) {
	dir := initCA(t, nil)
	out := filepath.Join(t.TempDir(), "o")
	if err := os.WriteFile(out+".pem", []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	csr := csrPEM(t, testpki.RequestTemplate{DNSNames: []string{"app.example.internal"}}, ecKey(t))
	if _, err := service().Sign(signRequest(dir, out, csr)); !errors.Is(err, casvc.ErrExists) {
		t.Fatalf("err %v, want ErrExists", err)
	}
}

func TestStageRefusesAMismatchedCA(t *testing.T) {
	a, b := initCA(t, nil), initCA(t, nil)
	cert, _ := os.ReadFile(filepath.Join(a, casvc.CertFile))
	key, _ := os.ReadFile(filepath.Join(b, casvc.KeyFile))
	if err := casvc.Stage(t.TempDir(), cert, key, nil); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("err %v, want a mismatch", err)
	}
}
