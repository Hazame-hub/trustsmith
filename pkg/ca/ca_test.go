package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/testpki"
	"github.com/Hazame-hub/trustsmith/pkg/ca"
	"github.com/Hazame-hub/trustsmith/pkg/inspect"
)

func now() time.Time { return testpki.Now }

// A caller holding a CA in memory (a secret store) creates one, signs a
// request with it, and gets a certificate inspect accepts for its name.
func TestInitAndSign(t *testing.T) {
	authority, err := ca.Init(ca.InitOptions{Now: now, Name: "Sybil CA", PermitDNS: []string{"example.internal"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(authority.KeyPEM), "PRIVATE KEY") || !strings.Contains(string(authority.CertPEM), "CERTIFICATE") {
		t.Fatal("Init returned no CA")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := testpki.Request(t, testpki.RequestTemplate{DNSNames: []string{"app.example.internal"}}, key)

	certPEM, err := ca.Sign(authority, csr, ca.SignOptions{Now: now, Days: 30})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(key.Public()) {
		t.Error("the certificate does not carry the request's key")
	}
	if got := cert.NotAfter.Sub(testpki.Now); got > 31*24*time.Hour {
		t.Errorf("valid for %s, want 30 days", got)
	}

	// The signed certificate passes inspect with the CA as the only anchor.
	dir := t.TempDir()
	chain := filepath.Join(dir, "chain.pem")
	if err := os.WriteFile(chain, append(certPEM, authority.CertPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := inspect.Target(chain, inspect.Options{Now: now, Hostname: "app.example.internal", Purpose: "tls-server"})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Findings []struct{ Code, Severity string } `json:"findings"`
	}
	if err := json.Unmarshal(doc, &got); err != nil {
		t.Fatal(err)
	}
	for _, f := range got.Findings {
		if f.Severity == "critical" {
			t.Errorf("critical finding %s on the signed certificate", f.Code)
		}
	}
}

func TestSignRefusesWithTheCommandsMessage(t *testing.T) {
	authority, err := ca.Init(ca.InitOptions{Now: now, PermitDNS: []string{"example.internal"}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := testpki.Request(t, testpki.RequestTemplate{DNSNames: []string{"bank.example.com"}}, key)
	if _, err := ca.Sign(authority, csr, ca.SignOptions{Now: now}); err == nil || !strings.Contains(err.Error(), "outside the CA's permitted names") {
		t.Errorf("err %v, want a refusal outside the constraints", err)
	}
	other, err := ca.Init(ca.InitOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	mixed := ca.CA{CertPEM: authority.CertPEM, KeyPEM: other.KeyPEM}
	if _, err := ca.Sign(mixed, csr, ca.SignOptions{Now: now}); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("err %v, want a mismatched CA refused", err)
	}
	if _, err := ca.Sign(authority, nil, ca.SignOptions{Now: now}); err == nil {
		t.Error("an empty request was accepted")
	}
}
