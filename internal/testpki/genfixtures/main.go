// Command genfixtures writes the committed inspection corpus used by the
// inspect service and CLI golden tests.
//
//	go run ./internal/testpki/genfixtures -out testdata/certs
//
// Signatures are randomised, so regenerating changes certificate bytes and
// fingerprints; refresh the goldens afterwards with UPDATE_GOLDEN=1. CI never
// runs this command. All validity periods are chosen relative to
// testpki.Now (2026-09-14T12:00:00Z), the fixed clock of every golden test.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/testpki"
)

type fatal struct{}

func (fatal) Helper()                           {}
func (fatal) Fatalf(format string, args ...any) { log.Fatalf(format, args...) }

var f fatal

func date(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

// rfc8410TestKey is the published RFC 8410 section 10.3 Ed25519 example key.
// It is used only to show that private-key blocks are reported, not decoded.
const rfc8410TestKey = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n-----END PRIVATE KEY-----\n"

func main() {
	out := flag.String("out", filepath.Join("testdata", "certs"), "output directory")
	force := flag.Bool("force", false, "rewrite existing fixtures (changes their fingerprints and every golden)")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	files := map[string]string{} // name -> description
	written := 0
	// write keeps committed fixtures unless -force: signatures are
	// randomised, so rewriting one changes its fingerprint and its goldens.
	write := func(name, description string, data []byte) {
		files[name] = description
		path := filepath.Join(*out, name)
		if _, err := os.Stat(path); err == nil && !*force {
			return
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			log.Fatal(err)
		}
		written++
	}
	pemOf := func(ders ...[]byte) []byte {
		var b []byte
		for _, d := range ders {
			b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
		}
		return b
	}

	root := testpki.Issue(f, testpki.Template{
		CommonName: "Trustsmith Test Root CA", Organization: "Trustsmith Tests", Serial: 1,
		NotBefore: date(2026, 1, 1), NotAfter: date(2036, 1, 1),
		IsCA: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, testpki.ECDSAKey(f), nil)
	inter := testpki.Issue(f, testpki.Template{
		CommonName: "Trustsmith Test Intermediate CA", Organization: "Trustsmith Tests", Serial: 2,
		NotBefore: date(2026, 1, 1), NotAfter: date(2031, 1, 1),
		IsCA: true, MaxPathLen: 0, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, testpki.ECDSAKey(f), root)

	server := func(cn string, serial int64, nb, na time.Time) testpki.Template {
		return testpki.Template{
			CommonName: cn, Serial: serial, NotBefore: nb, NotAfter: na,
			DNSNames:    []string{cn},
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
	}

	leafTpl := server("api.example.test", 100, date(2026, 9, 1), date(2026, 12, 1))
	leafTpl.DNSNames = []string{"api.example.test", "www.example.test"}
	leafTpl.IPAddresses = []string{"192.0.2.10"}
	leaf := testpki.Issue(f, leafTpl, testpki.ECDSAKey(f), inter)

	write("root-ca.pem", "self-signed root CA", pemOf(root.DER))
	write("leaf.pem", "TLS server certificate issued by the intermediate, valid", pemOf(leaf.DER))
	write("leaf.der", "leaf.pem as DER", leaf.DER)
	write("bundle.pem", "leaf, intermediate and root, in that order", pemOf(leaf.DER, inter.DER, root.DER))

	bad := "-----BEGIN CERTIFICATE-----\nthis block is !!! not base64\n-----END CERTIFICATE-----\n"
	write("bundle-with-bad-block.pem", "leaf, a corrupt block, then the intermediate",
		append(append(pemOf(leaf.DER), bad...), pemOf(inter.DER)...))
	write("bundle-with-private-key.pem", "leaf followed by a private key block (reported, never decoded)",
		append(pemOf(leaf.DER), rfc8410TestKey...))
	write("private-key-only.pem", "only a private key block: no certificates", []byte(rfc8410TestKey))
	write("text-around.pem", "openssl-style text before and after the leaf",
		append(append([]byte("subject=CN=api.example.test\nissuer=CN=Trustsmith Test Intermediate CA\n"), pemOf(leaf.DER)...), "\ntrailing note\n"...))
	write("trailing-data.der", "leaf.der followed by two stray bytes", append(append([]byte{}, leaf.DER...), 0xde, 0xad))
	write("malformed.pem", "a single corrupt certificate block", []byte(bad))
	write("empty.pem", "zero bytes", nil)
	write("not-a-certificate.txt", "plain text", []byte("This is not a certificate.\n"))

	write("expired.pem", "expired on 2026-06-01",
		pemOf(testpki.Issue(f, server("expired.example.test", 101, date(2025, 6, 1), date(2026, 6, 1)), testpki.ECDSAKey(f), inter).DER))
	write("not-yet-valid.pem", "valid from 2026-10-01",
		pemOf(testpki.Issue(f, server("future.example.test", 102, date(2026, 10, 1), date(2027, 10, 1)), testpki.ECDSAKey(f), inter).DER))
	write("expiring-warning.pem", "expires 2026-10-01 (16 days after the test clock)",
		pemOf(testpki.Issue(f, server("soon.example.test", 103, date(2026, 7, 1), date(2026, 10, 1)), testpki.ECDSAKey(f), inter).DER))
	write("expiring-critical.pem", "expires 2026-09-17 (2 days after the test clock)",
		pemOf(testpki.Issue(f, server("very-soon.example.test", 104, date(2026, 6, 17), date(2026, 9, 17)), testpki.ECDSAKey(f), inter).DER))
	write("self-signed-leaf.pem", "self-signed TLS server certificate",
		pemOf(testpki.Issue(f, server("self.example.test", 105, date(2026, 9, 1), date(2027, 9, 1)), testpki.ECDSAKey(f), nil).DER))

	clientTpl := server("client-1", 106, date(2026, 9, 1), date(2027, 9, 1))
	clientTpl.DNSNames, clientTpl.URIs = nil, []string{"spiffe://example.test/client-1"}
	clientTpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	write("client.pem", "TLS client certificate with a URI SAN",
		pemOf(testpki.Issue(f, clientTpl, testpki.ECDSAKey(f), inter).DER))

	cnOnly := server("cn-only.example.test", 107, date(2026, 9, 1), date(2027, 9, 1))
	cnOnly.DNSNames = nil
	write("cn-only.pem", "TLS server certificate with no Subject Alternative Names",
		pemOf(testpki.Issue(f, cnOnly, testpki.ECDSAKey(f), inter).DER))

	write("rsa-1024.pem", "TLS server certificate with an RSA-1024 key",
		pemOf(testpki.Issue(f, server("rsa1024.example.test", 108, date(2026, 9, 1), date(2027, 9, 1)), testpki.RSAKey(f, 1024), inter).DER))

	rsaCAKey := testpki.RSAKey(f, 2048)
	rsaCA := testpki.Issue(f, testpki.Template{
		CommonName: "Trustsmith Test Legacy RSA CA", Serial: 3, NotBefore: date(2026, 1, 1), NotAfter: date(2031, 1, 1),
		IsCA: true, MaxPathLen: 0, KeyUsage: x509.KeyUsageCertSign,
	}, rsaCAKey, root)
	legacy := testpki.Issue(f, server("legacy.example.test", 109, date(2026, 9, 1), date(2027, 9, 1)), testpki.ECDSAKey(f), rsaCA)
	write("sha1.pem", "leaf re-signed with sha1WithRSAEncryption", pemOf(testpki.Resign(f, legacy.DER, nil, testpki.RSAWithSHA1, rsaCAKey)))
	write("md5.pem", "leaf re-signed with md5WithRSAEncryption", pemOf(testpki.Resign(f, legacy.DER, nil, testpki.RSAWithMD5, rsaCAKey)))

	oddKey := testpki.RSAKey(f, 2048)
	odd := testpki.Issue(f, server("noncanonical.example.test", 110, date(2026, 9, 1), date(2027, 9, 1)), testpki.ECDSAKey(f), inter)
	write("noncanonical-rsa-key.pem", "RSA key encoded without NULL parameters (Go rejects the certificate)",
		pemOf(testpki.Resign(f, odd.DER, testpki.RSASPKIWithoutNULL(f, &oddKey.PublicKey), testpki.ECDSAWithSHA256, inter.Key)))

	xk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	xspki, err := x509.MarshalPKIXPublicKey(xk.PublicKey())
	if err != nil {
		log.Fatal(err)
	}
	write("x25519-key.pem", "certificate for an X25519 key (no ADR-0002 key identity)",
		pemOf(testpki.Resign(f, odd.DER, xspki, testpki.ECDSAWithSHA256, inter.Key)))

	relationshipFixtures(*out, write, pemOf)

	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var readme strings.Builder
	readme.WriteString("# Inspection corpus\n\nGenerated by `go run ./internal/testpki/genfixtures`; do not edit by hand.\n")
	readme.WriteString("Validity periods are relative to the test clock 2026-09-14T12:00:00Z.\n\n| File | Contents |\n|---|---|\n")
	for _, n := range names {
		fmt.Fprintf(&readme, "| `%s` | %s |\n", n, files[n])
	}
	if err := os.WriteFile(filepath.Join(*out, "README.md"), []byte(readme.String()), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("corpus has %d fixtures; wrote %d to %s\n", len(names), written, *out)
}
