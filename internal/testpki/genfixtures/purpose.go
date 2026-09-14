package main

import (
	"crypto/x509"

	"github.com/Hazame-hub/trustsmith/internal/testpki"
)

// purposeFixtures writes the fixtures for explicit purpose evaluation. They
// share one small PKI: purpose-root-ca.pem (also written as the roots file
// testdata/roots/purpose-root.pem), an unrestricted intermediate, and an
// intermediate restricted to server authentication. Each certificate file
// holds a leaf followed by its intermediate.
func purposeFixtures(write func(name, description string, data []byte), pemOf func(ders ...[]byte) []byte) {
	ca := func(cn string, serial int64) testpki.Template {
		return testpki.Template{
			CommonName: cn, Organization: "Trustsmith Purpose Tests", Serial: serial,
			NotBefore: date(2026, 1, 1), NotAfter: date(2031, 1, 1),
			IsCA: true, MaxPathLen: 0, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
	}
	rootTpl := ca("Trustsmith Purpose Root CA", 3000)
	rootTpl.NotAfter, rootTpl.MaxPathLen = date(2036, 1, 1), -1
	root := testpki.Issue(f, rootTpl, testpki.ECDSAKey(f), nil)
	inter := testpki.Issue(f, ca("Trustsmith Purpose Intermediate CA", 3001), testpki.ECDSAKey(f), root)
	serverOnlyTpl := ca("Trustsmith Purpose Server-Only Intermediate CA", 3002)
	serverOnlyTpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	serverOnly := testpki.Issue(f, serverOnlyTpl, testpki.ECDSAKey(f), root)

	leaf := func(cn string, serial int64, mutate func(*testpki.Template)) testpki.Template {
		t := testpki.Template{
			CommonName: cn, Serial: serial, NotBefore: date(2026, 9, 1), NotAfter: date(2027, 9, 1),
			KeyUsage: x509.KeyUsageDigitalSignature,
		}
		mutate(&t)
		return t
	}
	issue := func(t testpki.Template, parent *testpki.Cert) []byte {
		return testpki.Issue(f, t, testpki.ECDSAKey(f), parent).DER
	}

	write("purpose-root-ca.pem", "root CA of the purpose fixtures (also testdata/roots/purpose-root.pem)", pemOf(root.DER))
	write("purpose-code-signing.pem", "code signing leaf (extended key usage code signing) and its intermediate",
		pemOf(issue(leaf("Trustsmith Test Code Signer", 3010, func(t *testpki.Template) {
			t.URIs, t.ExtKeyUsage = []string{"https://publisher.example.test/"}, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		}), inter), inter.DER))
	write("purpose-email.pem", "email protection leaf with an email address and its intermediate",
		pemOf(issue(leaf("signer@example.test", 3011, func(t *testpki.Template) {
			t.EmailAddresses, t.ExtKeyUsage = []string{"signer@example.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
			t.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		}), inter), inter.DER))
	write("purpose-no-eku.pem", "leaf without extended key usage (no restriction) and its intermediate",
		pemOf(issue(leaf("no-eku.example.test", 3012, func(t *testpki.Template) {
			t.DNSNames = []string{"no-eku.example.test"}
		}), inter), inter.DER))
	write("purpose-any-eku.pem", "leaf with anyExtendedKeyUsage and its intermediate",
		pemOf(issue(leaf("any-eku.example.test", 3013, func(t *testpki.Template) {
			t.DNSNames, t.ExtKeyUsage = []string{"any-eku.example.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		}), inter), inter.DER))
	write("purpose-key-usage-conflict.pem", "code signing leaf whose key usage is key encipherment only, and its intermediate",
		pemOf(issue(leaf("Trustsmith Test Mismatched Signer", 3014, func(t *testpki.Template) {
			t.URIs, t.ExtKeyUsage = []string{"https://mismatched.example.test/"}, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
			t.KeyUsage = x509.KeyUsageKeyEncipherment
		}), inter), inter.DER))
	write("purpose-server-only-intermediate.pem", "client leaf under an intermediate restricted to server authentication",
		pemOf(issue(leaf("purpose-client", 3015, func(t *testpki.Template) {
			t.URIs, t.ExtKeyUsage = []string{"spiffe://example.test/purpose-client"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}), serverOnly), serverOnly.DER))
}
