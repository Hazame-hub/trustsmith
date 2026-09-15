package main

import (
	"crypto/x509"

	"github.com/Hazame-hub/trustsmith/internal/testpki"
)

// tlsEndpointFixtures writes the chain served by the in-process TLS endpoint
// of the CLI endpoint tests: leaf, intermediate and root. The leaf's key is
// the published RFC 9500 testECCP256 key, so the tests can serve these
// committed bytes. The root is also written as a trust-anchor file.
func tlsEndpointFixtures(write func(name, description string, data []byte), pemOf func(ders ...[]byte) []byte) {
	root := testpki.Issue(f, testpki.Template{
		CommonName: "Trustsmith Test Endpoint Root CA", Organization: "Trustsmith Tests", Serial: 3000,
		NotBefore: date(2026, 1, 1), NotAfter: date(2036, 1, 1),
		IsCA: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, testpki.ECDSAKey(f), nil)
	inter := testpki.Issue(f, testpki.Template{
		CommonName: "Trustsmith Test Endpoint Intermediate CA", Organization: "Trustsmith Tests", Serial: 3001,
		NotBefore: date(2026, 1, 1), NotAfter: date(2031, 1, 1),
		IsCA: true, MaxPathLen: 0, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, testpki.ECDSAKey(f), root)
	leaf := testpki.Issue(f, testpki.Template{
		CommonName: "api.example.test", Serial: 3002, NotBefore: date(2026, 9, 1), NotAfter: date(2026, 12, 1),
		DNSNames:    []string{"api.example.test", "xn--bcher-kva.example"},
		IPAddresses: []string{"192.0.2.10"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, testpki.RFC9500P256Key(f), inter)
	write("tls-endpoint.pem", "leaf (on the RFC 9500 testECCP256 key), intermediate and root served by the in-process TLS endpoint tests",
		pemOf(leaf.DER, inter.DER, root.DER))
}
