package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"

	"github.com/Hazame-hub/trustsmith/internal/testpki"
)

// requestFixtures writes the certificate signing request fixtures (ADR-0011).
// Fixtures derived from csr.pem read it back from disk, so they stay
// consistent with the committed bytes even when only some are regenerated.
func requestFixtures(out string, write func(name, description string, data []byte), pemOf func(ders ...[]byte) []byte) {
	pemRequest := func(label string, der []byte) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der})
	}
	ext := func(oid asn1.ObjectIdentifier, critical bool, value any) pkix.Extension {
		der, err := asn1.Marshal(value)
		if err != nil {
			log.Fatal(err)
		}
		return pkix.Extension{Id: oid, Critical: critical, Value: der}
	}
	digitalSignature := ext(asn1.ObjectIdentifier{2, 5, 29, 15}, true, asn1.BitString{Bytes: []byte{0x80}, BitLength: 1})
	serverAuth := ext(asn1.ObjectIdentifier{2, 5, 29, 37}, false, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}})
	server := func(cn string) testpki.RequestTemplate {
		return testpki.RequestTemplate{
			CommonName: cn, Organization: "Trustsmith Tests", DNSNames: []string{cn},
			ExtraExtensions: []pkix.Extension{digitalSignature, serverAuth},
		}
	}

	good := server("api.example.test")
	good.DNSNames = []string{"api.example.test", "www.example.test"}
	good.IPAddresses = []string{"192.0.2.10"}
	write("csr.pem", "ECDSA P-256 certificate signing request for DNS and IP names, with requested key usage and extended key usage",
		pemRequest("CERTIFICATE REQUEST", testpki.Request(f, good, testpki.ECDSAKey(f))))
	csr := loadRequest(filepath.Join(out, "csr.pem"))
	write("csr.der", "csr.pem as DER", csr)
	write("csr-legacy-label.pem", "csr.pem under the legacy NEW CERTIFICATE REQUEST label", pemRequest("NEW CERTIFICATE REQUEST", csr))
	write("csr-bad-signature.pem", "csr.pem with its signature corrupted", pemRequest("CERTIFICATE REQUEST", testpki.CorruptSignature(csr)))

	leaf := loadCertificates(filepath.Join(out, "leaf.pem"))
	if len(leaf) != 1 {
		log.Fatalf("leaf.pem must hold one certificate; found %d", len(leaf))
	}
	write("csr-with-leaf.pem", "leaf.pem followed by csr.pem: the request is not a certificate or an issuer candidate",
		append(pemOf(leaf[0]), pemRequest("CERTIFICATE REQUEST", csr)...))

	write("csr-rsa-1024.pem", "certificate signing request for an RSA-1024 key",
		pemRequest("CERTIFICATE REQUEST", testpki.Request(f, server("rsa1024.example.test"), testpki.RSAKey(f, 1024))))

	legacyKey := testpki.RSAKey(f, 2048)
	legacy := server("legacy.example.test")
	legacy.SignatureAlgorithm = x509.SHA1WithRSA // Go 1.27 still creates SHA-1 requests
	write("csr-sha1.pem", "certificate signing request signed with sha1WithRSAEncryption",
		pemRequest("CERTIFICATE REQUEST", testpki.Request(f, legacy, legacyKey)))
	write("csr-md5.pem", "certificate signing request re-signed with md5WithRSAEncryption (the engine refuses to check MD5)",
		pemRequest("CERTIFICATE REQUEST", testpki.ResignRequest(f, testpki.Request(f, server("legacy.example.test"), legacyKey), nil, testpki.RSAWithMD5, legacyKey)))

	cnOnly := server("cn-only.example.test")
	cnOnly.DNSNames = nil
	write("csr-cn-only.pem", "certificate signing request that names its host only in the Common Name",
		pemRequest("CERTIFICATE REQUEST", testpki.Request(f, cnOnly, testpki.ECDSAKey(f))))

	ca := testpki.RequestTemplate{
		CommonName: "Trustsmith Test Requested CA", Organization: "Trustsmith Tests",
		ExtraExtensions: []pkix.Extension{
			ext(asn1.ObjectIdentifier{2, 5, 29, 19}, true, struct {
				IsCA       bool
				MaxPathLen int
			}{true, 0}),
			// keyCertSign (bit 5) and cRLSign (bit 6).
			ext(asn1.ObjectIdentifier{2, 5, 29, 15}, true, asn1.BitString{Bytes: []byte{0x06}, BitLength: 7}),
		},
	}
	write("csr-ca.pem", "certificate signing request for a CA certificate with path length 0",
		pemRequest("CERTIFICATE REQUEST", testpki.Request(f, ca, testpki.ECDSAKey(f))))
}

// loadRequest reads the first certificate signing request of a PEM file.
func loadRequest(path string) []byte {
	data, err := os.ReadFile(path) //nolint:gosec // reads the committed corpus
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		log.Fatalf("%s holds no certificate signing request", path)
	}
	return block.Bytes
}
