package main

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"

	"github.com/Hazame-hub/trustsmith/internal/testpki"
)

// relationshipFixtures writes the fixtures for issuer relationships inside one
// input. Fixtures derived from existing corpus files read those files from
// disk, so they stay consistent with the committed bytes.
func relationshipFixtures(out string, write func(name, description string, data []byte), pemOf func(ders ...[]byte) []byte) {
	bundle := loadCertificates(filepath.Join(out, "bundle.pem"))
	if len(bundle) != 3 {
		log.Fatalf("bundle.pem must hold leaf, intermediate and root; found %d certificates", len(bundle))
	}
	leaf, inter, root := bundle[0], bundle[1], bundle[2]

	write("bundle-reversed.pem", "bundle.pem in reverse order: root, intermediate, leaf", pemOf(root, inter, leaf))
	write("bundle-duplicate.pem", "leaf, intermediate and the same leaf again", pemOf(leaf, inter, leaf))

	interCert, err := x509.ParseCertificate(inter)
	if err != nil {
		log.Fatal(err)
	}
	impostor := testpki.Template{
		CommonName: interCert.Subject.CommonName, Organization: interCert.Subject.Organization[0], Serial: 900,
		NotBefore: date(2026, 1, 1), NotAfter: date(2031, 1, 1),
		IsCA: true, MaxPathLen: 0, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	write("issuer-name-match-wrong-key.pem", "leaf and a CA with the intermediate's name but a different key",
		pemOf(leaf, testpki.Issue(f, impostor, testpki.ECDSAKey(f), nil).DER))

	sameKeyID := impostor
	sameKeyID.Serial = 901
	sameKeyID.SubjectKeyID = interCert.SubjectKeyId
	write("issuer-key-id-match-wrong-key.pem", "leaf and a CA with the intermediate's name and key identifier but a different key",
		pemOf(leaf, testpki.Issue(f, sameKeyID, testpki.ECDSAKey(f), nil).DER))

	legacyKey := testpki.RSAKey(f, 2048)
	legacyCA := testpki.Issue(f, testpki.Template{
		CommonName: "Trustsmith Test Legacy Signing CA", Organization: "Trustsmith Tests", Serial: 910,
		NotBefore: date(2026, 1, 1), NotAfter: date(2031, 1, 1),
		IsCA: true, MaxPathLen: 0, KeyUsage: x509.KeyUsageCertSign,
	}, legacyKey, nil)
	legacyLeaf := testpki.Issue(f, leafTemplate("legacy-signed.example.test", 911), testpki.ECDSAKey(f), legacyCA)
	write("sha1-with-issuer.pem", "SHA-1-signed leaf followed by its RSA issuer: the signature verifies",
		pemOf(testpki.Resign(f, legacyLeaf.DER, nil, testpki.RSAWithSHA1, legacyKey), legacyCA.DER))
	write("md5-with-issuer.pem", "MD5-signed leaf followed by its RSA issuer: the engine refuses to check MD5",
		pemOf(testpki.Resign(f, legacyLeaf.DER, nil, testpki.RSAWithMD5, legacyKey), legacyCA.DER))

	selfIssued := testpki.Issue(f, leafTemplate("self-issued.example.test", 920), testpki.ECDSAKey(f), nil)
	write("self-issued-not-self-signed.pem", "names itself as issuer but is signed by a different key",
		pemOf(testpki.Resign(f, selfIssued.DER, nil, testpki.ECDSAWithSHA256, testpki.ECDSAKey(f))))

	reissueRoot := testpki.Issue(f, testpki.Template{
		CommonName: "Trustsmith Test Reissue Root CA", Organization: "Trustsmith Tests", Serial: 930,
		NotBefore: date(2026, 1, 1), NotAfter: date(2036, 1, 1),
		IsCA: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign,
	}, testpki.ECDSAKey(f), nil)
	intermediateKey := testpki.ECDSAKey(f)
	reissued := func(serial int64) *testpki.Cert {
		return testpki.Issue(f, testpki.Template{
			CommonName: "Trustsmith Test Reissued Intermediate CA", Organization: "Trustsmith Tests", Serial: serial,
			NotBefore: date(2026, 1, 1), NotAfter: date(2031, 1, 1),
			IsCA: true, MaxPathLen: 0, KeyUsage: x509.KeyUsageCertSign,
		}, intermediateKey, reissueRoot)
	}
	first, second := reissued(931), reissued(932)
	reissuedLeaf := testpki.Issue(f, leafTemplate("reissued.example.test", 933), testpki.ECDSAKey(f), first)
	write("reissued-intermediates.pem", "leaf and two certificates for the same intermediate key: both verify the leaf",
		pemOf(reissuedLeaf.DER, first.DER, second.DER))
}

func leafTemplate(cn string, serial int64) testpki.Template {
	return testpki.Template{
		CommonName: cn, Serial: serial, NotBefore: date(2026, 9, 1), NotAfter: date(2027, 9, 1),
		DNSNames:    []string{cn},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

func loadCertificates(path string) [][]byte {
	data, err := os.ReadFile(path) //nolint:gosec // reads the committed corpus
	if err != nil {
		log.Fatal(err)
	}
	var ders [][]byte
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return ders
		}
		if block.Type == "CERTIFICATE" {
			ders = append(ders, block.Bytes)
		}
	}
}
