package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/Hazame-hub/trustsmith/internal/testpki"
)

// pathFixtures writes the fixtures for certification paths built inside one
// input. Each uses its own keys and names, so no fixture's issuer candidates
// leak into another.
func pathFixtures(write func(name, description string, data []byte), pemOf func(ders ...[]byte) []byte) {
	ca := func(cn string, serial int64, maxPathLen int) testpki.Template {
		return testpki.Template{
			CommonName: cn, Organization: "Trustsmith Path Tests", Serial: serial,
			NotBefore: date(2026, 1, 1), NotAfter: date(2031, 1, 1),
			IsCA: true, MaxPathLen: maxPathLen, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
	}
	root := func(cn string, serial int64, maxPathLen int) *testpki.Cert {
		return testpki.Issue(f, ca(cn, serial, maxPathLen), testpki.ECDSAKey(f), nil)
	}

	{
		r := root("Trustsmith Path Not-CA Root", 1000, -1)
		tpl := ca("Trustsmith Path Not-CA Issuer", 1001, -1)
		tpl.IsCA, tpl.BasicConstraintsNotCA = false, true
		issuer := testpki.Issue(f, tpl, testpki.ECDSAKey(f), r)
		leaf := testpki.Issue(f, leafTemplate("not-ca.path.example.test", 1002), testpki.ECDSAKey(f), issuer)
		write("path-not-ca.pem", "leaf, an issuer with basic constraints CA:FALSE, root: the structure fails",
			pemOf(leaf.DER, issuer.DER, r.DER))
	}
	{
		r := root("Trustsmith Path No-BC Root", 1010, -1)
		tpl := ca("Trustsmith Path No-BC Issuer", 1011, -1)
		tpl.IsCA = false
		issuer := testpki.Issue(f, tpl, testpki.ECDSAKey(f), r)
		leaf := testpki.Issue(f, leafTemplate("no-bc.path.example.test", 1012), testpki.ECDSAKey(f), issuer)
		write("path-no-basic-constraints.pem", "leaf, an issuer without basic constraints, root: the structure fails",
			pemOf(leaf.DER, issuer.DER, r.DER))
	}
	{
		r := root("Trustsmith Path Key-Usage Root", 1020, -1)
		tpl := ca("Trustsmith Path Key-Usage Issuer", 1021, -1)
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
		issuer := testpki.Issue(f, tpl, testpki.ECDSAKey(f), r)
		leaf := testpki.Issue(f, leafTemplate("key-usage.path.example.test", 1022), testpki.ECDSAKey(f), issuer)
		write("path-key-usage-no-certsign.pem", "leaf, a CA whose key usage lacks keyCertSign, root: the structure fails",
			pemOf(leaf.DER, issuer.DER, r.DER))
	}
	{
		r := root("Trustsmith Path Length Root", 1030, 0)
		inter := testpki.Issue(f, ca("Trustsmith Path Length Intermediate", 1031, -1), testpki.ECDSAKey(f), r)
		leaf := testpki.Issue(f, leafTemplate("length.path.example.test", 1032), testpki.ECDSAKey(f), inter)
		write("path-length-exceeded.pem", "leaf, intermediate, root with pathLenConstraint 0: the constraint is exceeded",
			pemOf(leaf.DER, inter.DER, r.DER))
	}
	{
		// A self-issued intermediate (same name as the root, different key) does
		// not count against the root's pathLenConstraint of 0.
		rootKey := testpki.ECDSAKey(f)
		r := testpki.Issue(f, ca("Trustsmith Path Self-Issued CA", 1040, 0), rootKey, nil)
		selfIssued := testpki.Issue(f, ca("Trustsmith Path Self-Issued CA", 1041, -1), testpki.ECDSAKey(f), r)
		leaf := testpki.Issue(f, leafTemplate("self-issued.path.example.test", 1042), testpki.ECDSAKey(f), selfIssued)
		write("path-length-self-issued.pem", "leaf, a self-issued intermediate, root with pathLenConstraint 0: not exceeded",
			pemOf(leaf.DER, selfIssued.DER, r.DER))
	}
	{
		r := root("Trustsmith Path Expired Root", 1050, -1)
		tpl := ca("Trustsmith Path Expired Intermediate", 1051, -1)
		tpl.NotBefore, tpl.NotAfter = date(2025, 1, 1), date(2026, 6, 1)
		inter := testpki.Issue(f, tpl, testpki.ECDSAKey(f), r)
		leaf := testpki.Issue(f, leafTemplate("expired-issuer.path.example.test", 1052), testpki.ECDSAKey(f), inter)
		write("path-expired-intermediate.pem", "leaf, an intermediate that expired on 2026-06-01, root",
			pemOf(leaf.DER, inter.DER, r.DER))
	}
	{
		keyA := testpki.ECDSAKey(f)
		rootA := testpki.Issue(f, ca("Trustsmith Path Root A", 1060, -1), keyA, nil)
		rootB := root("Trustsmith Path Root B", 1061, -1)
		crossA := testpki.Issue(f, ca("Trustsmith Path Root A", 1062, -1), keyA, rootB)
		inter := testpki.Issue(f, ca("Trustsmith Path Cross Intermediate", 1063, 0), testpki.ECDSAKey(f), rootA)
		leaf := testpki.Issue(f, leafTemplate("cross.path.example.test", 1064), testpki.ECDSAKey(f), inter)
		write("path-cross-signed.pem", "leaf, intermediate, root A, root A's key certified by root B, root B: two paths",
			pemOf(leaf.DER, inter.DER, rootA.DER, crossA.DER, rootB.DER))
	}
	{
		keyX, keyY := testpki.ECDSAKey(f), testpki.ECDSAKey(f)
		seedY := testpki.Issue(f, ca("Trustsmith Path Cycle Y", 1070, -1), keyY, nil)
		x := testpki.Issue(f, ca("Trustsmith Path Cycle X", 1071, -1), keyX, seedY)
		y := testpki.Issue(f, ca("Trustsmith Path Cycle Y", 1072, -1), keyY, &testpki.Cert{Cert: x.Cert, Key: keyX})
		write("path-cycle.pem", "two CA certificates that issued each other: construction stops at the cycle",
			pemOf(x.DER, y.DER))
	}
	{
		r := root("Trustsmith Path Critical-Extension Root", 1080, -1)
		tpl := ca("Trustsmith Path Critical-Extension Intermediate", 1081, -1)
		tpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Critical: true, Value: []byte{0x05, 0x00}}}
		inter := testpki.Issue(f, tpl, testpki.ECDSAKey(f), r)
		leaf := testpki.Issue(f, leafTemplate("critical.path.example.test", 1082), testpki.ECDSAKey(f), inter)
		write("path-critical-extension.pem", "leaf, an intermediate with an unknown critical extension, root: not fully evaluated",
			pemOf(leaf.DER, inter.DER, r.DER))
	}
}
