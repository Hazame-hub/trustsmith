package x509facts_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"slices"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

var (
	notBefore = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
)

func mustCertificate(t *testing.T, der []byte) *x509facts.Certificate {
	t.Helper()
	p := x509facts.FromDER(der)
	if p.Kind != x509facts.KindCertificate || p.Certificate == nil {
		t.Fatalf("want a parsed certificate, got kind %s (%+v)", p.Kind, p.Unparseable)
	}
	return p.Certificate
}

func TestLeafFacts(t *testing.T) {
	ca := testpki.Issue(t, testpki.Template{
		CommonName: "Test CA", Serial: 1, NotBefore: notBefore, NotAfter: notAfter.AddDate(5, 0, 0),
		IsCA: true, MaxPathLen: 0, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, testpki.ECDSAKey(t), nil)
	leafKey := testpki.ECDSAKey(t)
	leaf := testpki.Issue(t, testpki.Template{
		CommonName: "api.example.test", Organization: "Example", Serial: 0x0102abcd,
		DNSNames: []string{"api.example.test", "*.example.test"}, IPAddresses: []string{"192.0.2.10", "2001:db8::1"},
		EmailAddresses: []string{"ops@example.test"}, URIs: []string{"spiffe://example.test/api"},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}, leafKey, ca)

	c := mustCertificate(t, leaf.DER)

	if c.Fingerprint != fingerprint.CertFromDER(leaf.DER) {
		t.Error("fingerprint is not x509-cert-sha256 of the DER")
	}
	wantKeyID, err := fingerprint.KeyIDFromPublicKey(leafKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if c.KeyIdentity != x509facts.KeyIdentityCanonical || c.KeyID != wantKeyID {
		t.Errorf("key identity %s %s, want canonical %s", c.KeyIdentity, c.KeyID, wantKeyID)
	}
	if c.EncodedSPKI != fingerprint.EncodedSPKIFromDER(leaf.Cert.RawSubjectPublicKeyInfo) {
		t.Error("encoded SPKI fingerprint mismatch")
	}
	if c.Version != 3 || c.SerialHex != "0102abcd" {
		t.Errorf("version %d serial %s", c.Version, c.SerialHex)
	}
	if c.Subject.CommonName != "api.example.test" || c.Subject.DN != "CN=api.example.test,O=Example" {
		t.Errorf("subject %+v", c.Subject)
	}
	if c.Issuer.CommonName != "Test CA" {
		t.Errorf("issuer %+v", c.Issuer)
	}
	if !c.NotBefore.Equal(notBefore) || !c.NotAfter.Equal(notAfter) {
		t.Errorf("validity %s – %s", c.NotBefore, c.NotAfter)
	}
	if c.PublicKey.Algorithm != "ECDSA" || c.PublicKey.Detail != "P-256" || c.PublicKey.Bits != 256 {
		t.Errorf("public key %+v", c.PublicKey)
	}
	if c.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("signature algorithm %s", c.SignatureAlgorithm)
	}
	if !slices.Equal(c.DNSNames, []string{"api.example.test", "*.example.test"}) ||
		!slices.Equal(c.IPAddresses, []string{"192.0.2.10", "2001:db8::1"}) ||
		!slices.Equal(c.EmailAddresses, []string{"ops@example.test"}) ||
		!slices.Equal(c.URIs, []string{"spiffe://example.test/api"}) {
		t.Errorf("SANs dns=%v ip=%v email=%v uri=%v", c.DNSNames, c.IPAddresses, c.EmailAddresses, c.URIs)
	}
	if !slices.Equal(c.KeyUsage, []string{"digitalSignature"}) {
		t.Errorf("key usage %v", c.KeyUsage)
	}
	if !slices.Equal(c.ExtKeyUsage, []string{"serverAuth", "clientAuth"}) {
		t.Errorf("ext key usage %v", c.ExtKeyUsage)
	}
	if c.BasicConstraints.Present || c.BasicConstraints.IsCA {
		t.Errorf("basic constraints %+v", c.BasicConstraints)
	}
	if c.SelfIssued || c.SelfSignature != x509facts.SignatureNotApplicable {
		t.Errorf("self-issued %v self-signature %s", c.SelfIssued, c.SelfSignature)
	}
	// Go generates a Subject Key Identifier only for CA certificates; the
	// leaf carries its issuer's as its Authority Key Identifier.
	if len(c.AuthorityKeyID) == 0 {
		t.Error("authority key identifier missing")
	}

	ext := map[string]x509facts.Extension{}
	for _, e := range c.Extensions {
		ext[e.OID] = e
	}
	if e := ext["2.5.29.17"]; e.Name != "subjectAltName" || e.Critical {
		t.Errorf("subjectAltName extension %+v", e)
	}
	if e := ext["2.5.29.15"]; e.Name != "keyUsage" || !e.Critical {
		t.Errorf("keyUsage extension %+v", e)
	}
}

func TestSelfSignedCAIsVerified(t *testing.T) {
	root := testpki.Issue(t, testpki.Template{
		CommonName: "Root", Serial: 7, NotBefore: notBefore, NotAfter: notAfter,
		IsCA: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign,
	}, testpki.ECDSAKey(t), nil)
	c := mustCertificate(t, root.DER)
	if !c.SelfIssued || c.SelfSignature != x509facts.SignatureVerified {
		t.Errorf("self-issued %v self-signature %s (%s)", c.SelfIssued, c.SelfSignature, c.SelfSignatureDetail)
	}
	if !c.BasicConstraints.Present || !c.BasicConstraints.IsCA || c.BasicConstraints.MaxPathLen == nil || *c.BasicConstraints.MaxPathLen != 1 {
		t.Errorf("basic constraints %+v", c.BasicConstraints)
	}
}

// TestWeakSelfSignatures pins Go's low-level CheckSignature behaviour, which
// the self-signature fact is built on: a SHA-1 signature still verifies (it is
// mathematically valid; interpret flags the algorithm), while MD5 is refused
// and reported as unverifiable — never as a failed signature.
func TestWeakSelfSignatures(t *testing.T) {
	key := testpki.RSAKey(t, 2048)
	base := testpki.Issue(t, testpki.Template{CommonName: "legacy", Serial: 1, NotBefore: notBefore, NotAfter: notAfter}, key, nil)

	for _, tc := range []struct {
		alg   testpki.SigAlg
		want  x509.SignatureAlgorithm
		check x509facts.SignatureCheck
	}{
		{testpki.RSAWithSHA1, x509.SHA1WithRSA, x509facts.SignatureVerified},
		{testpki.RSAWithMD5, x509.MD5WithRSA, x509facts.SignatureUnverifiable},
	} {
		t.Run(tc.want.String(), func(t *testing.T) {
			c := mustCertificate(t, testpki.Resign(t, base.DER, nil, tc.alg, key))
			if c.SignatureAlgorithm != tc.want {
				t.Fatalf("signature algorithm %s", c.SignatureAlgorithm)
			}
			if !c.SelfIssued || c.SelfSignature != tc.check {
				t.Errorf("self-signature %s (%s), want %s", c.SelfSignature, c.SelfSignatureDetail, tc.check)
			}
			if c.PublicKey.Algorithm != "RSA" || c.PublicKey.Bits != 2048 {
				t.Errorf("public key %+v", c.PublicKey)
			}
		})
	}
}

func TestSelfIssuedSignedByAnotherKeyFailsVerification(t *testing.T) {
	key := testpki.ECDSAKey(t)
	base := testpki.Issue(t, testpki.Template{CommonName: "impostor", Serial: 1, NotBefore: notBefore, NotAfter: notAfter}, key, nil)
	der := testpki.Resign(t, base.DER, nil, testpki.ECDSAWithSHA256, testpki.ECDSAKey(t))

	c := mustCertificate(t, der)
	if !c.SelfIssued || c.SelfSignature != x509facts.SignatureDoesNotVerify {
		t.Errorf("self-signature %s, want failed", c.SelfSignature)
	}
}

// TestNonCanonicalKeysAreSalvaged proves that a certificate Go will not parse
// still yields both fingerprints, and that its canonical key identity joins
// the canonically encoded key.
func TestNonCanonicalKeysAreSalvaged(t *testing.T) {
	signer := testpki.ECDSAKey(t)
	base := testpki.Issue(t, testpki.Template{CommonName: "noncanonical", Serial: 1, NotBefore: notBefore, NotAfter: notAfter}, signer, nil)

	rsaKey := testpki.RSAKey(t, 2048)
	ecKey := testpki.ECDSAKey(t)
	for name, tc := range map[string]struct {
		spki []byte
		pub  any
	}{
		"RSA without NULL parameters": {testpki.RSASPKIWithoutNULL(t, &rsaKey.PublicKey), rsaKey.Public()},
		"compressed P-256 point":      {testpki.CompressedP256SPKI(t, &ecKey.PublicKey), ecKey.Public()},
	} {
		t.Run(name, func(t *testing.T) {
			der := testpki.Resign(t, base.DER, tc.spki, testpki.ECDSAWithSHA256, signer)
			p := x509facts.FromDER(der)
			if p.Kind != x509facts.KindUnparseable || p.Unparseable == nil {
				t.Fatalf("want unparseable, got %s", p.Kind)
			}
			u := p.Unparseable
			if u.ParseError == "" {
				t.Error("parse error must be recorded")
			}
			if u.Fingerprint != fingerprint.CertFromDER(der) {
				t.Error("certificate fingerprint must come from the bytes")
			}
			if u.EncodedSPKI != fingerprint.EncodedSPKIFromDER(tc.spki) {
				t.Error("encoded SPKI fingerprint must be of the bytes as encoded")
			}
			want, err := fingerprint.KeyIDFromPublicKey(tc.pub)
			if err != nil {
				t.Fatal(err)
			}
			if u.KeyIdentity != x509facts.KeyIdentityNoncanonical || u.KeyID != want {
				t.Errorf("key identity %s %s, want noncanonical %s", u.KeyIdentity, u.KeyID, want)
			}
		})
	}
}

func TestUnsupportedKeyHasNoIdentity(t *testing.T) {
	signer := testpki.ECDSAKey(t)
	base := testpki.Issue(t, testpki.Template{CommonName: "x25519", Serial: 1, NotBefore: notBefore, NotAfter: notAfter}, signer, nil)
	xk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(xk.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	der := testpki.Resign(t, base.DER, spki, testpki.ECDSAWithSHA256, signer)

	c := mustCertificate(t, der)
	if c.KeyIdentity != x509facts.KeyIdentityUnsupported || !c.KeyID.IsZero() {
		t.Errorf("key identity %s %s, want unsupported with no KeyID", c.KeyIdentity, c.KeyID)
	}
	if c.EncodedSPKI != fingerprint.EncodedSPKIFromDER(spki) {
		t.Error("encoded fingerprint must still be observable")
	}
}

func TestMalformedKeyIsReported(t *testing.T) {
	signer := testpki.ECDSAKey(t)
	base := testpki.Issue(t, testpki.Template{CommonName: "bad key", Serial: 1, NotBefore: notBefore, NotAfter: notAfter}, signer, nil)
	shortEd25519 := testpki.SPKI(t, asn1.ObjectIdentifier{1, 3, 101, 112}, nil, make([]byte, 31))
	der := testpki.Resign(t, base.DER, shortEd25519, testpki.ECDSAWithSHA256, signer)

	p := x509facts.FromDER(der)
	if p.Kind != x509facts.KindUnparseable {
		t.Fatalf("want unparseable, got %s", p.Kind)
	}
	if p.Unparseable.KeyIdentity != x509facts.KeyIdentityMalformed || !p.Unparseable.KeyID.IsZero() {
		t.Errorf("key identity %s", p.Unparseable.KeyIdentity)
	}
}

func TestGarbageCertificate(t *testing.T) {
	der := []byte{0x30, 0x03, 0x02, 0x01, 0x00}
	p := x509facts.FromDER(der)
	if p.Kind != x509facts.KindUnparseable {
		t.Fatalf("kind %s", p.Kind)
	}
	if p.Unparseable.KeyIdentity != x509facts.KeyIdentityUnavailable || !p.Unparseable.EncodedSPKI.IsZero() {
		t.Errorf("no SPKI can be located, got %s", p.Unparseable.KeyIdentity)
	}
	if p.Unparseable.Fingerprint != fingerprint.CertFromDER(der) {
		t.Error("fingerprint of the bytes is still defined")
	}
}

func TestCertificateRequestIsRecognised(t *testing.T) {
	key := testpki.ECDSAKey(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	if p := x509facts.FromDER(csr); p.Kind != x509facts.KindCertificateRequest || p.Request == nil || p.Certificate != nil || p.Unparseable != nil {
		t.Errorf("kind %s", p.Kind)
	}
}

func FuzzFromDER(f *testing.F) {
	key := testpki.ECDSAKey(f)
	base := testpki.Issue(f, testpki.Template{CommonName: "seed", Serial: 1, NotBefore: notBefore, NotAfter: notAfter}, key, nil)
	f.Add(base.DER)
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, der []byte) {
		p := x509facts.FromDER(der)
		switch p.Kind {
		case x509facts.KindCertificate:
			if p.Certificate == nil || p.Unparseable != nil {
				t.Fatal("inconsistent certificate result")
			}
		case x509facts.KindUnparseable:
			if p.Unparseable == nil || p.Certificate != nil {
				t.Fatal("inconsistent unparseable result")
			}
		case x509facts.KindCertificateRequest:
			if p.Request == nil || p.Unparseable != nil || p.Certificate != nil || p.UnparseableRequest != nil {
				t.Fatal("inconsistent CSR result")
			}
		default:
			t.Fatalf("unknown kind %q", p.Kind)
		}
	})
}
