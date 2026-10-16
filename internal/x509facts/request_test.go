package x509facts_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/sigcheck"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

func mustRequest(t *testing.T, der []byte) *x509facts.CertificateRequest {
	t.Helper()
	p := x509facts.FromRequestDER(der)
	if p.Kind != x509facts.KindCertificateRequest || p.Request == nil {
		t.Fatalf("want a parsed request, got kind %s (%+v)", p.Kind, p.UnparseableRequest)
	}
	return p.Request
}

func extension(t *testing.T, oid asn1.ObjectIdentifier, critical bool, value any) pkix.Extension {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oid, Critical: critical, Value: der}
}

var (
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
)

func TestRequestFacts(t *testing.T) {
	key := testpki.ECDSAKey(t)
	der := testpki.Request(t, testpki.RequestTemplate{
		CommonName: "api.example.test", Organization: "Example",
		DNSNames: []string{"api.example.test", "www.example.test"}, IPAddresses: []string{"192.0.2.10", "2001:db8::1"},
		EmailAddresses: []string{"ops@example.test"}, URIs: []string{"spiffe://example.test/api"},
		ExtraExtensions: []pkix.Extension{
			// digitalSignature (bit 0) and keyEncipherment (bit 2).
			extension(t, oidKeyUsage, true, asn1.BitString{Bytes: []byte{0xa0}, BitLength: 3}),
			extension(t, oidExtKeyUsage, false, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}, {1, 2, 3, 4}}),
			extension(t, oidBasicConstraints, true, struct{}{}),
		},
	}, key)

	r := mustRequest(t, der)
	wantKeyID, err := fingerprint.KeyIDFromPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	// The request's key identity is the identity of the certificate that
	// will be issued for it: that is how the two are matched.
	if r.KeyIdentity != x509facts.KeyIdentityCanonical || r.KeyID != wantKeyID {
		t.Errorf("key identity %s %s, want canonical %s", r.KeyIdentity, r.KeyID, wantKeyID)
	}
	issued := testpki.Issue(t, testpki.Template{CommonName: "api.example.test", Serial: 1, NotBefore: notBefore, NotAfter: notAfter}, key, nil)
	if mustCertificate(t, issued.DER).KeyID != r.KeyID {
		t.Error("a certificate for the requested key must have the same x509-spki-sha256")
	}
	if r.Subject.DN != "CN=api.example.test,O=Example" || r.Subject.CommonName != "api.example.test" {
		t.Errorf("subject %+v", r.Subject)
	}
	if r.PublicKey.Algorithm != "ECDSA" || r.PublicKey.Detail != "P-256" || r.PublicKey.Bits != 256 {
		t.Errorf("public key %+v", r.PublicKey)
	}
	if r.SignatureAlgorithm != x509.ECDSAWithSHA256 || r.SignatureAlgorithmOID != "1.2.840.10045.4.3.2" {
		t.Errorf("signature algorithm %s %s", r.SignatureAlgorithm, r.SignatureAlgorithmOID)
	}
	if r.Signature != x509facts.SignatureVerified || r.SignatureReason != sigcheck.ReasonNone {
		t.Errorf("signature %s %s", r.Signature, r.SignatureReason)
	}
	if !slices.Equal(r.DNSNames, []string{"api.example.test", "www.example.test"}) ||
		!slices.Equal(r.IPAddresses, []string{"192.0.2.10", "2001:db8::1"}) ||
		!slices.Equal(r.EmailAddresses, []string{"ops@example.test"}) ||
		!slices.Equal(r.URIs, []string{"spiffe://example.test/api"}) {
		t.Errorf("SANs %v %v %v %v", r.DNSNames, r.IPAddresses, r.EmailAddresses, r.URIs)
	}
	if !slices.Equal(r.KeyUsage, []string{"digitalSignature", "keyEncipherment"}) {
		t.Errorf("key usage %v", r.KeyUsage)
	}
	if !slices.Equal(r.ExtKeyUsage, []string{"serverAuth", "1.2.3.4"}) {
		t.Errorf("extended key usage %v", r.ExtKeyUsage)
	}
	if r.BasicConstraints != (x509facts.BasicConstraints{Present: true}) || len(r.UndecodedExtensions) != 0 {
		t.Errorf("basic constraints %+v undecoded %v", r.BasicConstraints, r.UndecodedExtensions)
	}
	var exts []string
	for _, e := range r.Extensions {
		exts = append(exts, e.OID+"/"+e.Name+"/"+map[bool]string{true: "critical", false: ""}[e.Critical])
	}
	if !slices.Equal(exts, []string{"2.5.29.17/subjectAltName/", "2.5.29.15/keyUsage/critical", "2.5.29.37/extKeyUsage/", "2.5.29.19/basicConstraints/critical"}) {
		t.Errorf("extensions %v", exts)
	}
	if !slices.Equal(r.Attributes, []x509facts.Attribute{{OID: "1.2.840.113549.1.9.14", Name: "extensionRequest"}}) {
		t.Errorf("attributes %+v", r.Attributes)
	}
}

func TestRequestBasicConstraints(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
		want  x509facts.BasicConstraints
	}{
		{"CA without limit", struct{ IsCA bool }{true}, x509facts.BasicConstraints{Present: true, IsCA: true}},
		{"CA with path length 0", struct {
			IsCA bool
			N    int
		}{true, 0}, x509facts.BasicConstraints{Present: true, IsCA: true, MaxPathLen: new(0)}},
		{"not a CA", struct{}{}, x509facts.BasicConstraints{Present: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := mustRequest(t, testpki.Request(t, testpki.RequestTemplate{
				CommonName: "CA", ExtraExtensions: []pkix.Extension{extension(t, oidBasicConstraints, true, tc.value)},
			}, testpki.ECDSAKey(t)))
			got := r.BasicConstraints
			if got.Present != tc.want.Present || got.IsCA != tc.want.IsCA || (got.MaxPathLen == nil) != (tc.want.MaxPathLen == nil) ||
				(got.MaxPathLen != nil && *got.MaxPathLen != *tc.want.MaxPathLen) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestUndecodableRequestedExtensionIsListed: a requested extension whose
// value Trustsmith cannot decode is named, never reported as absent.
func TestUndecodableRequestedExtensionIsListed(t *testing.T) {
	r := mustRequest(t, testpki.Request(t, testpki.RequestTemplate{
		CommonName: "odd", ExtraExtensions: []pkix.Extension{{Id: oidKeyUsage, Value: []byte{0x05, 0x00}}},
	}, testpki.ECDSAKey(t)))
	if r.KeyUsage != nil || !slices.Equal(r.UndecodedExtensions, []string{"2.5.29.15"}) {
		t.Errorf("key usage %v undecoded %v", r.KeyUsage, r.UndecodedExtensions)
	}
}

func TestRequestSignatureStates(t *testing.T) {
	rsaKey := testpki.RSAKey(t, 2048)
	base := testpki.Request(t, testpki.RequestTemplate{CommonName: "x"}, rsaKey)
	for _, tc := range []struct {
		name   string
		der    []byte
		state  x509facts.SignatureCheck
		reason sigcheck.Reason
	}{
		{"verified", base, x509facts.SignatureVerified, sigcheck.ReasonNone},
		{"SHA-1 verifies", testpki.ResignRequest(t, base, nil, testpki.RSAWithSHA1, rsaKey), x509facts.SignatureVerified, sigcheck.ReasonNone},
		{"MD5 is refused", testpki.ResignRequest(t, base, nil, testpki.RSAWithMD5, rsaKey), x509facts.SignatureUnverifiable, sigcheck.ReasonInsecureAlgorithm},
		{"corrupt", testpki.CorruptSignature(base), x509facts.SignatureDoesNotVerify, sigcheck.ReasonSignatureMismatch},
		{"algorithm does not match the key", testpki.ResignRequest(t, testpki.Request(t, testpki.RequestTemplate{CommonName: "x"}, testpki.ECDSAKey(t)), nil, testpki.RSAWithSHA256, rsaKey),
			x509facts.SignatureDoesNotVerify, sigcheck.ReasonKeyAlgorithmMismatch},
		// An X25519 key cannot sign, so possession of it cannot be proven.
		{"X25519 key", testpki.ResignRequest(t, base, testpki.X25519SPKI(t), testpki.RSAWithSHA256, rsaKey),
			x509facts.SignatureUnverifiable, sigcheck.ReasonUnsupportedAlgorithm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := mustRequest(t, tc.der)
			if r.Signature != tc.state || r.SignatureReason != tc.reason {
				t.Errorf("got %s/%s (%s), want %s/%s", r.Signature, r.SignatureReason, r.SignatureDetail, tc.state, tc.reason)
			}
		})
	}
}

// TestRequestLabelDecidesTheParser: a block labelled as a request is parsed
// only as a request, so a certificate inside it is an unparseable request,
// with its key still located where a request keeps it (here: nowhere).
func TestRequestLabelDecidesTheParser(t *testing.T) {
	cert := testpki.Issue(t, testpki.Template{CommonName: "c", Serial: 1, NotBefore: notBefore, NotAfter: notAfter}, testpki.ECDSAKey(t), nil)
	p := x509facts.FromRequestDER(cert.DER)
	if p.Kind != x509facts.KindUnparseableRequest || p.UnparseableRequest == nil || p.UnparseableRequest.ParseError == "" || p.Certificate != nil {
		t.Fatalf("got %+v", p)
	}
}

func TestUnparseableRequestKeepsKeyFingerprints(t *testing.T) {
	rsaKey := testpki.RSAKey(t, 2048)
	base := testpki.Request(t, testpki.RequestTemplate{CommonName: "x"}, rsaKey)
	spki := testpki.RSASPKIWithoutNULL(t, &rsaKey.PublicKey)
	p := x509facts.FromRequestDER(testpki.ResignRequest(t, base, spki, testpki.RSAWithSHA256, rsaKey))
	if p.Kind != x509facts.KindUnparseableRequest {
		t.Fatalf("kind %s", p.Kind)
	}
	u := p.UnparseableRequest
	wantKeyID, err := fingerprint.KeyIDFromPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if u.KeyIdentity != x509facts.KeyIdentityNoncanonical || u.KeyID != wantKeyID || u.EncodedSPKI != fingerprint.EncodedSPKIFromDER(spki) {
		t.Errorf("identity %+v", u.SPKIIdentity)
	}

	if p := x509facts.FromRequestDER([]byte{0x30, 0x03, 0x02, 0x01, 0x00}); p.Kind != x509facts.KindUnparseableRequest ||
		p.UnparseableRequest.KeyIdentity != x509facts.KeyIdentityUnavailable {
		t.Errorf("garbage: %+v", p)
	}
}

func FuzzFromRequestDER(f *testing.F) {
	f.Add(testpki.Request(f, testpki.RequestTemplate{CommonName: "seed", DNSNames: []string{"seed.example.test"}}, testpki.ECDSAKey(f)))
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, der []byte) {
		p := x509facts.FromRequestDER(der)
		switch p.Kind {
		case x509facts.KindCertificateRequest:
			if p.Request == nil || p.UnparseableRequest != nil {
				t.Fatal("inconsistent request result")
			}
		case x509facts.KindUnparseableRequest:
			if p.UnparseableRequest == nil || p.Request != nil {
				t.Fatal("inconsistent unparseable request result")
			}
		default:
			t.Fatalf("unexpected kind %q", p.Kind)
		}
		if p.Certificate != nil || p.Unparseable != nil || p.ParserPanicked {
			t.Fatal("a request-framed block is never a certificate, and the parser must not panic")
		}
	})
}
