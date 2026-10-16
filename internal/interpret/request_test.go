package interpret_test

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/artifact"
	"github.com/Hazame-hub/trustsmith/internal/interpret"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

// inspectRequest interprets one PEM-framed certificate signing request and
// checks every emitted code is catalogued.
func inspectRequest(t *testing.T, der []byte) interpret.Entry {
	t.Helper()
	p := x509facts.FromRequestDER(der)
	e := interpret.Block(artifact.Block{Kind: artifact.KindCertificateRequest, Label: "CERTIFICATE REQUEST", DER: der},
		&p, interpret.Issuers{}, notBefore, th)
	assertCatalogued(t, e.Findings)
	if e.Summary != nil {
		t.Error("a certificate signing request must never get a certificate summary")
	}
	return e
}

func serverRequest(cn string) testpki.RequestTemplate {
	return testpki.RequestTemplate{CommonName: cn, DNSNames: []string{cn}, IPAddresses: []string{"192.0.2.10"}}
}

func TestGoodRequestHasNoFindings(t *testing.T) {
	e := inspectRequest(t, testpki.Request(t, serverRequest("api.example.test"), testpki.ECDSAKey(t)))
	assertCodes(t, e.Findings)
	r := e.Request
	if r == nil {
		t.Fatal("no request summary")
	}
	if r.Kind != "Certificate signing request" || r.Key != "ECDSA P-256" || r.Signature != "ECDSA-SHA256" ||
		r.SignatureCheck != interpret.RequestSignatureVerified || r.SignatureReason != "" {
		t.Errorf("summary %+v", r)
	}
	if !slices.Equal(r.Requests, []string{"api.example.test", "192.0.2.10"}) || r.Subject != "CN=api.example.test" {
		t.Errorf("requests %v subject %q", r.Requests, r.Subject)
	}
}

func TestRequestFindings(t *testing.T) {
	rsaKey := testpki.RSAKey(t, 2048)
	base := testpki.Request(t, serverRequest("legacy.example.test"), rsaKey)
	caRequest := testpki.RequestTemplate{CommonName: "Example Issuing CA", ExtraExtensions: []pkix.Extension{basicConstraintsCA(t)}}

	for _, tc := range []struct {
		name  string
		der   []byte
		want  []string
		check interpret.RequestSignature
	}{
		{"RSA 1024", testpki.Request(t, serverRequest("small.example.test"), testpki.RSAKey(t, 1024)),
			[]string{"key.rsa_under_2048:critical"}, interpret.RequestSignatureVerified},
		// Go verifies SHA-1 request signatures, and refuses MD5: neither is
		// claimed invalid, and both are critical for a CA.
		{"SHA-1", testpki.ResignRequest(t, base, nil, testpki.RSAWithSHA1, rsaKey),
			[]string{"sig.sha1:critical"}, interpret.RequestSignatureVerified},
		{"MD5", testpki.ResignRequest(t, base, nil, testpki.RSAWithMD5, rsaKey),
			[]string{"csr.signature_unverifiable:warning", "sig.md5:critical"}, interpret.RequestSignatureUnverifiable},
		{"corrupted signature", testpki.CorruptSignature(base),
			[]string{"csr.signature_invalid:critical"}, interpret.RequestSignatureDoesNotVerify},
		{"signed by another key", testpki.ResignRequest(t, base, nil, testpki.RSAWithSHA256, testpki.RSAKey(t, 2048)),
			[]string{"csr.signature_invalid:critical"}, interpret.RequestSignatureDoesNotVerify},
		{"Common Name only", testpki.Request(t, testpki.RequestTemplate{CommonName: "cn-only.example.test"}, testpki.ECDSAKey(t)),
			[]string{"name.cn_only_no_san:warning"}, interpret.RequestSignatureVerified},
		// As for certificates, a CA is not expected to carry host names.
		{"CA request without SANs", testpki.Request(t, caRequest, testpki.ECDSAKey(t)), nil, interpret.RequestSignatureVerified},
		{"no names at all", testpki.Request(t, testpki.RequestTemplate{}, testpki.ECDSAKey(t)), nil, interpret.RequestSignatureVerified},
		// An X25519 key cannot sign, so nothing can prove possession of it.
		{"X25519 key", testpki.ResignRequest(t, base, testpki.X25519SPKI(t), testpki.RSAWithSHA256, rsaKey),
			[]string{"csr.signature_unverifiable:warning", "key.unsupported_for_identity:info"}, interpret.RequestSignatureUnverifiable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := inspectRequest(t, tc.der)
			assertCodes(t, e.Findings, tc.want...)
			if e.Request == nil || e.Request.SignatureCheck != tc.check {
				t.Fatalf("summary %+v, want signature %s", e.Request, tc.check)
			}
			if tc.check != interpret.RequestSignatureVerified && e.Request.SignatureReason == "" {
				t.Error("a signature that did not verify needs a reason")
			}
		})
	}
}

func TestRequestSignatureFindingEvidence(t *testing.T) {
	key := testpki.ECDSAKey(t)
	e := inspectRequest(t, testpki.CorruptSignature(testpki.Request(t, serverRequest("api.example.test"), key)))
	if len(e.Findings) != 1 || evidence(e.Findings[0], "reason") != "signature_mismatch" ||
		evidence(e.Findings[0], "signature_algorithm") != "ECDSA-SHA256" {
		t.Errorf("findings %+v", e.Findings)
	}
}

func TestCARequestKind(t *testing.T) {
	e := inspectRequest(t, testpki.Request(t, testpki.RequestTemplate{
		CommonName: "Example Issuing CA", ExtraExtensions: []pkix.Extension{basicConstraintsCA(t)},
	}, testpki.ECDSAKey(t)))
	if e.Request.Kind != "Certificate signing request for a CA certificate" || !slices.Equal(e.Request.Requests, []string{"CN=Example Issuing CA"}) {
		t.Errorf("summary %+v", e.Request)
	}
}

// TestUnparseableRequestKeepsKeyIdentity mirrors certificates: a request Go
// rejects (here for an RSA key without NULL parameters) still gets its key
// fingerprints, and the non-canonical encoding is reported.
func TestUnparseableRequestKeepsKeyIdentity(t *testing.T) {
	rsaKey := testpki.RSAKey(t, 2048)
	base := testpki.Request(t, serverRequest("odd.example.test"), rsaKey)
	der := testpki.ResignRequest(t, base, testpki.RSASPKIWithoutNULL(t, &rsaKey.PublicKey), testpki.RSAWithSHA256, rsaKey)

	e := inspectRequest(t, der)
	if e.Request != nil {
		t.Error("an unparseable request must not get a friendly summary")
	}
	assertCodes(t, e.Findings, "input.unparseable_certificate_request:critical", "key.noncanonical_spki:warning")
}

func basicConstraintsCA(t *testing.T) pkix.Extension {
	t.Helper()
	value, err := asn1.Marshal(struct{ IsCA bool }{true})
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: value}
}
