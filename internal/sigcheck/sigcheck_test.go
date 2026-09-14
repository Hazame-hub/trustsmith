package sigcheck_test

import (
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/sigcheck"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
)

var (
	notBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
)

func ca(t *testing.T, cn string, key crypto.Signer) *testpki.Cert {
	t.Helper()
	return testpki.Issue(t, testpki.Template{
		CommonName: cn, Serial: 1, NotBefore: notBefore, NotAfter: notAfter,
		IsCA: true, MaxPathLen: -1, KeyUsage: x509.KeyUsageCertSign,
	}, key, nil)
}

func leaf(t *testing.T, parent *testpki.Cert) *testpki.Cert {
	t.Helper()
	return testpki.Issue(t, testpki.Template{
		CommonName: "leaf.example.test", Serial: 2, NotBefore: notBefore, NotAfter: notAfter,
		DNSNames: []string{"leaf.example.test"},
	}, testpki.ECDSAKey(t), parent)
}

func parse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func assertResult(t *testing.T, got sigcheck.Result, state sigcheck.State, reason sigcheck.Reason) {
	t.Helper()
	if got.State != state || got.Reason != reason {
		t.Errorf("got %s/%s (%s), want %s/%s", got.State, got.Reason, got.Detail, state, reason)
	}
}

type keyType struct {
	name string
	key  func(*testing.T) crypto.Signer
}

var keyTypes = []keyType{
	{"ECDSA P-256", func(t *testing.T) crypto.Signer { return testpki.ECDSAKey(t) }},
	{"RSA 2048", func(t *testing.T) crypto.Signer { return testpki.RSAKey(t, 2048) }},
	{"Ed25519", func(t *testing.T) crypto.Signer { return testpki.Ed25519Key(t) }},
	{"ML-DSA-65", func(t *testing.T) crypto.Signer { return testpki.MLDSAKey(t, mldsa.MLDSA65()) }},
}

func TestSignatureVerifiesWithTheSignersKey(t *testing.T) {
	for _, kt := range keyTypes {
		t.Run(kt.name, func(t *testing.T) {
			issuer := ca(t, "CA", kt.key(t))
			child := leaf(t, issuer)
			assertResult(t, sigcheck.Certificate(child.Cert, issuer.Cert), sigcheck.Verified, sigcheck.ReasonNone)
		})
	}
}

func TestAnotherKeyOfTheSameTypeIsInvalid(t *testing.T) {
	for _, kt := range keyTypes {
		t.Run(kt.name, func(t *testing.T) {
			child := leaf(t, ca(t, "CA", kt.key(t)))
			impostor := ca(t, "CA", kt.key(t)) // same name, different key
			assertResult(t, sigcheck.Certificate(child.Cert, impostor.Cert), sigcheck.Invalid, sigcheck.ReasonSignatureMismatch)
		})
	}
}

func TestKeyAlgorithmMismatchIsInvalid(t *testing.T) {
	t.Run("ECDSA signature, RSA key", func(t *testing.T) {
		child := leaf(t, ca(t, "CA", testpki.ECDSAKey(t)))
		other := ca(t, "CA", testpki.RSAKey(t, 2048))
		assertResult(t, sigcheck.Certificate(child.Cert, other.Cert), sigcheck.Invalid, sigcheck.ReasonKeyAlgorithmMismatch)
	})
	t.Run("ML-DSA-65 signature, ML-DSA-44 key", func(t *testing.T) {
		child := leaf(t, ca(t, "CA", testpki.MLDSAKey(t, mldsa.MLDSA65())))
		other := ca(t, "CA", testpki.MLDSAKey(t, mldsa.MLDSA44()))
		assertResult(t, sigcheck.Certificate(child.Cert, other.Cert), sigcheck.Invalid, sigcheck.ReasonKeyAlgorithmMismatch)
	})
}

// TestSHA1CertificateSignaturesVerify pins Go 1.27 behaviour: the low-level
// Certificate.CheckSignature used by sigcheck verifies SHA-1 certificate
// signatures, while CheckSignatureFrom refuses them. A verified SHA-1
// signature is a cryptographic fact; whether SHA-1 is acceptable is a
// separate finding (sig.sha1).
func TestSHA1CertificateSignaturesVerify(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  func(*testing.T) crypto.Signer
		alg  testpki.SigAlg
		want x509.SignatureAlgorithm
	}{
		{"RSA", func(t *testing.T) crypto.Signer { return testpki.RSAKey(t, 2048) }, testpki.RSAWithSHA1, x509.SHA1WithRSA},
		{"ECDSA", func(t *testing.T) crypto.Signer { return testpki.ECDSAKey(t) }, testpki.ECDSAWithSHA1, x509.ECDSAWithSHA1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer := ca(t, "SHA-1 CA", tc.key(t))
			child := parse(t, testpki.Resign(t, leaf(t, issuer).DER, nil, tc.alg, issuer.Key))
			if child.SignatureAlgorithm != tc.want {
				t.Fatalf("signature algorithm %s", child.SignatureAlgorithm)
			}
			assertResult(t, sigcheck.Certificate(child, issuer.Cert), sigcheck.Verified, sigcheck.ReasonNone)

			var insecure x509.InsecureAlgorithmError
			if err := child.CheckSignatureFrom(issuer.Cert); !errors.As(err, &insecure) {
				t.Errorf("CheckSignatureFrom: got %v, want InsecureAlgorithmError (this is why sigcheck does not use it)", err)
			}
		})
	}
}

func TestMD5IsUnverifiableNotInvalid(t *testing.T) {
	issuer := ca(t, "MD5 CA", testpki.RSAKey(t, 2048))
	child := parse(t, testpki.Resign(t, leaf(t, issuer).DER, nil, testpki.RSAWithMD5, issuer.Key))
	assertResult(t, sigcheck.Certificate(child, issuer.Cert), sigcheck.Unverifiable, sigcheck.ReasonInsecureAlgorithm)

	// Even the wrong key cannot turn an algorithm the engine refuses into
	// "invalid": Go never evaluates the signature.
	other := ca(t, "MD5 CA", testpki.RSAKey(t, 2048))
	assertResult(t, sigcheck.Certificate(child, other.Cert), sigcheck.Unverifiable, sigcheck.ReasonInsecureAlgorithm)
}

func TestSignerKeyThatCannotVerifyIsUnverifiable(t *testing.T) {
	signerKey := testpki.ECDSAKey(t)
	issuer := ca(t, "CA", signerKey)
	child := leaf(t, issuer)
	// A certificate carrying an X25519 key: a key type that cannot verify
	// certificate signatures at all.
	x25519 := parse(t, testpki.Resign(t, issuer.DER, testpki.X25519SPKI(t), testpki.ECDSAWithSHA256, signerKey))
	assertResult(t, sigcheck.Certificate(child.Cert, x25519), sigcheck.Unverifiable, sigcheck.ReasonUnsupportedAlgorithm)
}

// TestNoCertificateAuthorityPolicyIsApplied pins that a relationship is only a
// signature check: a signer that is not a CA still verifies, which
// CheckSignatureFrom would reject as a constraint violation.
func TestNoCertificateAuthorityPolicyIsApplied(t *testing.T) {
	notCA := testpki.Issue(t, testpki.Template{
		CommonName: "not a CA", Serial: 9, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, testpki.ECDSAKey(t), nil)
	child := leaf(t, notCA)
	assertResult(t, sigcheck.Certificate(child.Cert, notCA.Cert), sigcheck.Verified, sigcheck.ReasonNone)

	var constraint x509.ConstraintViolationError
	if err := child.Cert.CheckSignatureFrom(notCA.Cert); !errors.As(err, &constraint) {
		t.Errorf("CheckSignatureFrom: got %v, want ConstraintViolationError", err)
	}
}

func TestVerificationUsesTheExactSignedBytes(t *testing.T) {
	issuer := ca(t, "CA", testpki.ECDSAKey(t))
	child := leaf(t, issuer)
	tampered := *child.Cert
	tampered.RawTBSCertificate = append([]byte{}, child.Cert.RawTBSCertificate...)
	tampered.RawTBSCertificate[len(tampered.RawTBSCertificate)-1] ^= 0x01
	assertResult(t, sigcheck.Certificate(&tampered, issuer.Cert), sigcheck.Invalid, sigcheck.ReasonSignatureMismatch)
}
