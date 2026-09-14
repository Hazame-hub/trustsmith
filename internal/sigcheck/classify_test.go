package sigcheck

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
)

// TestClassify pins how verification errors map to states. The string
// patterns are the only place Trustsmith depends on Go's error text; the
// real-signature tests in sigcheck_test.go detect if Go changes that text.
func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		state  State
		reason Reason
	}{
		{"success", nil, Verified, ReasonNone},
		{"insecure algorithm", x509.InsecureAlgorithmError(x509.MD5WithRSA), Unverifiable, ReasonInsecureAlgorithm},
		{"wrapped insecure algorithm", fmt.Errorf("context: %w", x509.InsecureAlgorithmError(x509.SHA1WithRSA)), Unverifiable, ReasonInsecureAlgorithm},
		{"unsupported algorithm", x509.ErrUnsupportedAlgorithm, Unverifiable, ReasonUnsupportedAlgorithm},
		{"RSA mismatch", rsa.ErrVerification, Invalid, ReasonSignatureMismatch},
		{"ECDSA mismatch", errors.New("x509: ECDSA verification failure"), Invalid, ReasonSignatureMismatch},
		{"Ed25519 mismatch", errors.New("x509: Ed25519 verification failure"), Invalid, ReasonSignatureMismatch},
		{"ML-DSA mismatch", fmt.Errorf("x509: ML-DSA verification failure: %w", errors.New("mldsa: invalid signature")), Invalid, ReasonSignatureMismatch},
		{"key algorithm mismatch", errors.New("x509: signature algorithm specifies an RSA public key, but have public key of type *ecdsa.PublicKey"), Invalid, ReasonKeyAlgorithmMismatch},
		{"ML-DSA parameter mismatch", errors.New("x509: signature algorithm specifies an ML-DSA public key with ML-DSA-65 parameters, but have a public key with ML-DSA-44 parameters"), Invalid, ReasonKeyAlgorithmMismatch},
		{"insecure RSA key size", errors.New("crypto/rsa: 1023-bit keys are insecure"), Unverifiable, ReasonEngineError},
		{"anything unrecognised", errors.New("something Go will say one day"), Unverifiable, ReasonEngineError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, reason := classify(tc.err)
			if state != tc.state || reason != tc.reason {
				t.Errorf("classify(%v) = %s/%s, want %s/%s", tc.err, state, reason, tc.state, tc.reason)
			}
		})
	}
}

// TestPanicDuringVerificationIsContained proves the recovery boundary: a
// panic inside the verification engine becomes an unverifiable result with a
// stable reason callers can count, never "invalid".
func TestPanicDuringVerificationIsContained(t *testing.T) {
	original := checkSignature
	t.Cleanup(func() { checkSignature = original })
	checkSignature = func(_, _ *x509.Certificate) error { panic("engine exploded") }

	got := Certificate(&x509.Certificate{}, &x509.Certificate{})
	if got.State != Unverifiable || got.Reason != ReasonEnginePanic {
		t.Errorf("got %s/%s, want unverifiable/engine_panic", got.State, got.Reason)
	}
}
