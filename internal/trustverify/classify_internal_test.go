package trustverify

import (
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestClassifyTypedErrors(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	future := &x509.Certificate{NotBefore: now.Add(time.Hour), NotAfter: now.Add(2 * time.Hour)}
	past := &x509.Certificate{NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)}
	for _, tc := range []struct {
		err    error
		state  State
		reason Reason
	}{
		{x509.UnhandledCriticalExtension{}, Failed, ReasonUnhandledCriticalExtension},
		{x509.InsecureAlgorithmError(x509.SHA1WithRSA), Failed, ReasonInsecureSignatureAlgorithm},
		{x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign}, Failed, ReasonIssuerNotAuthorized},
		{x509.CertificateInvalidError{Cert: past, Reason: x509.Expired}, Failed, ReasonExpired},
		{x509.CertificateInvalidError{Cert: future, Reason: x509.Expired}, Failed, ReasonNotYetValid},
		{x509.CertificateInvalidError{Reason: x509.CANotAuthorizedForThisName}, Failed, ReasonNameConstraints},
		{x509.CertificateInvalidError{Reason: x509.UnconstrainedName}, Failed, ReasonNameConstraints},
		{x509.CertificateInvalidError{Reason: x509.TooManyConstraints}, Unverifiable, ReasonEngineLimit},
		{x509.CertificateInvalidError{Reason: x509.TooManyIntermediates}, Failed, ReasonPathLength},
		{x509.CertificateInvalidError{Reason: x509.IncompatibleUsage}, Failed, ReasonIncompatibleUsage},
		{x509.CertificateInvalidError{Reason: x509.NoValidChains, Detail: "1 candidate chains with invalid policies"}, Failed, ReasonPolicy},
		{x509.CertificateInvalidError{Reason: x509.NoValidChains, Detail: "1 candidate chains with incompatible key usage, 1 candidate chains with invalid policies"}, Unverifiable, ReasonEngineError},
		{x509.CertificateInvalidError{Reason: x509.NoValidChains}, Unverifiable, ReasonEngineError},
		{x509.CertificateInvalidError{Reason: x509.InvalidReason(999)}, Unverifiable, ReasonEngineError},
		{x509.UnknownAuthorityError{}, Failed, ReasonNoAnchorPath},
		{fmt.Errorf("wrapped: %w", x509.CertificateInvalidError{Reason: x509.TooManyIntermediates}), Failed, ReasonPathLength},
		{errors.New("x509: signature check attempts limit reached while verifying certificate chain"), Unverifiable, ReasonEngineLimit},
		{errors.New("something the classifier has never seen"), Unverifiable, ReasonEngineError},
		{x509.SystemRootsError{}, Unverifiable, ReasonEngineError},
	} {
		state, reason := classify(tc.err, now)
		if state != tc.state || reason != tc.reason {
			t.Errorf("%T %v: %s/%s, want %s/%s", tc.err, tc.err, state, reason, tc.state, tc.reason)
		}
	}
}

func TestClassifyHint(t *testing.T) {
	wrap := func(hint string) string {
		return fmt.Sprintf("x509: certificate signed by unknown authority (possibly because of %q while trying to verify candidate authority certificate %q)", hint, "Some CA")
	}
	for _, tc := range []struct {
		msg    string
		state  State
		reason Reason
	}{
		{"x509: certificate signed by unknown authority", Failed, ReasonNoAnchorPath},
		{wrap("x509: cannot verify signature: insecure algorithm SHA1-RSA"), Failed, ReasonInsecureSignatureAlgorithm},
		{wrap("x509: certificate has expired or is not yet valid: current time 2026-09-14T12:00:00Z is after 2026-06-01T00:00:00Z"), Failed, ReasonExpired},
		{wrap("x509: certificate has expired or is not yet valid: current time 2026-09-14T12:00:00Z is before 2026-10-01T00:00:00Z"), Failed, ReasonNotYetValid},
		{wrap("x509: invalid signature: parent certificate cannot sign this kind of certificate"), Failed, ReasonIssuerNotAuthorized},
		{wrap("x509: certificate is not authorized to sign other certificates"), Failed, ReasonIssuerNotAuthorized},
		{wrap("x509: too many intermediates for path length constraint"), Failed, ReasonPathLength},
		{wrap("x509: unhandled critical extension"), Failed, ReasonUnhandledCriticalExtension},
		{wrap("x509: a root or intermediate certificate is not authorized to sign for this name: DNS name \"a.b\" is not permitted"), Failed, ReasonNameConstraints},
		{wrap("x509: ECDSA verification failure"), Failed, ReasonNoAnchorPath},
		{wrap("crypto/rsa: verification error"), Failed, ReasonNoAnchorPath},
		{wrap("x509: signature algorithm specifies an RSA public key, but have public key of type *ecdsa.PublicKey"), Failed, ReasonNoAnchorPath},
		{wrap("x509: a message Go has never produced"), Unverifiable, ReasonEngineError},
	} {
		state, reason := classifyHint(tc.msg)
		if state != tc.state || reason != tc.reason {
			t.Errorf("%q: %s/%s, want %s/%s", tc.msg, state, reason, tc.state, tc.reason)
		}
	}
}
