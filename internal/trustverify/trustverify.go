// Package trustverify validates a certificate against trust anchors the user
// supplied explicitly, using the Go standard library's crypto/x509 verifier.
//
// Trust comes only from the supplied anchors. Being present in the inspected
// input, or being self-signed, never makes a certificate an anchor.
//
// The result reports what Go's verifier concluded. It is not an independent
// implementation of RFC 5280 path validation, and it says nothing beyond the
// anchors it was given.
//
// This is the only package allowed to call x509.Certificate.Verify or build a
// certificate pool (internal/archtest). Every VerifyOptions field that
// matters is set at the call site, because Go's defaults are unsafe here:
//   - nil Roots load the system trust store;
//   - empty KeyUsages mean server authentication;
//   - a zero CurrentTime reads the system clock.
package trustverify

import (
	"bytes"
	"crypto/x509"
	"errors"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
)

// Engine names the verifier whose conclusion a Result reports.
const Engine = "go-x509"

// EngineVersion is the Go release whose crypto/x509 performed the validation.
func EngineVersion() string { return runtime.Version() }

// MaxConstraintComparisons is passed as VerifyOptions.MaxConstraintComparisions.
// Go 1.27.1's crypto/x509 does not read that field: its name-constraint checking
// no longer uses it. The value, Go's former default, is set explicitly anyway,
// so that no bound is left to a default if a later Go honours the option again.
const MaxConstraintComparisons = 250000

// State is the outcome of validating one certificate against the anchors.
type State string

const (
	// NotEvaluated: no anchors were supplied, so trust was not evaluated.
	NotEvaluated State = "not_evaluated"
	// Verified: Go's verifier built at least one chain from the certificate
	// to a supplied anchor.
	Verified State = "verified"
	// Failed: Go's verifier rejected the certificate, for a reason it states.
	Failed State = "failed"
	// Unverifiable: the verifier could not reach a conclusion Trustsmith can
	// classify, for example because a work limit was reached.
	Unverifiable State = "unverifiable"
)

// Reason is a stable code for a result that is not verified. Raw verifier
// messages are never part of the contract.
type Reason string

const (
	ReasonNone Reason = ""
	// ReasonNoAnchorPath: no chain to any supplied anchor could be built. The
	// only trust source checked was the supplied anchors.
	ReasonNoAnchorPath               Reason = "no_explicit_anchor_path"
	ReasonExpired                    Reason = "certificate_expired"
	ReasonNotYetValid                Reason = "certificate_not_yet_valid"
	ReasonIssuerNotAuthorized        Reason = "issuer_not_authorized"
	ReasonNameConstraints            Reason = "name_constraints"
	ReasonPathLength                 Reason = "path_length"
	ReasonUnhandledCriticalExtension Reason = "unhandled_critical_extension"
	ReasonIncompatibleUsage          Reason = "incompatible_usage"
	ReasonInsecureSignatureAlgorithm Reason = "insecure_signature_algorithm"
	ReasonPolicy                     Reason = "policy"
	ReasonEngineLimit                Reason = "engine_limit"
	ReasonEngineError                Reason = "engine_error"
)

// Chain is one chain Go's verifier built, as certificate fingerprints from
// the validated certificate to the anchor, both inclusive.
type Chain struct {
	Certificates []fingerprint.Cert
}

// Anchor is the supplied anchor the chain ends at.
func (c Chain) Anchor() fingerprint.Cert { return c.Certificates[len(c.Certificates)-1] }

// Result of Verify. Chains is non-empty exactly when State is Verified.
type Result struct {
	State  State
	Reason Reason
	Chains []Chain
}

// Verify validates target against anchors at now.
//
// intermediates are candidate intermediate certificates. Any of them that is
// also an anchor is left out of the intermediate pool, so each certificate
// plays exactly one role. Nothing is fetched and no system certificates are
// used.
//
// The verifier is asked for any extended key usage: generic inspection is not
// purpose validation. No host name is requested.
func Verify(target *x509.Certificate, anchors, intermediates []*x509.Certificate, now time.Time) Result {
	if target == nil || len(anchors) == 0 || now.IsZero() {
		// Refuse rather than let Go substitute the system roots or clock.
		return Result{State: Unverifiable, Reason: ReasonEngineError, Chains: []Chain{}}
	}
	roots := x509.NewCertPool()
	isAnchor := map[fingerprint.Cert]bool{}
	for _, a := range anchors {
		roots.AddCert(a)
		isAnchor[fingerprint.CertFromDER(a.Raw)] = true
	}
	pool := x509.NewCertPool()
	for _, c := range intermediates {
		if !isAnchor[fingerprint.CertFromDER(c.Raw)] {
			pool.AddCert(c)
		}
	}

	chains, err := target.Verify(x509.VerifyOptions{
		Roots:                     roots,
		Intermediates:             pool,
		CurrentTime:               now,
		KeyUsages:                 []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		MaxConstraintComparisions: MaxConstraintComparisons,
	})
	if err != nil {
		state, reason := classify(err, now)
		return Result{State: state, Reason: reason, Chains: []Chain{}}
	}
	return Result{State: Verified, Chains: normalise(chains)}
}

// normalise converts chains to fingerprints and orders them deterministically:
// shorter chains first, then by the fingerprints in order. Ordering is for
// presentation only; every chain the verifier returned is kept.
func normalise(chains [][]*x509.Certificate) []Chain {
	out := make([]Chain, 0, len(chains))
	for _, chain := range chains {
		c := Chain{Certificates: make([]fingerprint.Cert, len(chain))}
		for i, cert := range chain {
			c.Certificates[i] = fingerprint.CertFromDER(cert.Raw)
		}
		out = append(out, c)
	}
	slices.SortStableFunc(out, func(a, b Chain) int {
		if len(a.Certificates) != len(b.Certificates) {
			return len(a.Certificates) - len(b.Certificates)
		}
		for i := range a.Certificates {
			if c := bytes.Compare(a.Certificates[i][:], b.Certificates[i][:]); c != 0 {
				return c
			}
		}
		return 0
	})
	return out
}

// classify maps a verifier error to a state and reason. Typed errors are
// classified by type. For failures Go reports only inside an
// UnknownAuthorityError's message, classifyHint is the only code that reads
// verifier message text. Anything unrecognised is unverifiable/engine_error,
// never a guessed failure reason.
func classify(err error, now time.Time) (State, Reason) {
	var (
		critical x509.UnhandledCriticalExtension
		insecure x509.InsecureAlgorithmError
		invalid  x509.CertificateInvalidError
		unknown  x509.UnknownAuthorityError
	)
	switch {
	case errors.As(err, &critical):
		return Failed, ReasonUnhandledCriticalExtension
	case errors.As(err, &insecure):
		return Failed, ReasonInsecureSignatureAlgorithm
	case errors.As(err, &invalid):
		return classifyInvalid(invalid, now)
	case errors.As(err, &unknown):
		return classifyHint(err.Error())
	case strings.Contains(err.Error(), "signature check attempts limit reached"):
		return Unverifiable, ReasonEngineLimit
	}
	return Unverifiable, ReasonEngineError
}

func classifyInvalid(e x509.CertificateInvalidError, now time.Time) (State, Reason) {
	switch e.Reason {
	case x509.NotAuthorizedToSign:
		return Failed, ReasonIssuerNotAuthorized
	case x509.Expired:
		if e.Cert != nil && now.Before(e.Cert.NotBefore) {
			return Failed, ReasonNotYetValid
		}
		return Failed, ReasonExpired
	case x509.CANotAuthorizedForThisName, x509.UnconstrainedName, x509.NameConstraintsWithoutSANs:
		return Failed, ReasonNameConstraints
	case x509.TooManyConstraints:
		return Unverifiable, ReasonEngineLimit
	case x509.TooManyIntermediates:
		return Failed, ReasonPathLength
	case x509.IncompatibleUsage, x509.CANotAuthorizedForExtKeyUsage:
		return Failed, ReasonIncompatibleUsage
	case x509.NameMismatch:
		return Failed, ReasonNoAnchorPath
	case x509.NoValidChains:
		// With any extended key usage requested, Go discards candidate chains
		// only for invalid policies; anything else is not guessed at.
		if strings.Contains(e.Detail, "invalid policies") && !strings.Contains(e.Detail, "incompatible key usage") {
			return Failed, ReasonPolicy
		}
	}
	return Unverifiable, ReasonEngineError
}

// unknownAuthorityHint is how Go's UnknownAuthorityError introduces the error
// that rejected a candidate issuer. Go keeps only one such hint: the reason a
// candidate was rejected, not necessarily the only reason.
const unknownAuthorityHint = "(possibly because of "

// classifyHint reads Go's UnknownAuthorityError message. Without a hint, no
// candidate issuer was found among the anchors and intermediates.
func classifyHint(msg string) (State, Reason) {
	i := strings.Index(msg, unknownAuthorityHint)
	if i < 0 {
		return Failed, ReasonNoAnchorPath
	}
	hint := msg[i+len(unknownAuthorityHint):]
	switch {
	case strings.Contains(hint, "insecure algorithm"):
		return Failed, ReasonInsecureSignatureAlgorithm
	case strings.Contains(hint, "has expired or is not yet valid") && strings.Contains(hint, " is before "):
		return Failed, ReasonNotYetValid
	case strings.Contains(hint, "has expired or is not yet valid"):
		return Failed, ReasonExpired
	case strings.Contains(hint, "not authorized to sign other certificates"),
		strings.Contains(hint, "parent certificate cannot sign this kind of certificate"):
		return Failed, ReasonIssuerNotAuthorized
	case strings.Contains(hint, "too many intermediates for path length constraint"):
		return Failed, ReasonPathLength
	case strings.Contains(hint, "unhandled critical extension"):
		return Failed, ReasonUnhandledCriticalExtension
	case strings.Contains(hint, "not authorized to sign for this name"),
		strings.Contains(hint, "name constraints"),
		strings.Contains(hint, "unconstrained name"):
		return Failed, ReasonNameConstraints
	case strings.Contains(hint, "verification failure"),
		strings.Contains(hint, "verification error"),
		strings.Contains(hint, "signature algorithm specifies an "),
		strings.Contains(hint, "issuer name does not match subject"):
		// A candidate matched by name but did not sign the certificate.
		return Failed, ReasonNoAnchorPath
	}
	return Unverifiable, ReasonEngineError
}
