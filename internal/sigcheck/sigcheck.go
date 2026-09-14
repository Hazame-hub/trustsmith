// Package sigcheck answers one question: does a candidate certificate's public
// key verify another certificate's signature? It applies no certificate
// authority, validity, key-usage, path or trust policy — a verified result
// means only that the signature is cryptographically valid under that key.
package sigcheck

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
)

// State is the outcome of a signature check.
type State string

const (
	// Verified: the signer's public key verifies the child's signature over
	// its exact TBSCertificate bytes.
	Verified State = "verified"
	// Invalid: the engine evaluated the signature under that key and it does
	// not verify (or the key cannot have produced it).
	Invalid State = "invalid"
	// Unverifiable: the engine could not decide — the algorithm is refused or
	// unsupported, or an unrecognised error occurred. Never a failed check.
	Unverifiable State = "unverifiable"
)

// Reason is a stable code explaining a non-verified state.
type Reason string

const (
	ReasonNone                 Reason = ""
	ReasonSignatureMismatch    Reason = "signature_mismatch"     // Invalid
	ReasonKeyAlgorithmMismatch Reason = "key_algorithm_mismatch" // Invalid
	ReasonInsecureAlgorithm    Reason = "insecure_algorithm"     // Unverifiable: the engine refuses the algorithm (e.g. MD5)
	ReasonUnsupportedAlgorithm Reason = "unsupported_algorithm"  // Unverifiable: algorithm or signer key not supported
	ReasonEngineError          Reason = "engine_error"           // Unverifiable: unrecognised error
	ReasonEnginePanic          Reason = "engine_panic"           // Unverifiable: the engine panicked (recovered)
)

// Result of a signature check. Detail is the engine's message, for humans
// only; it is not a contract.
type Result struct {
	State  State
	Reason Reason
	Detail string
}

// checkSignature is the single verification call.
//
// It uses x509.Certificate.CheckSignature on the signer with the child's own
// SignatureAlgorithm, RawTBSCertificate and Signature — the exact signed bytes
// from the certificate, never a reconstruction. It deliberately does not use
// CheckSignatureFrom, which also enforces CA policy (BasicConstraints, the
// certSign key usage) and refuses SHA-1: those are chain-validation concerns,
// not facts about the signature. It is a variable only so tests can prove
// the panic boundary.
var checkSignature = func(child, signer *x509.Certificate) error {
	return signer.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)
}

// Certificate checks whether signer's public key verifies child's signature.
func Certificate(child, signer *x509.Certificate) (res Result) {
	// The verification engine processes attacker-supplied signatures and
	// keys; a panic there is contained and reported with a stable reason.
	defer func() {
		if r := recover(); r != nil {
			res = Result{State: Unverifiable, Reason: ReasonEnginePanic, Detail: "signature verification panicked"}
		}
	}()
	err := checkSignature(child, signer)
	state, reason := classify(err)
	res = Result{State: state, Reason: reason}
	if err != nil {
		res.Detail = err.Error()
	}
	return res
}

// classify maps a verification error to a state. It is the only code that
// inspects Go's error text, for the failures crypto/x509 reports as untyped
// errors. Anything it does not recognise is Unverifiable, never Invalid.
func classify(err error) (State, Reason) {
	var insecure x509.InsecureAlgorithmError
	switch {
	case err == nil:
		return Verified, ReasonNone
	case errors.As(err, &insecure):
		return Unverifiable, ReasonInsecureAlgorithm
	case errors.Is(err, x509.ErrUnsupportedAlgorithm):
		return Unverifiable, ReasonUnsupportedAlgorithm
	case errors.Is(err, rsa.ErrVerification):
		return Invalid, ReasonSignatureMismatch
	}
	msg := err.Error()
	switch {
	case msg == "x509: ECDSA verification failure",
		msg == "x509: Ed25519 verification failure",
		strings.HasPrefix(msg, "x509: ML-DSA verification failure"):
		return Invalid, ReasonSignatureMismatch
	case strings.HasPrefix(msg, "x509: signature algorithm specifies an "):
		return Invalid, ReasonKeyAlgorithmMismatch
	}
	return Unverifiable, ReasonEngineError
}
