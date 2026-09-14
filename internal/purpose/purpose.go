// Package purpose answers one question: do a certificate's own fields permit
// the purpose the user explicitly asked about?
//
// That is a separate question from:
//   - who signed the certificate and whether the signature verifies;
//   - whether its included path is structurally plausible;
//   - whether it validates to explicitly supplied trust anchors (which, for a
//     requested purpose, also enforces extended key usage along the whole
//     chain);
//   - whether it matches a host name.
//
// This package evaluates only the certificate itself, following RFC 5280
// section 4.2.1.12. It applies no TLS handshake, cipher-suite or WebPKI
// policy.
package purpose

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"
	"strings"
)

// Purpose is an application purpose the user can ask about. Its value is the
// exact spelling accepted by --purpose; there are no aliases.
type Purpose string

const (
	// Any asserts no application-specific purpose. It does not switch off any
	// other evaluation.
	Any         Purpose = "any"
	TLSServer   Purpose = "tls-server"
	TLSClient   Purpose = "tls-client"
	CodeSigning Purpose = "code-signing"
	Email       Purpose = "email"
)

// All lists every supported purpose.
func All() []Purpose { return []Purpose{Any, TLSServer, TLSClient, CodeSigning, Email} }

// Parse accepts exactly the documented spellings.
func Parse(s string) (Purpose, error) {
	names := make([]string, 0, len(All()))
	for _, p := range All() {
		if string(p) == s {
			return p, nil
		}
		names = append(names, string(p))
	}
	return "", fmt.Errorf("unknown purpose %q: want one of %s", s, strings.Join(names, ", "))
}

// ExtKeyUsage is the extended key usage that expresses the purpose, as passed
// to Go's verifier. Any maps to x509.ExtKeyUsageAny.
func (p Purpose) ExtKeyUsage() (x509.ExtKeyUsage, bool) {
	switch p {
	case Any:
		return x509.ExtKeyUsageAny, true
	case TLSServer:
		return x509.ExtKeyUsageServerAuth, true
	case TLSClient:
		return x509.ExtKeyUsageClientAuth, true
	case CodeSigning:
		return x509.ExtKeyUsageCodeSigning, true
	case Email:
		return x509.ExtKeyUsageEmailProtection, true
	}
	return 0, false
}

// ExtKeyUsageName is the stable name of the purpose's extended key usage.
func (p Purpose) ExtKeyUsageName() string {
	u, ok := p.ExtKeyUsage()
	if !ok {
		return ""
	}
	return ExtKeyUsageName(u)
}

// consistentKeyUsage lists, per purpose, the key usage bits RFC 5280 section
// 4.2.1.12 names as consistent with its extended key usage. A certificate
// whose key usage extension sets none of them does not permit the purpose.
// These are certificate semantics, not TLS cipher-suite policy.
var consistentKeyUsage = map[Purpose]x509.KeyUsage{
	TLSServer:   x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
	TLSClient:   x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
	CodeSigning: x509.KeyUsageDigitalSignature,
	Email:       x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
}

// ConsistentKeyUsages names the key usage bits consistent with p.
func (p Purpose) ConsistentKeyUsages() []string { return keyUsageNames(consistentKeyUsage[p]) }

// State is the outcome of evaluating a certificate for a purpose.
type State string

const (
	// NotEvaluated: no specific purpose was requested (Any).
	NotEvaluated State = "not_evaluated"
	// Suitable: the certificate's own fields permit the purpose.
	Suitable State = "suitable"
	// Unsuitable: the certificate's own fields do not permit the purpose.
	Unsuitable State = "unsuitable"
	// Unverifiable: the certificate could not be evaluated.
	Unverifiable State = "unverifiable"
)

// Reason is a stable code for an unsuitable or unverifiable result.
type Reason string

const (
	// ReasonExtKeyUsage: the extended key usage extension is present and lists
	// neither the purpose's usage nor anyExtendedKeyUsage (basis not_listed).
	ReasonExtKeyUsage Reason = "ext_key_usage_disallows_usage"
	// ReasonKeyUsage: the key usage extension is present and sets none of the
	// bits consistent with the purpose.
	ReasonKeyUsage       Reason = "key_usage_disallows_usage"
	ReasonNotParsed      Reason = "certificate_not_parsed"
	ReasonUnknownPurpose Reason = "unknown_purpose"
)

// ExtKeyUsageBasis records how the extended key usage decision was reached.
type ExtKeyUsageBasis string

const (
	// EKUNotPresent: no extended key usage extension, so the certificate is
	// not restricted by extended key usage.
	EKUNotPresent ExtKeyUsageBasis = "not_present"
	// EKUListed: the purpose's usage is listed.
	EKUListed ExtKeyUsageBasis = "listed"
	// EKUAny: anyExtendedKeyUsage is listed but the purpose's usage is not.
	// This evaluator treats the certificate as not restricted by extended key
	// usage. RFC 5280 lets an application that requires the specific usage
	// reject it, so this is not a claim that every application accepts it.
	EKUAny ExtKeyUsageBasis = "any_extended_key_usage"
	// EKUNotListed: other usages only; the purpose is not permitted.
	EKUNotListed ExtKeyUsageBasis = "not_listed"
)

// Result of Evaluate. Lists are never nil.
type Result struct {
	Purpose Purpose
	State   State
	Reasons []Reason // in the order extended key usage, key usage

	ExtKeyUsagePresent bool
	ExtKeyUsageBasis   ExtKeyUsageBasis // empty unless evaluated
	ExtKeyUsages       []string         // stable names; dotted OIDs for usages Go does not name
	KeyUsagePresent    bool
	KeyUsages          []string
	// CA reports BasicConstraints CA:TRUE. RFC 5280 does not make a CA
	// certificate unsuitable for these purposes, so it is a fact only.
	CA bool
}

var (
	oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 15}
)

// Evaluate reports whether c's own fields permit p:
//   - Extended key usage (RFC 5280 4.2.1.12): an absent extension does not
//     restrict the certificate; a listed purpose usage permits it; a listed
//     anyExtendedKeyUsage is treated by this evaluator as not restricting it
//     (see EKUAny: an application may still require the specific usage);
//     otherwise the purpose is not permitted. Unrecognised usages restrict
//     like any other listed usage.
//   - Key usage: an absent extension places no restriction; otherwise at least
//     one bit consistent with the purpose must be set.
func Evaluate(c *x509.Certificate, p Purpose) Result {
	r := Result{Purpose: p, Reasons: []Reason{}, ExtKeyUsages: []string{}, KeyUsages: []string{}}
	usage, known := p.ExtKeyUsage()
	switch {
	case !known:
		r.State, r.Reasons = Unverifiable, []Reason{ReasonUnknownPurpose}
		return r
	case p == Any:
		r.State = NotEvaluated
		return r
	case c == nil:
		r.State, r.Reasons = Unverifiable, []Reason{ReasonNotParsed}
		return r
	}

	r.CA = c.BasicConstraintsValid && c.IsCA
	for _, e := range c.Extensions {
		switch {
		case e.Id.Equal(oidExtKeyUsage):
			r.ExtKeyUsagePresent = true
		case e.Id.Equal(oidKeyUsage):
			r.KeyUsagePresent = true
		}
	}
	for _, u := range c.ExtKeyUsage {
		r.ExtKeyUsages = append(r.ExtKeyUsages, ExtKeyUsageName(u))
	}
	for _, oid := range c.UnknownExtKeyUsage {
		r.ExtKeyUsages = append(r.ExtKeyUsages, oid.String())
	}
	r.KeyUsages = keyUsageNames(c.KeyUsage)

	switch {
	case !r.ExtKeyUsagePresent:
		r.ExtKeyUsageBasis = EKUNotPresent
	case slices.Contains(c.ExtKeyUsage, usage):
		r.ExtKeyUsageBasis = EKUListed
	case slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageAny):
		r.ExtKeyUsageBasis = EKUAny
	default:
		r.ExtKeyUsageBasis = EKUNotListed
		r.Reasons = append(r.Reasons, ReasonExtKeyUsage)
	}
	if r.KeyUsagePresent && c.KeyUsage&consistentKeyUsage[p] == 0 {
		r.Reasons = append(r.Reasons, ReasonKeyUsage)
	}
	r.State = Suitable
	if len(r.Reasons) > 0 {
		r.State = Unsuitable
	}
	return r
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "any",
	x509.ExtKeyUsageServerAuth:                     "server_auth",
	x509.ExtKeyUsageClientAuth:                     "client_auth",
	x509.ExtKeyUsageCodeSigning:                    "code_signing",
	x509.ExtKeyUsageEmailProtection:                "email_protection",
	x509.ExtKeyUsageIPSECEndSystem:                 "ipsec_end_system",
	x509.ExtKeyUsageIPSECTunnel:                    "ipsec_tunnel",
	x509.ExtKeyUsageIPSECUser:                      "ipsec_user",
	x509.ExtKeyUsageTimeStamping:                   "time_stamping",
	x509.ExtKeyUsageOCSPSigning:                    "ocsp_signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "microsoft_server_gated_crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "netscape_server_gated_crypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "microsoft_commercial_code_signing",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "microsoft_kernel_code_signing",
}

// ExtKeyUsageName is the stable name of an extended key usage.
func ExtKeyUsageName(u x509.ExtKeyUsage) string {
	if n, ok := extKeyUsageNames[u]; ok {
		return n
	}
	return fmt.Sprintf("ext_key_usage_%d", u)
}

var keyUsageBitNames = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digital_signature"},
	{x509.KeyUsageContentCommitment, "content_commitment"},
	{x509.KeyUsageKeyEncipherment, "key_encipherment"},
	{x509.KeyUsageDataEncipherment, "data_encipherment"},
	{x509.KeyUsageKeyAgreement, "key_agreement"},
	{x509.KeyUsageCertSign, "key_cert_sign"},
	{x509.KeyUsageCRLSign, "crl_sign"},
	{x509.KeyUsageEncipherOnly, "encipher_only"},
	{x509.KeyUsageDecipherOnly, "decipher_only"},
}

func keyUsageNames(ku x509.KeyUsage) []string {
	names := []string{}
	for _, b := range keyUsageBitNames {
		if ku&b.bit != 0 {
			names = append(names, b.name)
		}
	}
	return names
}
