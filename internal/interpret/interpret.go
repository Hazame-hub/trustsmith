// Package interpret turns raw facts into a friendly summary and structured
// findings. Every function is pure: the inspection time is always passed in,
// never read from the system clock.
//
// This version applies generic interpretation only. No public-WebPKI policy
// (such as CA/Browser Forum validity limits) is applied, and no issuer or
// chain relationship is asserted.
package interpret

import (
	"crypto/x509"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/artifact"
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

// Thresholds configures expiry warnings.
type Thresholds struct {
	ExpiringWarning  time.Duration
	ExpiringCritical time.Duration
}

// DefaultThresholds warns at 30 days and is critical at 7 days.
func DefaultThresholds() Thresholds {
	return Thresholds{ExpiringWarning: 30 * 24 * time.Hour, ExpiringCritical: 7 * 24 * time.Hour}
}

type ValidityState string

const (
	Valid       ValidityState = "valid"
	Expired     ValidityState = "expired"
	NotYetValid ValidityState = "not_yet_valid"
)

// SelfSigned says whether a certificate is signed by its own key.
type SelfSigned string

const (
	SelfSignedNo           SelfSigned = "no"
	SelfSignedVerified     SelfSigned = "verified"
	SelfSignedInvalid      SelfSigned = "signature_invalid"
	SelfSignedUnverifiable SelfSigned = "signature_unverifiable"
)

// ChainState is the result of chain verification.
type ChainState string

// ChainNotChecked: this version does not verify chains, and says so rather
// than implying a result.
const ChainNotChecked ChainState = "not_checked"

type Validity struct {
	State         ValidityState
	NotBefore     time.Time
	NotAfter      time.Time
	DaysRemaining int // whole days until notAfter; negative once expired
}

// Summary is the friendly description of one parsed certificate.
type Summary struct {
	Kind       string   // e.g. "TLS server certificate"
	Purposes   []string // tls_server, tls_client, code_signing, email_protection, time_stamping, ocsp_signing, any, ca
	Identifies []string // SAN values, or "CN=..." when there are none
	Issuer     string   // the issuer name as stated in the certificate — not a verified relationship
	SelfSigned SelfSigned
	Validity   Validity
	Key        string // e.g. "ECDSA P-256", "RSA 2048"
	Signature  string // e.g. "ECDSA-SHA256"
	Chain      ChainState
}

// Entry is the interpretation of one input block.
type Entry struct {
	Summary  *Summary // set only for certificates that parsed
	Findings []findings.Finding
}

func finding(entry int, code findings.Code, sev findings.Severity, evidence ...findings.Evidence) findings.Finding {
	return findings.Finding{Code: code, Severity: sev, Entry: entry, Evidence: evidence}
}

func ev(key, value string) findings.Evidence { return findings.Evidence{Key: key, Value: value} }

// Block interprets one framed block. p is the result of x509facts.FromDER for
// certificate blocks and nil otherwise.
func Block(b artifact.Block, p *x509facts.Parsed, now time.Time, th Thresholds) Entry {
	switch b.Kind {
	case artifact.KindMalformed:
		if b.Label != "" {
			return Entry{Findings: []findings.Finding{finding(b.Entry, findings.InputMalformedPEM, findings.SeverityCritical,
				ev("problem", string(b.Problem)), ev("pem_label", b.Label))}}
		}
		return Entry{Findings: []findings.Finding{finding(b.Entry, findings.InputMalformedDER, findings.SeverityCritical,
			ev("problem", string(b.Problem)))}}
	case artifact.KindUnsupported:
		if b.Label != "" {
			return Entry{Findings: []findings.Finding{finding(b.Entry, findings.InputUnsupportedFormat, findings.SeverityWarning,
				ev("pem_label", b.Label))}}
		}
		return Entry{Findings: []findings.Finding{finding(b.Entry, findings.InputUnsupportedFormat, findings.SeverityWarning,
			ev("structure", "DER that is not a certificate"))}}
	}

	if p == nil {
		// A certificate block that was never parsed is a caller defect; report
		// it rather than let the block silently disappear.
		return Entry{Findings: []findings.Finding{finding(b.Entry, findings.InputUnparseableCertificate, findings.SeverityCritical,
			ev("parse_error", "certificate was not parsed"))}}
	}
	switch p.Kind {
	case x509facts.KindCertificateRequest:
		return Entry{Findings: []findings.Finding{finding(b.Entry, findings.InputUnsupportedFormat, findings.SeverityWarning,
			ev("kind", "certificate_request"))}}
	case x509facts.KindUnparseable:
		fs := []findings.Finding{finding(b.Entry, findings.InputUnparseableCertificate, findings.SeverityCritical,
			ev("parse_error", p.Unparseable.ParseError))}
		return Entry{Findings: append(fs, keyIdentity(b.Entry, p.Unparseable.Identity)...)}
	default:
		return certificate(b.Entry, p.Certificate, now, th)
	}
}

func certificate(entry int, c *x509facts.Certificate, now time.Time, th Thresholds) Entry {
	isCA := c.BasicConstraints.Present && c.BasicConstraints.IsCA
	var fs []findings.Finding
	add := func(code findings.Code, sev findings.Severity, evidence ...findings.Evidence) {
		fs = append(fs, finding(entry, code, sev, evidence...))
	}

	validity := Validity{
		NotBefore:     c.NotBefore,
		NotAfter:      c.NotAfter,
		DaysRemaining: int(math.Floor(c.NotAfter.Sub(now).Hours() / 24)),
	}
	switch {
	case now.Before(c.NotBefore):
		validity.State = NotYetValid
		add(findings.CertNotYetValid, findings.SeverityCritical, ev("not_before", timestamp(c.NotBefore)))
	case now.After(c.NotAfter):
		validity.State = Expired
		add(findings.CertExpired, findings.SeverityCritical, ev("not_after", timestamp(c.NotAfter)))
	default:
		validity.State = Valid
		remaining := c.NotAfter.Sub(now)
		evidence := []findings.Evidence{ev("not_after", timestamp(c.NotAfter)), ev("days_remaining", strconv.Itoa(validity.DaysRemaining))}
		switch {
		case remaining <= th.ExpiringCritical:
			add(findings.CertExpiringSoon, findings.SeverityCritical, evidence...)
		case remaining <= th.ExpiringWarning:
			add(findings.CertExpiringSoon, findings.SeverityWarning, evidence...)
		}
	}

	if c.SelfIssued && c.SelfSignature == x509facts.SignatureVerified && !isCA {
		add(findings.CertSelfSignedLeaf, findings.SeverityWarning)
	}

	// A trust anchor's self-signature is not checked during validation, so a
	// weak algorithm there is informational.
	weakSeverity := findings.SeverityCritical
	if c.SelfIssued && isCA {
		weakSeverity = findings.SeverityInfo
	}
	switch c.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		add(findings.SigSHA1, weakSeverity, ev("signature_algorithm", c.SignatureAlgorithm.String()))
	case x509.MD5WithRSA:
		add(findings.SigMD5, weakSeverity, ev("signature_algorithm", c.SignatureAlgorithm.String()))
	}

	if c.PublicKey.Algorithm == "RSA" && c.PublicKey.Bits < 2048 {
		add(findings.KeyRSAUnder2048, findings.SeverityCritical, ev("key_bits", strconv.Itoa(c.PublicKey.Bits)))
	}

	hasSAN := len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses)+len(c.URIs) > 0
	if !isCA && !hasSAN && c.Subject.CommonName != "" {
		add(findings.NameCNOnlyNoSAN, findings.SeverityWarning, ev("common_name", c.Subject.CommonName))
	}

	fs = append(fs, keyIdentity(entry, c.Identity)...)

	kind, purposes := describeKind(c, isCA)
	return Entry{
		Summary: &Summary{
			Kind:       kind,
			Purposes:   purposes,
			Identifies: identifies(c, hasSAN),
			Issuer:     c.Issuer.DN,
			SelfSigned: selfSigned(c),
			Validity:   validity,
			Key:        keySummary(c.PublicKey),
			Signature:  signatureSummary(c),
			Chain:      ChainNotChecked,
		},
		Findings: fs,
	}
}

func keyIdentity(entry int, id x509facts.Identity) []findings.Finding {
	switch id.KeyIdentity {
	case x509facts.KeyIdentityNoncanonical:
		return []findings.Finding{finding(entry, findings.KeyNoncanonicalSPKI, findings.SeverityWarning,
			ev("x509-spki-sha256", id.KeyID.Hex()), ev("x509-spki-encoded-sha256", id.EncodedSPKI.Hex()))}
	case x509facts.KeyIdentityUnsupported:
		return []findings.Finding{finding(entry, findings.KeyUnsupportedForIdentity, findings.SeverityInfo,
			ev("x509-spki-encoded-sha256", id.EncodedSPKI.Hex()), ev("detail", id.KeyIdentityDetail))}
	case x509facts.KeyIdentityMalformed:
		return []findings.Finding{finding(entry, findings.InputMalformedSPKI, findings.SeverityWarning,
			ev("detail", id.KeyIdentityDetail))}
	}
	return nil
}

// Input interprets the input as a whole. certificates is the number of blocks
// that were certificates (parseable or not).
func Input(d artifact.Decoded, certificates int) []findings.Finding {
	whole := func(code findings.Code, sev findings.Severity, evidence ...findings.Evidence) findings.Finding {
		return finding(findings.WholeInput, code, sev, evidence...)
	}
	switch d.Format {
	case artifact.FormatEmpty:
		return []findings.Finding{whole(findings.InputEmpty, findings.SeverityCritical)}
	case artifact.FormatUnknown:
		return []findings.Finding{whole(findings.InputUnsupportedFormat, findings.SeverityCritical, ev("detail", "neither PEM nor DER"))}
	}
	var fs []findings.Finding
	sev := findings.SeverityInfo
	if d.Format == artifact.FormatDER {
		sev = findings.SeverityWarning // bytes after a DER certificate break strict parsers
	}
	for _, s := range d.Extraneous {
		fs = append(fs, whole(findings.InputTrailingData, sev, ev("offset", strconv.Itoa(s.Offset)), ev("length", strconv.Itoa(s.Length))))
	}
	if certificates == 0 {
		fs = append(fs, whole(findings.InputNoCertificates, findings.SeverityCritical))
	}
	return fs
}

var purposeByEKU = map[string]string{
	x509.ExtKeyUsageServerAuth.String():      "tls_server",
	x509.ExtKeyUsageClientAuth.String():      "tls_client",
	x509.ExtKeyUsageCodeSigning.String():     "code_signing",
	x509.ExtKeyUsageEmailProtection.String(): "email_protection",
	x509.ExtKeyUsageTimeStamping.String():    "time_stamping",
	x509.ExtKeyUsageOCSPSigning.String():     "ocsp_signing",
	x509.ExtKeyUsageAny.String():             "any",
}

func describeKind(c *x509facts.Certificate, isCA bool) (string, []string) {
	purposes := []string{}
	if isCA {
		purposes = append(purposes, "ca")
	}
	for _, eku := range c.ExtKeyUsage {
		if p, ok := purposeByEKU[eku]; ok {
			purposes = append(purposes, p)
		}
	}

	if isCA {
		switch {
		case c.SelfIssued && c.SelfSignature == x509facts.SignatureVerified:
			return "Root certificate authority", purposes
		case c.SelfIssued:
			return "Self-issued certificate authority (signature not verified)", purposes
		default:
			return "Intermediate certificate authority", purposes
		}
	}

	has := func(p string) bool { return slices.Contains(purposes, p) }
	switch {
	case has("tls_server") && has("tls_client"):
		return "TLS server and client certificate", purposes
	case has("tls_server"):
		return "TLS server certificate", purposes
	case has("tls_client"):
		return "TLS client certificate", purposes
	case has("code_signing"):
		return "Code signing certificate", purposes
	case has("email_protection"):
		return "Email (S/MIME) certificate", purposes
	case len(c.ExtKeyUsage) == 0 || has("any"):
		return "Certificate with no extended key usage restriction", purposes
	default:
		return "Certificate for " + strings.Join(c.ExtKeyUsage, ", "), purposes
	}
}

func identifies(c *x509facts.Certificate, hasSAN bool) []string {
	if !hasSAN {
		if c.Subject.CommonName != "" {
			return []string{"CN=" + c.Subject.CommonName}
		}
		return []string{}
	}
	out := make([]string, 0, len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses)+len(c.URIs))
	out = append(out, c.DNSNames...)
	out = append(out, c.IPAddresses...)
	out = append(out, c.EmailAddresses...)
	return append(out, c.URIs...)
}

func selfSigned(c *x509facts.Certificate) SelfSigned {
	switch c.SelfSignature {
	case x509facts.SignatureVerified:
		return SelfSignedVerified
	case x509facts.SignatureFailed:
		return SelfSignedInvalid
	case x509facts.SignatureUnverifiable:
		return SelfSignedUnverifiable
	}
	return SelfSignedNo
}

func keySummary(k x509facts.PublicKey) string {
	switch {
	case k.Algorithm == "RSA":
		return "RSA " + strconv.Itoa(k.Bits)
	case k.Algorithm == "ML-DSA" && k.Detail != "":
		return k.Detail
	case k.Detail != "":
		return k.Algorithm + " " + k.Detail
	}
	return k.Algorithm
}

func signatureSummary(c *x509facts.Certificate) string {
	if c.SignatureAlgorithm == x509.UnknownSignatureAlgorithm && c.SignatureAlgorithmOID != "" {
		return c.SignatureAlgorithmOID
	}
	return c.SignatureAlgorithm.String()
}

func timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }
