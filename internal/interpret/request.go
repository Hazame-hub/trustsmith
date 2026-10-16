package interpret

import (
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

// RequestSignature says whether a certificate signing request's signature
// verifies with the public key the request contains.
type RequestSignature string

const (
	RequestSignatureVerified      RequestSignature = "verified"
	RequestSignatureDoesNotVerify RequestSignature = "does_not_verify"
	RequestSignatureUnverifiable  RequestSignature = "unverifiable"
)

// RequestSummary is the friendly description of one parsed certificate
// signing request. It says what the request asks a CA to certify; nothing in
// it is in force, and it has no validity, issuer or chain to describe.
type RequestSummary struct {
	Kind      string   // "Certificate signing request", or "... for a CA certificate"
	Requests  []string // requested SAN values, or "CN=..." when there are none
	Subject   string   // the requested subject name
	Key       string   // e.g. "ECDSA P-256", "RSA 2048"
	Signature string   // e.g. "ECDSA-SHA256"
	// SignatureCheck is the request's signature checked with its own key, and
	// SignatureReason the stable sigcheck reason when it did not verify.
	SignatureCheck  RequestSignature
	SignatureReason string
}

// request interprets a parsed certificate signing request. Only facts a CA
// would refuse the request for, or that make the issued certificate
// unusable, are findings; there is no policy on what a CA should accept
// beyond them (ADR-0011).
func request(entry int, r *x509facts.CertificateRequest) Entry {
	var fs []findings.Finding
	algorithm := ev("signature_algorithm", signatureSummary(r.SignatureAlgorithm, r.SignatureAlgorithmOID))

	check := RequestSignatureVerified
	switch r.Signature {
	case x509facts.SignatureDoesNotVerify:
		check = RequestSignatureDoesNotVerify
		fs = append(fs, finding(entry, findings.CSRSignatureInvalid, findings.SeverityCritical,
			ev("reason", string(r.SignatureReason)), algorithm))
	case x509facts.SignatureUnverifiable:
		check = RequestSignatureUnverifiable
		fs = append(fs, finding(entry, findings.CSRSignatureUnverifiable, findings.SeverityWarning,
			ev("reason", string(r.SignatureReason)), algorithm))
	}

	// A request is always checked by the CA that receives it, so a weak
	// algorithm is critical: unlike a trust anchor's self-signature, there
	// is no case in which its signature goes unchecked.
	fs = append(fs, weakAlgorithm(entry, r.SignatureAlgorithm, findings.SeverityCritical)...)
	fs = append(fs, shortKey(entry, r.PublicKey)...)

	isCA := r.BasicConstraints.Present && r.BasicConstraints.IsCA
	hasSAN := len(r.DNSNames)+len(r.IPAddresses)+len(r.EmailAddresses)+len(r.URIs) > 0
	if !isCA && !hasSAN && r.Subject.CommonName != "" {
		fs = append(fs, finding(entry, findings.NameCNOnlyNoSAN, findings.SeverityWarning, ev("common_name", r.Subject.CommonName)))
	}

	fs = append(fs, keyIdentity(entry, r.SPKIIdentity)...)

	kind := "Certificate signing request"
	if isCA {
		kind += " for a CA certificate"
	}
	reason := ""
	if check != RequestSignatureVerified {
		reason = string(r.SignatureReason)
	}
	return Entry{
		Request: &RequestSummary{
			Kind:            kind,
			Requests:        names(r.Subject, hasSAN, r.DNSNames, r.IPAddresses, r.EmailAddresses, r.URIs),
			Subject:         r.Subject.DN,
			Key:             keySummary(r.PublicKey),
			Signature:       signatureSummary(r.SignatureAlgorithm, r.SignatureAlgorithmOID),
			SignatureCheck:  check,
			SignatureReason: reason,
		},
		Findings: fs,
	}
}
