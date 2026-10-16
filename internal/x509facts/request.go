package x509facts

import (
	"crypto/x509"
	"encoding/asn1"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/Hazame-hub/trustsmith/internal/sigcheck"
)

// CertificateRequest is everything Trustsmith reads from a parseable PKCS #10
// certificate signing request (RFC 2986). Every field is what the request
// asks a CA to certify: nothing in it is in force, validated or trusted, and
// it has no issuer, serial number or validity period.
type CertificateRequest struct {
	SPKIIdentity

	Subject               Name
	PublicKey             PublicKey
	SignatureAlgorithm    x509.SignatureAlgorithm
	SignatureAlgorithmOID string

	// The requested subject alternative names, as Go parses them from the
	// requested subjectAltName extension.
	DNSNames       []string
	IPAddresses    []string
	EmailAddresses []string
	URIs           []string

	// Extensions are every extension in the request's extensionRequest
	// attribute. KeyUsage, ExtKeyUsage and BasicConstraints are decoded from
	// them by Trustsmith, because Go's request parser does not; an extension
	// whose value could not be decoded is listed in UndecodedExtensions (by
	// OID) instead of being reported as absent.
	Extensions          []Extension
	KeyUsage            []string
	ExtKeyUsage         []string
	BasicConstraints    BasicConstraints
	UndecodedExtensions []string

	// Attributes are the request's attribute types, in order. Their values
	// are never decoded or shown: a challengePassword is a shared secret.
	Attributes []Attribute

	// Signature is the request's signature checked with its own public key:
	// proof that whoever made the request held the private key, nothing more.
	Signature       SignatureCheck
	SignatureReason sigcheck.Reason
	SignatureDetail string

	// Parsed is the standard library's parse of the request. It is never
	// serialised.
	Parsed *x509.CertificateRequest
}

// Attribute is one attribute type of a certificate signing request.
type Attribute struct {
	OID  string
	Name string // empty when the OID is not one Trustsmith names
}

// UnparseableRequest is what can be said about a certificate signing request
// Go could not parse.
type UnparseableRequest struct {
	SPKIIdentity
	ParseError string
}

// FromRequestDER reads a DER object that was framed as a certificate signing
// request (a PEM CERTIFICATE REQUEST or NEW CERTIFICATE REQUEST block). It is
// parsed only as a request: the label decides what the block claims to be.
func FromRequestDER(der []byte) Parsed {
	csr, panicked, err := parse(func() (*x509.CertificateRequest, error) { return parseCertificateRequest(der) })
	switch {
	case panicked:
		return unparseableRequest(der, parserPanicMessage, true)
	case err != nil:
		return unparseableRequest(der, err.Error(), false)
	}
	return Parsed{Kind: KindCertificateRequest, Request: fromRequest(csr)}
}

func unparseableRequest(der []byte, parseError string, panicked bool) Parsed {
	return Parsed{
		Kind:               KindUnparseableRequest,
		UnparseableRequest: &UnparseableRequest{SPKIIdentity: identify(locateRequestSPKI(der)), ParseError: parseError},
		ParserPanicked:     panicked,
	}
}

func fromRequest(csr *x509.CertificateRequest) *CertificateRequest {
	r := &CertificateRequest{
		SPKIIdentity:          identify(csr.RawSubjectPublicKeyInfo),
		Subject:               Name{DN: csr.Subject.String(), CommonName: csr.Subject.CommonName},
		PublicKey:             publicKey(csr.PublicKey, csr.PublicKeyAlgorithm),
		SignatureAlgorithm:    csr.SignatureAlgorithm,
		SignatureAlgorithmOID: algorithmOID(csr.RawSignatureAlgorithm),
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		Extensions:            extensions(csr.Extensions),
		Attributes:            attributes(csr.RawTBSCertificateRequest),
		Parsed:                csr,
	}
	for _, ip := range csr.IPAddresses {
		r.IPAddresses = append(r.IPAddresses, ip.String())
	}
	for _, u := range csr.URIs {
		r.URIs = append(r.URIs, u.String())
	}
	for _, e := range csr.Extensions {
		ok := true
		switch {
		case e.Id.Equal(oidKeyUsage):
			r.KeyUsage, ok = decodeKeyUsage(e.Value)
		case e.Id.Equal(oidExtKeyUsage):
			r.ExtKeyUsage, ok = decodeExtKeyUsage(e.Value)
		case e.Id.Equal(oidBasicConstraints):
			r.BasicConstraints, ok = decodeBasicConstraints(e.Value)
		}
		if !ok {
			r.UndecodedExtensions = append(r.UndecodedExtensions, e.Id.String())
		}
	}

	result := sigcheck.Request(csr)
	r.SignatureReason, r.SignatureDetail = result.Reason, result.Detail
	switch result.State {
	case sigcheck.Verified:
		r.Signature = SignatureVerified
	case sigcheck.DoesNotVerify:
		r.Signature = SignatureDoesNotVerify
	default:
		r.Signature = SignatureUnverifiable
	}
	return r
}

var (
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
)

// decodeKeyUsage reads KeyUsage ::= BIT STRING (RFC 5280 section 4.2.1.3),
// naming the bits as certificates' key usage is named.
func decodeKeyUsage(value []byte) ([]string, bool) {
	in := cryptobyte.String(value)
	var bits asn1.BitString
	if !in.ReadASN1BitString(&bits) || !in.Empty() {
		return nil, false
	}
	var out []string
	for i := range 9 { // digitalSignature (0) through decipherOnly (8)
		if bits.At(i) != 0 {
			out = append(out, x509.KeyUsage(1<<i).String())
		}
	}
	return out, true
}

// decodeExtKeyUsage reads ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF
// KeyPurposeId (RFC 5280 section 4.2.1.12). Usages Go names are named as
// certificates' extended key usage is; others are listed by OID, as for
// certificates.
func decodeExtKeyUsage(value []byte) ([]string, bool) {
	in := cryptobyte.String(value)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() || seq.Empty() {
		return nil, false
	}
	var out []string
	for !seq.Empty() {
		var oid asn1.ObjectIdentifier
		if !seq.ReadASN1ObjectIdentifier(&oid) {
			return nil, false
		}
		name := oid.String()
		for _, known := range extKeyUsageOIDs {
			if oid.Equal(known.oid) {
				name = known.usage.String()
			}
		}
		out = append(out, name)
	}
	return out, true
}

// decodeBasicConstraints reads BasicConstraints ::= SEQUENCE { cA BOOLEAN
// DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL } (RFC 5280
// section 4.2.1.9). As for certificates, a path length is reported only for a
// CA.
func decodeBasicConstraints(value []byte) (BasicConstraints, bool) {
	in := cryptobyte.String(value)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() {
		return BasicConstraints{}, false
	}
	bc := BasicConstraints{Present: true}
	if seq.PeekASN1Tag(cbasn1.BOOLEAN) && !seq.ReadASN1Boolean(&bc.IsCA) {
		return BasicConstraints{}, false
	}
	if !seq.Empty() {
		var n int
		if !seq.ReadASN1Integer(&n) || n < 0 || !seq.Empty() {
			return BasicConstraints{}, false
		}
		if bc.IsCA {
			bc.MaxPathLen = &n
		}
	}
	return bc, true
}

// extKeyUsageOIDs are the extended key usages Go names (crypto/x509 does not
// export its own table).
var extKeyUsageOIDs = []struct {
	oid   asn1.ObjectIdentifier
	usage x509.ExtKeyUsage
}{
	{asn1.ObjectIdentifier{2, 5, 29, 37, 0}, x509.ExtKeyUsageAny},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}, x509.ExtKeyUsageServerAuth},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}, x509.ExtKeyUsageClientAuth},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}, x509.ExtKeyUsageCodeSigning},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}, x509.ExtKeyUsageEmailProtection},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}, x509.ExtKeyUsageIPSECEndSystem},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}, x509.ExtKeyUsageIPSECTunnel},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}, x509.ExtKeyUsageIPSECUser},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}, x509.ExtKeyUsageTimeStamping},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}, x509.ExtKeyUsageOCSPSigning},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}, x509.ExtKeyUsageMicrosoftServerGatedCrypto},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}, x509.ExtKeyUsageNetscapeServerGatedCrypto},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}, x509.ExtKeyUsageMicrosoftCommercialCodeSigning},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}, x509.ExtKeyUsageMicrosoftKernelCodeSigning},
}

// attributes lists the attribute types of a CertificationRequestInfo:
// SEQUENCE { version, subject, subjectPKInfo, [0] IMPLICIT SET OF Attribute },
// Attribute ::= SEQUENCE { type OBJECT IDENTIFIER, values SET }. Values are
// skipped unread.
func attributes(info []byte) []Attribute {
	in := cryptobyte.String(info)
	var body, attrs cryptobyte.String
	if !in.ReadASN1(&body, cbasn1.SEQUENCE) ||
		!body.SkipASN1(cbasn1.INTEGER) || !body.SkipASN1(cbasn1.SEQUENCE) || !body.SkipASN1(cbasn1.SEQUENCE) ||
		!body.ReadASN1(&attrs, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return nil
	}
	var out []Attribute
	for !attrs.Empty() {
		var attr cryptobyte.String
		var oid asn1.ObjectIdentifier
		if !attrs.ReadASN1(&attr, cbasn1.SEQUENCE) || !attr.ReadASN1ObjectIdentifier(&oid) {
			return out
		}
		out = append(out, Attribute{OID: oid.String(), Name: attributeNames[oid.String()]})
	}
	return out
}

var attributeNames = map[string]string{
	"1.2.840.113549.1.9.2":  "unstructuredName",
	"1.2.840.113549.1.9.7":  "challengePassword",
	"1.2.840.113549.1.9.14": "extensionRequest",
}

// locateRequestSPKI finds the SubjectPublicKeyInfo inside a certificate
// signing request structurally, without validating anything else.
func locateRequestSPKI(der []byte) []byte {
	in := cryptobyte.String(der)
	var csr, info, spki cryptobyte.String
	if !in.ReadASN1(&csr, cbasn1.SEQUENCE) || !csr.ReadASN1(&info, cbasn1.SEQUENCE) ||
		!info.SkipASN1(cbasn1.INTEGER) || // version
		!info.SkipASN1(cbasn1.SEQUENCE) || // subject
		!info.ReadASN1Element(&spki, cbasn1.SEQUENCE) {
		return nil
	}
	return spki
}
