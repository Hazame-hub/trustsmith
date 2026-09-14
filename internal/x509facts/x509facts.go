// Package x509facts describes what a certificate's bytes contain. It never
// decides whether something is good or bad; that is interpret's job. It
// describes one certificate at a time: relationships between certificates
// belong to issuerlinks.
//
// When Go's X.509 parser rejects a certificate, the package still locates the
// SubjectPublicKeyInfo structurally so both public-key fingerprints can be
// reported, and records the parse error rather than guessing other fields.
package x509facts

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/sigcheck"
)

// Kind is what a certificate-framed DER object turned out to be.
type Kind string

const (
	KindCertificate        Kind = "certificate"
	KindUnparseable        Kind = "unparseable_certificate"
	KindCertificateRequest Kind = "certificate_request"
)

// KeyIdentity is the status of the x509-spki-sha256 identity.
type KeyIdentity string

const (
	KeyIdentityCanonical    KeyIdentity = "canonical"    // KeyID set; encoding is canonical
	KeyIdentityNoncanonical KeyIdentity = "noncanonical" // KeyID set; encoded bytes differ from canonical
	KeyIdentityUnsupported  KeyIdentity = "unsupported"  // well-formed key outside ADR-0002; no KeyID
	KeyIdentityMalformed    KeyIdentity = "malformed"    // invalid SPKI; no KeyID
	KeyIdentityUnavailable  KeyIdentity = "unavailable"  // no SPKI could be located at all
)

// SignatureCheck is the result of verifying a self-issued certificate's
// signature with its own public key.
type SignatureCheck string

const (
	SignatureNotApplicable SignatureCheck = "not_applicable" // not self-issued: issuer and subject names differ
	SignatureVerified      SignatureCheck = "verified"       // self-signed
	SignatureFailed        SignatureCheck = "failed"         // self-issued, but its own key does not verify the signature
	SignatureUnverifiable  SignatureCheck = "unverifiable"   // the engine could not decide (e.g. MD5)
)

// Identity holds the fingerprints of a certificate-framed object.
type Identity struct {
	Fingerprint       fingerprint.Cert
	EncodedSPKI       fingerprint.EncodedSPKI // zero when KeyIdentity is unavailable
	KeyID             fingerprint.KeyID       // zero unless canonical or noncanonical
	KeyIdentity       KeyIdentity
	KeyIdentityDetail string // why there is no KeyID, when there is none
}

// Name is a distinguished name.
type Name struct {
	DN         string
	CommonName string
}

// PublicKey describes the certified key (never any private material).
type PublicKey struct {
	Algorithm string // RSA, ECDSA, Ed25519, ML-DSA, ...
	Detail    string // curve or parameter set, e.g. P-256, ML-DSA-65
	Bits      int    // RSA modulus or EC field size; 0 when not meaningful
}

// BasicConstraints as encoded.
type BasicConstraints struct {
	Present    bool
	IsCA       bool
	MaxPathLen *int // nil when absent or unlimited
}

// Extension is one certificate extension.
type Extension struct {
	OID      string
	Critical bool
	Name     string // empty when the OID is not one Trustsmith names
}

// Certificate is everything Trustsmith reads from a parseable certificate.
type Certificate struct {
	Identity

	Version               int
	SerialHex             string
	Subject               Name
	Issuer                Name
	NotBefore             time.Time
	NotAfter              time.Time
	PublicKey             PublicKey
	SignatureAlgorithm    x509.SignatureAlgorithm
	SignatureAlgorithmOID string

	KeyUsage         []string
	ExtKeyUsage      []string
	BasicConstraints BasicConstraints
	SubjectKeyID     []byte
	AuthorityKeyID   []byte

	DNSNames       []string
	IPAddresses    []string
	EmailAddresses []string
	URIs           []string

	Extensions             []Extension
	CRLDistributionPoints  []string
	OCSPServers            []string
	IssuingCertificateURLs []string
	PolicyOIDs             []string

	// SelfIssued: subject and issuer names are byte-identical. That is a
	// naming fact only; SelfSignature says whether the certificate is signed
	// by its own key (self-signed). The check is made for self-issued
	// certificates, following RFC 5280's definition of self-signed.
	SelfIssued          bool
	SelfSignature       SignatureCheck
	SelfSignatureReason sigcheck.Reason
	SelfSignatureDetail string

	// Parsed is the standard library's parse of the certificate, kept so
	// signature relationships can be checked against the exact signed bytes.
	// It is never serialised.
	Parsed *x509.Certificate
}

// Unparseable is what can be said about a certificate Go could not parse.
type Unparseable struct {
	Identity
	ParseError string
}

// Parsed is the result of FromDER; exactly the field matching Kind is set
// (neither is set for a certificate request).
type Parsed struct {
	Kind        Kind
	Certificate *Certificate
	Unparseable *Unparseable
	// ParserPanicked reports that the standard-library parser panicked on
	// this input and the panic was contained. It is always false unless the
	// parser has a bug; tests and fuzzing assert it.
	ParserPanicked bool
}

// The standard-library parsers are variables only so tests can prove the
// panic boundary below.
var (
	parseCertificate        = x509.ParseCertificate
	parseCertificateRequest = x509.ParseCertificateRequest
)

const parserPanicMessage = "the X.509 parser failed unexpectedly on this input"

// FromDER reads a DER object that was framed as a certificate.
func FromDER(der []byte) Parsed {
	cert, panicked, err := parse(func() (*x509.Certificate, error) { return parseCertificate(der) })
	if panicked {
		return unparseable(der, parserPanicMessage, true)
	}
	if err != nil {
		_, csrPanicked, csrErr := parse(func() (*x509.CertificateRequest, error) { return parseCertificateRequest(der) })
		if csrPanicked {
			return unparseable(der, parserPanicMessage, true)
		}
		if csrErr == nil {
			return Parsed{Kind: KindCertificateRequest}
		}
		return unparseable(der, err.Error(), false)
	}
	return Parsed{Kind: KindCertificate, Certificate: fromCertificate(cert)}
}

// parse is the recovery boundary around the standard-library parsers, which
// consume attacker-controlled bytes. Nothing else in this package recovers:
// a panic in Trustsmith's own code must surface as a bug.
func parse[T any](call func() (T, error)) (value T, panicked bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			var zero T
			value, panicked, err = zero, true, nil
		}
	}()
	value, err = call()
	return value, false, err
}

func unparseable(der []byte, parseError string, panicked bool) Parsed {
	return Parsed{
		Kind:           KindUnparseable,
		Unparseable:    &Unparseable{Identity: identify(der, locateSPKI(der)), ParseError: parseError},
		ParserPanicked: panicked,
	}
}

func fromCertificate(cert *x509.Certificate) *Certificate {
	c := &Certificate{
		Identity:               identify(cert.Raw, cert.RawSubjectPublicKeyInfo),
		Version:                cert.Version,
		SerialHex:              serialHex(cert),
		Subject:                Name{DN: cert.Subject.String(), CommonName: cert.Subject.CommonName},
		Issuer:                 Name{DN: cert.Issuer.String(), CommonName: cert.Issuer.CommonName},
		NotBefore:              cert.NotBefore.UTC(),
		NotAfter:               cert.NotAfter.UTC(),
		PublicKey:              publicKey(cert),
		SignatureAlgorithm:     cert.SignatureAlgorithm,
		SignatureAlgorithmOID:  algorithmOID(cert.RawSignatureAlgorithm),
		SubjectKeyID:           cert.SubjectKeyId,
		AuthorityKeyID:         cert.AuthorityKeyId,
		DNSNames:               cert.DNSNames,
		EmailAddresses:         cert.EmailAddresses,
		CRLDistributionPoints:  cert.CRLDistributionPoints,
		OCSPServers:            cert.OCSPServer,
		IssuingCertificateURLs: cert.IssuingCertificateURL,
		SelfIssued:             bytes.Equal(cert.RawSubject, cert.RawIssuer),
		Parsed:                 cert,
	}

	for bit := x509.KeyUsageDigitalSignature; bit <= x509.KeyUsageDecipherOnly; bit <<= 1 {
		if cert.KeyUsage&bit != 0 {
			c.KeyUsage = append(c.KeyUsage, bit.String())
		}
	}
	for _, eku := range cert.ExtKeyUsage {
		c.ExtKeyUsage = append(c.ExtKeyUsage, eku.String())
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		c.ExtKeyUsage = append(c.ExtKeyUsage, oid.String())
	}

	c.BasicConstraints = BasicConstraints{Present: cert.BasicConstraintsValid, IsCA: cert.IsCA}
	if cert.BasicConstraintsValid && cert.IsCA && (cert.MaxPathLen > 0 || cert.MaxPathLenZero) {
		n := cert.MaxPathLen
		c.BasicConstraints.MaxPathLen = &n
	}

	for _, ip := range cert.IPAddresses {
		c.IPAddresses = append(c.IPAddresses, ip.String())
	}
	for _, u := range cert.URIs {
		c.URIs = append(c.URIs, u.String())
	}
	for _, e := range cert.Extensions {
		oid := e.Id.String()
		c.Extensions = append(c.Extensions, Extension{OID: oid, Critical: e.Critical, Name: extensionNames[oid]})
	}
	for _, p := range cert.Policies {
		c.PolicyOIDs = append(c.PolicyOIDs, p.String())
	}

	c.SelfSignature = SignatureNotApplicable
	if c.SelfIssued {
		result := sigcheck.Certificate(cert, cert)
		c.SelfSignatureReason, c.SelfSignatureDetail = result.Reason, result.Detail
		switch result.State {
		case sigcheck.Verified:
			c.SelfSignature = SignatureVerified
		case sigcheck.Invalid:
			c.SelfSignature = SignatureFailed
		default:
			c.SelfSignature = SignatureUnverifiable
		}
	}
	return c
}

// identify computes the fingerprints of a certificate and of its SPKI (nil
// when none could be located).
func identify(der, spki []byte) Identity {
	id := Identity{Fingerprint: fingerprint.CertFromDER(der)}
	if spki == nil {
		id.KeyIdentity = KeyIdentityUnavailable
		id.KeyIdentityDetail = "no SubjectPublicKeyInfo could be located"
		return id
	}
	id.EncodedSPKI = fingerprint.EncodedSPKIFromDER(spki)

	canonical, err := fingerprint.CanonicalSPKI(spki)
	if err == nil {
		id.KeyID, err = fingerprint.KeyIDFromSPKI(spki)
	}
	switch {
	case errors.Is(err, fingerprint.ErrUnsupported):
		id.KeyIdentity, id.KeyIdentityDetail = KeyIdentityUnsupported, err.Error()
	case err != nil:
		id.KeyID = fingerprint.KeyID{}
		id.KeyIdentity, id.KeyIdentityDetail = KeyIdentityMalformed, err.Error()
	case bytes.Equal(canonical, spki):
		id.KeyIdentity = KeyIdentityCanonical
	default:
		id.KeyIdentity = KeyIdentityNoncanonical
	}
	return id
}

// locateSPKI finds the SubjectPublicKeyInfo inside a certificate structurally,
// without validating anything else.
func locateSPKI(der []byte) []byte {
	in := cryptobyte.String(der)
	var cert, tbs, spki cryptobyte.String
	if !in.ReadASN1(&cert, cbasn1.SEQUENCE) || !cert.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		return nil
	}
	versionTag := cbasn1.Tag(0).Constructed().ContextSpecific()
	if tbs.PeekASN1Tag(versionTag) && !tbs.SkipASN1(versionTag) {
		return nil
	}
	if !tbs.SkipASN1(cbasn1.INTEGER) || // serialNumber
		!tbs.SkipASN1(cbasn1.SEQUENCE) || // signature
		!tbs.SkipASN1(cbasn1.SEQUENCE) || // issuer
		!tbs.SkipASN1(cbasn1.SEQUENCE) || // validity
		!tbs.SkipASN1(cbasn1.SEQUENCE) || // subject
		!tbs.ReadASN1Element(&spki, cbasn1.SEQUENCE) {
		return nil
	}
	return spki
}

func serialHex(cert *x509.Certificate) string {
	if cert.SerialNumber == nil {
		return ""
	}
	b := cert.SerialNumber.Bytes()
	if len(b) == 0 {
		return "00"
	}
	if cert.SerialNumber.Sign() < 0 {
		return "-" + hex.EncodeToString(b)
	}
	return hex.EncodeToString(b)
}

func publicKey(cert *x509.Certificate) PublicKey {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return PublicKey{Algorithm: "RSA", Bits: k.N.BitLen()}
	case *ecdsa.PublicKey:
		return PublicKey{Algorithm: "ECDSA", Detail: k.Curve.Params().Name, Bits: k.Curve.Params().BitSize}
	case ed25519.PublicKey:
		return PublicKey{Algorithm: "Ed25519"}
	case *mldsa.PublicKey:
		return PublicKey{Algorithm: "ML-DSA", Detail: k.Parameters().String()}
	case *ecdh.PublicKey:
		return PublicKey{Algorithm: "ECDH", Detail: fmt.Sprint(k.Curve())}
	default:
		return PublicKey{Algorithm: cert.PublicKeyAlgorithm.String()}
	}
}

func algorithmOID(algorithmIdentifier []byte) string {
	in := cryptobyte.String(algorithmIdentifier)
	var seq cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1ObjectIdentifier(&oid) {
		return ""
	}
	return oid.String()
}

var extensionNames = map[string]string{
	"2.5.29.9":                "subjectDirectoryAttributes",
	"2.5.29.14":               "subjectKeyIdentifier",
	"2.5.29.15":               "keyUsage",
	"2.5.29.17":               "subjectAltName",
	"2.5.29.18":               "issuerAltName",
	"2.5.29.19":               "basicConstraints",
	"2.5.29.30":               "nameConstraints",
	"2.5.29.31":               "cRLDistributionPoints",
	"2.5.29.32":               "certificatePolicies",
	"2.5.29.33":               "policyMappings",
	"2.5.29.35":               "authorityKeyIdentifier",
	"2.5.29.36":               "policyConstraints",
	"2.5.29.37":               "extKeyUsage",
	"2.5.29.54":               "inhibitAnyPolicy",
	"1.3.6.1.5.5.7.1.1":       "authorityInfoAccess",
	"1.3.6.1.5.5.7.1.24":      "tlsFeature",
	"1.3.6.1.4.1.11129.2.4.2": "signedCertificateTimestampList",
}
