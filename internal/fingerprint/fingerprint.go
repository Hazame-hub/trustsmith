// Package fingerprint defines Trustsmith's deterministic identities for
// certificates and public keys, as specified in ADR-0002
// (docs/adr/0002-public-key-identity.md).
//
// Three schemes exist and are deliberately distinct Go types, so one cannot be
// passed where another is expected:
//
//   - Cert (x509-cert-sha256): SHA-256 of a certificate's DER exactly as encoded.
//   - KeyID (x509-spki-sha256): SHA-256 of the canonical SubjectPublicKeyInfo.
//     The only identity used to correlate one public key across certificates,
//     CSRs, public keys, private keys and other systems. It exists only for
//     keys ADR-0002 supports; it is never derived from non-canonical bytes.
//   - EncodedSPKI (x509-spki-encoded-sha256): SHA-256 of the SPKI bytes exactly
//     as they appear in an artifact. Provenance, diagnostics and RFC 7469 pins
//     only; never a join key.
package fingerprint

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// Scheme names a fingerprint definition. The values are part of Trustsmith's
// external contract (JSON output, future exports) and never change meaning.
type Scheme string

const (
	SchemeCert        Scheme = "x509-cert-sha256"
	SchemeKeyID       Scheme = "x509-spki-sha256"
	SchemeEncodedSPKI Scheme = "x509-spki-encoded-sha256"
)

// Cert is the x509-cert-sha256 fingerprint of a certificate.
type Cert [sha256.Size]byte

// KeyID is the x509-spki-sha256 cross-artifact public-key identity. Obtain one
// only from KeyIDFromSPKI or KeyIDFromPublicKey.
type KeyID [sha256.Size]byte

// EncodedSPKI is the x509-spki-encoded-sha256 fingerprint of SPKI bytes as
// they were encoded in an artifact.
type EncodedSPKI [sha256.Size]byte

// CertFromDER fingerprints a certificate's DER exactly as encoded.
func CertFromDER(der []byte) Cert { return Cert(sha256.Sum256(der)) }

// EncodedSPKIFromDER fingerprints SubjectPublicKeyInfo bytes exactly as
// encoded. It performs no parsing and is defined for any byte string.
func EncodedSPKIFromDER(spki []byte) EncodedSPKI { return EncodedSPKI(sha256.Sum256(spki)) }

func (c Cert) Scheme() Scheme        { return SchemeCert }
func (k KeyID) Scheme() Scheme       { return SchemeKeyID }
func (e EncodedSPKI) Scheme() Scheme { return SchemeEncodedSPKI }

// Hex is the wire form: 64 lowercase hexadecimal characters.
func (c Cert) Hex() string        { return hex.EncodeToString(c[:]) }
func (k KeyID) Hex() string       { return hex.EncodeToString(k[:]) }
func (e EncodedSPKI) Hex() string { return hex.EncodeToString(e[:]) }

// String is the human form: "sha256:" followed by the wire form.
func (c Cert) String() string        { return "sha256:" + c.Hex() }
func (k KeyID) String() string       { return "sha256:" + k.Hex() }
func (e EncodedSPKI) String() string { return "sha256:" + e.Hex() }

func (c Cert) IsZero() bool        { return c == Cert{} }
func (k KeyID) IsZero() bool       { return k == KeyID{} }
func (e EncodedSPKI) IsZero() bool { return e == EncodedSPKI{} }

// Colon renders the certificate fingerprint the way `openssl x509
// -fingerprint -sha256` does (uppercase, colon-separated), for comparison
// with other tools. Display only.
func (c Cert) Colon() string {
	h := strings.ToUpper(c.Hex())
	var b strings.Builder
	b.Grow(len(h) + len(h)/2)
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// PinSHA256 is the RFC 7469 pin-sha256 value: base64 of the digest of the SPKI
// as encoded. Display only.
func (e EncodedSPKI) PinSHA256() string { return base64.StdEncoding.EncodeToString(e[:]) }
