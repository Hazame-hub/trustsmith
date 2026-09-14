// Package testpki builds certificates for Trustsmith's tests and for the
// committed fixture corpus (cmd/genfixtures). Production code never imports
// it; internal/archtest enforces that.
//
// Besides ordinary issuance it can re-sign a certificate with a replaced
// public key or signature algorithm, to produce certificates that
// x509.CreateCertificate refuses to create (SHA-1, MD5, non-canonical keys).
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5" //nolint:gosec // test fixtures deliberately use weak algorithms
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // test fixtures deliberately use weak algorithms
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/url"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Now is the fixed inspection time used by every golden test and fixture.
var Now = time.Date(2026, time.September, 14, 12, 0, 0, 0, time.UTC)

// Fataler is the part of testing.TB this package needs, so the fixture
// generator can use it outside tests.
type Fataler interface {
	Helper()
	Fatalf(format string, args ...any)
}

// Cert is an issued certificate with the key it certifies.
type Cert struct {
	DER  []byte
	Cert *x509.Certificate
	Key  crypto.Signer
}

// Template describes a certificate to issue.
type Template struct {
	CommonName     string
	Organization   string
	DNSNames       []string
	IPAddresses    []string
	EmailAddresses []string
	URIs           []string
	NotBefore      time.Time
	NotAfter       time.Time
	IsCA           bool
	MaxPathLen     int // for CAs; -1 means no limit
	KeyUsage       x509.KeyUsage
	ExtKeyUsage    []x509.ExtKeyUsage
	Serial         int64
	// SubjectKeyID overrides the generated Subject Key Identifier, e.g. to
	// build a certificate whose key identifier matches another one's.
	SubjectKeyID []byte
	// BasicConstraintsNotCA encodes BasicConstraints with CA:FALSE (instead of
	// omitting the extension) when IsCA is false.
	BasicConstraintsNotCA bool
	// ExtraExtensions are added verbatim, e.g. an unknown critical extension.
	ExtraExtensions []pkix.Extension
	// PermittedDNSDomains adds a name constraints extension.
	PermittedDNSDomains []string
}

func ECDSAKey(f Fataler) *ecdsa.PrivateKey {
	f.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("ecdsa key: %v", err)
	}
	return k
}

func RSAKey(f Fataler, bits int) *rsa.PrivateKey {
	f.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		f.Fatalf("rsa key: %v", err)
	}
	return k
}

func Ed25519Key(f Fataler) ed25519.PrivateKey {
	f.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("ed25519 key: %v", err)
	}
	return k
}

func MLDSAKey(f Fataler, params mldsa.Parameters) *mldsa.PrivateKey {
	f.Helper()
	k, err := mldsa.GenerateKey(params)
	if err != nil {
		f.Fatalf("ml-dsa key: %v", err)
	}
	return k
}

// Issue creates a certificate for key, signed by parent (or self-signed when
// parent is nil).
func Issue(f Fataler, t Template, key crypto.Signer, parent *Cert) *Cert {
	f.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(t.Serial),
		Subject:               pkix.Name{CommonName: t.CommonName},
		DNSNames:              t.DNSNames,
		EmailAddresses:        t.EmailAddresses,
		NotBefore:             t.NotBefore,
		NotAfter:              t.NotAfter,
		KeyUsage:              t.KeyUsage,
		ExtKeyUsage:           t.ExtKeyUsage,
		BasicConstraintsValid: t.IsCA,
		IsCA:                  t.IsCA,
		SubjectKeyId:          t.SubjectKeyID,
		ExtraExtensions:       t.ExtraExtensions,
		PermittedDNSDomains:   t.PermittedDNSDomains,
	}
	if t.BasicConstraintsNotCA && !t.IsCA {
		tmpl.BasicConstraintsValid = true
	}
	if t.Organization != "" {
		tmpl.Subject.Organization = []string{t.Organization}
	}
	if t.IsCA {
		if t.MaxPathLen < 0 {
			tmpl.MaxPathLen = -1
		} else {
			tmpl.MaxPathLen = t.MaxPathLen
			tmpl.MaxPathLenZero = t.MaxPathLen == 0
		}
	}
	for _, ip := range t.IPAddresses {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	for _, u := range t.URIs {
		parsed, err := url.Parse(u)
		if err != nil {
			f.Fatalf("uri %q: %v", u, err)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}

	parentCert, parentKey := tmpl, key
	if parent != nil {
		parentCert, parentKey = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), parentKey)
	if err != nil {
		f.Fatalf("create certificate %q: %v", t.CommonName, err)
	}
	return &Cert{DER: der, Cert: mustParse(f, der), Key: key}
}

func mustParse(f Fataler, der []byte) *x509.Certificate {
	f.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		f.Fatalf("parse certificate: %v", err)
	}
	return c
}

// SigAlg selects the signature Resign produces.
type SigAlg int

const (
	ECDSAWithSHA256 SigAlg = iota
	ECDSAWithSHA1
	RSAWithSHA256
	RSAWithSHA1
	RSAWithMD5
)

var (
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidRSAWithSHA256   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidRSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidRSAWithMD5      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECPublicKey     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidP256            = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
)

// Resign rebuilds certDER with spki as its public key (nil keeps the
// original) and alg as its signature algorithm, and signs it with signer.
// Issuer and subject names, validity and extensions are kept.
func Resign(f Fataler, certDER, spki []byte, alg SigAlg, signer crypto.Signer) []byte {
	f.Helper()
	in := cryptobyte.String(certDER)
	var cert, tbs cryptobyte.String
	if !in.ReadASN1(&cert, cbasn1.SEQUENCE) || !cert.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		f.Fatalf("resign: not a certificate")
	}
	versionTag := cbasn1.Tag(0).Constructed().ContextSpecific()
	var version, serial, sigAlg, issuer, validity, subject, oldSPKI cryptobyte.String
	if tbs.PeekASN1Tag(versionTag) && !tbs.ReadASN1Element(&version, versionTag) {
		f.Fatalf("resign: bad version")
	}
	if !tbs.ReadASN1Element(&serial, cbasn1.INTEGER) || !tbs.ReadASN1Element(&sigAlg, cbasn1.SEQUENCE) ||
		!tbs.ReadASN1Element(&issuer, cbasn1.SEQUENCE) || !tbs.ReadASN1Element(&validity, cbasn1.SEQUENCE) ||
		!tbs.ReadASN1Element(&subject, cbasn1.SEQUENCE) || !tbs.ReadASN1Element(&oldSPKI, cbasn1.SEQUENCE) {
		f.Fatalf("resign: unexpected TBSCertificate structure")
	}
	if spki == nil {
		spki = oldSPKI
	}
	algID := algorithmIdentifier(f, alg)

	var tb cryptobyte.Builder
	tb.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(version)
		b.AddBytes(serial)
		b.AddBytes(algID)
		b.AddBytes(issuer)
		b.AddBytes(validity)
		b.AddBytes(subject)
		b.AddBytes(spki)
		b.AddBytes(tbs) // issuer/subject unique IDs and extensions, unchanged
	})
	tbsDER := mustBytes(f, &tb)
	sig := sign(f, alg, signer, tbsDER)

	var cb cryptobyte.Builder
	cb.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbsDER)
		b.AddBytes(algID)
		b.AddASN1BitString(sig)
	})
	return mustBytes(f, &cb)
}

func algorithmIdentifier(f Fataler, alg SigAlg) []byte {
	f.Helper()
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		switch alg {
		case ECDSAWithSHA256:
			b.AddASN1ObjectIdentifier(oidECDSAWithSHA256)
		case ECDSAWithSHA1:
			b.AddASN1ObjectIdentifier(oidECDSAWithSHA1)
		case RSAWithSHA256:
			b.AddASN1ObjectIdentifier(oidRSAWithSHA256)
			b.AddASN1NULL()
		case RSAWithSHA1:
			b.AddASN1ObjectIdentifier(oidRSAWithSHA1)
			b.AddASN1NULL()
		case RSAWithMD5:
			b.AddASN1ObjectIdentifier(oidRSAWithMD5)
			b.AddASN1NULL()
		}
	})
	return mustBytes(f, &b)
}

func sign(f Fataler, alg SigAlg, signer crypto.Signer, tbs []byte) []byte {
	f.Helper()
	var (
		sig []byte
		err error
	)
	switch alg {
	case ECDSAWithSHA256, ECDSAWithSHA1:
		k, ok := signer.(*ecdsa.PrivateKey)
		if !ok {
			f.Fatalf("resign: ECDSA signature needs an ECDSA key")
		}
		var digest []byte
		if alg == ECDSAWithSHA1 {
			h := sha1.Sum(tbs) //nolint:gosec // deliberate weak fixture
			digest = h[:]
		} else {
			h := sha256.Sum256(tbs)
			digest = h[:]
		}
		sig, err = ecdsa.SignASN1(rand.Reader, k, digest)
	case RSAWithSHA256, RSAWithSHA1, RSAWithMD5:
		k, ok := signer.(*rsa.PrivateKey)
		if !ok {
			f.Fatalf("resign: RSA signature needs an RSA key")
		}
		var digest []byte
		var hash crypto.Hash
		switch alg {
		case RSAWithSHA256:
			h := sha256.Sum256(tbs)
			digest, hash = h[:], crypto.SHA256
		case RSAWithSHA1:
			h := sha1.Sum(tbs) //nolint:gosec // deliberate weak fixture
			digest, hash = h[:], crypto.SHA1
		default:
			h := md5.Sum(tbs) //nolint:gosec // deliberate weak fixture
			digest, hash = h[:], crypto.MD5
		}
		sig, err = rsa.SignPKCS1v15(nil, k, hash, digest)
	}
	if err != nil {
		f.Fatalf("resign: sign: %v", err)
	}
	return sig
}

func mustBytes(f Fataler, b *cryptobyte.Builder) []byte {
	f.Helper()
	out, err := b.Bytes()
	if err != nil {
		f.Fatalf("encode: %v", err)
	}
	return out
}

// SPKI assembles SEQUENCE { SEQUENCE { oid, params }, BIT STRING key }, with
// params as raw DER (nil for absent).
func SPKI(f Fataler, oid asn1.ObjectIdentifier, params, key []byte) []byte {
	f.Helper()
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oid)
			if params != nil {
				b.AddBytes(params)
			}
		})
		b.AddASN1BitString(key)
	})
	return mustBytes(f, &b)
}

// RSASPKIWithoutNULL encodes pub with the rsaEncryption parameters omitted —
// a non-canonical encoding of the same key.
func RSASPKIWithoutNULL(f Fataler, pub *rsa.PublicKey) []byte {
	f.Helper()
	var kb cryptobyte.Builder
	kb.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(pub.N)
		b.AddASN1Int64(int64(pub.E))
	})
	return SPKI(f, oidRSAEncryption, nil, mustBytes(f, &kb))
}

// CompressedP256SPKI encodes pub with a compressed point — a non-canonical
// encoding of the same key.
func CompressedP256SPKI(f Fataler, pub *ecdsa.PublicKey) []byte {
	f.Helper()
	point, err := pub.Bytes()
	if err != nil || len(point) != 65 {
		f.Fatalf("compressed SPKI needs a P-256 key: %v", err)
	}
	compressed := append([]byte{0x02 | point[64]&1}, point[1:33]...)
	var params cryptobyte.Builder
	params.AddASN1ObjectIdentifier(oidP256)
	return SPKI(f, oidECPublicKey, mustBytes(f, &params), compressed)
}

// X25519SPKI returns the SPKI of a fresh X25519 key: a key type that can be
// certified but cannot verify certificate signatures.
func X25519SPKI(f Fataler) []byte {
	f.Helper()
	k, err := ecdhX25519()
	if err != nil {
		f.Fatalf("x25519 key: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		f.Fatalf("x25519 SPKI: %v", err)
	}
	return spki
}
