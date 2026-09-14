package fingerprint

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// ErrUnsupported means the key is well-formed but its algorithm or encoding
// family is outside ADR-0002, so it has no x509-spki-sha256 identity.
var ErrUnsupported = errors.New("public key is not supported for x509-spki-sha256")

// ErrMalformed means the bytes are not a valid SubjectPublicKeyInfo (or not a
// valid key for the algorithm they declare).
var ErrMalformed = errors.New("malformed SubjectPublicKeyInfo")

func malformed(why string) error { return fmt.Errorf("%w: %s", ErrMalformed, why) }

var (
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidP256          = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384          = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidP521          = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidEd25519       = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidMLDSA44       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

// KeyIDFromSPKI returns the x509-spki-sha256 identity of an encoded
// SubjectPublicKeyInfo. It never falls back to hashing the input bytes.
func KeyIDFromSPKI(spki []byte) (KeyID, error) {
	c, err := CanonicalSPKI(spki)
	if err != nil {
		return KeyID{}, err
	}
	return KeyID(sha256.Sum256(c)), nil
}

// KeyIDFromPublicKey returns the x509-spki-sha256 identity of a parsed Go
// public key (for example the Public() of a private key).
func KeyIDFromPublicKey(pub crypto.PublicKey) (KeyID, error) {
	c, err := CanonicalSPKIFromPublicKey(pub)
	if err != nil {
		return KeyID{}, err
	}
	return KeyID(sha256.Sum256(c)), nil
}

// CanonicalSPKI parses an encoded SubjectPublicKeyInfo with Trustsmith's own
// strict parser and returns the ADR-0002 canonical DER. It deliberately does
// not use x509.ParsePKIXPublicKey, whose strictness varies across Go versions:
// the ADR, not the standard library, defines key identity.
func CanonicalSPKI(spki []byte) ([]byte, error) {
	input := cryptobyte.String(spki)
	var (
		body, alg cryptobyte.String
		oid       asn1.ObjectIdentifier
		bits      asn1.BitString
	)
	if !input.ReadASN1(&body, cbasn1.SEQUENCE) || !input.Empty() {
		return nil, malformed("not exactly one DER SEQUENCE")
	}
	if !body.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&oid) ||
		!body.ReadASN1BitString(&bits) || !body.Empty() {
		return nil, malformed("invalid SubjectPublicKeyInfo structure")
	}
	if bits.BitLength%8 != 0 {
		return nil, malformed("public key BIT STRING has unused bits")
	}
	params, key := []byte(alg), bits.Bytes

	switch {
	case oid.Equal(oidRSAEncryption):
		return canonicalRSA(params, key)
	case oid.Equal(oidECPublicKey):
		return canonicalEC(params, key)
	case oid.Equal(oidEd25519):
		return canonicalEd25519(params, key)
	}
	if p, ok := mldsaParameters(oid); ok {
		return canonicalMLDSA(oid, p, params, key)
	}
	return nil, fmt.Errorf("%w: algorithm %s", ErrUnsupported, oid)
}

// CanonicalSPKIFromPublicKey encodes a parsed Go public key as ADR-0002
// canonical DER.
func CanonicalSPKIFromPublicKey(pub crypto.PublicKey) ([]byte, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil || k.N.Sign() <= 0 || k.E <= 0 {
			return nil, malformed("RSA modulus and exponent must be positive")
		}
		return marshalRSA(k.N, big.NewInt(int64(k.E)))
	case *ecdsa.PublicKey:
		if k == nil || k.Curve == nil {
			return nil, malformed("ECDSA public key has no curve")
		}
		curveOID, ok := namedCurveOID(k.Curve)
		if !ok {
			return nil, fmt.Errorf("%w: curve %s", ErrUnsupported, k.Curve.Params().Name)
		}
		point, err := k.Bytes()
		if err != nil {
			return nil, malformed("ECDSA public key is invalid: " + err.Error())
		}
		return marshalSPKI(oidECPublicKey, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(curveOID) }, point)
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, malformed("Ed25519 public key must be 32 bytes")
		}
		return marshalSPKI(oidEd25519, nil, k)
	case *mldsa.PublicKey:
		if k == nil {
			return nil, malformed("ML-DSA public key is nil")
		}
		oid, ok := mldsaOID(k.Parameters())
		if !ok {
			return nil, fmt.Errorf("%w: ML-DSA parameter set %s", ErrUnsupported, k.Parameters())
		}
		return marshalSPKI(oid, nil, k.Bytes())
	default:
		return nil, fmt.Errorf("%w: public key type %T", ErrUnsupported, pub)
	}
}

func canonicalRSA(params, key []byte) ([]byte, error) {
	// ADR-0002: parameters are explicit NULL; absent parameters are accepted
	// and canonicalised. Anything else is not rsaEncryption.
	if p := cryptobyte.String(params); !p.Empty() {
		var null cryptobyte.String
		if !p.ReadASN1(&null, cbasn1.NULL) || !null.Empty() || !p.Empty() {
			return nil, malformed("rsaEncryption parameters must be NULL or absent")
		}
	}
	var (
		k    = cryptobyte.String(key)
		seq  cryptobyte.String
		n, e = new(big.Int), new(big.Int)
	)
	if !k.ReadASN1(&seq, cbasn1.SEQUENCE) || !k.Empty() ||
		!seq.ReadASN1Integer(n) || !seq.ReadASN1Integer(e) || !seq.Empty() {
		return nil, malformed("RSA key is not a DER RSAPublicKey")
	}
	if n.Sign() <= 0 || e.Sign() <= 0 {
		return nil, malformed("RSA modulus and exponent must be positive")
	}
	return marshalRSA(n, e)
}

func marshalRSA(n, e *big.Int) ([]byte, error) {
	var kb cryptobyte.Builder
	kb.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(n)
		b.AddASN1BigInt(e)
	})
	key, err := kb.Bytes()
	if err != nil {
		return nil, err
	}
	return marshalSPKI(oidRSAEncryption, func(b *cryptobyte.Builder) { b.AddASN1NULL() }, key)
}

func canonicalEC(params, key []byte) ([]byte, error) {
	p := cryptobyte.String(params)
	switch {
	case p.Empty():
		return nil, malformed("id-ecPublicKey parameters are missing")
	case p.PeekASN1Tag(cbasn1.NULL), p.PeekASN1Tag(cbasn1.SEQUENCE):
		// implicitCurve / specifiedCurve: valid ECParameters that ADR-0002
		// does not support.
		return nil, fmt.Errorf("%w: EC parameters are not a named curve", ErrUnsupported)
	}
	var curveOID asn1.ObjectIdentifier
	if !p.ReadASN1ObjectIdentifier(&curveOID) || !p.Empty() {
		return nil, malformed("invalid ECParameters")
	}
	curve, ok := namedCurve(curveOID)
	if !ok {
		return nil, fmt.Errorf("%w: curve %s", ErrUnsupported, curveOID)
	}
	point, err := uncompressedPoint(curve, key)
	if err != nil {
		return nil, err
	}
	return marshalSPKI(oidECPublicKey, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(curveOID) }, point)
}

// uncompressedPoint validates an SEC 1 point and returns its uncompressed
// encoding. Compressed points are decompressed (ADR-0002 canonicalises them).
func uncompressedPoint(curve elliptic.Curve, key []byte) ([]byte, error) {
	size := (curve.Params().BitSize + 7) / 8
	switch {
	case len(key) == 1+2*size && key[0] == 4:
		if _, err := ecdsa.ParseUncompressedPublicKey(curve, key); err != nil {
			return nil, malformed("EC point is not on the curve")
		}
		return key, nil
	case len(key) == 1+size && (key[0] == 2 || key[0] == 3):
		x, y := elliptic.UnmarshalCompressed(curve, key)
		if x == nil {
			return nil, malformed("compressed EC point is not on the curve")
		}
		point := make([]byte, 1+2*size)
		point[0] = 4
		x.FillBytes(point[1 : 1+size])
		y.FillBytes(point[1+size:])
		return point, nil
	default:
		return nil, malformed("EC point has an invalid encoding")
	}
}

func canonicalEd25519(params, key []byte) ([]byte, error) {
	if len(params) != 0 {
		return nil, malformed("Ed25519 AlgorithmIdentifier parameters must be absent")
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, malformed("Ed25519 public key must be 32 bytes")
	}
	return marshalSPKI(oidEd25519, nil, key)
}

func canonicalMLDSA(oid asn1.ObjectIdentifier, p mldsa.Parameters, params, key []byte) ([]byte, error) {
	if len(params) != 0 {
		return nil, malformed("ML-DSA AlgorithmIdentifier parameters must be absent")
	}
	if len(key) != p.PublicKeySize() {
		return nil, malformed(fmt.Sprintf("%s public key must be %d bytes", p, p.PublicKeySize()))
	}
	return marshalSPKI(oid, nil, key)
}

// marshalSPKI builds SEQUENCE { SEQUENCE { oid, params }, BIT STRING key }.
func marshalSPKI(oid asn1.ObjectIdentifier, params func(*cryptobyte.Builder), key []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oid)
			if params != nil {
				params(b)
			}
		})
		b.AddASN1BitString(key)
	})
	return b.Bytes()
}

func namedCurve(oid asn1.ObjectIdentifier) (elliptic.Curve, bool) {
	switch {
	case oid.Equal(oidP256):
		return elliptic.P256(), true
	case oid.Equal(oidP384):
		return elliptic.P384(), true
	case oid.Equal(oidP521):
		return elliptic.P521(), true
	}
	return nil, false
}

func namedCurveOID(c elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch c {
	case elliptic.P256():
		return oidP256, true
	case elliptic.P384():
		return oidP384, true
	case elliptic.P521():
		return oidP521, true
	}
	return nil, false
}

func mldsaParameters(oid asn1.ObjectIdentifier) (mldsa.Parameters, bool) {
	switch {
	case oid.Equal(oidMLDSA44):
		return mldsa.MLDSA44(), true
	case oid.Equal(oidMLDSA65):
		return mldsa.MLDSA65(), true
	case oid.Equal(oidMLDSA87):
		return mldsa.MLDSA87(), true
	}
	return mldsa.Parameters{}, false
}

func mldsaOID(p mldsa.Parameters) (asn1.ObjectIdentifier, bool) {
	switch p {
	case mldsa.MLDSA44():
		return oidMLDSA44, true
	case mldsa.MLDSA65():
		return oidMLDSA65, true
	case mldsa.MLDSA87():
		return oidMLDSA87, true
	}
	return nil, false
}
