// Package keyfacts reads a private key file only far enough to name its
// public half (ADR-0013). It is the only package that decodes private keys
// for inspection: the private value is used to derive the public key and is
// never returned, rendered or stored.
package keyfacts

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
)

// Format is how the private key was encoded.
type Format string

const (
	FormatPKCS8 Format = "pkcs8" // PEM "PRIVATE KEY", or DER
	FormatPKCS1 Format = "pkcs1" // PEM "RSA PRIVATE KEY"
	FormatSEC1  Format = "sec1"  // PEM "EC PRIVATE KEY"
)

// Key describes a private key by its public half. It holds no private
// material.
type Key struct {
	Format    Format
	Label     string // PEM label; empty for DER
	Algorithm string // RSA, ECDSA, Ed25519, ML-DSA
	Detail    string // curve or parameter set
	Bits      int    // RSA modulus or EC field size; 0 when not meaningful
	// KeyID is the ADR-0002 x509-spki-sha256 identity of the public key: the
	// same value inspect reports for a certificate holding that key.
	KeyID fingerprint.KeyID
}

var (
	// ErrEncrypted: the key is protected by a passphrase. This version reads
	// unencrypted keys only and never asks for a passphrase.
	ErrEncrypted = errors.New("the private key is encrypted; this version reads unencrypted keys only")
	// ErrNoKey: no private key in the input.
	ErrNoKey = errors.New("no private key found")
	// ErrManyKeys: more than one private key, so which one is meant is
	// ambiguous.
	ErrManyKeys = errors.New("more than one private key found; give a file holding exactly one")
	// ErrUnreadable: a private key block that could not be decoded.
	ErrUnreadable = errors.New("the private key could not be read")
)

// ignoredLabels may accompany a key in the same file and are skipped:
// OpenSSL writes EC PARAMETERS before an EC key, and combined files put the
// certificate next to its key.
var ignoredLabels = map[string]bool{"EC PARAMETERS": true, "CERTIFICATE": true}

var keyLabels = map[string]Format{
	"PRIVATE KEY":     FormatPKCS8,
	"RSA PRIVATE KEY": FormatPKCS1,
	"EC PRIVATE KEY":  FormatSEC1,
}

// Parse reads exactly one private key from PEM, or DER PKCS #8, and returns
// its public description.
func Parse(data []byte) (Key, error) {
	if !bytes.Contains(data, []byte("-----BEGIN ")) {
		return fromDER(FormatPKCS8, "", data)
	}
	var (
		found *pem.Block
		rest  = data
	)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case block.Type == "ENCRYPTED PRIVATE KEY", block.Headers["Proc-Type"] == "4,ENCRYPTED":
			return Key{}, ErrEncrypted
		case ignoredLabels[block.Type]:
			continue
		case keyLabels[block.Type] == "":
			return Key{}, fmt.Errorf("%w: unexpected %s block", ErrUnreadable, block.Type)
		}
		if found != nil {
			return Key{}, ErrManyKeys
		}
		found = block
	}
	if found == nil {
		// pem.Decode skips a block it cannot decode; a key label that
		// produced no block is a corrupt key, not an absent one.
		if bytes.Contains(data, []byte("PRIVATE KEY-----")) {
			return Key{}, fmt.Errorf("%w: a private key block is corrupt", ErrUnreadable)
		}
		return Key{}, ErrNoKey
	}
	return fromDER(keyLabels[found.Type], found.Type, found.Bytes)
}

func fromDER(format Format, label string, der []byte) (Key, error) {
	var (
		priv any
		err  error
	)
	switch format {
	case FormatPKCS1:
		priv, err = x509.ParsePKCS1PrivateKey(der)
	case FormatSEC1:
		priv, err = x509.ParseECPrivateKey(der)
	default:
		priv, err = x509.ParsePKCS8PrivateKey(der)
	}
	if err != nil {
		if label == "" {
			return Key{}, ErrNoKey // DER that is not PKCS #8: not a key at all
		}
		return Key{}, fmt.Errorf("%w: %s", ErrUnreadable, err.Error())
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return Key{}, fmt.Errorf("%w: unsupported key type %T", ErrUnreadable, priv)
	}
	k := Key{Format: format, Label: label}
	pub := signer.Public()
	switch p := pub.(type) {
	case *rsa.PublicKey:
		k.Algorithm, k.Bits = "RSA", p.N.BitLen()
	case *ecdsa.PublicKey:
		k.Algorithm, k.Detail, k.Bits = "ECDSA", p.Curve.Params().Name, p.Curve.Params().BitSize
	case ed25519.PublicKey:
		k.Algorithm = "Ed25519"
	case *mldsa.PublicKey:
		k.Algorithm, k.Detail = "ML-DSA", p.Parameters().String()
	default:
		k.Algorithm = fmt.Sprintf("%T", pub)
	}
	if k.KeyID, err = fingerprint.KeyIDFromPublicKey(pub); err != nil {
		return Key{}, fmt.Errorf("%w: %s", ErrUnreadable, err.Error())
	}
	return k, nil
}
