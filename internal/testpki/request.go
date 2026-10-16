package testpki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// RequestTemplate describes a certificate signing request to create.
type RequestTemplate struct {
	CommonName     string
	Organization   string
	DNSNames       []string
	IPAddresses    []string
	EmailAddresses []string
	URIs           []string
	// SignatureAlgorithm is left to Go's default for the key when zero.
	SignatureAlgorithm x509.SignatureAlgorithm
	// ExtraExtensions are requested verbatim, e.g. keyUsage or extKeyUsage,
	// which x509.CreateCertificateRequest has no template fields for.
	ExtraExtensions []pkix.Extension
}

// Request creates a certificate signing request for key, signed by it.
func Request(f Fataler, t RequestTemplate, key crypto.Signer) []byte {
	f.Helper()
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: t.CommonName},
		DNSNames:           t.DNSNames,
		EmailAddresses:     t.EmailAddresses,
		SignatureAlgorithm: t.SignatureAlgorithm,
		ExtraExtensions:    t.ExtraExtensions,
	}
	if t.Organization != "" {
		tmpl.Subject.Organization = []string{t.Organization}
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
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		f.Fatalf("create certificate request %q: %v", t.CommonName, err)
	}
	return der
}

// ResignRequest rebuilds a certificate signing request with spki as its
// public key (nil keeps the original) and alg as its signature algorithm, and
// signs it with signer. The subject and attributes (requested extensions
// included) are kept. It produces requests x509.CreateCertificateRequest
// refuses to create (MD5, non-canonical keys) or whose signature does not
// match the requested key.
func ResignRequest(f Fataler, csrDER, spki []byte, alg SigAlg, signer crypto.Signer) []byte {
	f.Helper()
	in := cryptobyte.String(csrDER)
	var csr, info, version, subject, oldSPKI cryptobyte.String
	if !in.ReadASN1(&csr, cbasn1.SEQUENCE) || !csr.ReadASN1(&info, cbasn1.SEQUENCE) ||
		!info.ReadASN1Element(&version, cbasn1.INTEGER) || !info.ReadASN1Element(&subject, cbasn1.SEQUENCE) ||
		!info.ReadASN1Element(&oldSPKI, cbasn1.SEQUENCE) {
		f.Fatalf("resign request: unexpected CertificationRequestInfo structure")
	}
	if spki == nil {
		spki = oldSPKI
	}
	var ib cryptobyte.Builder
	ib.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(version)
		b.AddBytes(subject)
		b.AddBytes(spki)
		b.AddBytes(info) // attributes, unchanged
	})
	infoDER := mustBytes(f, &ib)
	algID := algorithmIdentifier(f, alg)
	sig := sign(f, alg, signer, infoDER)

	var cb cryptobyte.Builder
	cb.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(infoDER)
		b.AddBytes(algID)
		b.AddASN1BitString(sig)
	})
	return mustBytes(f, &cb)
}

// CorruptSignature returns a copy of a certificate or certificate signing
// request DER with the last byte of its signature flipped, so the signature
// no longer verifies while the structure still parses.
func CorruptSignature(der []byte) []byte {
	out := append([]byte{}, der...)
	out[len(out)-1] ^= 0x01
	return out
}
