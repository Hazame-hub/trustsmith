// Package issuance creates the certificates of Trustsmith's local private CA
// (ADR-0012). It is the only production package that creates certificates or
// generates private keys, which internal/archtest enforces.
//
// It is pure in the same sense as the domain packages: the time, the
// randomness source and every key are inputs, and it never touches the
// filesystem. Storing what it creates is internal/app/casvc's job.
package issuance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// KeyType is the algorithm of a generated key.
type KeyType string

const (
	KeyECDSAP256 KeyType = "ecdsa-p256" // the default: small, fast, accepted everywhere TLS 1.2 is
	KeyECDSAP384 KeyType = "ecdsa-p384"
	KeyRSA3072   KeyType = "rsa-3072" // for software that still accepts only RSA
)

// KeyTypes lists the accepted spellings, default first.
func KeyTypes() []KeyType { return []KeyType{KeyECDSAP256, KeyECDSAP384, KeyRSA3072} }

// ParseKeyType accepts exactly the spellings of KeyTypes.
func ParseKeyType(s string) (KeyType, error) {
	for _, k := range KeyTypes() {
		if string(k) == s {
			return k, nil
		}
	}
	return "", fmt.Errorf("unknown key type %q (want one of %s)", s, joinKeyTypes())
}

func joinKeyTypes() string {
	names := make([]string, 0, len(KeyTypes()))
	for _, k := range KeyTypes() {
		names = append(names, string(k))
	}
	return strings.Join(names, ", ")
}

// GenerateKey creates a private key of type t from rand.
func GenerateKey(rand io.Reader, t KeyType) (crypto.Signer, error) {
	switch t {
	case KeyECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand)
	case KeyECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand)
	case KeyRSA3072:
		return rsa.GenerateKey(rand, 3072)
	}
	return nil, fmt.Errorf("unknown key type %q", t)
}

// Limits on what the local CA issues. They are policy, not protocol: the
// leaf maximum follows the CA/Browser Forum's 398-day limit so a certificate
// from this CA is never rejected for its lifetime alone.
const (
	DefaultRootValidity = 5 * 365 * 24 * time.Hour
	MaxRootValidity     = 20 * 365 * 24 * time.Hour
	DefaultLeafValidity = 90 * 24 * time.Hour
	MaxLeafValidity     = 397 * 24 * time.Hour
	// Backdate starts each certificate slightly before the issuing time so a
	// relying party whose clock is a little behind still accepts it.
	Backdate = 5 * time.Minute
)

// closedDNSDomain is the only DNS subtree permitted to a CA constrained to IP
// ranges: "invalid" is reserved by RFC 6761 and never names a real host.
const closedDNSDomain = "invalid"

// ErrRequest marks a request the CA refuses; the message says why.
var ErrRequest = errors.New("refused")

// RootRequest describes a new self-signed root CA.
type RootRequest struct {
	CommonName   string
	Organization string
	Now          time.Time
	Validity     time.Duration
	// PermittedDNS and PermittedIPs, when either is non-empty, become a
	// critical name constraints extension: certificates for other DNS names
	// or IP addresses fail validation everywhere name constraints are
	// enforced, even if the CA key leaks. Naming only one type closes the
	// other. Empty means the CA may certify any name.
	PermittedDNS []string
	PermittedIPs []netip.Prefix
	Key          crypto.Signer
	Rand         io.Reader
}

// Root creates a self-signed root CA certificate and returns its DER.
//
// The root may sign end-entity certificates only (pathLenConstraint 0), so
// the local CA has no intermediates to manage and a leaked leaf key can never
// sign anything.
func Root(r RootRequest) ([]byte, error) {
	if strings.TrimSpace(r.CommonName) == "" {
		return nil, fmt.Errorf("%w: the CA needs a name", ErrRequest)
	}
	if err := checkValidity(r.Validity, MaxRootValidity); err != nil {
		return nil, err
	}
	for _, d := range r.PermittedDNS {
		if err := checkDNSName(d, false); err != nil {
			return nil, fmt.Errorf("%w: permitted domain %q: %w", ErrRequest, d, err)
		}
	}
	serial, err := newSerial(r.Rand)
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(r.Key.Public())
	if err != nil {
		return nil, err
	}
	subject := pkix.Name{CommonName: r.CommonName}
	if r.Organization != "" {
		subject.Organization = []string{r.Organization}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             r.Now.Add(-Backdate).UTC(),
		NotAfter:              r.Now.Add(r.Validity).UTC(),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski,
	}
	if len(r.PermittedDNS) > 0 || len(r.PermittedIPs) > 0 {
		// RFC 5280 leaves a name type with no permitted subtree
		// unconstrained, so naming only DNS domains would still let the CA
		// certify any IP address, and the reverse. Closing the other type
		// makes the constraint mean what the user asked: these names only.
		tmpl.PermittedDNSDomainsCritical = true
		tmpl.PermittedDNSDomains = slices.Clone(r.PermittedDNS)
		if len(r.PermittedDNS) == 0 {
			tmpl.PermittedDNSDomains = []string{closedDNSDomain}
		}
		if len(r.PermittedIPs) == 0 {
			tmpl.ExcludedIPRanges = []*net.IPNet{
				{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
				{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			}
		}
		for _, p := range r.PermittedIPs {
			p = p.Masked()
			tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, &net.IPNet{
				IP:   p.Addr().AsSlice(),
				Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
			})
		}
	}
	return x509.CreateCertificate(r.Rand, tmpl, tmpl, r.Key.Public(), r.Key)
}

// LeafRequest describes an end-entity certificate issued by a local CA.
type LeafRequest struct {
	DNSNames []string
	IPs      []netip.Addr
	// Server and Client select the extended key usages; at least one is
	// required.
	Server   bool
	Client   bool
	Now      time.Time
	Validity time.Duration
	Key      crypto.PublicKey // the subject's public key
	CA       *x509.Certificate
	CAKey    crypto.Signer
	Rand     io.Reader
}

// Leaf creates an end-entity certificate signed by the CA and returns its
// DER. Names live in the subject alternative names, which is all modern
// software reads; the Common Name repeats the first one for people.
//
// It refuses rather than adjusts: a certificate that would outlive its CA or
// fall outside the CA's name constraints is an error naming the problem, so
// what is issued is always what was asked for.
func Leaf(r LeafRequest) ([]byte, error) {
	if len(r.DNSNames) == 0 && len(r.IPs) == 0 {
		return nil, fmt.Errorf("%w: a certificate needs at least one DNS name or IP address", ErrRequest)
	}
	if !r.Server && !r.Client {
		return nil, fmt.Errorf("%w: a certificate needs a purpose (server, client or both)", ErrRequest)
	}
	for _, d := range r.DNSNames {
		if err := checkDNSName(d, true); err != nil {
			return nil, fmt.Errorf("%w: DNS name %q: %w", ErrRequest, d, err)
		}
	}
	if err := checkValidity(r.Validity, MaxLeafValidity); err != nil {
		return nil, err
	}
	notAfter := r.Now.Add(r.Validity).UTC()
	if notAfter.After(r.CA.NotAfter) {
		return nil, fmt.Errorf("%w: the certificate would be valid until %s, after its CA expires on %s; ask for a shorter validity",
			ErrRequest, notAfter.Format(time.DateOnly), r.CA.NotAfter.UTC().Format(time.DateOnly))
	}
	if r.Now.Before(r.CA.NotBefore) {
		return nil, fmt.Errorf("%w: the CA is not valid until %s", ErrRequest, r.CA.NotBefore.UTC().Format(time.RFC3339))
	}
	if err := withinConstraints(r.CA, r.DNSNames, r.IPs); err != nil {
		return nil, err
	}
	serial, err := newSerial(r.Rand)
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(r.Key)
	if err != nil {
		return nil, err
	}
	cn := ""
	if len(r.DNSNames) > 0 {
		cn = r.DNSNames[0]
	} else {
		cn = r.IPs[0].String()
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             r.Now.Add(-Backdate).UTC(),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              slices.Clone(r.DNSNames),
		SubjectKeyId:          ski,
		AuthorityKeyId:        r.CA.SubjectKeyId,
	}
	if _, ok := r.Key.(*rsa.PublicKey); ok {
		// RSA key transport in TLS 1.2 needs keyEncipherment.
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	for _, ip := range r.IPs {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip.AsSlice())
	}
	if r.Server {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if r.Client {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	return x509.CreateCertificate(r.Rand, tmpl, r.CA, r.Key, r.CAKey)
}

func checkValidity(v, maxValidity time.Duration) error {
	switch {
	case v < time.Hour:
		return fmt.Errorf("%w: validity must be at least one hour", ErrRequest)
	case v > maxValidity:
		return fmt.Errorf("%w: validity must be at most %d days", ErrRequest, int(maxValidity.Hours()/24))
	}
	return nil
}

// checkDNSName accepts lower-case LDH host names in A-label form, and, when
// wildcard is true, a "*." prefix on a name of at least two labels.
func checkDNSName(name string, wildcard bool) error {
	rest := name
	if wildcard && strings.HasPrefix(name, "*.") {
		rest = name[2:]
		if !strings.Contains(rest, ".") {
			return errors.New("a wildcard must cover a name of at least two labels")
		}
	}
	if rest == "" || len(name) > 253 {
		return errors.New("not a host name")
	}
	for label := range strings.SplitSeq(rest, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("not a host name")
		}
		for _, c := range label {
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			case c >= 'A' && c <= 'Z':
				return errors.New("write host names in lower case")
			default:
				return errors.New("not a host name (internationalised names must be written in their xn-- form)")
			}
		}
	}
	return nil
}

// withinConstraints applies RFC 5280's permitted-subtree rule for DNS names
// and IP ranges, the way Go's verifier does: a name matches a constraint
// equal to it or to one of its parent domains.
func withinConstraints(ca *x509.Certificate, dns []string, ips []netip.Addr) error {
	if len(ca.PermittedDNSDomains) > 0 || len(ca.PermittedIPRanges) > 0 {
		for _, d := range dns {
			name := strings.TrimPrefix(d, "*.")
			if !slices.ContainsFunc(ca.PermittedDNSDomains, func(c string) bool {
				c = strings.TrimPrefix(c, ".")
				return name == c || strings.HasSuffix(name, "."+c)
			}) {
				return fmt.Errorf("%w: %s is outside the CA's permitted names (%s)", ErrRequest, d, strings.Join(ca.PermittedDNSDomains, ", "))
			}
		}
		for _, ip := range ips {
			if !slices.ContainsFunc(ca.PermittedIPRanges, func(n *net.IPNet) bool { return n.Contains(ip.AsSlice()) }) {
				return fmt.Errorf("%w: %s is outside the CA's permitted IP ranges", ErrRequest, ip)
			}
		}
	}
	return nil
}

// newSerial returns a positive 128-bit random serial number (RFC 5280 allows
// up to 20 octets; CA/Browser Forum rules ask for at least 64 random bits).
func newSerial(rand io.Reader) (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand, b); err != nil {
		return nil, fmt.Errorf("serial number: %w", err)
	}
	b[0] &= 0x7f
	b[0] |= 0x40 // keep it 16 octets long and positive
	return new(big.Int).SetBytes(b), nil
}

// subjectKeyID is the SHA-256 of the subject public key, truncated to 160
// bits (RFC 7093 method 1).
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(info.PublicKey.Bytes)
	return sum[:20], nil
}

// EncodeCertificate returns the PEM encoding of a certificate.
func EncodeCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// EncodePrivateKey returns the unencrypted PKCS #8 PEM encoding of a key.
// Protecting the bytes is the caller's job (ADR-0012).
func EncodePrivateKey(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// DecodePrivateKey parses an unencrypted PKCS #8 PEM private key, the format
// EncodePrivateKey writes.
func DecodePrivateKey(data []byte) (crypto.Signer, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("not a single PKCS #8 PEM private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
	return signer, nil
}

// KeyMatches reports whether key is the private half of cert's public key.
func KeyMatches(cert *x509.Certificate, key crypto.Signer) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	pub, ok := key.Public().(equaler)
	return ok && pub.Equal(cert.PublicKey)
}
