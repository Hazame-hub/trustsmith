// Package casvc is the local CA application service (ADR-0012, ADR-0016): it
// creates a CA directory, and issues certificates from it, or signs requests
// for keys held elsewhere, after proving each one with the same inspection
// code path as `trustsmith inspect`. It is the only
// package that writes private keys to disk.
package casvc

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/hostname"
	"github.com/Hazame-hub/trustsmith/internal/issuance"
	"github.com/Hazame-hub/trustsmith/internal/purpose"
	"github.com/Hazame-hub/trustsmith/internal/trustverify"
)

// File names inside a CA directory.
const (
	CertFile = "ca.pem"
	KeyFile  = "ca.key"
)

// Permissions. On Windows these map to the read-only bit only; ADR-0012 says
// what that means for the key.
const (
	dirMode  fs.FileMode = 0o700
	keyMode  fs.FileMode = 0o600
	certMode fs.FileMode = 0o644
)

// Service creates and uses local CAs.
type Service struct {
	now  func() time.Time
	rand io.Reader
}

// New returns a service that reads the time from now and randomness from
// rand (crypto/rand.Reader outside tests).
func New(now func() time.Time, rand io.Reader) *Service {
	return &Service{now: now, rand: rand}
}

// InitRequest describes a new CA directory.
type InitRequest struct {
	Dir          string
	CommonName   string
	Organization string
	KeyType      issuance.KeyType
	Validity     time.Duration
	PermittedDNS []string
	PermittedIPs []netip.Prefix
}

// Init is a created CA.
type Init struct {
	CertPath    string
	KeyPath     string
	Certificate *x509.Certificate
	Fingerprint fingerprint.Cert
}

// ErrExists marks a refusal to overwrite: Trustsmith never replaces a key or
// certificate file.
var ErrExists = errors.New("already exists")

// Init creates the CA directory and its root certificate and key. It refuses
// if either file already exists, so an existing CA is never replaced.
func (s *Service) Init(r InitRequest) (Init, error) {
	certPath, keyPath := filepath.Join(r.Dir, CertFile), filepath.Join(r.Dir, KeyFile)
	if err := refuseExisting(certPath, keyPath); err != nil {
		return Init{}, err
	}
	key, err := issuance.GenerateKey(s.rand, r.KeyType)
	if err != nil {
		return Init{}, err
	}
	der, err := issuance.Root(issuance.RootRequest{
		CommonName: r.CommonName, Organization: r.Organization,
		Now: s.now(), Validity: r.Validity,
		PermittedDNS: r.PermittedDNS, PermittedIPs: r.PermittedIPs,
		Key: key, Rand: s.rand,
	})
	if err != nil {
		return Init{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Init{}, err
	}
	if err := os.MkdirAll(r.Dir, dirMode); err != nil {
		return Init{}, err
	}
	if err := writePair(certPath, issuance.EncodeCertificate(der), keyPath, key); err != nil {
		return Init{}, err
	}
	return Init{CertPath: certPath, KeyPath: keyPath, Certificate: cert, Fingerprint: fingerprint.CertFromDER(der)}, nil
}

// IssueRequest describes an end-entity certificate to issue from the CA in
// Dir, written to Out+".pem" and Out+".key".
type IssueRequest struct {
	Dir      string
	Out      string
	DNSNames []string
	IPs      []netip.Addr
	Server   bool
	Client   bool
	KeyType  issuance.KeyType
	Validity time.Duration
}

// Issued is an issued, proven and written certificate.
type Issued struct {
	CertPath    string
	KeyPath     string
	Certificate *x509.Certificate
	// Proof is the inspection of the issued certificate against the CA as the
	// only trust anchor, for the requested purpose and the first requested
	// name. Every requested name was checked the same way before writing.
	Proof inspectsvc.Result
}

// ErrNotProven marks an issued certificate that failed its own inspection.
// Nothing is written in that case.
var ErrNotProven = errors.New("the issued certificate did not pass inspection")

// Issue creates a key and a certificate signed by the CA in r.Dir, proves the
// certificate with the inspect service (trusted by this CA alone, suitable
// for each requested purpose, identifying every requested name), and only
// then writes the key and the certificate. Existing files are never replaced.
func (s *Service) Issue(r IssueRequest) (Issued, error) {
	certPath, keyPath := r.Out+".pem", r.Out+".key"
	if err := refuseExisting(certPath, keyPath); err != nil {
		return Issued{}, err
	}
	caCertPath := filepath.Join(r.Dir, CertFile)
	ca, caKey, err := loadCA(r.Dir)
	if err != nil {
		return Issued{}, err
	}
	key, err := issuance.GenerateKey(s.rand, r.KeyType)
	if err != nil {
		return Issued{}, err
	}
	now := s.now()
	der, err := issuance.Leaf(issuance.LeafRequest{
		DNSNames: r.DNSNames, IPs: r.IPs, Server: r.Server, Client: r.Client,
		Now: now, Validity: r.Validity,
		Key: key.Public(), CA: ca, CAKey: caKey, Rand: s.rand,
	})
	if err != nil {
		return Issued{}, err
	}
	certPEM := issuance.EncodeCertificate(der)
	proof, err := s.prove(certPEM, caCertPath, now, r.Out, r.Server, r.Client, r.DNSNames, r.IPs)
	if err != nil {
		return Issued{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Issued{}, err
	}
	if err := writePair(certPath, certPEM, keyPath, key); err != nil {
		return Issued{}, err
	}
	return Issued{CertPath: certPath, KeyPath: keyPath, Certificate: cert, Proof: proof}, nil
}

// SignRequest describes a certificate for a key someone else holds: the
// certificate signing request in CSR (PEM or DER) is signed by the CA in Dir
// and the certificate written to Out+".pem". No key is created or written.
//
// The names certified are DNSNames and IPs when either is set, and otherwise
// the subject alternative names the request asks for. The request's subject
// and any other extension it asks for are ignored: the CA decides what it
// certifies, the request only proves possession of the key.
type SignRequest struct {
	Dir      string
	Out      string
	CSR      []byte
	DNSNames []string
	IPs      []netip.Addr
	Server   bool
	Client   bool
	Validity time.Duration
}

// Signed is a signed, proven and written certificate.
type Signed struct {
	CertPath    string
	Certificate *x509.Certificate
	DNSNames    []string
	IPs         []netip.Addr
	// Proof is the inspection of the certificate against the CA as the only
	// trust anchor, as for Issue.
	Proof inspectsvc.Result
}

// Sign checks the request's self-signature and key, signs a certificate for
// its key, proves it exactly as Issue does, and only then writes it. An
// existing file is never replaced.
func (s *Service) Sign(r SignRequest) (Signed, error) {
	certPath := r.Out + ".pem"
	if err := refuseExisting(certPath); err != nil {
		return Signed{}, err
	}
	csr, err := ParseCSR(r.CSR)
	if err != nil {
		return Signed{}, err
	}
	if err := csr.CheckSignature(); err != nil {
		return Signed{}, fmt.Errorf("%w: the request's signature does not verify, so it does not prove possession of its key: %w", issuance.ErrRequest, err)
	}
	if err := issuance.CheckSubjectKey(csr.PublicKey); err != nil {
		return Signed{}, err
	}
	dnsNames, ips := r.DNSNames, r.IPs
	if len(dnsNames) == 0 && len(ips) == 0 {
		dnsNames = csr.DNSNames
		for _, ip := range csr.IPAddresses {
			a, _ := netip.AddrFromSlice(ip)
			ips = append(ips, a.Unmap())
		}
	}
	caCertPath := filepath.Join(r.Dir, CertFile)
	ca, caKey, err := loadCA(r.Dir)
	if err != nil {
		return Signed{}, err
	}
	now := s.now()
	der, err := issuance.Leaf(issuance.LeafRequest{
		DNSNames: dnsNames, IPs: ips, Server: r.Server, Client: r.Client,
		Now: now, Validity: r.Validity,
		Key: csr.PublicKey, CA: ca, CAKey: caKey, Rand: s.rand,
	})
	if err != nil {
		return Signed{}, err
	}
	certPEM := issuance.EncodeCertificate(der)
	proof, err := s.prove(certPEM, caCertPath, now, r.Out, r.Server, r.Client, dnsNames, ips)
	if err != nil {
		return Signed{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Signed{}, err
	}
	if err := writeExclusive(certPath, certPEM, certMode); err != nil {
		return Signed{}, err
	}
	return Signed{CertPath: certPath, Certificate: cert, DNSNames: dnsNames, IPs: ips, Proof: proof}, nil
}

// ParseCSR reads one certificate signing request, PEM ("CERTIFICATE REQUEST"
// or the legacy "NEW CERTIFICATE REQUEST") or DER.
func ParseCSR(data []byte) (*x509.CertificateRequest, error) {
	der := data
	if block, rest := pem.Decode(data); block != nil {
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			return nil, fmt.Errorf("%w: expected a certificate signing request, found a PEM %q block", issuance.ErrRequest, block.Type)
		}
		if len(strings.TrimSpace(string(rest))) != 0 {
			return nil, fmt.Errorf("%w: the request file holds more than one PEM block", issuance.ErrRequest)
		}
		der = block.Bytes
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("%w: not a certificate signing request: %w", issuance.ErrRequest, err)
	}
	return csr, nil
}

// wildcardProbeLabel stands in for "*" when proving a wildcard name: the
// certificate must identify that concrete name under the wildcard.
const wildcardProbeLabel = "trustsmith-wildcard-check"

// prove inspects the in-memory certificate once per requested purpose and
// name, with the CA certificate file as the only trust anchor, and returns
// the first inspection.
func (s *Service) prove(certPEM []byte, caCertPath string, now time.Time, out string, server, client bool, dnsNames []string, ips []netip.Addr) (inspectsvc.Result, error) {
	roots, err := inspectsvc.LoadRoots([]string{caCertPath})
	if err != nil {
		return inspectsvc.Result{}, err
	}
	var purposes []purpose.Purpose
	if server {
		purposes = append(purposes, purpose.TLSServer)
	}
	if client {
		purposes = append(purposes, purpose.TLSClient)
	}
	names := append([]string{}, dnsNames...)
	for _, ip := range ips {
		names = append(names, ip.String())
	}
	var first *inspectsvc.Result
	for _, p := range purposes {
		for _, name := range names {
			// A wildcard is proven through a name it must cover.
			req, err := hostname.ParseRequest(strings.Replace(name, "*", wildcardProbeLabel, 1))
			if err != nil {
				return inspectsvc.Result{}, fmt.Errorf("%w: %s: %w", ErrNotProven, name, err)
			}
			svc := inspectsvc.New(func() time.Time { return now },
				inspectsvc.WithRoots(roots), inspectsvc.WithPurpose(p), inspectsvc.WithHostname(req))
			res, err := svc.InspectBytes(inspectsvc.Source{Kind: inspectsvc.SourceFile, Locator: out + ".pem"}, certPEM)
			if err != nil {
				return inspectsvc.Result{}, err
			}
			if err := proven(res); err != nil {
				return inspectsvc.Result{}, fmt.Errorf("%w for %s as %s: %w", ErrNotProven, name, p, err)
			}
			if first == nil {
				first = &res
			}
		}
	}
	return *first, nil
}

// proven requires the three independent answers inspect gives: trusted by
// the CA, suitable for the purpose, identifying the name.
func proven(res inspectsvc.Result) error {
	if len(res.Trust.Targets) != 1 || res.Trust.Targets[0].Result.State != trustverify.Verified {
		return errors.New("it does not validate against its CA")
	}
	if len(res.Purpose.Targets) != 1 || res.Purpose.Targets[0].Usage.State != purpose.Suitable {
		return errors.New("its key usages do not permit the purpose")
	}
	if len(res.Hostname.Targets) != 1 || res.Hostname.Targets[0].Result.State != hostname.Matched {
		return errors.New("it does not identify the name")
	}
	return nil
}

// loadCA reads the CA certificate and key and checks that they belong
// together.
func loadCA(dir string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, CertFile)) //nolint:gosec // the CA directory the user named
	if err != nil {
		return nil, nil, fmt.Errorf("CA certificate: %w (create a CA with 'trustsmith ca init')", err)
	}
	certs, err := parseCertificates(certPEM)
	if err != nil || len(certs) != 1 {
		return nil, nil, fmt.Errorf("CA certificate %s: want exactly one PEM certificate", filepath.Join(dir, CertFile))
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, KeyFile)) //nolint:gosec // the CA directory the user named
	if err != nil {
		return nil, nil, fmt.Errorf("CA key: %w", err)
	}
	key, err := issuance.DecodePrivateKey(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("CA key %s: %w", filepath.Join(dir, KeyFile), err)
	}
	if !issuance.KeyMatches(certs[0], key) {
		return nil, nil, fmt.Errorf("CA key %s does not belong to %s", filepath.Join(dir, KeyFile), filepath.Join(dir, CertFile))
	}
	if !certs[0].IsCA {
		return nil, nil, fmt.Errorf("%s is not a CA certificate", filepath.Join(dir, CertFile))
	}
	return certs[0], key, nil
}

func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected %s block", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
		data = rest
	}
	return certs, nil
}

func refuseExisting(paths ...string) error {
	for _, p := range paths {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("%s %w; Trustsmith never overwrites keys or certificates", p, ErrExists)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// writePair writes the key, then the certificate, each created exclusively.
// If the certificate cannot be written the new key is removed, so a failure
// never leaves a key without its certificate.
func writePair(certPath string, certPEM []byte, keyPath string, key crypto.Signer) error {
	keyPEM, err := issuance.EncodePrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeExclusive(keyPath, keyPEM, keyMode); err != nil {
		return err
	}
	if err := writeExclusive(certPath, certPEM, certMode); err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	return nil
}

func writeExclusive(path string, data []byte, mode fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // the output path the user named
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s %w; Trustsmith never overwrites keys or certificates", path, ErrExists)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// Stage writes an existing CA and, when csr is set, a request to sign into
// dir, an empty directory the caller created, so the library in pkg/ca can
// run `trustsmith ca sign` on material it was handed in memory. The CA is
// loaded back and refused unless its key belongs to its certificate, so a
// mismatched pair fails here and not halfway through a signature. Files are
// written exclusively, the key with owner-only permissions.
func Stage(dir string, caCertPEM, caKeyPEM, csr []byte) error {
	if err := writeExclusive(filepath.Join(dir, KeyFile), caKeyPEM, keyMode); err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(dir, CertFile), caCertPEM, certMode); err != nil {
		return err
	}
	if _, _, err := loadCA(dir); err != nil {
		return err
	}
	if csr != nil {
		return writeExclusive(filepath.Join(dir, StagedRequestFile), csr, certMode)
	}
	return nil
}

// StagedRequestFile is the name Stage gives the request inside the directory.
const StagedRequestFile = "request.csr"
