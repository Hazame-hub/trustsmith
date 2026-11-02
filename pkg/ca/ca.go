// Package ca runs Trustsmith's local CA from Go (ADR-0012, ADR-0016): it
// creates a CA and signs certificate signing requests with it, for callers
// that hold the CA in memory, such as a secret store, rather than in a
// directory.
//
// Both functions run the `trustsmith ca` commands in process (ADR-0015) in a
// private temporary directory that is removed before they return, so every
// certificate is refused or proven exactly as the CLI would: trusted by the
// CA as the only anchor, suitable for its purpose, identifying every name.
// The library never does something the command cannot.
package ca

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/app/casvc"
	"github.com/Hazame-hub/trustsmith/pkg/internal/runcli"
)

// CA is a CA certificate and its private key, both PEM. The key is PKCS #8,
// unencrypted, as `trustsmith ca init` writes it. Treat KeyPEM as a secret.
type CA struct {
	CertPEM []byte
	KeyPEM  []byte
}

// InitOptions describe a new CA, as the flags of `trustsmith ca init` do.
// The zero value is the command's defaults.
type InitOptions struct {
	// Now is the clock the validity starts from; nil uses time.Now.
	Now func() time.Time
	// Name is the CA's common name (--name).
	Name string
	// Organization is the CA's organisation name (--org).
	Organization string
	// KeyType is ecdsa-p256 (the default), ecdsa-p384 or rsa-3072.
	KeyType string
	// Days is the validity in days; zero is the command's default.
	Days int
	// PermitDNS and PermitIP restrict the CA with critical name constraints.
	// Without either the CA can certify any name.
	PermitDNS []string
	PermitIP  []netip.Prefix
}

// Init creates a CA and returns it. Nothing is left on disk.
func Init(opts InitOptions) (CA, error) {
	dir, cleanup, err := privateDir()
	if err != nil {
		return CA{}, err
	}
	defer cleanup()
	caDir := filepath.Join(dir, "ca")
	args := []string{"ca", "init", "--dir", caDir}
	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}
	if opts.Organization != "" {
		args = append(args, "--org", opts.Organization)
	}
	if opts.KeyType != "" {
		args = append(args, "--key-type", opts.KeyType)
	}
	if opts.Days != 0 {
		args = append(args, "--days", strconv.Itoa(opts.Days))
	}
	for _, d := range opts.PermitDNS {
		args = append(args, "--permit-dns", d)
	}
	for _, p := range opts.PermitIP {
		args = append(args, "--permit-ip", p.String())
	}
	if _, err := runcli.JSON(opts.Now, args...); err != nil {
		return CA{}, err
	}
	cert, err := os.ReadFile(filepath.Join(caDir, casvc.CertFile)) //nolint:gosec // inside the private directory this call created
	if err != nil {
		return CA{}, err
	}
	key, err := os.ReadFile(filepath.Join(caDir, casvc.KeyFile)) //nolint:gosec // inside the private directory this call created
	if err != nil {
		return CA{}, err
	}
	return CA{CertPEM: cert, KeyPEM: key}, nil
}

// SignOptions describe the certificate, as the flags of `trustsmith ca sign`
// do. The zero value signs a TLS server certificate for the names the
// request asks for, valid for the command's default number of days.
type SignOptions struct {
	// Now is the clock the validity starts from; nil uses time.Now.
	Now func() time.Time
	// DNSNames and IPs, when either is set, are the names certified instead
	// of the request's subject alternative names.
	DNSNames []string
	IPs      []netip.Addr
	// Use is server (the default), client or both.
	Use string
	// Days is the validity in days, at most 397; zero is the default.
	Days int
}

// Sign signs csr (PEM or DER) with ca and returns the certificate, PEM. The
// request must carry a valid self-signature and an accepted key; the
// certificate is proven before it is returned. An error carries the
// command's message, such as a name outside the CA's constraints.
func Sign(ca CA, csr []byte, opts SignOptions) ([]byte, error) {
	if len(csr) == 0 {
		return nil, errors.New("no certificate signing request")
	}
	dir, cleanup, err := privateDir()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	if err := casvc.Stage(dir, ca.CertPEM, ca.KeyPEM, csr); err != nil {
		return nil, fmt.Errorf("the CA: %w", err)
	}
	out := filepath.Join(dir, "signed")
	args := []string{"ca", "sign", "--ca-dir", dir, "--csr", filepath.Join(dir, casvc.StagedRequestFile), "--out", out}
	for _, d := range opts.DNSNames {
		args = append(args, "--dns", d)
	}
	for _, ip := range opts.IPs {
		args = append(args, "--ip", ip.String())
	}
	if opts.Use != "" {
		args = append(args, "--use", opts.Use)
	}
	if opts.Days != 0 {
		args = append(args, "--days", strconv.Itoa(opts.Days))
	}
	if _, err := runcli.JSON(opts.Now, args...); err != nil {
		return nil, err
	}
	return os.ReadFile(out + ".pem") //nolint:gosec // inside the private directory this call created
}

// privateDir is an owner-only temporary directory (os.MkdirTemp creates it
// with mode 0700) and its removal.
func privateDir() (string, func(), error) {
	dir, err := os.MkdirTemp("", "trustsmith-ca-*")
	if err != nil {
		return "", nil, err
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}
