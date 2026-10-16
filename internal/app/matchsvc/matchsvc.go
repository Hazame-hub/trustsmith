// Package matchsvc answers "does this private key belong to this
// certificate?" (ADR-0013). It compares public keys by their ADR-0002
// identity, so the private key is only ever read, never shown.
package matchsvc

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Hazame-hub/trustsmith/internal/artifact"
	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/keyfacts"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

// State is the answer for one certificate.
type State string

const (
	Matches      State = "matches"        // the key is the private half of the certificate's key
	DoesNotMatch State = "does_not_match" // the certificate certifies a different key
	// Unverifiable: the certificate's key has no ADR-0002 identity
	// (unsupported or malformed), so no claim is made either way.
	Unverifiable State = "unverifiable"
)

// Certificate is one certificate of the certificate file and its answer.
type Certificate struct {
	Entry       int
	Fingerprint fingerprint.Cert
	Subject     string
	KeyID       fingerprint.KeyID // zero when Unverifiable
	State       State
	Detail      string // why, when Unverifiable
}

// Result is a complete comparison.
type Result struct {
	CertificateFile string
	KeyFile         string
	Key             keyfacts.Key
	Certificates    []Certificate // in input order
	// Matched is the entry of the first matching certificate, or -1.
	Matched int
}

// ErrNoCertificate: the certificate file holds no parseable certificate.
var ErrNoCertificate = errors.New("no certificate found")

// Match compares the key in keyPath with every certificate in certPath.
func Match(certPath, keyPath string) (Result, error) {
	keyData, err := readLimited(keyPath)
	if err != nil {
		return Result{}, err
	}
	key, err := keyfacts.Parse(keyData)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", keyPath, err)
	}
	certData, err := readLimited(certPath)
	if err != nil {
		return Result{}, err
	}
	decoded, err := artifact.Decode(certData)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", certPath, err)
	}
	res := Result{CertificateFile: certPath, KeyFile: keyPath, Key: key, Certificates: []Certificate{}, Matched: -1}
	for _, b := range decoded.Blocks {
		if b.Kind != artifact.KindCertificate {
			continue
		}
		p := x509facts.FromDER(b.DER)
		if p.Certificate == nil {
			continue
		}
		c := p.Certificate
		out := Certificate{Entry: b.Entry, Fingerprint: c.Fingerprint, Subject: c.Subject.DN, KeyID: c.KeyID}
		switch {
		case c.KeyIdentity != x509facts.KeyIdentityCanonical && c.KeyIdentity != x509facts.KeyIdentityNoncanonical:
			out.State, out.Detail = Unverifiable, c.KeyIdentityDetail
		case c.KeyID == key.KeyID:
			out.State = Matches
			if res.Matched < 0 {
				res.Matched = b.Entry
			}
		default:
			out.State = DoesNotMatch
		}
		res.Certificates = append(res.Certificates, out)
	}
	if len(res.Certificates) == 0 {
		return Result{}, fmt.Errorf("%s: %w", certPath, ErrNoCertificate)
	}
	return res, nil
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // reading the file the user named is the purpose
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if info, err := f.Stat(); err == nil && info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, artifact.MaxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > artifact.MaxInputBytes {
		return nil, fmt.Errorf("%s: %w (limit %d bytes)", path, artifact.ErrTooLarge, artifact.MaxInputBytes)
	}
	return data, nil
}
