package inspectsvc

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Hazame-hub/trustsmith/internal/artifact"
	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

// RootsFile is one file of explicitly supplied trust anchors.
type RootsFile struct {
	Locator      string
	Certificates int // certificate blocks it contains, duplicates included
}

// AnchorSource locates one occurrence of an anchor in a roots file.
type AnchorSource struct {
	File  string
	Entry int
}

// Anchor is a certificate the user explicitly supplied as a trust anchor. It
// is an anchor because it was supplied, not because of anything it contains:
// it need not be self-signed.
type Anchor struct {
	Certificate *x509facts.Certificate
	Sources     []AnchorSource
}

// Roots are the trust anchors explicitly supplied for an inspection.
type Roots struct {
	Files   []RootsFile
	Anchors []Anchor // deduplicated by x509-cert-sha256, in order of first appearance
}

// ErrRoots marks a roots file that cannot be used. Roots are all or nothing: a
// file that cannot be read completely and unambiguously is refused, and no
// other trust source is ever used instead.
var ErrRoots = errors.New("unusable roots file")

// LoadRoots reads files of explicitly supplied trust anchors.
//
// A roots file may contain only certificates, in PEM or DER. The whole file
// is refused, and the returned error names the entry, when it contains:
//   - any other block, such as a private key (never decoded);
//   - a malformed or unparseable block;
//   - a certificate request;
//   - no certificate at all.
func LoadRoots(paths []string) (Roots, error) {
	roots := Roots{Files: []RootsFile{}, Anchors: []Anchor{}}
	index := map[fingerprint.Cert]int{}
	for _, path := range paths {
		data, err := readLimited(path)
		if err != nil {
			return Roots{}, fmt.Errorf("roots file %s: %w", path, err)
		}
		entries, err := rootsCertificates(data)
		if err != nil {
			return Roots{}, fmt.Errorf("%w %s: %w", ErrRoots, path, err)
		}
		roots.Files = append(roots.Files, RootsFile{Locator: path, Certificates: len(entries)})
		for _, e := range entries {
			src := AnchorSource{File: path, Entry: e.entry}
			if i, ok := index[e.cert.Fingerprint]; ok {
				roots.Anchors[i].Sources = append(roots.Anchors[i].Sources, src)
				continue
			}
			index[e.cert.Fingerprint] = len(roots.Anchors)
			roots.Anchors = append(roots.Anchors, Anchor{Certificate: e.cert, Sources: []AnchorSource{src}})
		}
	}
	return roots, nil
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // reading the file the user named is the purpose
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, errors.New("is a directory, not a certificate file")
	}
	data, err := io.ReadAll(io.LimitReader(f, artifact.MaxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > artifact.MaxInputBytes {
		return nil, artifact.ErrTooLarge
	}
	return data, nil
}

type rootsEntry struct {
	entry int
	cert  *x509facts.Certificate
}

func rootsCertificates(data []byte) ([]rootsEntry, error) {
	decoded, err := artifact.Decode(data)
	if err != nil {
		return nil, err
	}
	switch {
	case decoded.Format == artifact.FormatEmpty:
		return nil, errors.New("the file is empty; a roots file must contain at least one certificate")
	case decoded.Format == artifact.FormatUnknown:
		return nil, errors.New("the file is neither PEM nor DER")
	case decoded.Format == artifact.FormatDER && len(decoded.Extraneous) > 0:
		return nil, errors.New("data follows the DER certificate")
	}
	var out []rootsEntry
	for _, b := range decoded.Blocks {
		switch b.Kind {
		case artifact.KindMalformed:
			return nil, fmt.Errorf("entry %d is malformed (%s)", b.Entry, b.Problem)
		case artifact.KindUnsupported:
			if b.Label != "" {
				return nil, fmt.Errorf("entry %d is a %q PEM block; a roots file may contain only certificates (the block was not decoded)", b.Entry, b.Label)
			}
			return nil, fmt.Errorf("entry %d is not a certificate", b.Entry)
		case artifact.KindCertificateRequest:
			return nil, fmt.Errorf("entry %d is a certificate request, not a certificate", b.Entry)
		}
		p := x509facts.FromDER(b.DER)
		switch {
		case p.Kind == x509facts.KindCertificateRequest:
			return nil, fmt.Errorf("entry %d is a certificate request, not a certificate", b.Entry)
		case p.Certificate == nil:
			return nil, fmt.Errorf("entry %d could not be parsed as a certificate", b.Entry)
		}
		out = append(out, rootsEntry{entry: b.Entry, cert: p.Certificate})
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates")
	}
	return out, nil
}
