// Package inspectsvc is the inspect application service. Every interface
// (today the CLI; later the browser UI and others) inspects through it, so
// there is exactly one inspection code path.
package inspectsvc

import (
	"cmp"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/artifact"
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/interpret"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

// SourceKind says where inspected bytes came from.
type SourceKind string

const (
	SourceFile  SourceKind = "file"
	SourceStdin SourceKind = "stdin"
)

// Source identifies the inspected input.
type Source struct {
	Kind    SourceKind
	Locator string // the path as given, or "-" for stdin
}

// ArtifactType classifies one entry of the input.
type ArtifactType string

const (
	TypeCertificate            ArtifactType = "certificate"
	TypeUnparseableCertificate ArtifactType = "unparseable_certificate"
	TypeCertificateRequest     ArtifactType = "certificate_request"
	TypeUnsupported            ArtifactType = "unsupported"
	TypeMalformed              ArtifactType = "malformed"
)

// Artifact is one inspected entry, in input order.
type Artifact struct {
	Entry       int
	Type        ArtifactType
	Label       string           // PEM label, empty for DER
	Offset      int              // byte offset in the input
	Problem     artifact.Problem // set for malformed entries
	Certificate *x509facts.Certificate
	Unparseable *x509facts.Unparseable
	Summary     *interpret.Summary
}

// Result is a complete inspection.
type Result struct {
	Source      Source
	Size        int
	Format      artifact.Format
	InspectedAt time.Time
	Artifacts   []Artifact
	Findings    []findings.Finding // whole-input first, then by entry, severity (highest first) and code
	Highest     findings.Severity  // empty when there are no findings
	// InternalErrors counts entries whose inspection panicked and was
	// recovered. It is always zero unless Trustsmith has a bug; tests and
	// fuzzing assert it.
	InternalErrors int
}

// Service inspects certificates.
type Service struct {
	now        func() time.Time
	thresholds interpret.Thresholds
}

// New returns a service that reads the inspection time from now.
func New(now func() time.Time) *Service {
	return &Service{now: now, thresholds: interpret.DefaultThresholds()}
}

// InspectFile inspects the file at path.
func (s *Service) InspectFile(path string) (Result, error) {
	f, err := os.Open(path) //nolint:gosec // opening the file the user asked to inspect is the purpose
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return Result{}, err
	}
	if info.IsDir() {
		return Result{}, fmt.Errorf("%s is a directory, not a certificate file", path)
	}
	return s.InspectReader(Source{Kind: SourceFile, Locator: path}, f)
}

// InspectReader reads at most artifact.MaxInputBytes from r and inspects it.
func (s *Service) InspectReader(src Source, r io.Reader) (Result, error) {
	data, err := io.ReadAll(io.LimitReader(r, artifact.MaxInputBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("read %s: %w", src.Locator, err)
	}
	if len(data) > artifact.MaxInputBytes {
		return Result{}, fmt.Errorf("%s: %w (limit %d bytes)", src.Locator, artifact.ErrTooLarge, artifact.MaxInputBytes)
	}
	return s.InspectBytes(src, data)
}

// InspectBytes inspects data.
func (s *Service) InspectBytes(src Source, data []byte) (Result, error) {
	decoded, err := artifact.Decode(data)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", src.Locator, err)
	}
	now := s.now().UTC()
	res := Result{
		Source:      src,
		Size:        len(data),
		Format:      decoded.Format,
		InspectedAt: now,
		Artifacts:   []Artifact{},
		Findings:    []findings.Finding{},
	}

	certificates := 0
	for _, b := range decoded.Blocks {
		a, entry, recovered := s.inspectBlock(b, now)
		if recovered {
			res.InternalErrors++
		}
		if a.Type == TypeCertificate || a.Type == TypeUnparseableCertificate {
			certificates++
		}
		res.Artifacts = append(res.Artifacts, a)
		res.Findings = append(res.Findings, entry.Findings...)
	}
	res.Findings = append(res.Findings, interpret.Input(decoded, certificates)...)

	slices.SortStableFunc(res.Findings, compareFindings)
	for _, f := range res.Findings {
		if res.Highest == "" || !res.Highest.AtLeast(f.Severity) {
			res.Highest = f.Severity
		}
	}
	return res, nil
}

// inspectBlock parses and interprets one block. A panic inside is converted
// into an unparseable-certificate result instead of crashing the process, and
// reported through recovered so it can never pass unnoticed.
func (s *Service) inspectBlock(b artifact.Block, now time.Time) (a Artifact, entry interpret.Entry, recovered bool) {
	defer func() {
		if r := recover(); r != nil {
			const reason = "internal error while inspecting this entry"
			recovered = true
			a = Artifact{Entry: b.Entry, Type: TypeUnparseableCertificate, Label: b.Label, Offset: b.Offset,
				Unparseable: &x509facts.Unparseable{
					Identity: x509facts.Identity{
						Fingerprint:       fingerprint.CertFromDER(b.DER),
						KeyIdentity:       x509facts.KeyIdentityUnavailable,
						KeyIdentityDetail: reason,
					},
					ParseError: reason,
				}}
			entry = interpret.Entry{Findings: []findings.Finding{{
				Code: findings.InputUnparseableCertificate, Severity: findings.SeverityCritical, Entry: b.Entry,
				Evidence: []findings.Evidence{{Key: "parse_error", Value: reason}},
			}}}
		}
	}()

	a = Artifact{Entry: b.Entry, Label: b.Label, Offset: b.Offset, Problem: b.Problem}
	var parsed *x509facts.Parsed
	switch b.Kind {
	case artifact.KindMalformed:
		a.Type = TypeMalformed
	case artifact.KindUnsupported:
		a.Type = TypeUnsupported
	case artifact.KindCertificate:
		p := x509facts.FromDER(b.DER)
		parsed = &p
		switch p.Kind {
		case x509facts.KindCertificate:
			a.Type, a.Certificate = TypeCertificate, p.Certificate
		case x509facts.KindUnparseable:
			a.Type, a.Unparseable = TypeUnparseableCertificate, p.Unparseable
		case x509facts.KindCertificateRequest:
			a.Type = TypeCertificateRequest
		}
	}
	entry = interpret.Block(b, parsed, now, s.thresholds)
	a.Summary = entry.Summary
	return a, entry, false
}

func compareFindings(x, y findings.Finding) int {
	if c := cmp.Compare(x.Entry, y.Entry); c != 0 {
		return c
	}
	if x.Severity != y.Severity {
		if x.Severity.AtLeast(y.Severity) {
			return -1
		}
		return 1
	}
	return cmp.Compare(x.Code, y.Code)
}
