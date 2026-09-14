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
	"github.com/Hazame-hub/trustsmith/internal/chainpath"
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/interpret"
	"github.com/Hazame-hub/trustsmith/internal/issuerlinks"
	"github.com/Hazame-hub/trustsmith/internal/purpose"
	"github.com/Hazame-hub/trustsmith/internal/sigcheck"
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
	// Relationships are the issuer relationships between certificates of this
	// input: signature checks only, never trust.
	Relationships []issuerlinks.Relationship
	// Paths are the certification paths that can be built from the verified
	// relationships inside this input, with their structural evaluation. A
	// path complete in the input is not trusted; trust is not evaluated.
	Paths []chainpath.Path
	// PathLimitReached: a path-construction limit was reached, so Paths is
	// incomplete.
	PathLimitReached bool
	// Trust is the validation against explicitly supplied trust anchors. Its
	// State is not_evaluated unless roots were supplied.
	Trust Trust
	// Purpose is the evaluation for the explicitly requested purpose. Its
	// State is not_evaluated for purpose.Any.
	Purpose PurposeEvaluation
	// RecoveredPanics counts panics contained at the untrusted-input
	// boundaries: the standard-library X.509 parser and the signature
	// verification engine. It is always zero unless one of them has a bug;
	// tests and fuzzing assert it. Panics anywhere else are not recovered.
	RecoveredPanics int
}

// Service inspects certificates.
type Service struct {
	now        func() time.Time
	thresholds interpret.Thresholds
	limits     issuerlinks.Limits
	pathLimits chainpath.Limits
	roots      *Roots // nil: trust is not evaluated
	purpose    purpose.Purpose
}

// Option configures a Service.
type Option func(*Service)

// New returns a service that reads the inspection time from now.
func New(now func() time.Time, opts ...Option) *Service {
	s := &Service{now: now, thresholds: interpret.DefaultThresholds(),
		limits: issuerlinks.DefaultLimits(), pathLimits: chainpath.DefaultLimits(), purpose: purpose.Any}
	for _, o := range opts {
		o(s)
	}
	return s
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

// InspectBytes inspects data: frame the input, parse every certificate,
// resolve issuer relationships among them, then interpret each entry.
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

	parsed := make([]*x509facts.Parsed, len(decoded.Blocks))
	var inputs []issuerlinks.Input
	certificates := 0
	for i, b := range decoded.Blocks {
		if b.Kind != artifact.KindCertificate {
			continue
		}
		p := x509facts.FromDER(b.DER)
		parsed[i] = &p
		if p.ParserPanicked {
			res.RecoveredPanics++
		}
		if p.Kind != x509facts.KindCertificateRequest {
			certificates++
		}
		if c := p.Certificate; c != nil {
			if c.SelfSignatureReason == sigcheck.ReasonEnginePanic {
				res.RecoveredPanics++
			}
			inputs = append(inputs, issuerlinks.Input{Entry: b.Entry, Certificate: c})
		}
	}

	links := issuerlinks.Resolve(inputs, s.limits)
	res.Relationships = links.Relationships
	res.RecoveredPanics += links.EnginePanics

	paths := chainpath.Build(inputs, links, now, s.pathLimits)
	res.Paths, res.PathLimitReached = paths.Paths, paths.LimitReached
	first := map[fingerprint.Cert]int{}
	for _, in := range inputs {
		if _, ok := first[in.Certificate.Fingerprint]; !ok {
			first[in.Certificate.Fingerprint] = in.Entry
		}
	}
	res.Findings = append(res.Findings, interpret.Paths(paths, first)...)

	targets, intermediates := selectTargets(inputs, links)
	res.Trust = s.evaluateTrust(targets, intermediates, now)
	res.Purpose = s.evaluatePurpose(targets, res.Trust)
	chainState := map[fingerprint.Cert]interpret.ChainState{}
	for _, t := range res.Trust.Targets {
		chainState[t.Certificate] = interpret.ChainFromTrust(t.Result.State)
		res.Findings = append(res.Findings, interpret.Trust(t.Entries[0], t.Result, res.Trust.Purpose)...)
	}
	for _, t := range res.Purpose.Targets {
		res.Findings = append(res.Findings, interpret.Purpose(t.Entries[0], t.Usage)...)
	}

	for i, b := range decoded.Blocks {
		a := Artifact{Entry: b.Entry, Label: b.Label, Offset: b.Offset, Problem: b.Problem}
		var issuers interpret.Issuers
		switch b.Kind {
		case artifact.KindMalformed:
			a.Type = TypeMalformed
		case artifact.KindUnsupported:
			a.Type = TypeUnsupported
		case artifact.KindCertificate:
			switch p := parsed[i]; p.Kind {
			case x509facts.KindCertificate:
				a.Type, a.Certificate = TypeCertificate, p.Certificate
				fp := p.Certificate.Fingerprint
				issuers = interpret.Issuers{Relationships: links.For(fp), CandidatesOmitted: links.CandidatesOmitted[fp]}
			case x509facts.KindUnparseable:
				a.Type, a.Unparseable = TypeUnparseableCertificate, p.Unparseable
			case x509facts.KindCertificateRequest:
				a.Type = TypeCertificateRequest
			}
		}
		entry := interpret.Block(b, parsed[i], issuers, now, s.thresholds)
		a.Summary = entry.Summary
		if a.Summary != nil {
			if state, ok := chainState[a.Certificate.Fingerprint]; ok {
				a.Summary.Chain = state
			}
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
