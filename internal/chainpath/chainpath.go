// Package chainpath builds certification paths from the verified issuer
// relationships found inside one inspection input, and evaluates a
// deliberately narrow set of structural issuer constraints along them.
//
// A path is never a trust decision. No certificate becomes a trust anchor
// because it is self-signed or because it was included in the input, and no
// relying-party policy is applied. It is also not full RFC 5280 path
// validation: anything relevant this package does not evaluate is reported as
// not evaluated, so a structure is never called satisfied by omission.
//
// It deliberately does not use x509.Certificate.Verify: supplying included
// certificates as VerifyOptions.Roots would declare them trusted.
package chainpath

import (
	"crypto/x509"
	"slices"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/issuerlinks"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

// Completeness says how far a path could be built from the input.
type Completeness string

const (
	// CompleteInInput: the path reaches a self-signed certificate contained in
	// the input. It says nothing about trust.
	CompleteInInput Completeness = "complete_in_input"
	// Partial: the path ends because no verified issuer relationship is
	// available in the input.
	Partial Completeness = "partial"
	// Cycle: the next issuer is already on the path; construction stopped.
	Cycle Completeness = "cycle"
	// LimitReached: construction stopped at a work limit; the path may
	// continue beyond what is shown.
	LimitReached Completeness = "limit_reached"
)

// End says why a path ends where it does.
type End string

const (
	EndSelfSignedTerminal        End = "self_signed_terminal"
	EndNoIssuerCandidate         End = "no_issuer_candidate"            // no candidate found (matching is by exact name and key identifier)
	EndIssuerCandidatesNotVerify End = "issuer_candidates_not_verified" // candidates exist; none verified the signature
	EndIssuerCandidatesUnchecked End = "issuer_candidates_not_checked"  // issuer-link limits left candidates unchecked
	EndCycle                     End = "cycle"
	EndDepthLimit                End = "depth_limit"
)

// StructureState is the result of the structural issuer checks for a path.
type StructureState string

const (
	// StructureSatisfied: every check this package performs passed and
	// nothing relevant was left unevaluated.
	StructureSatisfied StructureState = "satisfied"
	// StructureFailed: at least one structural issuer constraint is violated.
	StructureFailed StructureState = "failed"
	// StructureUnverifiable: no violation was found, but something relevant
	// could not be evaluated by this package.
	StructureUnverifiable StructureState = "structurally_unverifiable"
	// StructureNotApplicable: the path has no issuer (a single certificate).
	StructureNotApplicable StructureState = "not_applicable"
)

// ValidityState summarises the validity periods of a path's certificates at
// the inspection time.
type ValidityState string

const (
	ValiditySatisfied ValidityState = "satisfied"
	ValidityFailed    ValidityState = "failed"
)

// IssueKind identifies a structural issue on a path.
type IssueKind string

const (
	IssueIssuerNotCA                   IssueKind = "issuer_not_ca"
	IssueIssuerKeyUsageNoCertSign      IssueKind = "issuer_key_usage_without_key_cert_sign"
	IssuePathLengthExceeded            IssueKind = "path_length_exceeded"
	IssueIssuerCAStatusNotEvaluated    IssueKind = "issuer_ca_status_not_evaluated"
	IssueNameConstraintsNotEvaluated   IssueKind = "name_constraints_not_evaluated"
	IssuePolicyConstraintsNotEvaluated IssueKind = "policy_constraints_not_evaluated"
	IssueCriticalExtensionNotProcessed IssueKind = "critical_extension_not_processed"
)

// Outcome distinguishes a definite violation from something not evaluated.
type Outcome string

const (
	OutcomeViolation    Outcome = "violation"
	OutcomeNotEvaluated Outcome = "not_evaluated"
)

// Issue is one structural issue, located on a certificate of the path.
type Issue struct {
	Kind        IssueKind
	Outcome     Outcome
	Position    int // index into Path.Certificates
	Certificate fingerprint.Cert

	BasicConstraintsPresent bool   // issuer_not_ca: whether the extension exists at all
	PathLenConstraint       int    // path_length_exceeded
	FollowingIntermediates  int    // path_length_exceeded: non-self-issued intermediates after the issuer
	ExtensionOID            string // not-evaluated extension kinds
}

// NotValid is a certificate on the path outside its validity period.
type NotValid struct {
	Position    int
	Certificate fingerprint.Cert
	Expired     bool // true: after notAfter; false: before notBefore
}

// Path is one certification path built from certificates in the input,
// starting with the certificate furthest from any issuer.
type Path struct {
	Certificates []fingerprint.Cert
	Entries      [][]int // input entries of each certificate
	Completeness Completeness
	End          End
	CycleTo      int // for cycles: position of the certificate that would repeat; -1 otherwise
	Structure    StructureState
	Issues       []Issue
	Validity     ValidityState
	NotValid     []NotValid
}

// Limits bound path construction for hostile inputs.
type Limits struct {
	MaxDepth         int // certificates on one path
	MaxPathsPerStart int // paths built from one starting certificate
	MaxExpansions    int // path-extension steps for the whole input
}

// DefaultLimits: real certification paths are rarely deeper than a handful of
// certificates and rarely have more than a few alternatives; these values are
// generous for real bundles and bound adversarial ones.
func DefaultLimits() Limits {
	return Limits{MaxDepth: 16, MaxPathsPerStart: 32, MaxExpansions: 4096}
}

// Result of Build.
type Result struct {
	Paths []Path
	// LimitReached: some paths were not built, or were cut short, because a
	// limit was reached. The list of paths is then incomplete.
	LimitReached bool
	Expansions   int
}

type node struct {
	fp      fingerprint.Cert
	entries []int
	cert    *x509facts.Certificate
}

type builder struct {
	now           time.Time
	limits        Limits
	byFP          map[fingerprint.Cert]*node
	issuers       map[fingerprint.Cert][]fingerprint.Cert // verified issuer relationships, in resolution order
	hasCandidates map[fingerprint.Cert]bool
	unchecked     map[fingerprint.Cert]bool
	result        Result
	stopped       bool
}

// Build constructs every path it can within limits, in a deterministic order:
// starting certificates by first appearance, and at each fork issuers in the
// order of the issuer relationships.
func Build(inputs []issuerlinks.Input, links issuerlinks.Resolution, now time.Time, limits Limits) Result {
	b := &builder{
		now: now, limits: limits,
		byFP:          map[fingerprint.Cert]*node{},
		issuers:       map[fingerprint.Cert][]fingerprint.Cert{},
		hasCandidates: map[fingerprint.Cert]bool{},
		unchecked:     map[fingerprint.Cert]bool{},
		result:        Result{Paths: []Path{}},
	}

	var nodes []*node
	for _, in := range inputs {
		if in.Certificate == nil {
			continue
		}
		fp := in.Certificate.Fingerprint
		if n, ok := b.byFP[fp]; ok {
			n.entries = append(n.entries, in.Entry)
			continue
		}
		n := &node{fp: fp, entries: []int{in.Entry}, cert: in.Certificate}
		b.byFP[fp] = n
		nodes = append(nodes, n)
	}

	isIssuer := map[fingerprint.Cert]bool{}
	for _, r := range links.Relationships {
		if _, ok := b.byFP[r.Child]; !ok {
			continue
		}
		b.hasCandidates[r.Child] = true
		switch r.State {
		case issuerlinks.Verified:
			if _, ok := b.byFP[r.Candidate]; ok {
				b.issuers[r.Child] = append(b.issuers[r.Child], r.Candidate)
				isIssuer[r.Candidate] = true
			}
		case issuerlinks.NotChecked:
			b.unchecked[r.Child] = true
		}
	}
	for fp, omitted := range links.CandidatesOmitted {
		if omitted {
			b.unchecked[fp] = true
		}
	}

	// Paths start at certificates that issued no other certificate in the
	// input — the ones furthest from any issuer. A certificate not reachable
	// from those starts (only possible inside a cycle) starts its own paths, so
	// no certificate is silently left out. Reachability follows the verified
	// relationships themselves, not what construction visited: a certificate
	// cut off by a limit is reported through LimitReached, not as a new start.
	reachable := map[fingerprint.Cert]bool{}
	markReachable := func(start fingerprint.Cert) {
		stack := []fingerprint.Cert{start}
		for len(stack) > 0 {
			fp := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if reachable[fp] {
				continue
			}
			reachable[fp] = true
			stack = append(stack, b.issuers[fp]...)
		}
	}
	for _, n := range nodes {
		if !isIssuer[n.fp] {
			markReachable(n.fp)
			b.from(n)
		}
	}
	for _, n := range nodes {
		if !reachable[n.fp] {
			markReachable(n.fp)
			b.from(n)
		}
	}
	return b.result
}

func (b *builder) from(start *node) {
	built := 0
	var walk func(path []*node)
	walk = func(path []*node) {
		if b.stopped {
			return
		}
		if built >= b.limits.MaxPathsPerStart {
			b.result.LimitReached = true
			return
		}
		if b.result.Expansions >= b.limits.MaxExpansions {
			b.result.LimitReached = true
			b.stopped = true
			return
		}
		b.result.Expansions++

		last := path[len(path)-1]
		if last.cert.SelfSignature == x509facts.SignatureVerified {
			b.emit(path, CompleteInInput, EndSelfSignedTerminal, -1)
			built++
			return
		}
		next := b.issuers[last.fp]
		if len(next) == 0 {
			switch {
			case b.unchecked[last.fp]:
				b.emit(path, LimitReached, EndIssuerCandidatesUnchecked, -1)
			case b.hasCandidates[last.fp]:
				b.emit(path, Partial, EndIssuerCandidatesNotVerify, -1)
			default:
				b.emit(path, Partial, EndNoIssuerCandidate, -1)
			}
			built++
			return
		}
		if len(path) >= b.limits.MaxDepth {
			b.emit(path, LimitReached, EndDepthLimit, -1)
			b.result.LimitReached = true
			built++
			return
		}
		for _, fp := range next {
			if at := slices.IndexFunc(path, func(n *node) bool { return n.fp == fp }); at >= 0 {
				if built >= b.limits.MaxPathsPerStart {
					b.result.LimitReached = true
					return
				}
				b.emit(path, Cycle, EndCycle, at)
				built++
				continue
			}
			walk(append(slices.Clone(path), b.byFP[fp]))
		}
	}
	walk([]*node{start})
}

func (b *builder) emit(path []*node, completeness Completeness, end End, cycleTo int) {
	p := Path{Completeness: completeness, End: end, CycleTo: cycleTo}
	certs := make([]*x509facts.Certificate, len(path))
	for i, n := range path {
		p.Certificates = append(p.Certificates, n.fp)
		p.Entries = append(p.Entries, n.entries)
		certs[i] = n.cert
	}
	p.Structure, p.Issues = evaluateStructure(certs)
	p.Validity, p.NotValid = evaluateValidity(certs, b.now)
	b.result.Paths = append(b.result.Paths, p)
}

const (
	oidBasicConstraints  = "2.5.29.19"
	oidKeyUsage          = "2.5.29.15"
	oidExtKeyUsage       = "2.5.29.37"
	oidSubjectAltName    = "2.5.29.17"
	oidSubjectKeyID      = "2.5.29.14"
	oidAuthorityKeyID    = "2.5.29.35"
	oidNameConstraints   = "2.5.29.30"
	oidPolicyConstraints = "2.5.29.36"
	oidPolicyMappings    = "2.5.29.33"
	oidInhibitAnyPolicy  = "2.5.29.54"
)

// recognisedCritical are critical extensions whose presence does not require
// further path processing by this package: basic constraints and key usage
// are evaluated here; extended key usage is purpose policy, not path
// structure; subject alternative names and key identifiers carry no path
// constraint of their own. Any other critical extension is not processed.
var recognisedCritical = map[string]bool{
	oidBasicConstraints: true,
	oidKeyUsage:         true,
	oidExtKeyUsage:      true,
	oidSubjectAltName:   true,
	oidSubjectKeyID:     true,
	oidAuthorityKeyID:   true,
}

// constraintExtensions constrain the certificates below the one carrying
// them. On an issuer they would have to be evaluated, and this package does
// not evaluate them.
var constraintExtensions = map[string]IssueKind{
	oidNameConstraints:   IssueNameConstraintsNotEvaluated,
	oidPolicyConstraints: IssuePolicyConstraintsNotEvaluated,
	oidPolicyMappings:    IssuePolicyConstraintsNotEvaluated,
	oidInhibitAnyPolicy:  IssuePolicyConstraintsNotEvaluated,
}

// evaluateStructure checks, for each certificate that issued the one before
// it on the path (positions 1..n-1), the constraints on certificate signing,
// and reports what it did not evaluate.
func evaluateStructure(certs []*x509facts.Certificate) (StructureState, []Issue) {
	if len(certs) < 2 {
		return StructureNotApplicable, []Issue{}
	}
	issues := []Issue{}
	add := func(i Issue) { issues = append(issues, i) }

	for j := 1; j < len(certs); j++ {
		c := certs[j]
		switch {
		case c.Version < 3:
			// RFC 5280 6.1.4(k): a version 1 or 2 issuer's CA status can only
			// be established out of band.
			add(Issue{Kind: IssueIssuerCAStatusNotEvaluated, Outcome: OutcomeNotEvaluated, Position: j, Certificate: c.Fingerprint})
		case !c.BasicConstraints.Present || !c.BasicConstraints.IsCA:
			add(Issue{Kind: IssueIssuerNotCA, Outcome: OutcomeViolation, Position: j, Certificate: c.Fingerprint,
				BasicConstraintsPresent: c.BasicConstraints.Present})
		}

		// RFC 5280 6.1.4(n): if the key usage extension is present, keyCertSign
		// must be set. Absent key usage places no restriction.
		if hasExtension(c, oidKeyUsage) && (c.Parsed == nil || c.Parsed.KeyUsage&x509.KeyUsageCertSign == 0) {
			add(Issue{Kind: IssueIssuerKeyUsageNoCertSign, Outcome: OutcomeViolation, Position: j, Certificate: c.Fingerprint})
		}

		// RFC 5280 4.2.1.9 / 6.1.4(l)(m): pathLenConstraint limits the number of
		// non-self-issued intermediate certificates that may follow this one.
		// Following means towards the start of the path; the start itself is
		// not an intermediate and does not count.
		if bc := c.BasicConstraints; bc.Present && bc.IsCA && bc.MaxPathLen != nil {
			following := 0
			for _, below := range certs[1:j] {
				if !below.SelfIssued {
					following++
				}
			}
			if following > *bc.MaxPathLen {
				add(Issue{Kind: IssuePathLengthExceeded, Outcome: OutcomeViolation, Position: j, Certificate: c.Fingerprint,
					PathLenConstraint: *bc.MaxPathLen, FollowingIntermediates: following})
			}
		}
	}

	for i, c := range certs {
		for _, e := range c.Extensions {
			if kind, ok := constraintExtensions[e.OID]; ok {
				if i >= 1 {
					add(Issue{Kind: kind, Outcome: OutcomeNotEvaluated, Position: i, Certificate: c.Fingerprint, ExtensionOID: e.OID})
				}
				continue
			}
			if e.Critical && !recognisedCritical[e.OID] {
				add(Issue{Kind: IssueCriticalExtensionNotProcessed, Outcome: OutcomeNotEvaluated, Position: i, Certificate: c.Fingerprint, ExtensionOID: e.OID})
			}
		}
	}

	state := StructureSatisfied
	for _, is := range issues {
		if is.Outcome == OutcomeViolation {
			return StructureFailed, issues
		}
		state = StructureUnverifiable
	}
	return state, issues
}

func evaluateValidity(certs []*x509facts.Certificate, now time.Time) (ValidityState, []NotValid) {
	notValid := []NotValid{}
	for i, c := range certs {
		switch {
		case now.After(c.NotAfter):
			notValid = append(notValid, NotValid{Position: i, Certificate: c.Fingerprint, Expired: true})
		case now.Before(c.NotBefore):
			notValid = append(notValid, NotValid{Position: i, Certificate: c.Fingerprint})
		}
	}
	if len(notValid) > 0 {
		return ValidityFailed, notValid
	}
	return ValiditySatisfied, notValid
}

func hasExtension(c *x509facts.Certificate, oid string) bool {
	return slices.ContainsFunc(c.Extensions, func(e x509facts.Extension) bool { return e.OID == oid })
}
