package inspectsvc

import (
	"crypto/x509"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/issuerlinks"
	"github.com/Hazame-hub/trustsmith/internal/trustverify"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

// TrustEvaluationState says whether trust was evaluated at all.
type TrustEvaluationState string

const (
	// TrustNotEvaluated: no trust anchors were supplied. Certificates in the
	// input, self-signed or not, are never used as anchors.
	TrustNotEvaluated TrustEvaluationState = "not_evaluated"
	// TrustEvaluated: the targets were validated against explicitly supplied
	// anchors; each target carries its own result.
	TrustEvaluated TrustEvaluationState = "evaluated"
)

// TrustSourceSuppliedRoots is the only trust source in this version.
const TrustSourceSuppliedRoots = "supplied_roots"

// Trust is the validation of the input's certificates against explicitly
// supplied trust anchors. It is separate from, and never changes, the issuer
// relationships and included paths.
type Trust struct {
	State         TrustEvaluationState
	Source        string // TrustSourceSuppliedRoots when evaluated
	Engine        string // trustverify.Engine when evaluated
	EngineVersion string
	Roots         Roots
	Targets       []TrustTarget
}

// TrustTarget is one certificate validated against the anchors.
type TrustTarget struct {
	Certificate fingerprint.Cert
	Entries     []int
	Result      trustverify.Result
}

// WithRoots makes the service validate the input against explicitly supplied
// trust anchors.
func WithRoots(r Roots) Option {
	return func(s *Service) { s.roots = &r }
}

// evaluateTrust validates the input's targets against the supplied anchors.
//
// Targets are the certificates that issued no other certificate of the input
// (end entities and the ends of partial bundles), or every certificate when
// all of them issue another (a cycle). All certificates of the input are
// offered to the verifier as candidate intermediates. None of them is ever an
// anchor unless it is also in the supplied roots, in which case it is only an
// anchor.
func (s *Service) evaluateTrust(inputs []issuerlinks.Input, links issuerlinks.Resolution, now time.Time) Trust {
	if s.roots == nil {
		return Trust{State: TrustNotEvaluated, Roots: Roots{Files: []RootsFile{}, Anchors: []Anchor{}}, Targets: []TrustTarget{}}
	}
	trust := Trust{
		State: TrustEvaluated, Source: TrustSourceSuppliedRoots,
		Engine: trustverify.Engine, EngineVersion: trustverify.EngineVersion(),
		Roots: *s.roots, Targets: []TrustTarget{},
	}
	anchors := make([]*x509.Certificate, 0, len(s.roots.Anchors))
	for _, a := range s.roots.Anchors {
		anchors = append(anchors, a.Certificate.Parsed)
	}

	issuesAnother := map[fingerprint.Cert]bool{}
	for _, r := range links.Relationships {
		if r.State == issuerlinks.Verified && r.Candidate != r.Child {
			issuesAnother[r.Candidate] = true
		}
	}
	type candidate struct {
		cert    *x509facts.Certificate
		entries []int
	}
	var distinct []*candidate
	byFP := map[fingerprint.Cert]*candidate{}
	intermediates := []*x509.Certificate{}
	for _, in := range inputs {
		fp := in.Certificate.Fingerprint
		if c, ok := byFP[fp]; ok {
			c.entries = append(c.entries, in.Entry)
			continue
		}
		c := &candidate{cert: in.Certificate, entries: []int{in.Entry}}
		byFP[fp] = c
		distinct = append(distinct, c)
		intermediates = append(intermediates, in.Certificate.Parsed)
	}
	var targets []*candidate
	for _, c := range distinct {
		if !issuesAnother[c.cert.Fingerprint] {
			targets = append(targets, c)
		}
	}
	if len(targets) == 0 {
		targets = distinct
	}
	for _, c := range targets {
		trust.Targets = append(trust.Targets, TrustTarget{
			Certificate: c.cert.Fingerprint,
			Entries:     c.entries,
			Result:      trustverify.Verify(c.cert.Parsed, anchors, intermediates, now),
		})
	}
	return trust
}
