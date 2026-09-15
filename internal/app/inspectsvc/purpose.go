package inspectsvc

import (
	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/purpose"
	"github.com/Hazame-hub/trustsmith/internal/trustverify"
)

// purposeName is the purpose type as used in this package's results.
type purposeName = purpose.Purpose

// PurposeEvaluationState says whether a specific purpose was evaluated.
type PurposeEvaluationState string

const (
	// PurposeNotEvaluated: purpose.Any was requested, so no application
	// purpose is asserted. Other layers are unaffected.
	PurposeNotEvaluated PurposeEvaluationState = "not_evaluated"
	// PurposeEvaluated: each target carries its own result.
	PurposeEvaluated PurposeEvaluationState = "evaluated"
)

// PurposeEvaluation is the evaluation of the input's certificates for the
// purpose requested explicitly. It keeps two facts apart:
//   - Usage: what the certificate's own fields permit (always evaluated);
//   - AnchoredPath: whether Go's verifier validated the certificate for the
//     purpose to explicitly supplied roots (only with roots).
//
// Host names are never evaluated.
type PurposeEvaluation struct {
	Requested purpose.Purpose
	Source    PurposeSource
	State     PurposeEvaluationState
	Targets   []PurposeTarget
}

// PurposeTarget is one certificate evaluated for the requested purpose.
type PurposeTarget struct {
	Certificate fingerprint.Cert
	Entries     []int
	Usage       purpose.Result
	// AnchoredPath is the trust evaluation result for the same certificate
	// and purpose; trustverify.NotEvaluated when no roots were supplied.
	AnchoredPath       trustverify.State
	AnchoredPathReason trustverify.Reason
}

// PurposeSource says where the requested purpose came from.
type PurposeSource string

const (
	// PurposeSourceDefault: nothing was requested; purpose.Any applies.
	PurposeSourceDefault PurposeSource = "default"
	// PurposeSourceExplicit: requested with WithPurpose (--purpose).
	PurposeSourceExplicit PurposeSource = "explicit"
	// PurposeSourceEndpoint: derived from inspecting a TLS endpoint, which
	// implies tls-server unless a purpose was requested explicitly.
	PurposeSourceEndpoint PurposeSource = "endpoint"
)

// WithPurpose sets the purpose to evaluate explicitly. The default is
// purpose.Any; an explicit purpose also overrides the one an endpoint implies.
func WithPurpose(p purpose.Purpose) Option {
	return func(s *Service) { s.purpose, s.purposeSource = p, PurposeSourceExplicit }
}

func (s *Service) evaluatePurpose(targets []*target, trust Trust) PurposeEvaluation {
	e := PurposeEvaluation{Requested: s.purpose, Source: s.purposeSource, State: PurposeNotEvaluated, Targets: []PurposeTarget{}}
	if s.purpose == purpose.Any {
		return e
	}
	e.State = PurposeEvaluated
	anchored := map[fingerprint.Cert]trustverify.Result{}
	for _, t := range trust.Targets {
		anchored[t.Certificate] = t.Result
	}
	for _, c := range targets {
		pt := PurposeTarget{
			Certificate:  c.cert.Fingerprint,
			Entries:      c.entries,
			Usage:        purpose.Evaluate(c.cert.Parsed, s.purpose),
			AnchoredPath: trustverify.NotEvaluated,
		}
		if r, ok := anchored[c.cert.Fingerprint]; ok {
			pt.AnchoredPath, pt.AnchoredPathReason = r.State, r.Reason
		}
		e.Targets = append(e.Targets, pt)
	}
	return e
}
