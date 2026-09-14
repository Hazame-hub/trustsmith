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

// WithPurpose sets the purpose to evaluate. The default is purpose.Any.
func WithPurpose(p purpose.Purpose) Option {
	return func(s *Service) { s.purpose = p }
}

func (s *Service) evaluatePurpose(targets []*target, trust Trust) PurposeEvaluation {
	e := PurposeEvaluation{Requested: s.purpose, State: PurposeNotEvaluated, Targets: []PurposeTarget{}}
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
