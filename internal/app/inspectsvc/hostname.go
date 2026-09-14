package inspectsvc

import (
	"runtime"

	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/hostname"
)

// HostnameEvaluationState says whether host name identity was evaluated.
type HostnameEvaluationState string

const (
	// HostnameNotEvaluated: no host name was requested.
	HostnameNotEvaluated HostnameEvaluationState = "not_evaluated"
	// HostnameEvaluated: each target carries its own result.
	HostnameEvaluated HostnameEvaluationState = "evaluated"
)

// HostnameMatcher names the engine that matched host names.
const HostnameMatcher = "go-x509-verifyhostname"

// HostnameEvaluation is whether the input's certificates identify the host
// name or IP address requested explicitly. It is separate from trust and
// purpose: a certificate may match and fail either, and the reverse.
type HostnameEvaluation struct {
	State         HostnameEvaluationState
	Request       hostname.Request // zero when not evaluated
	Matcher       string
	EngineVersion string
	Targets       []HostnameTarget
}

// HostnameTarget is one certificate matched against the requested name.
type HostnameTarget struct {
	Certificate fingerprint.Cert
	Entries     []int
	Result      hostname.Result
}

// WithHostname makes the service evaluate whether the targets identify r.
func WithHostname(r hostname.Request) Option {
	return func(s *Service) { s.hostname = &r }
}

func (s *Service) evaluateHostname(targets []*target) HostnameEvaluation {
	e := HostnameEvaluation{State: HostnameNotEvaluated, Targets: []HostnameTarget{}}
	if s.hostname == nil {
		return e
	}
	e.State, e.Request, e.Matcher, e.EngineVersion = HostnameEvaluated, *s.hostname, HostnameMatcher, runtime.Version()
	for _, c := range targets {
		e.Targets = append(e.Targets, HostnameTarget{
			Certificate: c.cert.Fingerprint,
			Entries:     c.entries,
			Result:      hostname.Evaluate(c.cert.Parsed, *s.hostname),
		})
	}
	return e
}
