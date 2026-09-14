// Package findings defines Trustsmith's machine-readable diagnostics
// (ADR-0003): stable codes, severities, typed evidence, and a catalog of the
// human text that explains each code. Text lives in the catalog so it can be
// improved without changing the codes scripts depend on.
package findings

import "fmt"

// Code is a stable, dotted identifier such as "cert.expired".
type Code string

// Severity orders findings. The zero value is not a severity.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

func (s Severity) rank() int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityWarning:
		return 2
	case SeverityCritical:
		return 3
	}
	return 0
}

// AtLeast reports whether s is a valid severity no lower than t.
func (s Severity) AtLeast(t Severity) bool { return s.rank() > 0 && s.rank() >= t.rank() }

// ParseSeverity accepts exactly "info", "warning" or "critical".
func ParseSeverity(v string) (Severity, error) {
	s := Severity(v)
	if s.rank() == 0 {
		return "", fmt.Errorf("unknown severity %q (want info, warning or critical)", v)
	}
	return s, nil
}

// WholeInput is the Entry of a finding about the input rather than one block.
const WholeInput = -1

// Evidence is one fact supporting a finding. Keys are stable snake_case.
type Evidence struct {
	Key   string
	Value string
}

// Finding is one diagnostic about an input or one of its entries.
type Finding struct {
	Code     Code
	Severity Severity
	Entry    int // index of the block it concerns, or WholeInput
	Evidence []Evidence
}
