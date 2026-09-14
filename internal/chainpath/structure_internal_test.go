package chainpath

import (
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

// TestVersion1IssuerCAStatusIsNotEvaluated: RFC 5280 6.1.4(k) says the CA
// status of a version 1 or 2 issuer can only be established out of band, so
// it must be reported as not evaluated — never as a violation, and never as
// satisfied. Go cannot create such certificates, so the facts are built
// directly.
func TestVersion1IssuerCAStatusIsNotEvaluated(t *testing.T) {
	leaf := &x509facts.Certificate{Version: 3}
	v1Issuer := &x509facts.Certificate{Version: 1}

	state, issues := evaluateStructure([]*x509facts.Certificate{leaf, v1Issuer})
	if state != StructureUnverifiable {
		t.Errorf("structure %s, want structurally_unverifiable", state)
	}
	if len(issues) != 1 || issues[0].Kind != IssueIssuerCAStatusNotEvaluated || issues[0].Outcome != OutcomeNotEvaluated || issues[0].Position != 1 {
		t.Errorf("issues %+v", issues)
	}
}

func TestSingleCertificateHasNoStructureToEvaluate(t *testing.T) {
	state, issues := evaluateStructure([]*x509facts.Certificate{{Version: 3}})
	if state != StructureNotApplicable || len(issues) != 0 {
		t.Errorf("structure %s issues %+v", state, issues)
	}
}
