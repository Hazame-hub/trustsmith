package interpret

import (
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/trustverify"
)

// Chain states for a certificate validated against explicitly supplied roots.
// Each names its trust source; none says "trusted" on its own.
const (
	ChainVerifiedToSuppliedRoots          ChainState = "verified_to_supplied_roots"
	ChainFailedAgainstSuppliedRoots       ChainState = "failed_against_supplied_roots"
	ChainUnverifiableAgainstSuppliedRoots ChainState = "unverifiable_against_supplied_roots"
)

// ChainFromTrust is the summary chain state for a validated certificate.
func ChainFromTrust(s trustverify.State) ChainState {
	switch s {
	case trustverify.Verified:
		return ChainVerifiedToSuppliedRoots
	case trustverify.Failed:
		return ChainFailedAgainstSuppliedRoots
	case trustverify.Unverifiable:
		return ChainUnverifiableAgainstSuppliedRoots
	}
	return ChainNotChecked
}

// Trust turns one validation against the supplied roots into findings. A
// verified result is not a finding. The stable reason is evidence; findings
// the certificate already has (such as cert.expired) are not repeated as
// separate trust findings.
func Trust(entry int, r trustverify.Result) []findings.Finding {
	switch r.State {
	case trustverify.Failed:
		return []findings.Finding{finding(entry, findings.TrustFailed, findings.SeverityCritical, ev("reason", string(r.Reason)))}
	case trustverify.Unverifiable:
		return []findings.Finding{finding(entry, findings.TrustUnverifiable, findings.SeverityWarning, ev("reason", string(r.Reason)))}
	}
	return nil
}
