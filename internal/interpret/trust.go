package interpret

import (
	"strings"

	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/purpose"
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
// verified result is not a finding. The stable reason is evidence, and so is
// the purpose when a specific one was requested; findings the certificate
// already has (such as cert.expired) are not repeated as separate trust
// findings.
func Trust(entry int, r trustverify.Result, p purpose.Purpose) []findings.Finding {
	evidence := []findings.Evidence{ev("reason", string(r.Reason))}
	if p != purpose.Any && p != "" {
		evidence = append(evidence, ev("purpose", string(p)))
	}
	switch r.State {
	case trustverify.Failed:
		return []findings.Finding{finding(entry, findings.TrustFailed, findings.SeverityCritical, evidence...)}
	case trustverify.Unverifiable:
		return []findings.Finding{finding(entry, findings.TrustUnverifiable, findings.SeverityWarning, evidence...)}
	}
	return nil
}

// Purpose turns what a certificate's own fields permit into findings: one per
// extension that disallows the requested purpose. Suitable, not-evaluated and
// unverifiable results are not findings.
func Purpose(entry int, r purpose.Result) []findings.Finding {
	var fs []findings.Finding
	for _, reason := range r.Reasons {
		switch reason {
		case purpose.ReasonExtKeyUsage:
			fs = append(fs, finding(entry, findings.PurposeEKUDisallowsUsage, findings.SeverityCritical,
				ev("requested", string(r.Purpose)),
				ev("required_ext_key_usage", r.Purpose.ExtKeyUsageName()),
				ev("ext_key_usage", strings.Join(r.ExtKeyUsages, ","))))
		case purpose.ReasonKeyUsage:
			fs = append(fs, finding(entry, findings.PurposeKeyUsageDisallowsUsage, findings.SeverityCritical,
				ev("requested", string(r.Purpose)),
				ev("key_usage", strings.Join(r.KeyUsages, ",")),
				ev("consistent_key_usage", strings.Join(r.Purpose.ConsistentKeyUsages(), ","))))
		}
	}
	return fs
}
