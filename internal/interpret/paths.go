package interpret

import (
	"strconv"

	"github.com/Hazame-hub/trustsmith/internal/chainpath"
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
)

// Paths turns included certification paths into findings. first maps each
// certificate to the first input entry that contains it.
//
// Findings stay sparse: a structural problem is reported once on the issuer
// certificate that carries it, however many paths pass through it, and
// validity is never repeated here because every certificate already has its
// own validity findings. A complete path is not a finding, and nothing here
// says anything about trust.
func Paths(r chainpath.Result, first map[fingerprint.Cert]int) []findings.Finding {
	var fs []findings.Finding
	type key struct {
		code findings.Code
		fp   fingerprint.Cert
		kind chainpath.IssueKind
		oid  string
	}
	seen := map[key]int{} // index into fs

	for _, p := range r.Paths {
		for _, is := range p.Issues {
			entry := first[is.Certificate]
			switch is.Kind {
			case chainpath.IssueIssuerNotCA:
				k := key{code: findings.ChainIssuerNotCA, fp: is.Certificate}
				if _, ok := seen[k]; ok {
					continue
				}
				bc := "ca_false"
				if !is.BasicConstraintsPresent {
					bc = "absent"
				}
				seen[k] = len(fs)
				fs = append(fs, finding(entry, findings.ChainIssuerNotCA, findings.SeverityWarning, ev("basic_constraints", bc)))
			case chainpath.IssueIssuerKeyUsageNoCertSign:
				k := key{code: findings.ChainIssuerKeyUsage, fp: is.Certificate}
				if _, ok := seen[k]; ok {
					continue
				}
				seen[k] = len(fs)
				fs = append(fs, finding(entry, findings.ChainIssuerKeyUsage, findings.SeverityWarning))
			case chainpath.IssuePathLengthExceeded:
				// One finding per constrained certificate, carrying the longest
				// excess seen on any path through it.
				k := key{code: findings.ChainPathLengthExceeded, fp: is.Certificate}
				evidence := []findings.Evidence{
					ev("path_len_constraint", strconv.Itoa(is.PathLenConstraint)),
					ev("following_intermediates", strconv.Itoa(is.FollowingIntermediates)),
				}
				if i, ok := seen[k]; ok {
					if prev, _ := strconv.Atoi(fs[i].Evidence[1].Value); is.FollowingIntermediates > prev {
						fs[i].Evidence = evidence
					}
					continue
				}
				seen[k] = len(fs)
				fs = append(fs, finding(entry, findings.ChainPathLengthExceeded, findings.SeverityWarning, evidence...))
			default:
				if is.Outcome != chainpath.OutcomeNotEvaluated {
					continue
				}
				k := key{code: findings.ChainStructureUnverifiable, fp: is.Certificate, kind: is.Kind, oid: is.ExtensionOID}
				if _, ok := seen[k]; ok {
					continue
				}
				evidence := []findings.Evidence{ev("reason", string(is.Kind))}
				if is.ExtensionOID != "" {
					evidence = append(evidence, ev("extension_oid", is.ExtensionOID))
				}
				seen[k] = len(fs)
				fs = append(fs, finding(entry, findings.ChainStructureUnverifiable, findings.SeverityInfo, evidence...))
			}
		}

		if p.Completeness == chainpath.Cycle && p.CycleTo >= 0 && p.CycleTo < len(p.Certificates) {
			repeated := p.Certificates[p.CycleTo]
			k := key{code: findings.ChainCycle, fp: repeated}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = len(fs)
			entry := first[repeated]
			fs = append(fs, finding(entry, findings.ChainCycle, findings.SeverityInfo, ev("repeats_entry", strconv.Itoa(entry))))
		}
	}

	if r.LimitReached {
		fs = append(fs, finding(findings.WholeInput, findings.ChainPathLimitReached, findings.SeverityInfo,
			ev("paths_built", strconv.Itoa(len(r.Paths)))))
	}
	return fs
}
