// Package issuerlinks finds issuer relationships between the certificates of
// one inspection input: which certificates might have issued which (from
// naming and key-identifier evidence), and whether each candidate's public
// key actually verifies the child's signature.
//
// A relationship is a signer relationship only. It never means the issuer is
// trusted, is a valid CA, or that any chain is valid; those are later
// concerns. This is an in-memory computation over one input, not a graph
// store.
package issuerlinks

import (
	"bytes"
	"slices"

	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/sigcheck"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

// Input is one parsed certificate of the inspected input.
type Input struct {
	Entry       int
	Certificate *x509facts.Certificate
}

// Evidence is non-cryptographic, heuristic evidence that a certificate may
// have issued another. It never makes a relationship verified.
type Evidence string

const (
	// EvidenceIssuerNameMatch: the child's issuer name is byte-identical to
	// the candidate's subject name.
	EvidenceIssuerNameMatch Evidence = "issuer_dn_match"
	// EvidenceAuthorityKeyIDMatch: the child's Authority Key Identifier
	// equals the candidate's Subject Key Identifier.
	EvidenceAuthorityKeyIDMatch Evidence = "authority_key_id_match"
)

// State of a relationship. Every relationship is a candidate (it has
// evidence); the state is the result of the signature check.
type State string

const (
	Verified      State = State(sigcheck.Verified)
	DoesNotVerify State = State(sigcheck.DoesNotVerify)
	Unverifiable  State = State(sigcheck.Unverifiable)
	// NotChecked: the verification budget was exhausted before this
	// candidate could be checked. Unknown, not absent.
	NotChecked State = "not_checked"
)

// Relationship between a child certificate and one candidate issuer.
// Certificates are identified by fingerprint; identical certificates at
// several entries are one certificate listing all of its entries.
type Relationship struct {
	Child            fingerprint.Cert
	ChildEntries     []int
	Candidate        fingerprint.Cert
	CandidateEntries []int
	Evidence         []Evidence // in a fixed order: issuer name, then key identifier
	State            State
	Reason           sigcheck.Reason
	Detail           string
}

// Limits bound the work done for hostile inputs.
type Limits struct {
	// MaxCandidatesPerCertificate caps the candidates recorded for one child.
	MaxCandidatesPerCertificate int
	// MaxVerifications caps signature checks for the whole input.
	MaxVerifications int
}

// DefaultLimits are generous for real bundles and bound hostile ones.
func DefaultLimits() Limits {
	return Limits{MaxCandidatesPerCertificate: 32, MaxVerifications: 4096}
}

// Resolution is the result of Resolve.
type Resolution struct {
	Relationships []Relationship // by child, then candidate, in first-appearance order
	// CandidatesOmitted marks children that had more candidates than the
	// limit; the omitted ones are not listed.
	CandidatesOmitted map[fingerprint.Cert]bool
	Verifications     int // signature checks performed
	EnginePanics      int // checks whose engine panicked (always zero unless something is badly wrong)

	byChild map[fingerprint.Cert][]int
}

// For returns the relationships whose child is the given certificate.
func (r Resolution) For(child fingerprint.Cert) []Relationship {
	idx := r.byChild[child]
	out := make([]Relationship, 0, len(idx))
	for _, i := range idx {
		out = append(out, r.Relationships[i])
	}
	return out
}

type node struct {
	fp      fingerprint.Cert
	entries []int
	cert    *x509facts.Certificate
}

// Resolve finds issuer relationships among inputs.
//
// Candidates come from two indexes — subject name and Subject Key Identifier
// — so a certificate is compared only with certificates its own issuer name
// or Authority Key Identifier point at. Signature checks are memoised per
// child by candidate key, so several certificates carrying the same key cost
// one check. Ordinary inputs therefore cost roughly one check per issued
// certificate, and hostile ones are bounded by limits.
func Resolve(inputs []Input, limits Limits) Resolution {
	res := Resolution{
		Relationships:     []Relationship{},
		CandidatesOmitted: map[fingerprint.Cert]bool{},
		byChild:           map[fingerprint.Cert][]int{},
	}

	var nodes []*node
	byFingerprint := map[fingerprint.Cert]*node{}
	for _, in := range inputs {
		if in.Certificate == nil || in.Certificate.Parsed == nil {
			continue
		}
		fp := in.Certificate.Fingerprint
		if n, ok := byFingerprint[fp]; ok {
			n.entries = append(n.entries, in.Entry)
			continue
		}
		n := &node{fp: fp, entries: []int{in.Entry}, cert: in.Certificate}
		byFingerprint[fp] = n
		nodes = append(nodes, n)
	}

	bySubject := map[string][]int{}
	byKeyID := map[string][]int{}
	for i, n := range nodes {
		subject := string(n.cert.Parsed.RawSubject)
		bySubject[subject] = append(bySubject[subject], i)
		if len(n.cert.SubjectKeyID) > 0 {
			keyID := string(n.cert.SubjectKeyID)
			byKeyID[keyID] = append(byKeyID[keyID], i)
		}
	}

	for ci, child := range nodes {
		candidates, omitted := collectCandidates(ci, child, bySubject, byKeyID, limits.MaxCandidatesPerCertificate)
		if omitted {
			res.CandidatesOmitted[child.fp] = true
		}

		checked := map[fingerprint.EncodedSPKI]sigcheck.Result{}
		for _, idx := range candidates {
			cand := nodes[idx]
			rel := Relationship{
				Child: child.fp, ChildEntries: child.entries,
				Candidate: cand.fp, CandidateEntries: cand.entries,
				Evidence: evidence(child.cert, cand.cert),
			}
			result, done := checked[cand.cert.EncodedSPKI]
			switch {
			case done:
			case res.Verifications >= limits.MaxVerifications:
				rel.State = NotChecked
			default:
				result = sigcheck.Certificate(child.cert.Parsed, cand.cert.Parsed)
				res.Verifications++
				if result.Reason == sigcheck.ReasonEnginePanic {
					res.EnginePanics++
				}
				checked[cand.cert.EncodedSPKI] = result
				done = true
			}
			if done {
				rel.State, rel.Reason, rel.Detail = State(result.State), result.Reason, result.Detail
			}
			res.byChild[child.fp] = append(res.byChild[child.fp], len(res.Relationships))
			res.Relationships = append(res.Relationships, rel)
		}
	}
	return res
}

// collectCandidates returns up to limit candidate node indexes for child, in
// first-appearance order: certificates matching its Authority Key Identifier
// first (the more specific evidence), then those matching its issuer name.
// omitted reports whether further candidates exist beyond the limit. The
// child itself is never its own candidate; self-signature is a fact of the
// certificate (x509facts), not a relationship.
func collectCandidates(self int, child *node, bySubject, byKeyID map[string][]int, limit int) (candidates []int, omitted bool) {
	seen := map[int]bool{self: true}
	take := func(bucket []int) {
		for _, idx := range bucket {
			if seen[idx] {
				continue
			}
			if len(candidates) == limit {
				omitted = true
				return
			}
			seen[idx] = true
			candidates = append(candidates, idx)
		}
	}
	if aki := child.cert.AuthorityKeyID; len(aki) > 0 {
		take(byKeyID[string(aki)])
	}
	if !omitted {
		take(bySubject[string(child.cert.Parsed.RawIssuer)])
	}
	slices.Sort(candidates)
	return candidates, omitted
}

func evidence(child, candidate *x509facts.Certificate) []Evidence {
	var out []Evidence
	if bytes.Equal(child.Parsed.RawIssuer, candidate.Parsed.RawSubject) {
		out = append(out, EvidenceIssuerNameMatch)
	}
	if len(child.AuthorityKeyID) > 0 && bytes.Equal(child.AuthorityKeyID, candidate.SubjectKeyID) {
		out = append(out, EvidenceAuthorityKeyIDMatch)
	}
	return out
}
