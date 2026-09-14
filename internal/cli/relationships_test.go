package cli_test

import (
	"encoding/json"
	"slices"
	"testing"
)

type jsonRelationships struct {
	Artifacts []struct {
		Entry   int `json:"entry"`
		Summary *struct {
			IssuerInInput          string `json:"issuer_in_input"`
			VerifiedIssuerEntries  []int  `json:"verified_issuer_entries"`
			CandidateIssuerEntries []int  `json:"candidate_issuer_entries"`
		} `json:"summary"`
	} `json:"artifacts"`
	Relationships []struct {
		Type  string `json:"type"`
		Child struct {
			Fingerprint string `json:"x509-cert-sha256"`
			Entries     []int  `json:"entries"`
		} `json:"child"`
		Candidate struct {
			Fingerprint string `json:"x509-cert-sha256"`
			Entries     []int  `json:"entries"`
		} `json:"candidate"`
		Evidence []string `json:"evidence"`
		State    string   `json:"state"`
		Reason   string   `json:"reason"`
	} `json:"relationships"`
}

func decodeRelationships(t *testing.T, out string) jsonRelationships {
	t.Helper()
	var r jsonRelationships
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return r
}

func TestRelationshipsJSONContract(t *testing.T) {
	chdirRoot(t)

	_, out, _ := run(t, nil, "inspect", "--output", "json", "testdata/certs/bundle.pem")
	r := decodeRelationships(t, out)
	if len(r.Relationships) != 2 {
		t.Fatalf("relationships %+v", r.Relationships)
	}
	for i, rel := range r.Relationships {
		if rel.Type != "certificate_issuer" || rel.State != "verified" || rel.Reason != "" {
			t.Errorf("relationship %d: %+v", i, rel)
		}
		if !slices.Equal(rel.Evidence, []string{"issuer_dn_match", "authority_key_id_match"}) {
			t.Errorf("relationship %d evidence %v", i, rel.Evidence)
		}
		if len(rel.Child.Fingerprint) != 64 || len(rel.Candidate.Fingerprint) != 64 {
			t.Errorf("relationship %d must identify certificates by x509-cert-sha256", i)
		}
		if !slices.Equal(rel.Child.Entries, []int{i}) || !slices.Equal(rel.Candidate.Entries, []int{i + 1}) {
			t.Errorf("relationship %d entries %v -> %v", i, rel.Child.Entries, rel.Candidate.Entries)
		}
	}
	leaf := r.Artifacts[0].Summary
	if leaf.IssuerInInput != "verified" || !slices.Equal(leaf.VerifiedIssuerEntries, []int{1}) || leaf.CandidateIssuerEntries == nil {
		t.Errorf("leaf summary %+v", leaf)
	}
	if root := r.Artifacts[2].Summary; root.IssuerInInput != "self_signed" {
		t.Errorf("root issuer_in_input %q", root.IssuerInInput)
	}

	_, out, _ = run(t, nil, "inspect", "--output", "json", "--fail-on", "never", "testdata/certs/md5-with-issuer.pem")
	r = decodeRelationships(t, out)
	if len(r.Relationships) != 1 || r.Relationships[0].State != "unverifiable" || r.Relationships[0].Reason != "insecure_algorithm" {
		t.Errorf("md5 relationship %+v", r.Relationships)
	}
	if s := r.Artifacts[0].Summary; s.IssuerInInput != "candidate_unverifiable" || !slices.Equal(s.CandidateIssuerEntries, []int{1}) {
		t.Errorf("md5 leaf summary %+v", s)
	}

	_, out, _ = run(t, nil, "inspect", "--output", "json", "testdata/certs/leaf.pem")
	r = decodeRelationships(t, out)
	if r.Relationships == nil || len(r.Relationships) != 0 || r.Artifacts[0].Summary.IssuerInInput != "no_candidate_found" {
		t.Errorf("a lone certificate has an empty relationships array and no_candidate_found: %s", out)
	}
}
