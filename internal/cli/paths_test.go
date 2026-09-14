package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type jsonPaths struct {
	Overview struct {
		IncludedPaths    int  `json:"included_paths"`
		PathLimitReached bool `json:"path_limit_reached"`
	} `json:"overview"`
	Paths []struct {
		Type         string `json:"type"`
		Certificates []struct {
			Fingerprint string `json:"x509-cert-sha256"`
			Entries     []int  `json:"entries"`
		} `json:"certificates"`
		Completeness    string `json:"completeness"`
		End             string `json:"end"`
		CycleToPosition *int   `json:"cycle_to_position"`
		Signatures      string `json:"signatures"`
		Structure       struct {
			State  string `json:"state"`
			Issues []struct {
				Kind                   string `json:"kind"`
				Outcome                string `json:"outcome"`
				Position               int    `json:"position"`
				PathLenConstraint      *int   `json:"path_len_constraint"`
				FollowingIntermediates *int   `json:"following_intermediates"`
			} `json:"issues"`
		} `json:"structure"`
		Validity struct {
			State                 string `json:"state"`
			OutsideValidityPeriod []struct {
				Position int    `json:"position"`
				State    string `json:"state"`
			} `json:"outside_validity_period"`
		} `json:"validity"`
		Trust string `json:"trust"`
	} `json:"paths"`
}

func decodePaths(t *testing.T, args ...string) jsonPaths {
	t.Helper()
	_, out, _ := run(t, nil, append([]string{"inspect", "--output", "json", "--fail-on", "never"}, args...)...)
	var p jsonPaths
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return p
}

func TestPathsJSONContract(t *testing.T) {
	chdirRoot(t)

	p := decodePaths(t, "testdata/certs/bundle.pem")
	if p.Overview.IncludedPaths != 1 || p.Overview.PathLimitReached || len(p.Paths) != 1 {
		t.Fatalf("bundle paths %+v", p)
	}
	path := p.Paths[0]
	if path.Type != "included_certification_path" || path.Completeness != "complete_in_input" || path.End != "self_signed_terminal" ||
		path.CycleToPosition != nil || path.Signatures != "verified" || path.Structure.State != "satisfied" ||
		path.Structure.Issues == nil || path.Validity.State != "satisfied" || path.Validity.OutsideValidityPeriod == nil {
		t.Errorf("bundle path %+v", path)
	}
	if path.Trust != "not_evaluated" {
		t.Errorf("a path complete in the input is not trusted: trust %q", path.Trust)
	}
	for i, c := range path.Certificates {
		if len(c.Fingerprint) != 64 || !slices.Equal(c.Entries, []int{i}) {
			t.Errorf("certificate %d %+v", i, c)
		}
	}

	p = decodePaths(t, "testdata/certs/leaf.pem")
	if len(p.Paths) != 1 || p.Paths[0].Completeness != "partial" || p.Paths[0].End != "no_issuer_candidate" ||
		p.Paths[0].Signatures != "not_applicable" || p.Paths[0].Structure.State != "not_applicable" {
		t.Errorf("lone leaf paths %+v", p.Paths)
	}

	p = decodePaths(t, "testdata/certs/path-cycle.pem")
	if len(p.Paths) != 1 || p.Paths[0].Completeness != "cycle" || p.Paths[0].CycleToPosition == nil || *p.Paths[0].CycleToPosition != 0 {
		t.Errorf("cycle paths %+v", p.Paths)
	}

	p = decodePaths(t, "testdata/certs/path-length-exceeded.pem")
	if len(p.Paths) != 1 || p.Paths[0].Structure.State != "failed" || len(p.Paths[0].Structure.Issues) != 1 {
		t.Fatalf("path length paths %+v", p.Paths)
	}
	if is := p.Paths[0].Structure.Issues[0]; is.Kind != "path_length_exceeded" || is.Outcome != "violation" || is.Position != 2 ||
		is.PathLenConstraint == nil || *is.PathLenConstraint != 0 || is.FollowingIntermediates == nil || *is.FollowingIntermediates != 1 {
		t.Errorf("path length issue %+v", is)
	}

	p = decodePaths(t, "testdata/certs/path-expired-intermediate.pem")
	if len(p.Paths) != 1 || p.Paths[0].Validity.State != "failed" || len(p.Paths[0].Validity.OutsideValidityPeriod) != 1 ||
		p.Paths[0].Validity.OutsideValidityPeriod[0].Position != 1 || p.Paths[0].Validity.OutsideValidityPeriod[0].State != "expired" {
		t.Errorf("expired intermediate paths %+v", p.Paths)
	}
}

// TestOutputNeverClaimsTrustOrValidity scans every golden: no output says a
// certificate or path is trusted, no JSON object has a validity or trust
// verdict key, and the only trust field is a path's "not_evaluated".
func TestOutputNeverClaimsTrustOrValidity(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("testdata", "golden"))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join("testdata", "golden", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(string(data)), "trusted") {
			t.Errorf("%s contains \"trusted\"", e.Name())
		}
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		walkKeys(t, e.Name(), doc)
		checked++
	}
	if checked == 0 {
		t.Fatal("no JSON goldens found")
	}
}

func walkKeys(t *testing.T, name string, v any) {
	t.Helper()
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			lower := strings.ToLower(k)
			switch {
			case lower == "valid" || lower == "is_valid" || lower == "trusted" || lower == "is_trusted" || lower == "trust_anchor" || lower == "root":
				t.Errorf("%s: key %q reads as a verdict", name, k)
			case lower == "trust":
				if child != "not_evaluated" {
					t.Errorf("%s: trust is %v, want not_evaluated", name, child)
				}
			case strings.Contains(lower, "trust"):
				t.Errorf("%s: key %q", name, k)
			}
			if _, isBool := child.(bool); isBool && (strings.Contains(lower, "valid") || strings.Contains(lower, "trust")) {
				t.Errorf("%s: boolean %q reads as a verdict", name, k)
			}
			walkKeys(t, name, child)
		}
	case []any:
		for _, child := range v {
			walkKeys(t, name, child)
		}
	}
}
