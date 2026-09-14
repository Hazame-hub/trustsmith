package cli_test

import (
	"encoding/json"
	"runtime"
	"slices"
	"strings"
	"testing"
)

type jsonTrust struct {
	Artifacts []struct {
		Entry        int                `json:"entry"`
		Fingerprints map[string]*string `json:"fingerprints"`
		Summary      *struct {
			Chain string `json:"chain"`
		} `json:"summary"`
	} `json:"artifacts"`
	Relationships []struct {
		State string `json:"state"`
	} `json:"relationships"`
	Paths []struct {
		Completeness string `json:"completeness"`
		Trust        string `json:"trust"`
	} `json:"paths"`
	TrustEvaluation struct {
		State         string   `json:"state"`
		Source        *string  `json:"source"`
		Engine        *string  `json:"engine"`
		EngineVersion *string  `json:"engine_version"`
		KeyUsages     []string `json:"requested_extended_key_usages"`
		RootsFiles    []struct {
			Locator      string `json:"locator"`
			Certificates int    `json:"certificates"`
		} `json:"roots_files"`
		Anchors []struct {
			Fingerprint  string `json:"x509-cert-sha256"`
			InputEntries []int  `json:"input_entries"`
		} `json:"anchors"`
		Targets []struct {
			Certificate struct {
				Entries []int `json:"entries"`
			} `json:"certificate"`
			State  string `json:"state"`
			Reason string `json:"reason"`
			Chains []struct {
				Certificates []struct {
					Fingerprint string `json:"x509-cert-sha256"`
					Entries     []int  `json:"entries"`
				} `json:"certificates"`
				Anchor string `json:"anchor"`
			} `json:"chains"`
		} `json:"targets"`
	} `json:"trust_evaluation"`
}

func decodeTrust(t *testing.T, args ...string) (int, jsonTrust) {
	t.Helper()
	code, out, stderr := run(t, nil, append([]string{"inspect", "--output", "json"}, args...)...)
	if stderr != "" {
		t.Fatalf("stderr: %s", stderr)
	}
	var j jsonTrust
	if err := json.Unmarshal([]byte(out), &j); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return code, j
}

var trustGoldens = []struct {
	name string
	args []string
}{
	{"trust-bundle-verified", []string{"testdata/certs/bundle.pem", "--roots", "testdata/roots/test-root.pem"}},
	{"trust-leaf-no-anchor-path", []string{"testdata/certs/leaf.pem", "--roots", "testdata/roots/test-root.pem"}},
	{"trust-bundle-unrelated-root", []string{"testdata/certs/bundle.pem", "--roots", "testdata/roots/unrelated-root.pem"}},
	{"trust-multiple-roots-files", []string{"testdata/certs/bundle.pem", "--roots", "testdata/roots/unrelated-root.pem", "--roots", "testdata/roots/test-root.pem"}},
	{"trust-intermediate-anchor", []string{"testdata/certs/leaf.pem", "--roots", "testdata/roots/intermediate-as-anchor.pem"}},
	{"trust-sha1-rejected", []string{"testdata/certs/sha1-with-issuer.pem", "--roots", "testdata/roots/legacy-signing-ca.pem"}},
	{"trust-cross-signed", []string{"testdata/certs/path-cross-signed.pem", "--roots", "testdata/roots/path-cross-roots.pem"}},
	{"trust-expired-intermediate", []string{"testdata/certs/path-expired-intermediate.pem", "--roots", "testdata/roots/path-expired-root.pem"}},
}

// 25, 26. Text and JSON goldens for trust evaluation.
func TestTrustGoldens(t *testing.T) {
	chdirRoot(t)
	for _, tc := range trustGoldens {
		t.Run(tc.name, func(t *testing.T) {
			_, text, stderr := run(t, nil, append([]string{"inspect", "--fail-on", "never"}, tc.args...)...)
			if stderr != "" {
				t.Errorf("unexpected stderr: %s", stderr)
			}
			golden(t, tc.name+".txt", text)
			_, js, _ := run(t, nil, append([]string{"inspect", "--fail-on", "never", "--output", "json"}, tc.args...)...)
			if !json.Valid([]byte(js)) {
				t.Fatalf("invalid JSON:\n%s", js)
			}
			golden(t, tc.name+".json", js)
		})
	}
}

func TestTrustJSONContract(t *testing.T) {
	chdirRoot(t)

	// 2. Without --roots nothing is evaluated, even though the bundle holds a
	// self-signed root.
	code, j := decodeTrust(t, "testdata/certs/bundle.pem")
	te := j.TrustEvaluation
	if code != 0 || te.State != "not_evaluated" || te.Source != nil || te.Engine != nil || te.EngineVersion != nil ||
		te.KeyUsages == nil || len(te.KeyUsages) != 0 || te.RootsFiles == nil || te.Anchors == nil || te.Targets == nil || len(te.Targets) != 0 {
		t.Errorf("without roots: %+v", te)
	}
	for i, a := range j.Artifacts {
		if a.Summary.Chain != "not_checked" {
			t.Errorf("artifact %d chain %q without roots", i, a.Summary.Chain)
		}
	}

	// 1, 5. With the root supplied, the bundle validates; the root is one
	// anchor identity although it is also entry 2 of the input.
	code, j = decodeTrust(t, "testdata/certs/bundle.pem", "--roots", "testdata/roots/test-root.pem")
	te = j.TrustEvaluation
	if code != 0 || te.State != "evaluated" || te.Source == nil || *te.Source != "supplied_roots" || te.Engine == nil || *te.Engine != "go-x509" ||
		te.EngineVersion == nil || *te.EngineVersion != runtime.Version() || !slices.Equal(te.KeyUsages, []string{"any"}) {
		t.Fatalf("with roots: %+v", te)
	}
	if len(te.RootsFiles) != 1 || te.RootsFiles[0].Locator != "testdata/roots/test-root.pem" || te.RootsFiles[0].Certificates != 1 {
		t.Errorf("roots files %+v", te.RootsFiles)
	}
	rootFP := *j.Artifacts[2].Fingerprints["x509-cert-sha256"]
	if len(te.Anchors) != 1 || te.Anchors[0].Fingerprint != rootFP || !slices.Equal(te.Anchors[0].InputEntries, []int{2}) {
		t.Errorf("anchors %+v", te.Anchors)
	}
	if len(te.Targets) != 1 || !slices.Equal(te.Targets[0].Certificate.Entries, []int{0}) || te.Targets[0].State != "verified" ||
		te.Targets[0].Reason != "" || len(te.Targets[0].Chains) != 1 {
		t.Fatalf("targets %+v", te.Targets)
	}
	chain := te.Targets[0].Chains[0]
	if chain.Anchor != rootFP || len(chain.Certificates) != 3 || chain.Certificates[2].Fingerprint != rootFP || !slices.Equal(chain.Certificates[1].Entries, []int{1}) {
		t.Errorf("chain %+v", chain)
	}
	if j.Artifacts[0].Summary.Chain != "verified_to_supplied_roots" || j.Artifacts[2].Summary.Chain != "not_checked" {
		t.Errorf("summary chains %q / %q", j.Artifacts[0].Summary.Chain, j.Artifacts[2].Summary.Chain)
	}
	// The included-path layer still does not evaluate trust.
	if len(j.Paths) != 1 || j.Paths[0].Completeness != "complete_in_input" || j.Paths[0].Trust != "not_evaluated" {
		t.Errorf("paths %+v", j.Paths)
	}
}

// 3, 4, 18. Trust failures reach the exit code; the SHA-1 layers each keep
// their own fact.
func TestTrustExitCodesAndLayers(t *testing.T) {
	chdirRoot(t)
	code, j := decodeTrust(t, "testdata/certs/bundle.pem", "--roots", "testdata/roots/unrelated-root.pem")
	if code != 3 || len(j.TrustEvaluation.Targets) != 1 || j.TrustEvaluation.Targets[0].State != "failed" || j.TrustEvaluation.Targets[0].Reason != "no_explicit_anchor_path" {
		t.Errorf("unrelated root: exit %d %+v", code, j.TrustEvaluation.Targets)
	}

	code, j = decodeTrust(t, "--fail-on", "never", "testdata/certs/sha1-with-issuer.pem", "--roots", "testdata/roots/legacy-signing-ca.pem")
	if code != 0 || len(j.Relationships) != 1 || j.Relationships[0].State != "verified" || len(j.Paths) != 1 || j.Paths[0].Completeness != "complete_in_input" {
		t.Errorf("sha1 relationships %+v paths %+v", j.Relationships, j.Paths)
	}
	if tt := j.TrustEvaluation.Targets; len(tt) != 1 || tt[0].State != "failed" || tt[0].Reason != "insecure_signature_algorithm" {
		t.Errorf("sha1 trust %+v", tt)
	}
}

// 19, 20, 21. An unusable roots file stops the inspection: nothing is
// inspected, nothing falls back to another trust source, and secret material
// is never decoded or echoed.
func TestRootsFileErrors(t *testing.T) {
	chdirRoot(t)
	for _, tc := range []struct {
		name   string
		roots  []string
		code   int
		stderr []string
	}{
		{"missing", []string{"testdata/roots/does-not-exist.pem"}, 1, []string{"roots file"}},
		{"directory", []string{"testdata/roots"}, 1, []string{"directory"}},
		{"empty", []string{"testdata/roots/empty.pem"}, 1, []string{"unusable roots file", "empty"}},
		{"malformed", []string{"testdata/roots/malformed.pem"}, 1, []string{"unusable roots file", "malformed"}},
		{"private key", []string{"testdata/roots/with-private-key.pem"}, 1, []string{"PRIVATE KEY", "only certificates", "not decoded"}},
		{"not a certificate", []string{"testdata/certs/not-a-certificate.txt"}, 1, []string{"unusable roots file"}},
		{"one usable, one not", []string{"testdata/roots/test-root.pem", "testdata/roots/malformed.pem"}, 1, []string{"malformed"}},
		{"empty name", []string{""}, 2, []string{"--roots"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"inspect"}
			for _, r := range tc.roots {
				args = append(args, "--roots", r)
			}
			code, out, stderr := run(t, nil, append(args, "testdata/certs/bundle.pem")...)
			if code != tc.code {
				t.Errorf("exit %d, want %d (stderr %s)", code, tc.code, stderr)
			}
			if out != "" {
				t.Errorf("an unusable roots file must produce no inspection output:\n%s", out)
			}
			for _, s := range tc.stderr {
				if !strings.Contains(stderr, s) {
					t.Errorf("stderr %q does not mention %q", stderr, s)
				}
			}
			lower := strings.ToLower(stderr)
			if strings.Contains(lower, "system trust") || strings.Contains(lower, "system root") || strings.Contains(stderr, "MC4CAQAw") {
				t.Errorf("stderr mentions a system trust store or key material: %s", stderr)
			}
		})
	}
}
