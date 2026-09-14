package cli_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

type jsonPurposeDoc struct {
	Relationships []struct {
		State string `json:"state"`
	} `json:"relationships"`
	Paths []struct {
		Completeness string `json:"completeness"`
	} `json:"paths"`
	TrustEvaluation struct {
		State            string   `json:"state"`
		RequestedPurpose *string  `json:"requested_purpose"`
		KeyUsages        []string `json:"requested_extended_key_usages"`
		Targets          []struct {
			State  string `json:"state"`
			Reason string `json:"reason"`
		} `json:"targets"`
	} `json:"trust_evaluation"`
	PurposeEvaluation struct {
		Requested         string `json:"requested"`
		State             string `json:"state"`
		HostnameEvaluated *bool  `json:"hostname_evaluated"`
		Targets           []struct {
			Certificate struct {
				Entries []int `json:"entries"`
			} `json:"certificate"`
			CertificateUsage struct {
				State               string   `json:"state"`
				Reasons             []string `json:"reasons"`
				RequiredExtKeyUsage string   `json:"required_ext_key_usage"`
				ExtKeyUsagePresent  bool     `json:"ext_key_usage_present"`
				ExtKeyUsage         []string `json:"ext_key_usage"`
				KeyUsage            []string `json:"key_usage"`
			} `json:"certificate_usage"`
			AnchoredPath struct {
				State  string `json:"state"`
				Reason string `json:"reason"`
			} `json:"anchored_path"`
		} `json:"targets"`
	} `json:"purpose_evaluation"`
	Findings []struct {
		Code     string `json:"code"`
		Severity string `json:"severity"`
	} `json:"findings"`
}

func decodePurpose(t *testing.T, args ...string) (int, jsonPurposeDoc) {
	t.Helper()
	code, out, stderr := run(t, nil, append([]string{"inspect", "--output", "json"}, args...)...)
	if stderr != "" {
		t.Fatalf("stderr: %s", stderr)
	}
	var d jsonPurposeDoc
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return code, d
}

func findingCodes(d jsonPurposeDoc) []string {
	out := []string{}
	for _, f := range d.Findings {
		out = append(out, f.Code+":"+f.Severity)
	}
	return out
}

var purposeGoldens = []struct {
	name string
	args []string
}{
	{"purpose-leaf-tls-server", []string{"testdata/certs/leaf.pem", "--purpose", "tls-server"}},
	{"purpose-client-as-tls-server", []string{"testdata/certs/client.pem", "--purpose", "tls-server"}},
	{"purpose-code-signing", []string{"testdata/certs/purpose-code-signing.pem", "--purpose", "code-signing"}},
	{"purpose-email", []string{"testdata/certs/purpose-email.pem", "--purpose", "email"}},
	{"purpose-bundle-tls-server-roots", []string{"testdata/certs/bundle.pem", "--purpose", "tls-server", "--roots", "testdata/roots/test-root.pem"}},
	{"purpose-bundle-tls-client-roots", []string{"testdata/certs/bundle.pem", "--purpose", "tls-client", "--roots", "testdata/roots/test-root.pem"}},
	{"purpose-intermediate-restriction", []string{"testdata/certs/purpose-server-only-intermediate.pem", "--purpose", "tls-client", "--roots", "testdata/roots/purpose-root.pem"}},
	{"purpose-key-usage-conflict-roots", []string{"testdata/certs/purpose-key-usage-conflict.pem", "--purpose", "code-signing", "--roots", "testdata/roots/purpose-root.pem"}},
}

// 21, 22. Text and JSON goldens for purpose evaluation.
func TestPurposeGoldens(t *testing.T) {
	chdirRoot(t)
	for _, tc := range purposeGoldens {
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

// 1, 2. Without --purpose the output is exactly that of --purpose any.
func TestPurposeDefaultIsAny(t *testing.T) {
	chdirRoot(t)
	for _, args := range [][]string{
		{"testdata/certs/bundle.pem"},
		{"testdata/certs/bundle.pem", "--roots", "testdata/roots/test-root.pem"},
		{"testdata/certs/client.pem"},
	} {
		for _, output := range []string{"text", "json"} {
			base := append([]string{"inspect", "--fail-on", "never", "--output", output}, args...)
			codeA, outA, _ := run(t, nil, base...)
			codeB, outB, _ := run(t, nil, append(base, "--purpose", "any")...)
			if codeA != codeB || outA != outB {
				t.Errorf("%v (%s): --purpose any differs from the default", args, output)
			}
		}
	}
	_, d := decodePurpose(t, "testdata/certs/bundle.pem")
	if d.PurposeEvaluation.Requested != "any" || d.PurposeEvaluation.State != "not_evaluated" || d.PurposeEvaluation.Targets == nil || len(d.PurposeEvaluation.Targets) != 0 {
		t.Errorf("default purpose evaluation %+v", d.PurposeEvaluation)
	}
}

func TestPurposeJSONContract(t *testing.T) {
	chdirRoot(t)

	// 3, 17. Suitable by its own fields; no roots, so trust is not evaluated.
	code, d := decodePurpose(t, "testdata/certs/leaf.pem", "--purpose", "tls-server")
	pe := d.PurposeEvaluation
	if code != 0 || pe.Requested != "tls-server" || pe.State != "evaluated" || len(pe.Targets) != 1 {
		t.Fatalf("leaf.pem: exit %d %+v", code, pe)
	}
	if u := pe.Targets[0].CertificateUsage; u.State != "suitable" || u.Reasons == nil || len(u.Reasons) != 0 || u.RequiredExtKeyUsage != "server_auth" ||
		!u.ExtKeyUsagePresent || !slices.Equal(u.ExtKeyUsage, []string{"server_auth"}) {
		t.Errorf("leaf.pem usage %+v", u)
	}
	if pe.Targets[0].AnchoredPath.State != "not_evaluated" || d.TrustEvaluation.State != "not_evaluated" || d.TrustEvaluation.RequestedPurpose != nil {
		t.Errorf("leaf.pem anchored %+v trust %+v", pe.Targets[0].AnchoredPath, d.TrustEvaluation)
	}

	// 4. A client-only certificate is unsuitable for tls-server; the finding
	// reaches the exit code.
	code, d = decodePurpose(t, "testdata/certs/client.pem", "--purpose", "tls-server")
	if u := d.PurposeEvaluation.Targets[0].CertificateUsage; code != 3 || u.State != "unsuitable" ||
		!slices.Equal(u.Reasons, []string{"ext_key_usage_disallows_usage"}) || !slices.Equal(u.ExtKeyUsage, []string{"client_auth"}) {
		t.Errorf("client.pem: exit %d %+v", code, u)
	}
	if got := findingCodes(d); !slices.Equal(got, []string{"purpose.eku_disallows_usage:critical"}) {
		t.Errorf("client.pem findings %v", got)
	}

	// Generic trust success does not imply tls-client success.
	_, generic := decodePurpose(t, "testdata/certs/bundle.pem", "--roots", "testdata/roots/test-root.pem")
	if generic.TrustEvaluation.Targets[0].State != "verified" || generic.TrustEvaluation.RequestedPurpose == nil || *generic.TrustEvaluation.RequestedPurpose != "any" ||
		!slices.Equal(generic.TrustEvaluation.KeyUsages, []string{"any"}) {
		t.Fatalf("generic trust %+v", generic.TrustEvaluation)
	}
	_, d = decodePurpose(t, "--fail-on", "never", "testdata/certs/bundle.pem", "--purpose", "tls-client", "--roots", "testdata/roots/test-root.pem")
	te := d.TrustEvaluation
	if te.RequestedPurpose == nil || *te.RequestedPurpose != "tls-client" || !slices.Equal(te.KeyUsages, []string{"client_auth"}) ||
		te.Targets[0].State != "failed" || te.Targets[0].Reason != "incompatible_usage" {
		t.Errorf("tls-client trust %+v", te)
	}
	target := d.PurposeEvaluation.Targets[0]
	if target.CertificateUsage.State != "unsuitable" || target.AnchoredPath.State != "failed" || target.AnchoredPath.Reason != "incompatible_usage" {
		t.Errorf("tls-client purpose %+v", target)
	}
	if len(d.Relationships) != 2 || d.Relationships[0].State != "verified" || d.Paths[0].Completeness != "complete_in_input" {
		t.Errorf("earlier layers changed: %+v %+v", d.Relationships, d.Paths)
	}

	// Leaf suitability does not imply anchored-path validation, and the
	// reverse.
	_, d = decodePurpose(t, "--fail-on", "never", "testdata/certs/purpose-server-only-intermediate.pem", "--purpose", "tls-client", "--roots", "testdata/roots/purpose-root.pem")
	if tt := d.PurposeEvaluation.Targets[0]; tt.CertificateUsage.State != "suitable" || tt.AnchoredPath.State != "failed" || tt.AnchoredPath.Reason != "incompatible_usage" {
		t.Errorf("intermediate restriction %+v", tt)
	}
	_, d = decodePurpose(t, "--fail-on", "never", "testdata/certs/purpose-key-usage-conflict.pem", "--purpose", "code-signing", "--roots", "testdata/roots/purpose-root.pem")
	if tt := d.PurposeEvaluation.Targets[0]; tt.CertificateUsage.State != "unsuitable" || !slices.Equal(tt.CertificateUsage.Reasons, []string{"key_usage_disallows_usage"}) ||
		tt.AnchoredPath.State != "verified" {
		t.Errorf("key usage conflict %+v", tt)
	}
}

// 18. No purpose evaluates host names.
func TestPurposeNeverEvaluatesHostnames(t *testing.T) {
	chdirRoot(t)
	for _, p := range []string{"any", "tls-server", "tls-client", "code-signing", "email"} {
		_, d := decodePurpose(t, "--fail-on", "never", "testdata/certs/leaf.pem", "--purpose", p)
		if d.PurposeEvaluation.HostnameEvaluated == nil || *d.PurposeEvaluation.HostnameEvaluated {
			t.Errorf("%s: hostname_evaluated %v", p, d.PurposeEvaluation.HostnameEvaluated)
		}
	}
	_, text, _ := run(t, nil, "inspect", "--fail-on", "never", "--purpose", "tls-server", "testdata/certs/leaf.pem")
	if !strings.Contains(text, "Host name        not evaluated") {
		t.Errorf("text does not say host names were not evaluated:\n%s", text)
	}
}

// 20. Purposes are spelled exactly; anything else is a usage error.
func TestUnknownPurpose(t *testing.T) {
	chdirRoot(t)
	for _, p := range []string{"banana", "TLS-Server", "tls_server", "server", "", "ocsp-signing"} {
		code, out, stderr := run(t, nil, "inspect", "--purpose", p, "testdata/certs/leaf.pem")
		if code != 2 || out != "" || !strings.Contains(stderr, "--purpose") {
			t.Errorf("--purpose %q: exit %d, stdout %q, stderr %q", p, code, out, stderr)
		}
	}
}
