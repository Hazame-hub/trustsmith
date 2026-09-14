package cli_test

import (
	"encoding/json"
	"runtime"
	"slices"
	"strings"
	"testing"
)

type jsonHostnameDoc struct {
	TrustEvaluation struct {
		Targets []struct {
			State string `json:"state"`
		} `json:"targets"`
	} `json:"trust_evaluation"`
	PurposeEvaluation struct {
		Requested string `json:"requested"`
		State     string `json:"state"`
	} `json:"purpose_evaluation"`
	HostnameEvaluation struct {
		State         string  `json:"state"`
		Requested     *string `json:"requested"`
		Normalized    *string `json:"normalized"`
		Kind          *string `json:"kind"`
		Matcher       *string `json:"matcher"`
		EngineVersion *string `json:"engine_version"`
		Targets       []struct {
			Certificate struct {
				Entries []int `json:"entries"`
			} `json:"certificate"`
			State                  string   `json:"state"`
			Reason                 string   `json:"reason"`
			CertificateDNSNames    []string `json:"certificate_dns_names"`
			CertificateIPAddresses []string `json:"certificate_ip_addresses"`
			CommonNameIgnored      bool     `json:"common_name_ignored"`
		} `json:"targets"`
	} `json:"hostname_evaluation"`
	Findings []struct {
		Code string `json:"code"`
	} `json:"findings"`
}

func decodeHostname(t *testing.T, args ...string) (int, jsonHostnameDoc) {
	t.Helper()
	code, out, stderr := run(t, nil, append([]string{"inspect", "--output", "json"}, args...)...)
	if stderr != "" {
		t.Fatalf("stderr: %s", stderr)
	}
	var d jsonHostnameDoc
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return code, d
}

var hostnameGoldens = []struct {
	name string
	args []string
}{
	{"hostname-leaf-match", []string{"testdata/certs/leaf.pem", "--hostname", "API.Example.TEST."}},
	{"hostname-leaf-ip", []string{"testdata/certs/leaf.pem", "--hostname", "192.0.2.10"}},
	{"hostname-leaf-mismatch", []string{"testdata/certs/leaf.pem", "--hostname", "other.example.test"}},
	{"hostname-leaf-ip-mismatch", []string{"testdata/certs/leaf.pem", "--hostname", "[2001:db8::1]"}},
	{"hostname-cn-only", []string{"testdata/certs/cn-only.pem", "--hostname", "cn-only.example.test"}},
	{"hostname-roots-tls-server-mismatch", []string{"testdata/certs/bundle.pem", "--roots", "testdata/roots/test-root.pem", "--purpose", "tls-server", "--hostname", "other.example.test"}},
	{"hostname-match-purpose-mismatch", []string{"testdata/certs/leaf.pem", "--purpose", "tls-client", "--hostname", "www.example.test"}},
	{"hostname-unicode-mismatch", []string{"testdata/certs/leaf.pem", "--hostname", "Bücher.example"}},
}

// IDNA 16. JSON keeps the requested value as given and the normalised A-label,
// deterministically.
func TestHostnameUnicodeJSON(t *testing.T) {
	chdirRoot(t)
	args := []string{"--fail-on", "never", "testdata/certs/leaf.pem", "--hostname", "Bücher.example."}
	_, first, _ := run(t, nil, append([]string{"inspect", "--output", "json"}, args...)...)
	_, second, _ := run(t, nil, append([]string{"inspect", "--output", "json"}, args...)...)
	if first != second {
		t.Error("JSON output differs between identical runs")
	}
	_, d := decodeHostname(t, args...)
	he := d.HostnameEvaluation
	if he.Requested == nil || *he.Requested != "Bücher.example." || he.Normalized == nil || *he.Normalized != "xn--bcher-kva.example" ||
		he.Kind == nil || *he.Kind != "dns" || he.Targets[0].State != "mismatch" {
		t.Errorf("%+v", he)
	}
	// The certificate's SANs are reported as encoded, never normalised.
	if !slices.Equal(he.Targets[0].CertificateDNSNames, []string{"api.example.test", "www.example.test"}) {
		t.Errorf("SAN facts %v", he.Targets[0].CertificateDNSNames)
	}
}

// 28, 29. Text and JSON goldens for host name identity.
func TestHostnameGoldens(t *testing.T) {
	chdirRoot(t)
	for _, tc := range hostnameGoldens {
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

func TestHostnameJSONContract(t *testing.T) {
	chdirRoot(t)

	_, d := decodeHostname(t, "testdata/certs/leaf.pem")
	he := d.HostnameEvaluation
	if he.State != "not_evaluated" || he.Requested != nil || he.Normalized != nil || he.Kind != nil || he.Matcher != nil || he.Targets == nil || len(he.Targets) != 0 {
		t.Errorf("without --hostname: %+v", he)
	}

	// 21, 25. A match without roots or purpose.
	code, d := decodeHostname(t, "testdata/certs/leaf.pem", "--hostname", "API.Example.TEST.")
	he = d.HostnameEvaluation
	if code != 0 || he.State != "evaluated" || *he.Requested != "API.Example.TEST." || *he.Normalized != "api.example.test" || *he.Kind != "dns" ||
		*he.Matcher != "go-x509-verifyhostname" || *he.EngineVersion != runtime.Version() || len(he.Targets) != 1 {
		t.Fatalf("match: exit %d %+v", code, he)
	}
	if tt := he.Targets[0]; tt.State != "matched" || tt.Reason != "" || !slices.Equal(tt.Certificate.Entries, []int{0}) ||
		!slices.Equal(tt.CertificateDNSNames, []string{"api.example.test", "www.example.test"}) || !slices.Equal(tt.CertificateIPAddresses, []string{"192.0.2.10"}) {
		t.Errorf("target %+v", tt)
	}
	if d.PurposeEvaluation.Requested != "any" || d.PurposeEvaluation.State != "not_evaluated" || len(d.TrustEvaluation.Targets) != 0 {
		t.Errorf("--hostname implied another layer: %+v %+v", d.PurposeEvaluation, d.TrustEvaluation)
	}

	// A mismatch reaches the exit code and names its evidence.
	code, d = decodeHostname(t, "testdata/certs/leaf.pem", "--hostname", "[2001:db8::1]")
	he = d.HostnameEvaluation
	if code != 3 || *he.Kind != "ip" || *he.Normalized != "2001:db8::1" || he.Targets[0].State != "mismatch" {
		t.Errorf("IPv6 mismatch: exit %d %+v", code, he)
	}
	if len(d.Findings) != 1 || d.Findings[0].Code != "name.hostname_mismatch" {
		t.Errorf("findings %+v", d.Findings)
	}

	// 22. Trust verified for TLS server use, host name mismatch.
	_, d = decodeHostname(t, "--fail-on", "never", "testdata/certs/bundle.pem", "--roots", "testdata/roots/test-root.pem", "--purpose", "tls-server", "--hostname", "other.example.test")
	if d.TrustEvaluation.Targets[0].State != "verified" || d.HostnameEvaluation.Targets[0].State != "mismatch" {
		t.Errorf("trust %+v hostname %+v", d.TrustEvaluation, d.HostnameEvaluation)
	}

	// 12. CN-only.
	_, d = decodeHostname(t, "--fail-on", "never", "testdata/certs/cn-only.pem", "--hostname", "cn-only.example.test")
	if tt := d.HostnameEvaluation.Targets[0]; tt.State != "mismatch" || !tt.CommonNameIgnored || tt.CertificateDNSNames == nil || len(tt.CertificateDNSNames) != 0 {
		t.Errorf("CN-only %+v", tt)
	}
}

// 18, 19, 20. Invalid --hostname values are usage errors; nothing is stripped
// and nothing is inspected.
func TestHostnameUsageErrors(t *testing.T) {
	chdirRoot(t)
	for _, h := range []string{
		"", "https://api.example.test", "api.example.test/path", "api.example.test:443", "192.0.2.10:443",
		"[2001:db8::1]:443", "api..example.test", "*.example.test", "bad host", "fe80::1%eth0",
		"_service.example.test", "a\u200db.example.test", "אa.example.test", "ab--cd.example.test", "xn--example-.test",
		strings.Repeat("a", 300), strings.Repeat("a", 2000),
	} {
		code, out, stderr := run(t, nil, "inspect", "--hostname", h, "testdata/certs/leaf.pem")
		if code != 2 || out != "" || !strings.Contains(stderr, "--hostname") {
			t.Errorf("--hostname %q: exit %d, stdout %q, stderr %q", h, code, out, stderr)
		}
	}
}
