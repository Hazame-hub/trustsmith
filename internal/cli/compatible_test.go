package cli_test

import (
	"crypto/tls"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/probe"
)

// cbcOnlyDial serves the endpoint chain from a server that accepts only TLS 1.2
// with one ECDHE AES-CBC-SHA suite.
func cbcOnlyDial(t *testing.T) probe.DialFunc {
	_, dial := serveTLSEndpointWith(t, func(cfg *tls.Config) {
		cfg.MaxVersion = tls.VersionTLS12
		cfg.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
	})
	return dial
}

var compatibleGoldens = []struct {
	name   string
	dial   func(t *testing.T) probe.DialFunc
	args   []string
	code   int
	stderr string
}{
	{"endpoint-compatible-cbc", cbcOnlyDial, []string{"inspect", "--probe-policy", "compatible", "api.example.test:443"}, 0, ""},
	{"endpoint-compatible-modern-server", tlsDial, []string{"inspect", "--probe-policy", "compatible", "api.example.test:443"}, 0, ""},
	{"endpoint-modern-cbc-server", cbcOnlyDial, []string{"inspect", "api.example.test:443"}, 1, "tls_negotiation_failed"},
}

func TestCompatibleGoldens(t *testing.T) {
	chdirRoot(t)
	for _, tc := range compatibleGoldens {
		t.Run(tc.name, func(t *testing.T) {
			for _, output := range []string{"text", "json"} {
				code, out, stderr := runDial(t, tc.dial(t), append([]string{"--output", output}, tc.args...)...)
				if code != tc.code {
					t.Errorf("%s: exit %d, want %d (stderr %q)", output, code, tc.code, stderr)
				}
				if (tc.stderr == "") != (stderr == "") || !strings.Contains(stderr, tc.stderr) {
					t.Errorf("%s: stderr %q, want it to mention %q", output, stderr, tc.stderr)
				}
				if output == "json" {
					golden(t, tc.name+".json", out)
				} else {
					golden(t, tc.name+".txt", out)
				}
			}
		})
	}
}

type jsonCompatibleDoc struct {
	Probe struct {
		State  string `json:"state"`
		Policy struct {
			ID                string   `json:"id"`
			Name              string   `json:"name"`
			Version           int      `json:"version"`
			TLS12CipherSuites []string `json:"tls12_cipher_suites"`
			Groups            []string `json:"groups"`
		} `json:"policy"`
		Negotiated *struct {
			Version          string  `json:"version"`
			CipherSuite      string  `json:"cipher_suite"`
			KeyExchangeGroup *string `json:"key_exchange_group"`
		} `json:"negotiated"`
		CompatibilityFeaturesUsed []string `json:"compatibility_features_used"`
	} `json:"probe"`
	Findings []struct {
		Code     string `json:"code"`
		Severity string `json:"severity"`
		Entry    *int   `json:"entry"`
	} `json:"findings"`
}

func decodeCompatible(t *testing.T, out string) jsonCompatibleDoc {
	t.Helper()
	var d jsonCompatibleDoc
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return d
}

func TestCompatibleJSONContract(t *testing.T) {
	chdirRoot(t)
	_, out, _ := runDial(t, cbcOnlyDial(t), "inspect", "--output", "json", "--probe-policy", "compatible", "api.example.test:443")
	d := decodeCompatible(t, out)
	p := d.Probe
	if p.State != "complete" || p.Policy.ID != "compatible-v1" || p.Policy.Name != "compatible" || p.Policy.Version != 1 {
		t.Fatalf("probe %+v", p)
	}
	if !slices.IsSorted(p.Policy.TLS12CipherSuites) || !slices.IsSorted(p.Policy.Groups) {
		t.Error("policy sets must be listed by name, not in a suggested preference order")
	}
	if len(p.Policy.TLS12CipherSuites) != 10 || !slices.Contains(p.Policy.Groups, "CurveP521") {
		t.Errorf("policy sets %v %v", p.Policy.TLS12CipherSuites, p.Policy.Groups)
	}
	for _, s := range p.Policy.TLS12CipherSuites {
		if !strings.HasPrefix(s, "TLS_ECDHE_") || strings.Contains(s, "3DES") || strings.Contains(s, "RC4") || strings.HasSuffix(s, "_CBC_SHA256") {
			t.Errorf("compatible-v1 offers %s", s)
		}
	}
	if n := p.Negotiated; n == nil || n.Version != "TLS 1.2" || n.CipherSuite != "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" || n.KeyExchangeGroup == nil {
		t.Errorf("negotiated %+v", p.Negotiated)
	}
	if !slices.Equal(p.CompatibilityFeaturesUsed, []string{"tls12_aes_cbc_sha1"}) {
		t.Errorf("features %v", p.CompatibilityFeaturesUsed)
	}
	if len(d.Findings) != 1 || d.Findings[0].Code != "tls.cbc_cipher_negotiated" || d.Findings[0].Severity != "warning" || d.Findings[0].Entry != nil {
		t.Errorf("findings %+v", d.Findings)
	}

	_, out, _ = runDial(t, tlsDial(t), "inspect", "--output", "json", "--probe-policy", "compatible", "api.example.test:443")
	d = decodeCompatible(t, out)
	if d.Probe.CompatibilityFeaturesUsed == nil || len(d.Probe.CompatibilityFeaturesUsed) != 0 || len(d.Findings) != 0 {
		t.Errorf("compatible against a modern server: features %v, findings %+v", d.Probe.CompatibilityFeaturesUsed, d.Findings)
	}

	_, out, _ = runDial(t, tlsDial(t), "inspect", "--output", "json", "api.example.test:443")
	d = decodeCompatible(t, out)
	if d.Probe.Policy.ID != "modern-v1" || len(d.Probe.Policy.TLS12CipherSuites) != 6 || slices.Contains(d.Probe.Policy.Groups, "CurveP521") {
		t.Errorf("the default policy must stay modern-v1: %+v", d.Probe.Policy)
	}
}

// One policy, one handshake: a modern failure is reported, never retried.
func TestNoAutomaticFallback(t *testing.T) {
	chdirRoot(t)
	srv, dial := serveTLSEndpointWith(t, func(cfg *tls.Config) {
		cfg.MaxVersion = tls.VersionTLS12
		cfg.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
	})
	code, out, stderr := runDial(t, dial, "inspect", "--output", "json", "api.example.test:443")
	d := decodeCompatible(t, out)
	if code != 1 || d.Probe.State != "failed" || d.Probe.Policy.ID != "modern-v1" || !strings.Contains(stderr, "tls_negotiation_failed") {
		t.Errorf("exit %d, probe %+v, stderr %q", code, d.Probe, stderr)
	}
	if len(srv.dialled) != 1 {
		t.Errorf("%d connection attempts, want exactly one", len(srv.dialled))
	}
}

func TestProbePolicyUsage(t *testing.T) {
	chdirRoot(t)
	for _, args := range [][]string{
		{"inspect", "--probe-policy", "compatible", "testdata/certs/leaf.pem"},
		{"inspect", "--probe-policy", "legacy-diagnostic", "api.example.test:443"},
		{"inspect", "--probe-policy", "compatible-v1", "api.example.test:443"},
		{"inspect", "--probe-policy", "", "api.example.test:443"},
	} {
		code, out, stderr := run(t, nil, args...)
		if code != 2 || out != "" || !strings.Contains(stderr, "--probe-policy") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, out, stderr)
		}
	}
}
