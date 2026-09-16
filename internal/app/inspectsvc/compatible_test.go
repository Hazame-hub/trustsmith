package inspectsvc_test

import (
	"crypto/tls"
	"slices"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/probe"
)

// cbcOnly makes a test server accept only TLS 1.2 with one ECDHE AES-CBC-SHA
// suite (the endpoint key is ECDSA P-256).
func cbcOnly(cfg *tls.Config) {
	cfg.MaxVersion = tls.VersionTLS12
	cfg.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
}

func withPolicy(p probe.Policy, dial probe.DialFunc) inspectsvc.Option {
	s := inspectsvc.DefaultProbeSettings()
	s.Policy, s.Dial = p, dial
	return inspectsvc.WithProbeSettings(s)
}

func TestCompatibleCBCNegotiationIsAWarningFinding(t *testing.T) {
	chain := endpointChain(t)
	_, dial := serveEndpointWith(t, chain[:2], cbcOnly)
	res := inspectEndpoint(t, "api.example.test:443", dial, withPolicy(probe.CompatibleV1(), dial))
	wantAcquired(t, res, 2)
	if res.Probe.Policy.ID() != "compatible-v1" || res.Probe.Negotiated.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA {
		t.Fatalf("probe %+v", res.Probe)
	}
	if got := findingKeys(res.Findings); !slices.Equal(got, []string{"-1:tls.cbc_cipher_negotiated:warning"}) {
		t.Errorf("findings %v", got)
	}
	if res.Highest != findings.SeverityWarning {
		t.Errorf("highest %q", res.Highest)
	}
	// Transport and certificate layers stay separate.
	if res.Hostname.Targets[0].Result.State != "matched" || res.Purpose.Targets[0].Usage.State != "suitable" {
		t.Errorf("certificate evaluations changed: %+v %+v", res.Hostname, res.Purpose)
	}
}

func TestCompatibleWithModernServerHasNoTransportFinding(t *testing.T) {
	chain := endpointChain(t)
	_, dial := serveEndpoint(t, chain[:2])
	res := inspectEndpoint(t, "api.example.test:443", dial, withPolicy(probe.CompatibleV1(), dial))
	wantAcquired(t, res, 2)
	if len(res.Findings) != 0 || len(res.Probe.Negotiated.CompatibilityFeatures()) != 0 {
		t.Errorf("findings %v, features %v", findingKeys(res.Findings), res.Probe.Negotiated.CompatibilityFeatures())
	}
}

// Modern against a CBC-only server fails once and is not retried: no
// certificate, no transport finding.
func TestModernAgainstCBCOnlyServerDoesNotFallBack(t *testing.T) {
	chain := endpointChain(t)
	srv, dial := serveEndpointWith(t, chain[:2], cbcOnly)
	res := inspectEndpoint(t, "api.example.test:443", dial)
	if res.Probe == nil || res.Probe.State != probe.StateFailed || res.Probe.Reason != probe.ReasonTLSNegotiationFailed || res.Probe.Policy.ID() != "modern-v1" {
		t.Fatalf("probe %+v", res.Probe)
	}
	if len(res.Findings) != 0 || len(res.Artifacts) != 0 {
		t.Errorf("findings %v, artifacts %d", findingKeys(res.Findings), len(res.Artifacts))
	}
	if len(srv.dialled) != 1 {
		t.Errorf("%d connection attempts, want exactly one", len(srv.dialled))
	}
}

// Transport and certificate findings are ordered together: whole-input first.
func TestTransportFindingOrderedWithCertificateFindings(t *testing.T) {
	chain := endpointChain(t)
	_, dial := serveEndpointWith(t, chain[:2], cbcOnly)
	res := inspectEndpoint(t, "other.example.test:443", dial, withPolicy(probe.CompatibleV1(), dial))
	want := []string{"-1:tls.cbc_cipher_negotiated:warning", "0:name.hostname_mismatch:critical"}
	if got := findingKeys(res.Findings); !slices.Equal(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
	if res.Highest != findings.SeverityCritical {
		t.Errorf("highest %q", res.Highest)
	}
}
