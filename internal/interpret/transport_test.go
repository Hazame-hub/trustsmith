package interpret_test

import (
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/interpret"
)

func TestTransportCBCFinding(t *testing.T) {
	fs := interpret.Transport(interpret.TransportFacts{
		Negotiated:  true,
		Version:     "TLS 1.2",
		CipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		Policy:      "compatible-v1",
		Features:    []string{"tls12_aes_cbc_sha1"},
	})
	if len(fs) != 1 {
		t.Fatalf("findings %+v", fs)
	}
	f := fs[0]
	if f.Code != findings.TLSCBCCipherNegotiated || f.Severity != findings.SeverityWarning || f.Entry != findings.WholeInput {
		t.Errorf("finding %+v", f)
	}
	want := map[string]string{"tls_version": "TLS 1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "policy": "compatible-v1"}
	if len(f.Evidence) != len(want) {
		t.Errorf("evidence %+v", f.Evidence)
	}
	for _, e := range f.Evidence {
		if want[e.Key] != e.Value {
			t.Errorf("evidence %s=%s", e.Key, e.Value)
		}
	}
	if _, ok := findings.Describe(f.Code); !ok {
		t.Error("finding code has no catalog entry")
	}
}

// Only a negotiated CBC suite is a finding: not the compatible policy itself,
// not an added group, and never a handshake that did not complete.
func TestTransportNoFindingWithoutNegotiatedCBC(t *testing.T) {
	for name, facts := range map[string]interpret.TransportFacts{
		"compatible, modern parameters": {Negotiated: true, Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256", Policy: "compatible-v1", Features: []string{}},
		"p-521 only":                    {Negotiated: true, Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256", Policy: "compatible-v1", Features: []string{"ecdhe_p521"}},
		"modern":                        {Negotiated: true, Version: "TLS 1.2", CipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Policy: "modern-v1", Features: []string{}},
		"not negotiated":                {Negotiated: false, Policy: "compatible-v1", Features: []string{"tls12_aes_cbc_sha1"}},
	} {
		if fs := interpret.Transport(facts); len(fs) != 0 {
			t.Errorf("%s: findings %+v", name, fs)
		}
	}
}
