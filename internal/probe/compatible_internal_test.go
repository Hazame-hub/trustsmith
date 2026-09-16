package probe

import (
	"crypto/tls"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestCompatibleV1IsExact pins the compatible policy, version 1: modern-v1's
// capabilities plus four ECDHE AES-CBC-SHA suites and the P-521 group, and
// nothing else. Changing any value is a new policy version.
func TestCompatibleV1IsExact(t *testing.T) {
	m, c := ModernV1(), CompatibleV1()
	if c.Name != "compatible" || c.Version != 1 || c.ID() != "compatible-v1" || c.MinVersion != tls.VersionTLS12 || c.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("policy header %+v", c)
	}
	added := []uint16{
		0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
		0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
		0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
		0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	}
	wantSuites := append(slices.Clone(m.TLS12CipherSuites), added...)
	slices.Sort(wantSuites)
	gotSuites := slices.Clone(c.TLS12CipherSuites)
	slices.Sort(gotSuites)
	if !slices.Equal(gotSuites, wantSuites) {
		t.Errorf("TLS 1.2 suites % x, want % x", gotSuites, wantSuites)
	}
	for _, id := range added {
		if !strings.HasSuffix(tls.CipherSuiteName(id), "_CBC_SHA") {
			t.Errorf("suite %#x is %s", id, tls.CipherSuiteName(id))
		}
	}
	insecure := map[uint16]bool{}
	for _, s := range tls.InsecureCipherSuites() {
		insecure[s.ID] = true
	}
	for _, id := range c.TLS12CipherSuites {
		name := tls.CipherSuiteName(id)
		switch {
		case insecure[id]:
			t.Errorf("%s is among Go's insecure cipher suites", name)
		case !strings.HasPrefix(name, "TLS_ECDHE_"):
			t.Errorf("%s does not use ECDHE key exchange", name)
		case strings.Contains(name, "3DES"), strings.Contains(name, "RC4"), strings.HasSuffix(name, "_CBC_SHA256"):
			t.Errorf("%s is excluded from compatible-v1", name)
		}
	}
	wantGroups := append(slices.Clone(m.CurvePreferences), tls.CurveP521)
	if !slices.Equal(c.CurvePreferences, wantGroups) {
		t.Errorf("groups %v, want %v", c.CurvePreferences, wantGroups)
	}

	// Building compatible-v1 leaves modern-v1 untouched.
	if ModernV1().ID() != "modern-v1" || len(ModernV1().TLS12CipherSuites) != 6 || slices.Contains(ModernV1().CurvePreferences, tls.CurveP521) {
		t.Error("modern-v1 changed")
	}

	// The configuration hands Go exactly the policy's sets.
	requested := false
	cfg := clientConfig(c, "api.example.test", time.Now, &requested)
	if !slices.Equal(cfg.CipherSuites, c.TLS12CipherSuites) || !slices.Equal(cfg.CurvePreferences, c.CurvePreferences) ||
		cfg.MinVersion != tls.VersionTLS12 || cfg.MaxVersion != tls.VersionTLS13 || !cfg.InsecureSkipVerify || cfg.RootCAs != nil {
		t.Error("client configuration differs from compatible-v1")
	}

	// Every compatibility addition maps to a reported feature.
	for _, id := range added {
		if got := (Negotiated{Version: tls.VersionTLS12, CipherSuite: id, Group: tls.X25519}).CompatibilityFeatures(); len(got) != 1 {
			t.Errorf("suite %s reports features %v", tls.CipherSuiteName(id), got)
		}
	}
}
