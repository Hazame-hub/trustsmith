package probe

import (
	"crypto/tls"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestModernV1IsExact pins the modern policy, version 1. Changing any value
// is a new policy version.
func TestModernV1IsExact(t *testing.T) {
	p := ModernV1()
	if p.Name != "modern" || p.Version != 1 || p.MinVersion != tls.VersionTLS12 || p.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("policy header %+v", p)
	}
	wantSuites := []uint16{0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8}
	if !slices.Equal(p.TLS12CipherSuites, wantSuites) {
		t.Errorf("TLS 1.2 suites % x, want % x", p.TLS12CipherSuites, wantSuites)
	}
	insecure := map[uint16]bool{}
	for _, s := range tls.InsecureCipherSuites() {
		insecure[s.ID] = true
	}
	for _, id := range p.TLS12CipherSuites {
		name := tls.CipherSuiteName(id)
		if insecure[id] || !strings.Contains(name, "ECDHE") || strings.Contains(name, "CBC") || strings.Contains(name, "3DES") || strings.Contains(name, "RC4") {
			t.Errorf("suite %s is not ECDHE with an AEAD cipher", name)
		}
	}
	wantGroups := []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384}
	if !slices.Equal(p.CurvePreferences, wantGroups) {
		t.Errorf("groups %v, want %v", p.CurvePreferences, wantGroups)
	}
	if !slices.Equal(EngineManaged, []string{"tls13_cipher_suites", "signature_schemes"}) {
		t.Errorf("engine-managed %v", EngineManaged)
	}
}

func TestClientConfig(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC) }
	requested := false
	c := clientConfig(ModernV1(), "api.example.test", now, &requested)

	if c.ServerName != "api.example.test" || !c.InsecureSkipVerify {
		t.Errorf("server name %q, InsecureSkipVerify %v", c.ServerName, c.InsecureSkipVerify)
	}
	if c.MinVersion != tls.VersionTLS12 || c.MaxVersion != tls.VersionTLS13 {
		t.Errorf("versions %x-%x", c.MinVersion, c.MaxVersion)
	}
	if !slices.Equal(c.CipherSuites, ModernV1().TLS12CipherSuites) || !slices.Equal(c.CurvePreferences, ModernV1().CurvePreferences) {
		t.Error("suites or groups differ from the policy")
	}
	if c.Renegotiation != tls.RenegotiateNever || c.ClientSessionCache != nil || !c.SessionTicketsDisabled {
		t.Error("renegotiation or session resumption enabled")
	}
	if c.NextProtos != nil {
		t.Errorf("ALPN offered: %v", c.NextProtos)
	}
	if c.Time == nil || !c.Time().Equal(now()) {
		t.Error("clock not injected")
	}
	// Never verification, trust or identity in the handshake.
	if c.RootCAs != nil || c.VerifyPeerCertificate != nil || c.VerifyConnection != nil {
		t.Error("the probe configuration verifies peers")
	}
	if c.Certificates != nil || c.GetCertificate != nil || c.KeyLogWriter != nil {
		t.Error("unexpected certificate or key log configuration")
	}

	got, err := c.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil || got == nil || len(got.Certificate) != 0 || got.PrivateKey != nil {
		t.Errorf("GetClientCertificate returned %+v, %v; want an empty certificate", got, err)
	}
	if !requested {
		t.Error("certificate request not recorded")
	}

	// Policies are copied: mutating the config cannot change the policy.
	c.CipherSuites[0] = 0
	if ModernV1().TLS12CipherSuites[0] == 0 {
		t.Error("policy slices are shared")
	}
}
