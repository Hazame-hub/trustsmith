package probe_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/probe"
)

func compatibleOptions() probe.Options {
	o := options()
	o.Policy = probe.CompatibleV1()
	return o
}

// certificates for both key types, so a server can offer ECDSA- and RSA-signed
// ECDHE suites.
func ecdsaAndRSACertificates(t *testing.T) (tls.Certificate, tls.Certificate) {
	t.Helper()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ec := issue(t, "api.example.test", nil, false, ecKey)
	rs := issue(t, "api.example.test", nil, false, rsaKey)
	return tls.Certificate{Certificate: [][]byte{ec.der}, PrivateKey: ecKey},
		tls.Certificate{Certificate: [][]byte{rs.der}, PrivateKey: rsaKey}
}

// TLS 1.2 servers that accept only an ECDHE AES-CBC-SHA suite: modern fails,
// compatible succeeds and reports that a compatibility suite was negotiated.
func TestCompatibleNegotiatesCBCOnlyServers(t *testing.T) {
	ecCert, rsaCert := ecdsaAndRSACertificates(t)
	for _, tc := range []struct {
		suite uint16
		cert  tls.Certificate
	}{
		{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, ecCert},
		{tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, ecCert},
		{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, rsaCert},
		{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, rsaCert},
	} {
		t.Run(tls.CipherSuiteName(tc.suite), func(t *testing.T) {
			cfg := &tls.Config{Certificates: []tls.Certificate{tc.cert}, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tc.suite}}

			addr, srv := serveTLS(t, cfg)
			wantFailure(t, run(t, addr, "api.example.test", options()), probe.StageHandshake, probe.ReasonTLSNegotiationFailed)
			receive(t, srv)

			addr, srv = serveTLS(t, cfg)
			r := run(t, addr, "api.example.test", compatibleOptions())
			wantComplete(t, r)
			receive(t, srv)
			if r.Policy.ID() != "compatible-v1" {
				t.Errorf("policy %s", r.Policy.ID())
			}
			n := r.Negotiated
			if n.Version != tls.VersionTLS12 || n.CipherSuite != tc.suite {
				t.Errorf("negotiated %s %s", n.VersionName(), n.CipherSuiteName())
			}
			if n.Group == 0 || !slices.Contains(probe.CompatibleV1().CurvePreferences, n.Group) {
				t.Errorf("ECDHE suite negotiated with key exchange group %v", n.Group)
			}
			if got := n.CompatibilityFeatures(); !slices.Equal(got, []probe.Feature{probe.FeatureTLS12AESCBCSHA1}) {
				t.Errorf("features %v", got)
			}
		})
	}
}

// A compatible handshake with a server that also accepts modern parameters
// uses no compatibility feature: the policy name alone says nothing about
// what was negotiated.
func TestCompatibleWithModernCapableServers(t *testing.T) {
	ecCert, _ := ecdsaAndRSACertificates(t)
	for name, cfg := range map[string]*tls.Config{
		"tls1.3":                  {Certificates: []tls.Certificate{ecCert}},
		"tls1.2 gcm":              {Certificates: []tls.Certificate{ecCert}, MaxVersion: tls.VersionTLS12},
		"tls1.2 gcm and cbc both": {Certificates: []tls.Certificate{ecCert}, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}},
	} {
		t.Run(name, func(t *testing.T) {
			addr, srv := serveTLS(t, cfg)
			r := run(t, addr, "api.example.test", compatibleOptions())
			wantComplete(t, r)
			receive(t, srv)
			if got := r.Negotiated.CompatibilityFeatures(); len(got) != 0 {
				t.Errorf("negotiated %s %s %s, features %v", r.Negotiated.VersionName(), r.Negotiated.CipherSuiteName(), r.Negotiated.GroupName(), got)
			}
		})
	}
}

// compatible-v1 does not reach into legacy territory.
func TestCompatibleStillRefusesLegacyServers(t *testing.T) {
	_, rsaCert := ecdsaAndRSACertificates(t)
	for name, cfg := range map[string]*tls.Config{
		"tls1.0 only":           {MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10},
		"tls1.1 only":           {MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11},
		"rsa key exchange only": {MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_128_CBC_SHA}},
		"3des only":             {MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA}},
		"cbc sha256 only":       {MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256}},
		"rc4 only":              {MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg.Certificates = []tls.Certificate{rsaCert}
			addr, srv := serveTLS(t, cfg)
			wantFailure(t, run(t, addr, "api.example.test", compatibleOptions()), probe.StageHandshake, probe.ReasonTLSNegotiationFailed)
			receive(t, srv)
		})
	}
}

// A server that only accepts P-521: modern does not offer it, compatible does
// and reports the group as a compatibility feature.
func TestCompatibleOffersP521(t *testing.T) {
	ecCert, _ := ecdsaAndRSACertificates(t)
	for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(v), func(t *testing.T) {
			cfg := &tls.Config{Certificates: []tls.Certificate{ecCert}, MinVersion: v, MaxVersion: v, CurvePreferences: []tls.CurveID{tls.CurveP521}}

			addr, srv := serveTLS(t, cfg)
			wantFailure(t, run(t, addr, "api.example.test", options()), probe.StageHandshake, probe.ReasonTLSNegotiationFailed)
			receive(t, srv)

			addr, srv = serveTLS(t, cfg)
			r := run(t, addr, "api.example.test", compatibleOptions())
			wantComplete(t, r)
			receive(t, srv)
			if r.Negotiated.Group != tls.CurveP521 || r.Negotiated.GroupName() != "CurveP521" {
				t.Errorf("group %v", r.Negotiated.Group)
			}
			if got := r.Negotiated.CompatibilityFeatures(); !slices.Equal(got, []probe.Feature{probe.FeatureECDHEP521}) {
				t.Errorf("features %v", got)
			}
		})
	}
}

// A policy is chosen before the handshake and used for exactly one attempt:
// a failed modern probe is not retried with compatible.
func TestNoFallbackBetweenPolicies(t *testing.T) {
	_, rsaCert := ecdsaAndRSACertificates(t)
	addr, srv := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{rsaCert}, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}})
	var dials atomic.Int32
	o := options()
	o.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	r := run(t, addr, "api.example.test", o)
	wantFailure(t, r, probe.StageHandshake, probe.ReasonTLSNegotiationFailed)
	receive(t, srv)
	if dials.Load() != 1 || r.Policy.ID() != "modern-v1" {
		t.Errorf("%d connection attempts under policy %s; want exactly one, under modern-v1", dials.Load(), r.Policy.ID())
	}
}

func TestCompatibilityFeatures(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    probe.Negotiated
		want []probe.Feature
	}{
		{"tls1.3", probe.Negotiated{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, Group: tls.X25519MLKEM768}, []probe.Feature{}},
		{"tls1.2 gcm", probe.Negotiated{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, Group: tls.X25519}, []probe.Feature{}},
		{"tls1.2 cbc", probe.Negotiated{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, Group: tls.CurveP256}, []probe.Feature{probe.FeatureTLS12AESCBCSHA1}},
		{"p-521", probe.Negotiated{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_256_GCM_SHA384, Group: tls.CurveP521}, []probe.Feature{probe.FeatureECDHEP521}},
		{"cbc and p-521", probe.Negotiated{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, Group: tls.CurveP521}, []probe.Feature{probe.FeatureECDHEP521, probe.FeatureTLS12AESCBCSHA1}},
		{"no group reported", probe.Negotiated{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, []probe.Feature{}},
	} {
		got := tc.n.CompatibilityFeatures()
		if got == nil || !slices.Equal(got, tc.want) {
			t.Errorf("%s: features %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPolicyIDs(t *testing.T) {
	for name, id := range map[string]string{"modern": "modern-v1", "compatible": "compatible-v1"} {
		p, err := probe.PolicyByName(name)
		if err != nil || p.ID() != id {
			t.Errorf("PolicyByName(%q) = %s, %v; want %s", name, p.ID(), err, id)
		}
	}
	for _, name := range []string{"legacy", "legacy-diagnostic", "compatible-v1", "Compatible", "fallback"} {
		if _, err := probe.PolicyByName(name); !errors.Is(err, probe.ErrUnknownPolicy) {
			t.Errorf("PolicyByName(%q) = %v", name, err)
		}
	}
}
