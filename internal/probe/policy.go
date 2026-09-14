package probe

import (
	"crypto/tls"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Policy is a named, versioned TLS client policy. Its values are set
// explicitly so that probe results never depend on crypto/tls defaults, which
// change between Go releases.
type Policy struct {
	Name       string
	Version    int
	MinVersion uint16
	MaxVersion uint16
	// TLS12CipherSuites are the TLS 1.2 suites offered. TLS 1.3 suites are
	// chosen by Go and cannot be configured (see EngineManaged).
	TLS12CipherSuites []uint16
	CurvePreferences  []tls.CurveID
}

// ErrUnknownPolicy marks an unsupported --probe-policy value.
var ErrUnknownPolicy = errors.New("unknown probe policy")

// ModernV1 is the modern policy, version 1: TLS 1.2 and 1.3 only; TLS 1.2
// with ECDHE key exchange and AEAD ciphers only (no CBC, no RSA key exchange,
// no 3DES); groups X25519MLKEM768, X25519, P-256 and P-384. There is no
// fallback to a weaker policy.
func ModernV1() Policy {
	return Policy{
		Name:       "modern",
		Version:    1,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		TLS12CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384},
	}
}

// PolicyByName returns the policy for a --probe-policy value. Only "modern"
// exists.
func PolicyByName(name string) (Policy, error) {
	if name == "modern" {
		return ModernV1(), nil
	}
	return Policy{}, fmt.Errorf("%w %q: want modern", ErrUnknownPolicy, name)
}

// EngineManaged names client behaviour that Go's public crypto/tls API does
// not let a policy fix, so a policy cannot claim to determine it.
var EngineManaged = []string{"tls13_cipher_suites", "signature_schemes"}

// clientConfig is the complete client configuration for a probe. Every field
// with a bearing on what is offered or verified is set here explicitly.
func clientConfig(p Policy, serverName string, now func() time.Time, clientCertRequested *bool) *tls.Config {
	return &tls.Config{
		ServerName: serverName,
		// InsecureSkipVerify is used only to collect peer certificate material
		// for diagnostics. Trustsmith performs trust and host name evaluation
		// separately and reports them independently.
		InsecureSkipVerify:     true, //nolint:gosec // G402: diagnostic acquisition only; see ADR-0009 and internal/archtest
		MinVersion:             p.MinVersion,
		MaxVersion:             p.MaxVersion,
		CipherSuites:           slices.Clone(p.TLS12CipherSuites),
		CurvePreferences:       slices.Clone(p.CurvePreferences),
		Renegotiation:          tls.RenegotiateNever,
		ClientSessionCache:     nil, // no session resumption
		SessionTicketsDisabled: true,
		NextProtos:             nil, // no ALPN is offered: no application protocol is spoken
		Time:                   now,
		// GetClientCertificate only observes a certificate request; it never
		// supplies a certificate.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			*clientCertRequested = true
			return &tls.Certificate{}, nil
		},
	}
}
