package probe

import (
	"crypto/tls"
	"slices"
)

// Names for protocol values, as crypto/tls spells them, so that callers
// render probe results without depending on crypto/tls themselves.

// VersionName is the protocol version, e.g. "TLS 1.3".
func (n Negotiated) VersionName() string { return tls.VersionName(n.Version) }

// CipherSuiteName is the cipher suite, e.g. "TLS_AES_128_GCM_SHA256".
func (n Negotiated) CipherSuiteName() string { return tls.CipherSuiteName(n.CipherSuite) }

// GroupName is the key exchange group, e.g. "X25519MLKEM768", or "" when
// crypto/tls reports none (CurveID 0): no ECDHE or hybrid key exchange, as
// with RSA key exchange, which no current policy offers. An ECDHE handshake
// reporting 0 is unexpected engine behaviour, shown as an absent group.
func (n Negotiated) GroupName() string {
	if n.Group == 0 {
		return ""
	}
	return n.Group.String()
}

// MinVersionName is the lowest protocol version the policy offers.
func (p Policy) MinVersionName() string { return tls.VersionName(p.MinVersion) }

// MaxVersionName is the highest protocol version the policy offers.
func (p Policy) MaxVersionName() string { return tls.VersionName(p.MaxVersion) }

// TLS12CipherSuiteNames is the set of TLS 1.2 suites the policy offers,
// sorted by name. The order is not a preference: Go applies its own.
func (p Policy) TLS12CipherSuiteNames() []string {
	out := make([]string, len(p.TLS12CipherSuites))
	for i, id := range p.TLS12CipherSuites {
		out[i] = tls.CipherSuiteName(id)
	}
	slices.Sort(out)
	return out
}

// GroupNames is the set of key exchange groups the policy offers, sorted by
// name. The order is not a preference: Go applies its own.
func (p Policy) GroupNames() []string {
	out := make([]string, len(p.CurvePreferences))
	for i, g := range p.CurvePreferences {
		out[i] = g.String()
	}
	slices.Sort(out)
	return out
}
