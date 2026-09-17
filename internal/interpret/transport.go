package interpret

import (
	"slices"

	"github.com/Hazame-hub/trustsmith/internal/findings"
)

// TransportFacts are the negotiated parameters of an endpoint probe, as plain
// values: interpretation never depends on the TLS engine itself.
type TransportFacts struct {
	// Negotiated: a handshake completed. Without it there are no facts to
	// interpret.
	Negotiated  bool
	Version     string // e.g. "TLS 1.2"
	CipherSuite string // e.g. "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	Policy      string // policy identifier, e.g. "compatible-v1"
	// Features are the negotiated parameters the modern policy does not
	// offer (probe.Feature values).
	Features []string
}

// Transport interprets negotiated transport parameters. It reports only what
// was negotiated in this handshake; it never grades the endpoint.
func Transport(t TransportFacts) []findings.Finding {
	if !t.Negotiated || !slices.Contains(t.Features, "tls12_aes_cbc_sha1") {
		return []findings.Finding{}
	}
	return []findings.Finding{finding(findings.WholeInput, findings.TLSCBCCipherNegotiated, findings.SeverityWarning,
		ev("tls_version", t.Version), ev("cipher_suite", t.CipherSuite), ev("policy", t.Policy))}
}
