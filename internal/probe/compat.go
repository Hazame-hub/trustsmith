package probe

import (
	"crypto/tls"
	"slices"
)

// Feature names a negotiated parameter that modern-v1 does not offer. A
// feature records what this handshake actually used; it does not say that a
// modern handshake would have failed, only that it could not have negotiated
// this parameter.
type Feature string

const (
	// FeatureTLS12AESCBCSHA1: a TLS 1.2 ECDHE suite with AES in CBC mode and
	// HMAC-SHA1 was negotiated.
	FeatureTLS12AESCBCSHA1 Feature = "tls12_aes_cbc_sha1"
	// FeatureECDHEP521: the P-521 key exchange group was negotiated.
	FeatureECDHEP521 Feature = "ecdhe_p521"
)

// aesCBCSHA1Suites are the TLS 1.2 suites behind FeatureTLS12AESCBCSHA1.
var aesCBCSHA1Suites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
}

// CompatibilityFeatures lists, in sorted order, the negotiated parameters
// that modern-v1 does not offer. It is empty, never nil, when the handshake
// used only parameters modern-v1 also offers, whatever policy was selected.
func (n Negotiated) CompatibilityFeatures() []Feature {
	out := []Feature{}
	if n.Group == tls.CurveP521 {
		out = append(out, FeatureECDHEP521)
	}
	if n.Version == tls.VersionTLS12 && slices.Contains(aesCBCSHA1Suites, n.CipherSuite) {
		out = append(out, FeatureTLS12AESCBCSHA1)
	}
	slices.Sort(out)
	return out
}
