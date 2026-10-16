package findings

// Stable finding codes (ADR-0003). They are an external contract: JSON output
// and scripts depend on them. Codes are append-only — testdata/codes.golden
// fails the build if one disappears. Every constant here must be a string
// literal of type Code with an entry in catalog.json.

// Input framing and parsing.
const (
	InputEmpty                  Code = "input.empty"
	InputUnsupportedFormat      Code = "input.unsupported_format"
	InputNoCertificates         Code = "input.no_certificates"
	InputMalformedPEM           Code = "input.malformed_pem"
	InputMalformedDER           Code = "input.malformed_der"
	InputTrailingData           Code = "input.trailing_data"
	InputUnparseableCertificate Code = "input.unparseable_certificate"
	InputMalformedSPKI          Code = "input.malformed_spki"
	// InputUnparseableRequest: a block labelled as a certificate signing
	// request that Go's parser rejected (ADR-0011).
	InputUnparseableRequest Code = "input.unparseable_certificate_request"
)

// Validity.
const (
	CertExpired        Code = "cert.expired"
	CertNotYetValid    Code = "cert.not_yet_valid"
	CertExpiringSoon   Code = "cert.expiring_soon"
	CertSelfSignedLeaf Code = "cert.self_signed_leaf"
)

// Certificate signing requests (ADR-0011): the request's signature checked
// with its own key. Weak algorithms, short keys and names reuse the sig.*,
// key.* and name.* codes.
const (
	CSRSignatureInvalid      Code = "csr.signature_invalid"
	CSRSignatureUnverifiable Code = "csr.signature_unverifiable"
)

// Signatures and keys.
const (
	SigSHA1                   Code = "sig.sha1"
	SigMD5                    Code = "sig.md5"
	KeyRSAUnder2048           Code = "key.rsa_under_2048"
	KeyNoncanonicalSPKI       Code = "key.noncanonical_spki"
	KeyUnsupportedForIdentity Code = "key.unsupported_for_identity"
)

// Names.
const (
	NameCNOnlyNoSAN Code = "name.cn_only_no_san"
	// NameHostnameMismatch: the certificate does not identify the host name
	// or IP address requested with --hostname.
	NameHostnameMismatch Code = "name.hostname_mismatch"
)

// Issuer relationships inside the input (signature checks only, never trust).
const (
	IssuerCandidateUnverifiable Code = "issuer.candidate_unverifiable"
	IssuerCandidatesNotChecked  Code = "issuer.candidates_not_checked"
)

// Structural certification paths inside the input (never trust).
const (
	ChainIssuerNotCA           Code = "chain.issuer_not_ca"
	ChainIssuerKeyUsage        Code = "chain.issuer_key_usage"
	ChainPathLengthExceeded    Code = "chain.path_length_exceeded"
	ChainStructureUnverifiable Code = "chain.structure_unverifiable"
	ChainCycle                 Code = "chain.cycle"
	ChainPathLimitReached      Code = "chain.path_limit_reached"
)

// Validation against explicitly supplied trust anchors (never system roots).
const (
	TrustFailed       Code = "trust.failed"
	TrustUnverifiable Code = "trust.unverifiable"
)

// Suitability for an explicitly requested purpose (the certificate's own fields).
const (
	PurposeEKUDisallowsUsage      Code = "purpose.eku_disallows_usage"
	PurposeKeyUsageDisallowsUsage Code = "purpose.key_usage_disallows_usage"
)

// Transport parameters negotiated with a TLS endpoint (what one handshake
// used, never a grade of the endpoint).
const (
	// TLSCBCCipherNegotiated: a TLS 1.2 AES-CBC suite with HMAC-SHA1 was
	// negotiated, which only the explicitly selected compatible policy offers.
	TLSCBCCipherNegotiated Code = "tls.cbc_cipher_negotiated"
)
