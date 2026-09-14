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
)

// Validity.
const (
	CertExpired        Code = "cert.expired"
	CertNotYetValid    Code = "cert.not_yet_valid"
	CertExpiringSoon   Code = "cert.expiring_soon"
	CertSelfSignedLeaf Code = "cert.self_signed_leaf"
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
