package cli

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/chainpath"
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/issuerlinks"
	"github.com/Hazame-hub/trustsmith/internal/probe"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

// inspectSchema versions the JSON contract below. The types in this file are
// that contract; internal Go structures are never serialised directly. Fields
// may be added within v1; renaming, removing or changing the meaning of one
// requires v2.
const inspectSchema = "trustsmith.inspect/v1"

type jsonInspect struct {
	Schema      string    `json:"schema"`
	InspectedAt string    `json:"inspected_at"`
	Input       jsonInput `json:"input"`
	// Probe is how certificates were acquired from a TLS endpoint; null for
	// files and standard input.
	Probe         *jsonProbe         `json:"probe"`
	Overview      jsonOverview       `json:"overview"`
	Artifacts     []jsonArtifact     `json:"artifacts"`
	Relationships []jsonRelationship `json:"relationships"`
	Paths         []jsonPath         `json:"paths"`
	// TrustEvaluation is validation against explicitly supplied trust
	// anchors. It is separate from paths, whose trust is never evaluated.
	TrustEvaluation jsonTrustEvaluation `json:"trust_evaluation"`
	// PurposeEvaluation is suitability for the purpose requested with
	// --purpose. It is separate from trust_evaluation.
	PurposeEvaluation jsonPurposeEvaluation `json:"purpose_evaluation"`
	// HostnameEvaluation is host name identity for the name requested with
	// --hostname. It is separate from trust and purpose.
	HostnameEvaluation jsonHostnameEvaluation `json:"hostname_evaluation"`
	Findings           []jsonFinding          `json:"findings"`
}

// jsonPurposeEvaluation is the evaluation for an explicitly requested purpose.
// requested is the exact --purpose value. state is not_evaluated for "any"
// (targets is then empty) or evaluated. source is default (nothing
// requested), explicit (--purpose) or endpoint (implied by inspecting a TLS
// endpoint). Host name identity is never part of it; see hostname_evaluation.
type jsonPurposeEvaluation struct {
	Requested string              `json:"requested"`
	Source    string              `json:"source"`
	State     string              `json:"state"`
	Targets   []jsonPurposeTarget `json:"targets"`
}

// jsonHostnameEvaluation is whether the targets identify the host name or IP
// address requested with --hostname. state is not_evaluated without a request
// (requested, normalized, kind, matcher and engine_version are then null and
// targets empty) or evaluated. requested is the input as given; normalized is
// what was matched; kind is dns or ip. source is explicit (--hostname) or
// endpoint (the host of the inspected TLS endpoint), null when not evaluated.
type jsonHostnameEvaluation struct {
	State         string               `json:"state"`
	Source        *string              `json:"source"`
	Requested     *string              `json:"requested"`
	Normalized    *string              `json:"normalized"`
	Kind          *string              `json:"kind"`
	Matcher       *string              `json:"matcher"`
	EngineVersion *string              `json:"engine_version"`
	Targets       []jsonHostnameTarget `json:"targets"`
}

// jsonHostnameTarget is one certificate's result: matched, mismatch or
// unverifiable (with a reason). The certificate's subject alternative names
// are listed as encoded. common_name_ignored says the Common Name equals the
// request but, as always, was not used.
type jsonHostnameTarget struct {
	Certificate            jsonCertificateRef `json:"certificate"`
	State                  string             `json:"state"`
	Reason                 string             `json:"reason,omitempty"`
	CertificateDNSNames    []string           `json:"certificate_dns_names"`
	CertificateIPAddresses []string           `json:"certificate_ip_addresses"`
	CommonNameIgnored      bool               `json:"common_name_ignored"`
}

// jsonPurposeTarget keeps two facts apart: certificate_usage is what the
// certificate's own fields permit; anchored_path is the trust_evaluation
// result for the same certificate and purpose (not_evaluated without roots).
type jsonPurposeTarget struct {
	Certificate      jsonCertificateRef   `json:"certificate"`
	CertificateUsage jsonCertificateUsage `json:"certificate_usage"`
	AnchoredPath     jsonAnchoredPath     `json:"anchored_path"`
}

type jsonCertificateUsage struct {
	State               string   `json:"state"`   // suitable, unsuitable or unverifiable
	Reasons             []string `json:"reasons"` // ext_key_usage_disallows_usage, key_usage_disallows_usage, ...
	RequiredExtKeyUsage string   `json:"required_ext_key_usage"`
	ExtKeyUsagePresent  bool     `json:"ext_key_usage_present"`
	ExtKeyUsageBasis    string   `json:"ext_key_usage_basis,omitempty"` // not_present, listed, any_extended_key_usage or not_listed
	ExtKeyUsage         []string `json:"ext_key_usage"`
	KeyUsagePresent     bool     `json:"key_usage_present"`
	KeyUsage            []string `json:"key_usage"`
	ConsistentKeyUsage  []string `json:"consistent_key_usage"` // RFC 5280 4.2.1.12 bits consistent with the purpose
	CACertificate       bool     `json:"ca_certificate"`       // a fact; not decisive
}

type jsonAnchoredPath struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// jsonTrustEvaluation is validation against trust anchors supplied with
// --roots. state is not_evaluated when no roots were supplied (source, engine
// and engine_version are then null and the arrays empty), or evaluated, in
// which case every target has its own result. An anchor is always a
// certificate from a roots file, never one inferred from the input.
type jsonTrustEvaluation struct {
	State                      string            `json:"state"`
	Source                     *string           `json:"source"`
	Engine                     *string           `json:"engine"`
	EngineVersion              *string           `json:"engine_version"`
	RequestedPurpose           *string           `json:"requested_purpose"`
	RequestedExtendedKeyUsages []string          `json:"requested_extended_key_usages"`
	RootsFiles                 []jsonRootsFile   `json:"roots_files"`
	Anchors                    []jsonAnchor      `json:"anchors"`
	Targets                    []jsonTrustTarget `json:"targets"`
}

type jsonRootsFile struct {
	Locator      string `json:"locator"`
	Certificates int    `json:"certificates"`
}

type jsonAnchor struct {
	Fingerprint   string             `json:"x509-cert-sha256"`
	Subject       string             `json:"subject"`
	SelfSignature string             `json:"self_signature"` // a fact about the certificate, not why it is an anchor
	Sources       []jsonAnchorSource `json:"sources"`
	InputEntries  []int              `json:"input_entries"` // entries of the inspected input holding the same certificate
}

type jsonAnchorSource struct {
	RootsFile string `json:"roots_file"`
	Entry     int    `json:"entry"`
}

// jsonTrustTarget is one certificate validated by Go's crypto/x509 verifier:
// state verified, failed or unverifiable, with a stable reason unless
// verified. chains lists every chain the verifier built, shortest first, then
// by fingerprint.
type jsonTrustTarget struct {
	Certificate jsonCertificateRef `json:"certificate"`
	State       string             `json:"state"`
	Reason      string             `json:"reason,omitempty"`
	Chains      []jsonTrustChain   `json:"chains"`
}

type jsonTrustChain struct {
	Certificates []jsonCertificateRef `json:"certificates"` // the target first, the anchor last; entries are input entries
	Anchor       string               `json:"anchor"`
}

type jsonInput struct {
	Kind      string `json:"kind"`
	Locator   string `json:"locator"`
	Format    string `json:"format"`
	SizeBytes int    `json:"size_bytes"`
}

type jsonOverview struct {
	Artifacts       int    `json:"artifacts"`
	Certificates    int    `json:"certificates"`
	Findings        int    `json:"findings"`
	HighestSeverity string `json:"highest_severity"`
	// IncludedPaths counts the certification paths built inside the input;
	// PathLimitReached says that list is incomplete.
	IncludedPaths    int  `json:"included_paths"`
	PathLimitReached bool `json:"path_limit_reached"`
}

type jsonArtifact struct {
	Entry        int               `json:"entry"`
	Type         string            `json:"type"`
	PEMLabel     string            `json:"pem_label,omitempty"`
	Locator      string            `json:"locator,omitempty"`
	Offset       int               `json:"offset"`
	Problem      string            `json:"problem,omitempty"`
	ParseError   string            `json:"parse_error,omitempty"`
	Fingerprints *jsonFingerprints `json:"fingerprints,omitempty"`
	KeyIdentity  *jsonKeyIdentity  `json:"key_identity,omitempty"`
	Summary      *jsonSummary      `json:"summary,omitempty"`
	Technical    *jsonTechnical    `json:"technical,omitempty"`
}

type jsonFingerprints struct {
	Cert        string  `json:"x509-cert-sha256"`
	KeyID       *string `json:"x509-spki-sha256"`
	EncodedSPKI *string `json:"x509-spki-encoded-sha256"`
}

type jsonKeyIdentity struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type jsonSummary struct {
	Kind           string       `json:"kind"`
	Purposes       []string     `json:"purposes"`
	Identifies     []string     `json:"identifies"`
	IssuerAsStated string       `json:"issuer_as_stated"`
	SelfSigned     string       `json:"self_signed"`
	Validity       jsonValidity `json:"validity"`
	Key            string       `json:"key"`
	Signature      string       `json:"signature"`
	Chain          string       `json:"chain"`
	// IssuerInInput summarises the certificate_issuer relationships of this
	// certificate: signature checks inside this input, never trust.
	IssuerInInput          string `json:"issuer_in_input"`
	VerifiedIssuerEntries  []int  `json:"verified_issuer_entries"`
	CandidateIssuerEntries []int  `json:"candidate_issuer_entries"`
}

type jsonValidity struct {
	State         string `json:"state"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
	DaysRemaining int    `json:"days_remaining"`
}

type jsonTechnical struct {
	Version                int                  `json:"version"`
	Serial                 string               `json:"serial"`
	Subject                string               `json:"subject"`
	Issuer                 string               `json:"issuer"`
	NotBefore              string               `json:"not_before"`
	NotAfter               string               `json:"not_after"`
	PublicKey              jsonPublicKey        `json:"public_key"`
	SignatureAlgorithm     jsonAlgorithm        `json:"signature_algorithm"`
	KeyUsage               []string             `json:"key_usage"`
	ExtendedKeyUsage       []string             `json:"extended_key_usage"`
	BasicConstraints       jsonBasicConstraints `json:"basic_constraints"`
	SubjectKeyID           string               `json:"subject_key_id,omitempty"`
	AuthorityKeyID         string               `json:"authority_key_id,omitempty"`
	SubjectAltNames        jsonSANs             `json:"subject_alt_names"`
	Extensions             []jsonExtension      `json:"extensions"`
	CRLDistributionPoints  []string             `json:"crl_distribution_points"`
	OCSPServers            []string             `json:"ocsp_servers"`
	IssuingCertificateURLs []string             `json:"issuing_certificate_urls"`
	PolicyOIDs             []string             `json:"policy_oids"`
	SelfIssued             bool                 `json:"self_issued"`
	SelfSignature          string               `json:"self_signature"`
	PinSHA256              string               `json:"pin_sha256"`
}

type jsonPublicKey struct {
	Algorithm string `json:"algorithm"`
	Detail    string `json:"detail,omitempty"`
	Bits      int    `json:"bits,omitempty"`
}

type jsonAlgorithm struct {
	Name string `json:"name"`
	OID  string `json:"oid,omitempty"`
}

type jsonBasicConstraints struct {
	Present    bool `json:"present"`
	IsCA       bool `json:"is_ca"`
	MaxPathLen *int `json:"max_path_len"`
}

type jsonSANs struct {
	DNS   []string `json:"dns"`
	IP    []string `json:"ip"`
	Email []string `json:"email"`
	URI   []string `json:"uri"`
}

type jsonExtension struct {
	OID      string `json:"oid"`
	Critical bool   `json:"critical"`
	Name     string `json:"name,omitempty"`
}

// jsonRelationship is a certificate_issuer relationship: the candidate has
// naming or key-identifier evidence of having issued the child, and state is
// the result of checking the child's signature with the candidate's key
// (verified, does_not_verify, unverifiable or not_checked). A relationship that
// does not verify says nothing about the candidate certificate itself, and a
// verified one never means trusted.
type jsonRelationship struct {
	Type      string             `json:"type"`
	Child     jsonCertificateRef `json:"child"`
	Candidate jsonCertificateRef `json:"candidate"`
	Evidence  []string           `json:"evidence"`
	State     string             `json:"state"`
	Reason    string             `json:"reason,omitempty"` // stable code; engine messages are never part of the contract
}

// jsonPath is an included certification path: certificates of this input,
// from the one furthest from any issuer towards its issuers, each linked to the
// next by a verified issuer relationship. complete_in_input means the path
// reaches a self-signed certificate contained in the input — never that it is
// trusted: trust is always not_evaluated, and no path field asserts validity or
// trust. signatures is "verified" when the path has issuer links (every link is
// a verified signature by construction) and "not_applicable" otherwise.
type jsonPath struct {
	Type            string               `json:"type"`
	Certificates    []jsonCertificateRef `json:"certificates"`
	Completeness    string               `json:"completeness"`
	End             string               `json:"end"`
	CycleToPosition *int                 `json:"cycle_to_position"` // null unless completeness is cycle
	Signatures      string               `json:"signatures"`
	Structure       jsonPathStructure    `json:"structure"`
	Validity        jsonPathValidity     `json:"validity"`
	Trust           string               `json:"trust"`
}

type jsonPathStructure struct {
	State  string          `json:"state"` // satisfied, failed, structurally_unverifiable, not_applicable
	Issues []jsonPathIssue `json:"issues"`
}

type jsonPathIssue struct {
	Kind                    string `json:"kind"`
	Outcome                 string `json:"outcome"` // violation or not_evaluated
	Position                int    `json:"position"`
	Certificate             string `json:"x509-cert-sha256"`
	BasicConstraintsPresent *bool  `json:"basic_constraints_present,omitempty"`
	PathLenConstraint       *int   `json:"path_len_constraint,omitempty"`
	FollowingIntermediates  *int   `json:"following_intermediates,omitempty"`
	ExtensionOID            string `json:"extension_oid,omitempty"`
}

type jsonPathValidity struct {
	State                 string                `json:"state"` // satisfied or failed, at inspected_at
	OutsideValidityPeriod []jsonOutsideValidity `json:"outside_validity_period"`
}

type jsonOutsideValidity struct {
	Position    int    `json:"position"`
	Certificate string `json:"x509-cert-sha256"`
	State       string `json:"state"` // expired or not_yet_valid
}

type jsonCertificateRef struct {
	Fingerprint string `json:"x509-cert-sha256"`
	Entries     []int  `json:"entries"`
}

type jsonFinding struct {
	Code        string         `json:"code"`
	Severity    string         `json:"severity"`
	Entry       *int           `json:"entry"` // null when the finding concerns the whole input
	Title       string         `json:"title"`
	Explanation string         `json:"explanation"`
	Evidence    []jsonEvidence `json:"evidence"`
	Remediation []jsonAction   `json:"remediation"`
}

type jsonEvidence struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type jsonAction struct {
	Code string `json:"code"`
	Text string `json:"text"`
}

func renderJSON(w io.Writer, res inspectsvc.Result) error {
	doc := jsonInspect{
		Schema:      inspectSchema,
		InspectedAt: stamp(res.InspectedAt),
		Input: jsonInput{
			Kind: string(res.Source.Kind), Locator: res.Source.Locator,
			Format: string(res.Format), SizeBytes: res.Size,
		},
		Overview: jsonOverview{
			Artifacts: len(res.Artifacts), Findings: len(res.Findings),
			HighestSeverity: string(res.Highest),
			IncludedPaths:   len(res.Paths), PathLimitReached: res.PathLimitReached,
		},
		Probe:         probeJSON(res),
		Artifacts:     []jsonArtifact{},
		Relationships: []jsonRelationship{},
		Paths:         []jsonPath{},
		Findings:      []jsonFinding{},
	}
	if doc.Overview.HighestSeverity == "" {
		doc.Overview.HighestSeverity = "none"
	}
	for _, a := range res.Artifacts {
		if a.Type == inspectsvc.TypeCertificate || a.Type == inspectsvc.TypeUnparseableCertificate {
			doc.Overview.Certificates++
		}
		doc.Artifacts = append(doc.Artifacts, artifactJSON(a))
	}
	for _, r := range res.Relationships {
		doc.Relationships = append(doc.Relationships, relationshipJSON(r))
	}
	for _, p := range res.Paths {
		doc.Paths = append(doc.Paths, pathJSON(p))
	}
	doc.TrustEvaluation = trustJSON(res)
	doc.PurposeEvaluation = purposeJSON(res)
	doc.HostnameEvaluation = hostnameJSON(res)
	for _, f := range res.Findings {
		doc.Findings = append(doc.Findings, findingJSON(f))
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

func artifactJSON(a inspectsvc.Artifact) jsonArtifact {
	out := jsonArtifact{Entry: a.Entry, Type: string(a.Type), PEMLabel: a.Label, Locator: a.Locator, Offset: a.Offset, Problem: string(a.Problem)}
	switch {
	case a.Certificate != nil:
		c := a.Certificate
		out.Fingerprints, out.KeyIdentity = identityJSON(c.Identity)
		s := a.Summary
		out.Summary = &jsonSummary{
			Kind: s.Kind, Purposes: orEmpty(s.Purposes), Identifies: orEmpty(s.Identifies),
			IssuerAsStated: s.Issuer, SelfSigned: string(s.SelfSigned),
			Validity: jsonValidity{
				State: string(s.Validity.State), NotBefore: stamp(s.Validity.NotBefore),
				NotAfter: stamp(s.Validity.NotAfter), DaysRemaining: s.Validity.DaysRemaining,
			},
			Key: s.Key, Signature: s.Signature, Chain: string(s.Chain),
			IssuerInInput:          string(s.IssuerInInput),
			VerifiedIssuerEntries:  intsOrEmpty(s.VerifiedIssuerEntries),
			CandidateIssuerEntries: intsOrEmpty(s.CandidateEntries),
		}
		out.Technical = technicalJSON(c)
	case a.Unparseable != nil:
		out.ParseError = a.Unparseable.ParseError
		out.Fingerprints, out.KeyIdentity = identityJSON(a.Unparseable.Identity)
	}
	return out
}

func identityJSON(id x509facts.Identity) (*jsonFingerprints, *jsonKeyIdentity) {
	fp := &jsonFingerprints{Cert: id.Fingerprint.Hex()}
	if id.KeyIdentity != x509facts.KeyIdentityUnavailable {
		encoded := id.EncodedSPKI.Hex()
		fp.EncodedSPKI = &encoded
	}
	if id.KeyIdentity == x509facts.KeyIdentityCanonical || id.KeyIdentity == x509facts.KeyIdentityNoncanonical {
		keyID := id.KeyID.Hex()
		fp.KeyID = &keyID
	}
	return fp, &jsonKeyIdentity{Status: string(id.KeyIdentity), Detail: id.KeyIdentityDetail}
}

func relationshipJSON(r issuerlinks.Relationship) jsonRelationship {
	out := jsonRelationship{
		Type:      "certificate_issuer",
		Child:     jsonCertificateRef{Fingerprint: r.Child.Hex(), Entries: intsOrEmpty(r.ChildEntries)},
		Candidate: jsonCertificateRef{Fingerprint: r.Candidate.Hex(), Entries: intsOrEmpty(r.CandidateEntries)},
		Evidence:  []string{},
		State:     string(r.State),
		Reason:    string(r.Reason),
	}
	for _, e := range r.Evidence {
		out.Evidence = append(out.Evidence, string(e))
	}
	return out
}

// inputEntries maps each parsed certificate of the input to its entries.
func inputEntries(res inspectsvc.Result) map[fingerprint.Cert][]int {
	m := map[fingerprint.Cert][]int{}
	for _, a := range res.Artifacts {
		if a.Certificate != nil {
			m[a.Certificate.Fingerprint] = append(m[a.Certificate.Fingerprint], a.Entry)
		}
	}
	return m
}

func trustJSON(res inspectsvc.Result) jsonTrustEvaluation {
	t := res.Trust
	out := jsonTrustEvaluation{
		State:                      string(t.State),
		RequestedExtendedKeyUsages: []string{},
		RootsFiles:                 []jsonRootsFile{},
		Anchors:                    []jsonAnchor{},
		Targets:                    []jsonTrustTarget{},
	}
	if t.State != inspectsvc.TrustEvaluated {
		return out
	}
	source, engine, version, requested := t.Source, t.Engine, t.EngineVersion, string(t.Purpose)
	out.Source, out.Engine, out.EngineVersion, out.RequestedPurpose = &source, &engine, &version, &requested
	out.RequestedExtendedKeyUsages = []string{t.Purpose.ExtKeyUsageName()}
	inInput := inputEntries(res)
	for _, f := range t.Roots.Files {
		out.RootsFiles = append(out.RootsFiles, jsonRootsFile{Locator: f.Locator, Certificates: f.Certificates})
	}
	for _, a := range t.Roots.Anchors {
		j := jsonAnchor{
			Fingerprint: a.Certificate.Fingerprint.Hex(), Subject: a.Certificate.Subject.DN,
			SelfSignature: string(a.Certificate.SelfSignature), Sources: []jsonAnchorSource{},
			InputEntries: intsOrEmpty(inInput[a.Certificate.Fingerprint]),
		}
		for _, s := range a.Sources {
			j.Sources = append(j.Sources, jsonAnchorSource{RootsFile: s.File, Entry: s.Entry})
		}
		out.Anchors = append(out.Anchors, j)
	}
	for _, target := range t.Targets {
		j := jsonTrustTarget{
			Certificate: jsonCertificateRef{Fingerprint: target.Certificate.Hex(), Entries: intsOrEmpty(target.Entries)},
			State:       string(target.Result.State), Reason: string(target.Result.Reason),
			Chains: []jsonTrustChain{},
		}
		for _, c := range target.Result.Chains {
			chain := jsonTrustChain{Certificates: []jsonCertificateRef{}, Anchor: c.Anchor().Hex()}
			for _, fp := range c.Certificates {
				chain.Certificates = append(chain.Certificates, jsonCertificateRef{Fingerprint: fp.Hex(), Entries: intsOrEmpty(inInput[fp])})
			}
			j.Chains = append(j.Chains, chain)
		}
		out.Targets = append(out.Targets, j)
	}
	return out
}

func hostnameJSON(res inspectsvc.Result) jsonHostnameEvaluation {
	e := res.Hostname
	out := jsonHostnameEvaluation{State: string(e.State), Targets: []jsonHostnameTarget{}}
	if e.State != inspectsvc.HostnameEvaluated {
		return out
	}
	requested, normalized, kind, matcher, version, source := e.Request.Input, e.Request.Normalized, string(e.Request.Kind), e.Matcher, e.EngineVersion, string(e.Source)
	out.Requested, out.Normalized, out.Kind, out.Matcher, out.EngineVersion, out.Source = &requested, &normalized, &kind, &matcher, &version, &source
	for _, t := range e.Targets {
		out.Targets = append(out.Targets, jsonHostnameTarget{
			Certificate:            jsonCertificateRef{Fingerprint: t.Certificate.Hex(), Entries: intsOrEmpty(t.Entries)},
			State:                  string(t.Result.State),
			Reason:                 string(t.Result.Reason),
			CertificateDNSNames:    orEmpty(t.Result.DNSNames),
			CertificateIPAddresses: orEmpty(t.Result.IPAddresses),
			CommonNameIgnored:      t.Result.CommonNameIgnored,
		})
	}
	return out
}

func purposeJSON(res inspectsvc.Result) jsonPurposeEvaluation {
	e := res.Purpose
	out := jsonPurposeEvaluation{Requested: string(e.Requested), Source: string(e.Source), State: string(e.State), Targets: []jsonPurposeTarget{}}
	for _, t := range e.Targets {
		u := t.Usage
		reasons := make([]string, len(u.Reasons))
		for i, r := range u.Reasons {
			reasons[i] = string(r)
		}
		out.Targets = append(out.Targets, jsonPurposeTarget{
			Certificate: jsonCertificateRef{Fingerprint: t.Certificate.Hex(), Entries: intsOrEmpty(t.Entries)},
			CertificateUsage: jsonCertificateUsage{
				State: string(u.State), Reasons: reasons, RequiredExtKeyUsage: u.Purpose.ExtKeyUsageName(),
				ExtKeyUsagePresent: u.ExtKeyUsagePresent, ExtKeyUsageBasis: string(u.ExtKeyUsageBasis), ExtKeyUsage: orEmpty(u.ExtKeyUsages),
				KeyUsagePresent: u.KeyUsagePresent, KeyUsage: orEmpty(u.KeyUsages),
				ConsistentKeyUsage: orEmpty(u.Purpose.ConsistentKeyUsages()), CACertificate: u.CA,
			},
			AnchoredPath: jsonAnchoredPath{State: string(t.AnchoredPath), Reason: string(t.AnchoredPathReason)},
		})
	}
	return out
}

func pathJSON(p chainpath.Path) jsonPath {
	out := jsonPath{
		Type:         "included_certification_path",
		Certificates: []jsonCertificateRef{},
		Completeness: string(p.Completeness),
		End:          string(p.End),
		Signatures:   "not_applicable",
		Structure:    jsonPathStructure{State: string(p.Structure), Issues: []jsonPathIssue{}},
		Validity:     jsonPathValidity{State: string(p.Validity), OutsideValidityPeriod: []jsonOutsideValidity{}},
		Trust:        "not_evaluated",
	}
	for i, fp := range p.Certificates {
		out.Certificates = append(out.Certificates, jsonCertificateRef{Fingerprint: fp.Hex(), Entries: intsOrEmpty(p.Entries[i])})
	}
	if len(p.Certificates) > 1 {
		out.Signatures = "verified"
	}
	if p.Completeness == chainpath.Cycle {
		at := p.CycleTo
		out.CycleToPosition = &at
	}
	for _, is := range p.Issues {
		j := jsonPathIssue{Kind: string(is.Kind), Outcome: string(is.Outcome), Position: is.Position,
			Certificate: is.Certificate.Hex(), ExtensionOID: is.ExtensionOID}
		switch is.Kind {
		case chainpath.IssueIssuerNotCA:
			present := is.BasicConstraintsPresent
			j.BasicConstraintsPresent = &present
		case chainpath.IssuePathLengthExceeded:
			limit, following := is.PathLenConstraint, is.FollowingIntermediates
			j.PathLenConstraint, j.FollowingIntermediates = &limit, &following
		}
		out.Structure.Issues = append(out.Structure.Issues, j)
	}
	for _, nv := range p.NotValid {
		state := "not_yet_valid"
		if nv.Expired {
			state = "expired"
		}
		out.Validity.OutsideValidityPeriod = append(out.Validity.OutsideValidityPeriod,
			jsonOutsideValidity{Position: nv.Position, Certificate: nv.Certificate.Hex(), State: state})
	}
	return out
}

func technicalJSON(c *x509facts.Certificate) *jsonTechnical {
	t := &jsonTechnical{
		Version: c.Version, Serial: c.SerialHex, Subject: c.Subject.DN, Issuer: c.Issuer.DN,
		NotBefore: stamp(c.NotBefore), NotAfter: stamp(c.NotAfter),
		PublicKey:          jsonPublicKey{Algorithm: c.PublicKey.Algorithm, Detail: c.PublicKey.Detail, Bits: c.PublicKey.Bits},
		SignatureAlgorithm: jsonAlgorithm{Name: c.SignatureAlgorithm.String(), OID: c.SignatureAlgorithmOID},
		KeyUsage:           orEmpty(c.KeyUsage),
		ExtendedKeyUsage:   orEmpty(c.ExtKeyUsage),
		BasicConstraints: jsonBasicConstraints{
			Present: c.BasicConstraints.Present, IsCA: c.BasicConstraints.IsCA, MaxPathLen: c.BasicConstraints.MaxPathLen,
		},
		SubjectKeyID:   hex.EncodeToString(c.SubjectKeyID),
		AuthorityKeyID: hex.EncodeToString(c.AuthorityKeyID),
		SubjectAltNames: jsonSANs{
			DNS: orEmpty(c.DNSNames), IP: orEmpty(c.IPAddresses), Email: orEmpty(c.EmailAddresses), URI: orEmpty(c.URIs),
		},
		Extensions:             []jsonExtension{},
		CRLDistributionPoints:  orEmpty(c.CRLDistributionPoints),
		OCSPServers:            orEmpty(c.OCSPServers),
		IssuingCertificateURLs: orEmpty(c.IssuingCertificateURLs),
		PolicyOIDs:             orEmpty(c.PolicyOIDs),
		SelfIssued:             c.SelfIssued,
		SelfSignature:          string(c.SelfSignature),
		PinSHA256:              c.EncodedSPKI.PinSHA256(),
	}
	for _, e := range c.Extensions {
		t.Extensions = append(t.Extensions, jsonExtension{OID: e.OID, Critical: e.Critical, Name: e.Name})
	}
	return t
}

func findingJSON(f findings.Finding) jsonFinding {
	out := jsonFinding{Code: string(f.Code), Severity: string(f.Severity), Evidence: []jsonEvidence{}, Remediation: []jsonAction{}}
	if f.Entry != findings.WholeInput {
		entry := f.Entry
		out.Entry = &entry
	}
	if d, ok := findings.Describe(f.Code); ok {
		out.Title, out.Explanation = d.Title, d.Explanation
		for _, a := range d.Remediation {
			out.Remediation = append(out.Remediation, jsonAction{Code: a.Code, Text: a.Text})
		}
	}
	for _, e := range f.Evidence {
		out.Evidence = append(out.Evidence, jsonEvidence{Key: e.Key, Value: e.Value})
	}
	return out
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func intsOrEmpty(s []int) []int {
	if s == nil {
		return []int{}
	}
	return s
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// jsonProbe is how certificates were acquired from a TLS endpoint. A complete
// state means one handshake completed under the policy and the server's
// certificates were kept; it is not a verdict on trust, host name identity or
// suitability, which the evaluations report separately.
//
// stage is how far the probe got (resolve, connect, handshake or complete).
// reason is null when complete, otherwise dns_error, connect_refused,
// connect_timeout, handshake_timeout, tls_negotiation_failed, not_tls,
// connection_closed, certificate_unparseable_by_engine or engine_error.
// certificate_acquisition is acquired, not_acquired, or unverifiable when the
// server sent certificates Go's TLS engine could not parse. sni is the server
// name sent, null for an IP address. negotiated is null unless complete.
type jsonProbe struct {
	Kind                       string          `json:"kind"`
	Endpoint                   jsonEndpoint    `json:"endpoint"`
	State                      string          `json:"state"`
	Stage                      string          `json:"stage"`
	Reason                     *string         `json:"reason"`
	CertificateAcquisition     string          `json:"certificate_acquisition"`
	Policy                     jsonProbePolicy `json:"policy"`
	Engine                     jsonEngine      `json:"engine"`
	SNI                        *string         `json:"sni"`
	Negotiated                 *jsonNegotiated `json:"negotiated"`
	PeerCertificateCount       int             `json:"peer_certificate_count"`
	ClientCertificateRequested bool            `json:"client_certificate_requested"`
	ElapsedMS                  int64           `json:"elapsed_ms"`
	HandshakeMS                int64           `json:"handshake_ms"`
}

// jsonEndpoint is the endpoint as parsed: host is the normalised DNS name
// (A-labels) or canonical IP address; kind is dns or ip.
type jsonEndpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Kind string `json:"kind"`
}

// jsonProbePolicy is the named, versioned client policy and the values it
// sets. tls13_cipher_suites and signature_schemes are engine_managed: Go's
// crypto/tls chooses them and a policy cannot. alpn is what is offered.
type jsonProbePolicy struct {
	Name              string   `json:"name"`
	Version           int      `json:"version"`
	MinVersion        string   `json:"min_version"`
	MaxVersion        string   `json:"max_version"`
	TLS12CipherSuites []string `json:"tls12_cipher_suites"`
	TLS13CipherSuites string   `json:"tls13_cipher_suites"`
	SignatureSchemes  string   `json:"signature_schemes"`
	Groups            []string `json:"groups"`
	ALPN              []string `json:"alpn"`
}

type jsonEngine struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// jsonNegotiated are the parameters of the completed handshake, named as Go's
// crypto/tls names them. key_exchange_group and alpn are null when none.
type jsonNegotiated struct {
	Version          string  `json:"version"`
	CipherSuite      string  `json:"cipher_suite"`
	KeyExchangeGroup *string `json:"key_exchange_group"`
	ALPN             *string `json:"alpn"`
}

const engineManaged = "engine_managed"

func probeJSON(res inspectsvc.Result) *jsonProbe {
	p, e := res.Probe, res.Endpoint
	if p == nil || e == nil {
		return nil
	}
	out := &jsonProbe{
		Kind:                   "tls",
		Endpoint:               jsonEndpoint{Host: e.Host.Normalized, Port: e.Port, Kind: string(e.Host.Kind)},
		State:                  string(p.State),
		Stage:                  string(p.Stage),
		CertificateAcquisition: string(p.Acquisition),
		Policy: jsonProbePolicy{
			Name: p.Policy.Name, Version: p.Policy.Version,
			MinVersion: p.Policy.MinVersionName(), MaxVersion: p.Policy.MaxVersionName(),
			TLS12CipherSuites: p.Policy.TLS12CipherSuiteNames(), TLS13CipherSuites: engineManaged,
			SignatureSchemes: engineManaged, Groups: p.Policy.GroupNames(), ALPN: []string{},
		},
		Engine:                     jsonEngine{Name: "go", Version: p.EngineVersion},
		PeerCertificateCount:       len(p.PeerCertificates),
		ClientCertificateRequested: p.ClientCertificateRequested,
		ElapsedMS:                  p.Elapsed.Milliseconds(),
		HandshakeMS:                p.HandshakeElapsed.Milliseconds(),
	}
	if p.Reason != probe.ReasonNone {
		reason := string(p.Reason)
		out.Reason = &reason
	}
	if sni := p.Target.ServerName; sni != "" {
		out.SNI = &sni
	}
	if n := p.Negotiated; n != nil {
		out.Negotiated = &jsonNegotiated{Version: n.VersionName(), CipherSuite: n.CipherSuiteName()}
		if g := n.GroupName(); g != "" {
			out.Negotiated.KeyExchangeGroup = &g
		}
		if n.ALPN != "" {
			alpn := n.ALPN
			out.Negotiated.ALPN = &alpn
		}
	}
	return out
}
