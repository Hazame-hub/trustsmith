package cli

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/issuerlinks"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

// inspectSchema versions the JSON contract below. The types in this file are
// that contract; internal Go structures are never serialised directly. Fields
// may be added within v1; renaming, removing or changing the meaning of one
// requires v2.
const inspectSchema = "trustsmith.inspect/v1"

type jsonInspect struct {
	Schema        string             `json:"schema"`
	InspectedAt   string             `json:"inspected_at"`
	Input         jsonInput          `json:"input"`
	Overview      jsonOverview       `json:"overview"`
	Artifacts     []jsonArtifact     `json:"artifacts"`
	Relationships []jsonRelationship `json:"relationships"`
	Findings      []jsonFinding      `json:"findings"`
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
}

type jsonArtifact struct {
	Entry        int               `json:"entry"`
	Type         string            `json:"type"`
	PEMLabel     string            `json:"pem_label,omitempty"`
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
		},
		Artifacts:     []jsonArtifact{},
		Relationships: []jsonRelationship{},
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
	for _, f := range res.Findings {
		doc.Findings = append(doc.Findings, findingJSON(f))
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

func artifactJSON(a inspectsvc.Artifact) jsonArtifact {
	out := jsonArtifact{Entry: a.Entry, Type: string(a.Type), PEMLabel: a.Label, Offset: a.Offset, Problem: string(a.Problem)}
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
