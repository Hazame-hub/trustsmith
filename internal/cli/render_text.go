package cli

import (
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/artifact"
	"github.com/Hazame-hub/trustsmith/internal/chainpath"
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/interpret"
	"github.com/Hazame-hub/trustsmith/internal/issuerlinks"
	"github.com/Hazame-hub/trustsmith/internal/trustverify"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

const humanTime = "2006-01-02 15:04:05 UTC"

func renderText(w io.Writer, res inspectsvc.Result, advanced bool) error {
	var b strings.Builder
	source := res.Source.Locator
	if res.Source.Kind == inspectsvc.SourceStdin {
		source = "standard input"
	}
	fmt.Fprintf(&b, "Inspected %s (%s, %s) at %s\n", source, formatName(res.Format),
		plural(len(res.Artifacts), "entry", "entries"), res.InspectedAt.UTC().Format(humanTime))

	trustEvaluated := res.Trust.State == inspectsvc.TrustEvaluated
	for _, a := range res.Artifacts {
		b.WriteString("\n")
		writeArtifact(&b, a, advanced, trustEvaluated)
	}
	if len(res.Relationships) > 0 {
		b.WriteString("\n")
		writeRelationships(&b, res.Relationships)
	}
	if showPaths(res) {
		b.WriteString("\n")
		writePaths(&b, res)
	}
	b.WriteString("\n")
	writeTrust(&b, res)
	b.WriteString("\n")
	writeFindings(&b, res.Findings)

	_, err := io.WriteString(w, b.String())
	return err
}

func formatName(f artifact.Format) string {
	switch f {
	case artifact.FormatPEM:
		return "PEM"
	case artifact.FormatDER:
		return "DER"
	case artifact.FormatEmpty:
		return "empty"
	}
	return "unrecognised format"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func field(b *strings.Builder, label, value string) {
	fmt.Fprintf(b, "    %-15s%s\n", label, value)
}

// topField is a section-level field; its value aligns with field's.
func topField(b *strings.Builder, label, value string) {
	fmt.Fprintf(b, "  %-17s%s\n", label, value)
}

// entries renders "entry 1" or "entries 1, 3".
func entries(v []int) string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = strconv.Itoa(n)
	}
	if len(v) == 1 {
		return "entry " + parts[0]
	}
	return "entries " + strings.Join(parts, ", ")
}

// issuerInInputText explains what the input says about the issuer. It
// describes signature checks only and never says "trusted".
func issuerInInputText(s *interpret.Summary) string {
	switch s.IssuerInInput {
	case interpret.IssuerVerified:
		return "signature verified with the key of the certificate in " + entries(s.VerifiedIssuerEntries) + " of this input"
	case interpret.IssuerSelfSigned:
		return "this certificate names itself as issuer and its own key verifies its signature"
	case interpret.IssuerCandidateUnverifiable:
		return "a matching certificate is in " + entries(s.CandidateEntries) + " of this input, but this engine could not check the signature with it"
	case interpret.IssuerCandidateNotChecked:
		return "matching certificates are in this input, but not all of them were checked"
	case interpret.IssuerCandidateSignatureMismatch:
		return "a certificate in " + entries(s.CandidateEntries) + " matches the issuer name or key identifier, but its key does not verify this signature"
	}
	return "no matching issuer candidate found in this input"
}

func writeRelationships(b *strings.Builder, rels []issuerlinks.Relationship) {
	fmt.Fprintf(b, "Issuer relationships (%d)\n", len(rels))
	b.WriteString("  Signature checks between certificates of this input. A verified signature is not a trust decision.\n")
	for _, r := range rels {
		state := string(r.State)
		if r.Reason != "" {
			state += " (" + string(r.Reason) + ")"
		}
		evidence := make([]string, len(r.Evidence))
		for i, e := range r.Evidence {
			evidence[i] = string(e)
		}
		fmt.Fprintf(b, "  %s, candidate issuer %s: %s; evidence: %s\n",
			entries(r.ChildEntries), entries(r.CandidateEntries), state, strings.Join(evidence, ", "))
	}
}

// showPaths: a path of one certificate is already fully described by that
// certificate's own entry, so the section appears only when some path links
// certificates, or construction hit a cycle or a limit.
func showPaths(res inspectsvc.Result) bool {
	if res.PathLimitReached {
		return true
	}
	for _, p := range res.Paths {
		if len(p.Certificates) > 1 || p.Completeness == chainpath.Cycle || p.Completeness == chainpath.LimitReached {
			return true
		}
	}
	return false
}

func writePaths(b *strings.Builder, res inspectsvc.Result) {
	names := map[int]string{}
	for _, a := range res.Artifacts {
		if a.Certificate != nil {
			names[a.Entry] = subjectName(a.Certificate)
		}
	}
	fmt.Fprintf(b, "Included certification paths (%d)\n", len(res.Paths))
	b.WriteString("  Built only from certificates in this input, linked by verified signatures. Trust is not evaluated:\n")
	b.WriteString("  no certificate is treated as a trust anchor, including self-signed ones.\n")
	if res.PathLimitReached {
		b.WriteString("  A path construction limit was reached: not all paths are shown, and some may be cut short.\n")
	}
	for i, p := range res.Paths {
		steps := make([]string, len(p.Certificates))
		for j := range p.Certificates {
			first := p.Entries[j][0]
			steps[j] = fmt.Sprintf("entry %d (%s)", first, names[first])
		}
		fmt.Fprintf(b, "  Path %d: %s\n", i+1, strings.Join(steps, " > "))
		field(b, "Ends", pathEndText(p))
		field(b, "Completeness", pathCompletenessText(p.Completeness))
		if len(p.Certificates) > 1 {
			field(b, "Signatures", "verified: each certificate's signature verifies with the key of the next")
		} else {
			field(b, "Signatures", "not applicable (no issuer on this path)")
		}
		field(b, "CA constraints", pathStructureText(p.Structure))
		for _, is := range p.Issues {
			field(b, "", fmt.Sprintf("entry %d: %s", p.Entries[is.Position][0], pathIssueText(is)))
		}
		if p.Validity == chainpath.ValiditySatisfied {
			field(b, "Validity", "every certificate on the path is within its validity period")
		} else {
			field(b, "Validity", "not every certificate on the path is within its validity period")
			for _, nv := range p.NotValid {
				state := "not yet valid"
				if nv.Expired {
					state = "expired"
				}
				field(b, "", fmt.Sprintf("entry %d: %s", p.Entries[nv.Position][0], state))
			}
		}
		field(b, "Trust", "not evaluated by this layer (see Trust evaluation)")
	}
}

func subjectName(c *x509facts.Certificate) string {
	switch {
	case c.Subject.CommonName != "":
		return c.Subject.CommonName
	case c.Subject.DN != "":
		return c.Subject.DN
	}
	return "empty subject"
}

func pathEndText(p chainpath.Path) string {
	switch p.End {
	case chainpath.EndSelfSignedTerminal:
		return "at a self-signed certificate in this input"
	case chainpath.EndNoIssuerCandidate:
		return "no matching issuer candidate found in this input"
	case chainpath.EndIssuerCandidatesNotVerify:
		return "no issuer candidate in this input verified the last certificate's signature"
	case chainpath.EndIssuerCandidatesUnchecked:
		return "issuer candidates in this input were not all checked (limit reached)"
	case chainpath.EndCycle:
		return fmt.Sprintf("the next issuer, entry %d, is already on this path", p.Entries[p.CycleTo][0])
	case chainpath.EndDepthLimit:
		return "the maximum path length for construction was reached"
	}
	return string(p.End)
}

func pathCompletenessText(c chainpath.Completeness) string {
	switch c {
	case chainpath.CompleteInInput:
		return "complete in this input (not a trust decision)"
	case chainpath.Partial:
		return "partial"
	case chainpath.Cycle:
		return "cycle"
	case chainpath.LimitReached:
		return "limit reached; the path may continue"
	}
	return string(c)
}

func pathStructureText(s chainpath.StructureState) string {
	switch s {
	case chainpath.StructureSatisfied:
		return "satisfied (basic constraints, key usage, path length)"
	case chainpath.StructureFailed:
		return "failed"
	case chainpath.StructureUnverifiable:
		return "not fully evaluated"
	case chainpath.StructureNotApplicable:
		return "not applicable (no issuer on this path)"
	}
	return string(s)
}

func pathIssueText(is chainpath.Issue) string {
	switch is.Kind {
	case chainpath.IssueIssuerNotCA:
		if is.BasicConstraintsPresent {
			return "issues a certificate on this path but is not a CA certificate (basic constraints CA: no)"
		}
		return "issues a certificate on this path but is not a CA certificate (no basic constraints)"
	case chainpath.IssueIssuerKeyUsageNoCertSign:
		return "key usage does not include certificate signing"
	case chainpath.IssuePathLengthExceeded:
		return fmt.Sprintf("path length constraint %d exceeded by %s below it", is.PathLenConstraint,
			plural(is.FollowingIntermediates, "intermediate CA certificate", "intermediate CA certificates"))
	case chainpath.IssueIssuerCAStatusNotEvaluated:
		return "CA status not evaluated (version 1 or 2 certificate)"
	case chainpath.IssueNameConstraintsNotEvaluated:
		return "name constraints not evaluated (" + is.ExtensionOID + ")"
	case chainpath.IssuePolicyConstraintsNotEvaluated:
		return "policy constraints not evaluated (" + is.ExtensionOID + ")"
	case chainpath.IssueCriticalExtensionNotProcessed:
		return "critical extension " + is.ExtensionOID + " not processed"
	}
	return string(is.Kind)
}

// writeTrust renders validation against explicitly supplied roots. It always
// names where trust came from, and never prints a bare "trusted".
func writeTrust(b *strings.Builder, res inspectsvc.Result) {
	t := res.Trust
	b.WriteString("Trust evaluation\n")
	if t.State != inspectsvc.TrustEvaluated {
		b.WriteString("  Not evaluated: no trust anchors were supplied (use --roots <file>).\n")
		b.WriteString("  Certificates in the inspected input are never used as trust anchors.\n")
		return
	}
	names := map[int]string{}
	for _, a := range res.Artifacts {
		if a.Certificate != nil {
			names[a.Entry] = subjectName(a.Certificate)
		}
	}
	inInput := inputEntries(res)

	files := make([]string, len(t.Roots.Files))
	for i, f := range t.Roots.Files {
		files[i] = fmt.Sprintf("%s (%s)", f.Locator, plural(f.Certificates, "certificate", "certificates"))
	}
	topField(b, "Source", "explicitly supplied roots: "+strings.Join(files, ", "))
	topField(b, "Verifier", "Go crypto/x509 ("+t.EngineVersion+"), any extended key usage, no host name")
	anchorNames := map[fingerprint.Cert]string{}
	for _, a := range t.Roots.Anchors {
		fp := a.Certificate.Fingerprint
		anchorNames[fp] = subjectName(a.Certificate)
		where := make([]string, len(a.Sources))
		for i, s := range a.Sources {
			where[i] = fmt.Sprintf("entry %d of %s", s.Entry, s.File)
		}
		text := fmt.Sprintf("%s (%s), %s", anchorNames[fp], fp, strings.Join(where, ", "))
		if e := inInput[fp]; len(e) > 0 {
			text += "; also " + entries(e) + " of this input"
		}
		topField(b, "Anchor", text)
	}

	for _, target := range t.Targets {
		first := target.Entries[0]
		fmt.Fprintf(b, "  Entry %d (%s)\n", first, names[first])
		r := target.Result
		switch r.State {
		case trustverify.Verified:
			field(b, "Result", "verified against the explicitly supplied roots")
			for i, c := range r.Chains {
				field(b, fmt.Sprintf("Chain %d", i+1), trustChainText(c, first, names, inInput, anchorNames))
			}
		case trustverify.Failed:
			field(b, "Result", "could not validate to the explicitly supplied roots")
			field(b, "Reason", trustReasonText(r.Reason))
		default:
			field(b, "Result", "inconclusive: the verifier reached no conclusion Trustsmith can classify")
			field(b, "Reason", trustReasonText(r.Reason))
		}
	}
}

func trustChainText(c trustverify.Chain, target int, names map[int]string, inInput map[fingerprint.Cert][]int, anchorNames map[fingerprint.Cert]string) string {
	if len(c.Certificates) == 1 {
		return fmt.Sprintf("entry %d (%s), itself a supplied anchor", target, names[target])
	}
	steps := make([]string, len(c.Certificates))
	for i, fp := range c.Certificates {
		switch e := inInput[fp]; {
		case i == len(c.Certificates)-1:
			steps[i] = "anchor " + anchorNames[fp]
		case len(e) > 0:
			steps[i] = fmt.Sprintf("entry %d (%s)", e[0], names[e[0]])
		default:
			steps[i] = fp.String()
		}
	}
	return strings.Join(steps, " > ")
}

func trustReasonText(r trustverify.Reason) string {
	switch r {
	case trustverify.ReasonNoAnchorPath:
		return "no chain to any of the supplied roots could be built"
	case trustverify.ReasonExpired:
		return "certificate expired"
	case trustverify.ReasonNotYetValid:
		return "certificate not yet valid"
	case trustverify.ReasonIssuerNotAuthorized:
		return "an issuer is not allowed to sign certificates"
	case trustverify.ReasonNameConstraints:
		return "a name is not permitted by a CA certificate's name constraints"
	case trustverify.ReasonPathLength:
		return "path length constraint exceeded"
	case trustverify.ReasonUnhandledCriticalExtension:
		return "unhandled critical extension"
	case trustverify.ReasonIncompatibleUsage:
		return "incompatible key usage"
	case trustverify.ReasonInsecureSignatureAlgorithm:
		return "signature algorithm rejected by the Go verifier"
	case trustverify.ReasonPolicy:
		return "certificate policy validation failed"
	case trustverify.ReasonEngineLimit:
		return "a verifier work limit was reached"
	case trustverify.ReasonEngineError:
		return "the verifier returned an error Trustsmith does not classify"
	}
	return string(r)
}

// chainText is the per-certificate Chain line.
func chainText(c interpret.ChainState, trustEvaluated bool) string {
	switch c {
	case interpret.ChainVerifiedToSuppliedRoots:
		return "verified to the explicitly supplied roots (see Trust evaluation)"
	case interpret.ChainFailedAgainstSuppliedRoots:
		return "could not validate to the explicitly supplied roots (see Trust evaluation)"
	case interpret.ChainUnverifiableAgainstSuppliedRoots:
		return "validation against the explicitly supplied roots was inconclusive (see Trust evaluation)"
	}
	if trustEvaluated {
		return "not validated on its own: it issues another certificate in this input"
	}
	return "not validated against trust anchors (none supplied; see --roots)"
}

func writeArtifact(b *strings.Builder, a inspectsvc.Artifact, advanced, trustEvaluated bool) {
	switch a.Type {
	case inspectsvc.TypeCertificate:
		writeCertificate(b, a, advanced, trustEvaluated)
	case inspectsvc.TypeUnparseableCertificate:
		fmt.Fprintf(b, "[%d] Certificate that could not be parsed\n", a.Entry)
		field(b, "Parse error", a.Unparseable.ParseError)
		field(b, "Certificate", a.Unparseable.Fingerprint.String())
		field(b, "Key identity", keyIdentityText(a.Unparseable.Identity))
		if advanced && a.Unparseable.KeyIdentity != x509facts.KeyIdentityUnavailable {
			field(b, "Encoded SPKI", a.Unparseable.EncodedSPKI.String()+" (x509-spki-encoded-sha256)")
		}
	case inspectsvc.TypeCertificateRequest:
		fmt.Fprintf(b, "[%d] Certificate signing request (not inspected by this version)\n", a.Entry)
	case inspectsvc.TypeUnsupported:
		if a.Label != "" {
			fmt.Fprintf(b, "[%d] PEM block %q (not inspected; contents not decoded)\n", a.Entry, a.Label)
		} else {
			fmt.Fprintf(b, "[%d] DER structure that is not a certificate (not inspected)\n", a.Entry)
		}
	case inspectsvc.TypeMalformed:
		if a.Label != "" {
			fmt.Fprintf(b, "[%d] Malformed PEM block %q: %s\n", a.Entry, a.Label, problemText(a.Problem))
		} else {
			fmt.Fprintf(b, "[%d] Malformed DER: %s\n", a.Entry, problemText(a.Problem))
		}
	}
}

func problemText(p artifact.Problem) string {
	switch p {
	case artifact.ProblemBadArmour:
		return "invalid BEGIN line"
	case artifact.ProblemMissingEnd:
		return "no matching END line"
	case artifact.ProblemBadEncoding:
		return "contents could not be decoded"
	}
	return string(p)
}

func writeCertificate(b *strings.Builder, a inspectsvc.Artifact, advanced, trustEvaluated bool) {
	c, s := a.Certificate, a.Summary
	fmt.Fprintf(b, "[%d] %s\n", a.Entry, s.Kind)

	identifies := "(no names)"
	if len(s.Identifies) > 0 {
		identifies = strings.Join(s.Identifies, ", ")
	}
	field(b, "Identifies", identifies)
	field(b, "Issuer", s.Issuer)
	field(b, "", issuerInInputText(s))
	switch s.SelfSigned {
	case interpret.SelfSignedVerified:
		field(b, "Self-signed", "yes (signature verified)")
	case interpret.SelfSignedUnverifiable:
		field(b, "Self-signed", "self-issued; its signature could not be verified")
	case interpret.SelfSignedDoesNotVerify:
		field(b, "Self-signed", "self-issued, but its signature does not verify")
	}
	field(b, "Valid", validityText(s.Validity))
	field(b, "Key", s.Key)
	field(b, "Signature", s.Signature)
	field(b, "Chain", chainText(s.Chain, trustEvaluated))
	field(b, "Certificate", c.Fingerprint.String())
	field(b, "Key identity", keyIdentityText(c.Identity))

	if !advanced {
		return
	}
	b.WriteString("    Technical details\n")
	tech := func(label, value string) {
		if value != "" {
			fmt.Fprintf(b, "      %-19s%s\n", label, value)
		}
	}
	list := func(label string, values []string) { tech(label, strings.Join(values, ", ")) }

	tech("Version", strconv.Itoa(c.Version))
	tech("Serial", c.SerialHex)
	tech("Subject", c.Subject.DN)
	tech("Issuer", c.Issuer.DN)
	tech("Not before", stamp(c.NotBefore))
	tech("Not after", stamp(c.NotAfter))
	key := c.PublicKey.Algorithm
	if c.PublicKey.Detail != "" {
		key += " " + c.PublicKey.Detail
	}
	if c.PublicKey.Bits > 0 {
		key += ", " + strconv.Itoa(c.PublicKey.Bits) + " bits"
	}
	tech("Public key", key)
	tech("Signature alg.", strings.TrimSpace(c.SignatureAlgorithm.String()+" ("+c.SignatureAlgorithmOID+")"))
	list("Key usage", c.KeyUsage)
	list("Ext. key usage", c.ExtKeyUsage)
	tech("Basic constraints", basicConstraintsText(c.BasicConstraints))
	tech("Subject key ID", hex.EncodeToString(c.SubjectKeyID))
	tech("Authority key ID", hex.EncodeToString(c.AuthorityKeyID))
	list("DNS names", c.DNSNames)
	list("IP addresses", c.IPAddresses)
	list("Email addresses", c.EmailAddresses)
	list("URIs", c.URIs)
	for i, e := range c.Extensions {
		label := ""
		if i == 0 {
			label = "Extensions"
		}
		value := e.OID
		if e.Name != "" {
			value += " " + e.Name
		}
		if e.Critical {
			value += " (critical)"
		}
		fmt.Fprintf(b, "      %-19s%s\n", label, value)
	}
	list("CRL distribution", c.CRLDistributionPoints)
	list("OCSP servers", c.OCSPServers)
	list("Issuer URLs", c.IssuingCertificateURLs)
	list("Policies", c.PolicyOIDs)
	tech("Self-issued", yesNo(c.SelfIssued))
	tech("Encoded SPKI", c.EncodedSPKI.String()+" (x509-spki-encoded-sha256)")
	tech("pin-sha256", c.EncodedSPKI.PinSHA256())
	tech("OpenSSL format", c.Fingerprint.Colon())
}

func validityText(v interpret.Validity) string {
	switch v.State {
	case interpret.Expired:
		return "no, expired on " + v.NotAfter.UTC().Format(humanTime)
	case interpret.NotYetValid:
		return "no, not valid until " + v.NotBefore.UTC().Format(humanTime)
	}
	left := plural(v.DaysRemaining, "day", "days") + " left"
	if v.DaysRemaining < 1 {
		left = "less than a day left"
	}
	return "yes, until " + v.NotAfter.UTC().Format(humanTime) + " (" + left + ")"
}

func keyIdentityText(id x509facts.Identity) string {
	switch id.KeyIdentity {
	case x509facts.KeyIdentityCanonical:
		return id.KeyID.String() + " (x509-spki-sha256)"
	case x509facts.KeyIdentityNoncanonical:
		return id.KeyID.String() + " (x509-spki-sha256; the key is encoded non-canonically as " + id.EncodedSPKI.String() + ")"
	case x509facts.KeyIdentityUnsupported:
		return "none: this key type has no x509-spki-sha256 identity"
	case x509facts.KeyIdentityMalformed:
		return "none: the public key is malformed"
	}
	return "none: no public key could be located"
}

func basicConstraintsText(bc x509facts.BasicConstraints) string {
	switch {
	case !bc.Present:
		return "not present"
	case !bc.IsCA:
		return "CA: no"
	case bc.MaxPathLen != nil:
		return "CA: yes, max path length " + strconv.Itoa(*bc.MaxPathLen)
	}
	return "CA: yes, no path length limit"
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func writeFindings(b *strings.Builder, fs []findings.Finding) {
	if len(fs) == 0 {
		b.WriteString("No findings.\n")
		return
	}
	fmt.Fprintf(b, "Findings (%d)\n", len(fs))
	for _, f := range fs {
		where := "input"
		if f.Entry != findings.WholeInput {
			where = "entry " + strconv.Itoa(f.Entry)
		}
		d, _ := findings.Describe(f.Code)
		fmt.Fprintf(b, "  %-9s %s  %s [%s]\n", strings.ToUpper(string(f.Severity)), where, d.Title, f.Code)
		fmt.Fprintf(b, "            %s\n", d.Explanation)
		if len(f.Evidence) > 0 {
			parts := make([]string, 0, len(f.Evidence))
			for _, e := range f.Evidence {
				parts = append(parts, e.Key+"="+e.Value)
			}
			fmt.Fprintf(b, "            Evidence: %s\n", strings.Join(parts, "; "))
		}
		for _, a := range d.Remediation {
			fmt.Fprintf(b, "            Fix: %s\n", a.Text)
		}
	}
}
