package cli

import (
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/artifact"
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/interpret"
	"github.com/Hazame-hub/trustsmith/internal/issuerlinks"
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

	for _, a := range res.Artifacts {
		b.WriteString("\n")
		writeArtifact(&b, a, advanced)
	}
	if len(res.Relationships) > 0 {
		b.WriteString("\n")
		writeRelationships(&b, res.Relationships)
	}
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

func writeArtifact(b *strings.Builder, a inspectsvc.Artifact, advanced bool) {
	switch a.Type {
	case inspectsvc.TypeCertificate:
		writeCertificate(b, a, advanced)
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

func writeCertificate(b *strings.Builder, a inspectsvc.Artifact, advanced bool) {
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
	field(b, "Chain", "not checked (chain verification is not available in this version)")
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
