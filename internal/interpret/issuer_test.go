package interpret_test

import (
	"crypto/x509"
	"slices"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/artifact"
	"github.com/Hazame-hub/trustsmith/internal/interpret"
	"github.com/Hazame-hub/trustsmith/internal/issuerlinks"
	"github.com/Hazame-hub/trustsmith/internal/sigcheck"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

// interpretInput parses ders as one input, resolves issuer relationships and
// interprets every entry, as the inspect service does.
func interpretInput(t *testing.T, ders ...[]byte) []interpret.Entry {
	t.Helper()
	parsedList := make([]*x509facts.Parsed, len(ders))
	var inputs []issuerlinks.Input
	for i, der := range ders {
		p := x509facts.FromDER(der)
		parsedList[i] = &p
		if p.Certificate != nil {
			inputs = append(inputs, issuerlinks.Input{Entry: i, Certificate: p.Certificate})
		}
	}
	res := issuerlinks.Resolve(inputs, issuerlinks.DefaultLimits())

	var entries []interpret.Entry
	for i, der := range ders {
		var issuers interpret.Issuers
		if c := parsedList[i].Certificate; c != nil {
			issuers = interpret.Issuers{Relationships: res.For(c.Fingerprint), CandidatesOmitted: res.CandidatesOmitted[c.Fingerprint]}
		}
		e := interpret.Block(artifact.Block{Entry: i, Kind: artifact.KindCertificate, DER: der}, parsedList[i], issuers, notBefore.AddDate(0, 0, 1), th)
		assertCatalogued(t, e.Findings)
		entries = append(entries, e)
	}
	return entries
}

func assertIssuer(t *testing.T, e interpret.Entry, state interpret.IssuerInInput, verified, candidates []int) {
	t.Helper()
	if e.Summary == nil {
		t.Fatal("no summary")
	}
	s := e.Summary
	if s.IssuerInInput != state || !slices.Equal(s.VerifiedIssuerEntries, verified) || !slices.Equal(s.CandidateEntries, candidates) {
		t.Errorf("issuer in input %s verified %v candidates %v; want %s %v %v",
			s.IssuerInInput, s.VerifiedIssuerEntries, s.CandidateEntries, state, verified, candidates)
	}
}

func TestIssuerVerifiedInInput(t *testing.T) {
	root := testpki.Issue(t, caTemplate("Root"), testpki.ECDSAKey(t), nil)
	inter := testpki.Issue(t, caTemplate("Intermediate"), testpki.ECDSAKey(t), root)
	leaf := testpki.Issue(t, serverTemplate("api.example.test"), testpki.ECDSAKey(t), inter)

	e := interpretInput(t, leaf.DER, inter.DER, root.DER)
	assertIssuer(t, e[0], interpret.IssuerVerified, []int{1}, []int{})
	assertIssuer(t, e[1], interpret.IssuerVerified, []int{2}, []int{})
	assertIssuer(t, e[2], interpret.IssuerSelfSigned, []int{}, []int{})
	for i := range e {
		assertCodes(t, e[i].Findings) // relationships alone produce no findings
	}
}

func TestIssuerNoCandidateFoundIsNotAFinding(t *testing.T) {
	inter := testpki.Issue(t, caTemplate("Intermediate"), testpki.ECDSAKey(t), nil)
	leaf := testpki.Issue(t, serverTemplate("api.example.test"), testpki.ECDSAKey(t), inter)
	e := interpretInput(t, leaf.DER)
	assertIssuer(t, e[0], interpret.IssuerNoCandidateFound, []int{}, []int{})
	assertCodes(t, e[0].Findings)
}

func TestCandidateThatDoesNotVerifyIsNotAWarning(t *testing.T) {
	inter := testpki.Issue(t, caTemplate("Intermediate"), testpki.ECDSAKey(t), nil)
	leaf := testpki.Issue(t, serverTemplate("api.example.test"), testpki.ECDSAKey(t), inter)
	impostor := testpki.Issue(t, caTemplate("Intermediate"), testpki.ECDSAKey(t), nil)

	e := interpretInput(t, leaf.DER, impostor.DER)
	assertIssuer(t, e[0], interpret.IssuerCandidateSignatureMismatch, []int{}, []int{1})
	assertCodes(t, e[0].Findings)
}

func TestUnverifiableCandidateIsInformational(t *testing.T) {
	caKey := testpki.RSAKey(t, 2048)
	ca := testpki.Issue(t, caTemplate("RSA CA"), caKey, nil)
	md5Leaf := testpki.Resign(t, testpki.Issue(t, serverTemplate("md5.example.test"), testpki.ECDSAKey(t), ca).DER, nil, testpki.RSAWithMD5, caKey)

	e := interpretInput(t, md5Leaf, ca.DER)
	assertIssuer(t, e[0], interpret.IssuerCandidateUnverifiable, []int{}, []int{1})
	assertCodes(t, e[0].Findings, "issuer.candidate_unverifiable:info", "sig.md5:critical")
	for _, f := range e[0].Findings {
		if f.Code == "issuer.candidate_unverifiable" {
			if evidence(f, "candidate_entries") != "1" || evidence(f, "reason") != string(sigcheck.ReasonInsecureAlgorithm) {
				t.Errorf("evidence %+v", f.Evidence)
			}
		}
	}
}

// TestVerifiedSHA1SignatureKeepsTheAlgorithmFinding: cryptographically
// verified and algorithm recommended are different questions.
func TestVerifiedSHA1SignatureKeepsTheAlgorithmFinding(t *testing.T) {
	caKey := testpki.RSAKey(t, 2048)
	ca := testpki.Issue(t, caTemplate("RSA CA"), caKey, nil)
	sha1Leaf := testpki.Resign(t, testpki.Issue(t, serverTemplate("sha1.example.test"), testpki.ECDSAKey(t), ca).DER, nil, testpki.RSAWithSHA1, caKey)

	e := interpretInput(t, sha1Leaf, ca.DER)
	assertIssuer(t, e[0], interpret.IssuerVerified, []int{1}, []int{})
	assertCodes(t, e[0].Findings, "sig.sha1:critical")
}

func TestCandidatesNotCheckedAreReported(t *testing.T) {
	ca := testpki.Issue(t, caTemplate("CA"), testpki.ECDSAKey(t), nil)
	leaf := testpki.Issue(t, serverTemplate("api.example.test"), testpki.ECDSAKey(t), ca)
	p := x509facts.FromDER(leaf.DER)
	issuers := interpret.Issuers{
		Relationships:     []issuerlinks.Relationship{{CandidateEntries: []int{4}, State: issuerlinks.NotChecked}},
		CandidatesOmitted: true,
	}
	e := interpret.Block(certBlock(leaf.DER), &p, issuers, notBefore.AddDate(0, 0, 1), th)
	assertCatalogued(t, e.Findings)
	if e.Summary.IssuerInInput != interpret.IssuerCandidateNotChecked {
		t.Errorf("issuer in input %s", e.Summary.IssuerInInput)
	}
	if !slices.Contains(codes(e.Findings), "issuer.candidates_not_checked:info") {
		t.Errorf("findings %v", codes(e.Findings))
	}
}

// TestSelfIssuedButNotSelfSignedIsNotASelfSignedLeaf: equal names are not
// enough; the certificate's own key must verify its signature.
func TestSelfIssuedButNotSelfSignedIsNotASelfSignedLeaf(t *testing.T) {
	base := testpki.Issue(t, serverTemplate("self.example.test"), testpki.ECDSAKey(t), nil)
	der := testpki.Resign(t, base.DER, nil, testpki.ECDSAWithSHA256, testpki.ECDSAKey(t))

	e := interpretInput(t, der)
	if e[0].Summary.SelfSigned != interpret.SelfSignedDoesNotVerify {
		t.Errorf("self-signed %s", e[0].Summary.SelfSigned)
	}
	assertIssuer(t, e[0], interpret.IssuerNoCandidateFound, []int{}, []int{})
	assertCodes(t, e[0].Findings)

	selfSigned := interpretInput(t, base.DER)
	assertIssuer(t, selfSigned[0], interpret.IssuerSelfSigned, []int{}, []int{})
	assertCodes(t, selfSigned[0].Findings, "cert.self_signed_leaf:warning")
}

var _ = x509.KeyUsageCertSign
