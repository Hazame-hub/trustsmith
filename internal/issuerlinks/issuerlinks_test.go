package issuerlinks_test

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/issuerlinks"
	"github.com/Hazame-hub/trustsmith/internal/sigcheck"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

var (
	notBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
)

func caTemplate(cn string, serial int64) testpki.Template {
	return testpki.Template{
		CommonName: cn, Organization: "Tests", Serial: serial, NotBefore: notBefore, NotAfter: notAfter,
		IsCA: true, MaxPathLen: -1, KeyUsage: x509.KeyUsageCertSign,
	}
}

func issueCA(t *testing.T, cn string, key crypto.Signer, parent *testpki.Cert) *testpki.Cert {
	t.Helper()
	return testpki.Issue(t, caTemplate(cn, 1), key, parent)
}

func issueLeaf(t *testing.T, parent *testpki.Cert) *testpki.Cert {
	t.Helper()
	return testpki.Issue(t, testpki.Template{
		CommonName: "leaf.example.test", Serial: 10, NotBefore: notBefore, NotAfter: notAfter,
		DNSNames: []string{"leaf.example.test"},
	}, testpki.ECDSAKey(t), parent)
}

type chain struct{ root, inter, leaf *testpki.Cert }

func newChain(t *testing.T) chain {
	t.Helper()
	root := issueCA(t, "Root", testpki.ECDSAKey(t), nil)
	inter := issueCA(t, "Intermediate", testpki.ECDSAKey(t), root)
	return chain{root: root, inter: inter, leaf: issueLeaf(t, inter)}
}

func inputs(t *testing.T, ders ...[]byte) []issuerlinks.Input {
	t.Helper()
	var in []issuerlinks.Input
	for i, der := range ders {
		p := x509facts.FromDER(der)
		if p.Kind != x509facts.KindCertificate {
			t.Fatalf("input %d does not parse: %s", i, p.Kind)
		}
		in = append(in, issuerlinks.Input{Entry: i, Certificate: p.Certificate})
	}
	return in
}

func resolve(t *testing.T, ders ...[]byte) issuerlinks.Resolution {
	t.Helper()
	return issuerlinks.Resolve(inputs(t, ders...), issuerlinks.DefaultLimits())
}

// describe renders relationships by entry as "child->candidate:state:evidence".
func describe(res issuerlinks.Resolution) []string {
	out := []string{}
	for _, r := range res.Relationships {
		ev := make([]string, len(r.Evidence))
		for i, e := range r.Evidence {
			ev[i] = string(e)
		}
		out = append(out, fmt.Sprintf("%v->%v:%s:%s", r.ChildEntries, r.CandidateEntries, r.State, strings.Join(ev, "+")))
	}
	return out
}

// byFingerprint renders relationships independent of input order.
func byFingerprint(res issuerlinks.Resolution) []string {
	out := []string{}
	for _, r := range res.Relationships {
		out = append(out, fmt.Sprintf("%s->%s:%s:%v", r.Child.Hex()[:12], r.Candidate.Hex()[:12], r.State, r.Evidence))
	}
	slices.Sort(out)
	return out
}

func assertRelationships(t *testing.T, res issuerlinks.Resolution, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if got := describe(res); !slices.Equal(got, want) {
		t.Errorf("relationships\n got %v\nwant %v", got, want)
	}
}

const bothEvidence = "issuer_dn_match+authority_key_id_match"

func TestLeafAndIntermediate(t *testing.T) {
	c := newChain(t)
	assertRelationships(t, resolve(t, c.leaf.DER, c.inter.DER), "[0]->[1]:verified:"+bothEvidence)
}

func TestIntermediateAndRoot(t *testing.T) {
	c := newChain(t)
	assertRelationships(t, resolve(t, c.inter.DER, c.root.DER), "[0]->[1]:verified:"+bothEvidence)
}

func TestFullBundle(t *testing.T) {
	c := newChain(t)
	assertRelationships(t, resolve(t, c.leaf.DER, c.inter.DER, c.root.DER),
		"[0]->[1]:verified:"+bothEvidence,
		"[1]->[2]:verified:"+bothEvidence,
	)
}

func TestInputOrderDoesNotChangeRelationships(t *testing.T) {
	c := newChain(t)
	forward := resolve(t, c.leaf.DER, c.inter.DER, c.root.DER)
	reversed := resolve(t, c.root.DER, c.inter.DER, c.leaf.DER)
	if !slices.Equal(byFingerprint(forward), byFingerprint(reversed)) {
		t.Errorf("forward %v\nreversed %v", byFingerprint(forward), byFingerprint(reversed))
	}
	assertRelationships(t, reversed,
		"[1]->[0]:verified:"+bothEvidence,
		"[2]->[1]:verified:"+bothEvidence,
	)
}

func TestDuplicateCertificatesAreDeduplicated(t *testing.T) {
	c := newChain(t)
	assertRelationships(t, resolve(t, c.leaf.DER, c.inter.DER, c.leaf.DER, c.inter.DER),
		"[0 2]->[1 3]:verified:"+bothEvidence)
}

func TestIssuerNameMatchWithWrongKeyIsNotVerified(t *testing.T) {
	c := newChain(t)
	impostor := issueCA(t, "Intermediate", testpki.ECDSAKey(t), c.root) // same name, different key and SKI
	res := resolve(t, c.leaf.DER, impostor.DER)
	assertRelationships(t, res, "[0]->[1]:invalid:issuer_dn_match")
	if res.Relationships[0].Reason != sigcheck.ReasonSignatureMismatch {
		t.Errorf("reason %s", res.Relationships[0].Reason)
	}
}

// TestAuthorityKeyIDMatchIsNotVerification makes it impossible to replace the
// signature check with key-identifier matching: every heuristic matches, and
// the relationship must still be invalid.
func TestAuthorityKeyIDMatchIsNotVerification(t *testing.T) {
	c := newChain(t)
	sameSKI := caTemplate("Intermediate", 1)
	sameSKI.SubjectKeyID = c.inter.Cert.SubjectKeyId
	impostor := testpki.Issue(t, sameSKI, testpki.ECDSAKey(t), c.root)
	assertRelationships(t, resolve(t, c.leaf.DER, impostor.DER), "[0]->[1]:invalid:"+bothEvidence)

	differentName := caTemplate("Unrelated Name", 1)
	differentName.SubjectKeyID = c.inter.Cert.SubjectKeyId
	onlyKeyID := testpki.Issue(t, differentName, testpki.ECDSAKey(t), c.root)
	assertRelationships(t, resolve(t, c.leaf.DER, onlyKeyID.DER), "[0]->[1]:invalid:authority_key_id_match")
}

// TestSignatureNotEvidenceDecidesTheState: the right key with a mismatching
// key identifier still verifies.
func TestSignatureNotEvidenceDecidesTheState(t *testing.T) {
	c := newChain(t)
	rekeyedID := caTemplate("Intermediate", 2)
	rekeyedID.SubjectKeyID = []byte{1, 2, 3, 4}
	sameKey := testpki.Issue(t, rekeyedID, c.inter.Key, c.root)
	assertRelationships(t, resolve(t, c.leaf.DER, sameKey.DER), "[0]->[1]:verified:issuer_dn_match")
}

func TestUnverifiableSignatureIsNotInvalid(t *testing.T) {
	rsaCA := issueCA(t, "RSA CA", testpki.RSAKey(t, 2048), nil)
	md5Leaf := testpki.Resign(t, issueLeaf(t, rsaCA).DER, nil, testpki.RSAWithMD5, rsaCA.Key)
	res := resolve(t, md5Leaf, rsaCA.DER)
	assertRelationships(t, res, "[0]->[1]:unverifiable:"+bothEvidence)
	if res.Relationships[0].Reason != sigcheck.ReasonInsecureAlgorithm {
		t.Errorf("reason %s", res.Relationships[0].Reason)
	}
}

func TestSHA1SignatureVerifies(t *testing.T) {
	rsaCA := issueCA(t, "RSA CA", testpki.RSAKey(t, 2048), nil)
	sha1Leaf := testpki.Resign(t, issueLeaf(t, rsaCA).DER, nil, testpki.RSAWithSHA1, rsaCA.Key)
	assertRelationships(t, resolve(t, sha1Leaf, rsaCA.DER), "[0]->[1]:verified:"+bothEvidence)
}

func TestNoIssuerPresentMeansNoRelationship(t *testing.T) {
	c := newChain(t)
	assertRelationships(t, resolve(t, c.leaf.DER))
	unrelated := issueCA(t, "Somebody Else", testpki.ECDSAKey(t), nil)
	assertRelationships(t, resolve(t, c.leaf.DER, unrelated.DER))
}

func TestSelfSignedCertificateHasNoSelfRelationship(t *testing.T) {
	c := newChain(t)
	assertRelationships(t, resolve(t, c.root.DER))
	if f := x509facts.FromDER(c.root.DER).Certificate; !f.SelfIssued || f.SelfSignature != x509facts.SignatureVerified {
		t.Errorf("root: self-issued %v, self-signature %s", f.SelfIssued, f.SelfSignature)
	}
}

func TestSelfIssuedButNotSelfSigned(t *testing.T) {
	key := testpki.ECDSAKey(t)
	base := issueCA(t, "Same Name", key, nil)
	notSelfSigned := testpki.Resign(t, base.DER, nil, testpki.ECDSAWithSHA256, testpki.ECDSAKey(t))
	f := x509facts.FromDER(notSelfSigned).Certificate
	if !f.SelfIssued || f.SelfSignature != x509facts.SignatureFailed {
		t.Errorf("self-issued %v, self-signature %s; want self-issued but not self-signed", f.SelfIssued, f.SelfSignature)
	}
	assertRelationships(t, resolve(t, notSelfSigned))
}

// TestAllVerifyingIssuersAreKept: two distinct certificates for the same
// issuer key (for example a reissued intermediate) both verify; neither is
// chosen over the other.
func TestAllVerifyingIssuersAreKept(t *testing.T) {
	c := newChain(t)
	reissued := testpki.Issue(t, caTemplate("Intermediate", 2), c.inter.Key, c.root)
	assertRelationships(t, resolve(t, c.leaf.DER, c.inter.DER, reissued.DER),
		"[0]->[1]:verified:"+bothEvidence,
		"[0]->[2]:verified:"+bothEvidence,
	)
}

func TestCandidateLimits(t *testing.T) {
	c := newChain(t)
	impostors := [][]byte{c.leaf.DER}
	for i := range 3 {
		impostors = append(impostors, testpki.Issue(t, caTemplate("Intermediate", int64(100+i)), testpki.ECDSAKey(t), c.root).DER)
	}
	res := issuerlinks.Resolve(inputs(t, impostors...), issuerlinks.Limits{MaxCandidatesPerCertificate: 2, MaxVerifications: 1})
	assertRelationships(t, res, "[0]->[1]:invalid:issuer_dn_match", "[0]->[2]:not_checked:issuer_dn_match")
	leafFP := fingerprint.CertFromDER(c.leaf.DER)
	if !res.CandidatesOmitted[leafFP] {
		t.Error("the omitted third candidate must be reported")
	}
	if res.Verifications != 1 {
		t.Errorf("verifications %d, want 1", res.Verifications)
	}
}

// TestCandidateIndexKeepsWorkLinear: unrelated certificates trigger no
// signature checks, and a set of independent chains costs one check per
// certificate rather than one per pair.
func TestCandidateIndexKeepsWorkLinear(t *testing.T) {
	var roots [][]byte
	for i := range 150 {
		roots = append(roots, issueCA(t, fmt.Sprintf("Root %d", i), testpki.ECDSAKey(t), nil).DER)
	}
	if res := resolve(t, roots...); res.Verifications != 0 || len(res.Relationships) != 0 {
		t.Errorf("unrelated roots: %d verifications, %d relationships", res.Verifications, len(res.Relationships))
	}

	var pairs [][]byte
	for i := range 75 {
		ca := issueCA(t, fmt.Sprintf("CA %d", i), testpki.ECDSAKey(t), nil)
		pairs = append(pairs, issueLeaf(t, ca).DER, ca.DER)
	}
	res := resolve(t, pairs...)
	if res.Verifications != 75 || len(res.Relationships) != 75 {
		t.Errorf("independent chains: %d verifications, %d relationships, want 75 each", res.Verifications, len(res.Relationships))
	}
}

func TestSameKeyIsVerifiedOncePerChild(t *testing.T) {
	c := newChain(t)
	ders := [][]byte{c.leaf.DER}
	for i := range 4 {
		ders = append(ders, testpki.Issue(t, caTemplate("Intermediate", int64(200+i)), c.inter.Key, c.root).DER)
	}
	res := resolve(t, ders...)
	if len(res.Relationships) != 4 || res.Verifications != 1 {
		t.Errorf("%d relationships, %d verifications; want 4 verified relationships from 1 check", len(res.Relationships), res.Verifications)
	}
}

var _ = rand.Reader
