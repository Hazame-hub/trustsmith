package trustverify_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"reflect"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/purpose"
	"github.com/Hazame-hub/trustsmith/internal/sigcheck"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
	"github.com/Hazame-hub/trustsmith/internal/trustverify"
)

var (
	now       = testpki.Now // 2026-09-14T12:00:00Z
	caFrom    = date(2026, 1, 1)
	caUntil   = date(2031, 1, 1)
	leafFrom  = date(2026, 9, 1)
	leafUntil = date(2027, 9, 1)
)

func date(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

func caTemplate(cn string, serial int64, maxPathLen int) testpki.Template {
	return testpki.Template{
		CommonName: cn, Organization: "Trustsmith Trust Tests", Serial: serial, NotBefore: caFrom, NotAfter: caUntil,
		IsCA: true, MaxPathLen: maxPathLen, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

func leafTemplate(cn string, serial int64) testpki.Template {
	return testpki.Template{
		CommonName: cn, Serial: serial, NotBefore: leafFrom, NotAfter: leafUntil,
		DNSNames: []string{cn}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

type pki struct{ root, inter, leaf *testpki.Cert }

func newPKI(t *testing.T) pki {
	t.Helper()
	root := testpki.Issue(t, caTemplate("Root", 1, -1), testpki.ECDSAKey(t), nil)
	inter := testpki.Issue(t, caTemplate("Intermediate", 2, -1), testpki.ECDSAKey(t), root)
	return pki{root: root, inter: inter, leaf: testpki.Issue(t, leafTemplate("api.example.test", 3), testpki.ECDSAKey(t), inter)}
}

func certs(cs []*testpki.Cert) []*x509.Certificate {
	out := make([]*x509.Certificate, len(cs))
	for i, c := range cs {
		out[i] = c.Cert
	}
	return out
}

func anchors(cs ...*testpki.Cert) []*testpki.Cert { return cs }

func verifyAt(at time.Time, target *testpki.Cert, anchors []*testpki.Cert, intermediates ...*testpki.Cert) trustverify.Result {
	return trustverify.Verify(target.Cert, certs(anchors), certs(intermediates), at, purpose.Any)
}

func verifyFor(p purpose.Purpose, target *testpki.Cert, anchors []*testpki.Cert, intermediates ...*testpki.Cert) trustverify.Result {
	return trustverify.Verify(target.Cert, certs(anchors), certs(intermediates), now, p)
}

func verify(target *testpki.Cert, anchors []*testpki.Cert, intermediates ...*testpki.Cert) trustverify.Result {
	return verifyAt(now, target, anchors, intermediates...)
}

func chainOf(cs ...*testpki.Cert) trustverify.Chain {
	c := trustverify.Chain{}
	for _, cert := range cs {
		c.Certificates = append(c.Certificates, fingerprint.CertFromDER(cert.DER))
	}
	return c
}

func assertResult(t *testing.T, r trustverify.Result, state trustverify.State, reason trustverify.Reason) {
	t.Helper()
	if r.State != state || r.Reason != reason {
		t.Fatalf("result %s/%s, want %s/%s", r.State, r.Reason, state, reason)
	}
	if r.Chains == nil {
		t.Error("chains must be an empty slice, never nil")
	}
	if (state == trustverify.Verified) != (len(r.Chains) > 0) {
		t.Errorf("%s result with %d chains", state, len(r.Chains))
	}
}

func assertChains(t *testing.T, r trustverify.Result, want ...trustverify.Chain) {
	t.Helper()
	if !reflect.DeepEqual(r.Chains, want) {
		t.Errorf("chains %v, want %v", r.Chains, want)
	}
}

// 1. The inspected leaf and intermediate validate to a root supplied separately.
func TestVerifiedToSuppliedRoot(t *testing.T) {
	p := newPKI(t)
	r := verify(p.leaf, anchors(p.root), p.inter)
	assertResult(t, r, trustverify.Verified, trustverify.ReasonNone)
	assertChains(t, r, chainOf(p.leaf, p.inter, p.root))
	if r.Chains[0].Anchor() != fingerprint.CertFromDER(p.root.DER) {
		t.Error("the chain must end at the supplied anchor")
	}
}

// 3. A self-signed root that is only among the inspected certificates is a
// candidate intermediate at most, never an anchor.
func TestSelfSignedInputCertificateIsNeverAnAnchor(t *testing.T) {
	p := newPKI(t)
	other := testpki.Issue(t, caTemplate("Other Root", 9, -1), testpki.ECDSAKey(t), nil)
	assertResult(t, verify(p.leaf, anchors(other), p.inter, p.root), trustverify.Failed, trustverify.ReasonNoAnchorPath)
}

// 4. A wrong root, including one impersonating the real root's name.
func TestWrongRootHasNoAnchorPath(t *testing.T) {
	p := newPKI(t)
	other := testpki.Issue(t, caTemplate("Other Root", 9, -1), testpki.ECDSAKey(t), nil)
	assertResult(t, verify(p.leaf, anchors(other), p.inter), trustverify.Failed, trustverify.ReasonNoAnchorPath)

	impostor := testpki.Issue(t, caTemplate("Root", 10, -1), testpki.ECDSAKey(t), nil)
	assertResult(t, verify(p.leaf, anchors(impostor), p.inter), trustverify.Failed, trustverify.ReasonNoAnchorPath)
}

// 5. An anchor also offered as an intermediate plays one role: anchor.
func TestAnchorAlsoAmongIntermediates(t *testing.T) {
	p := newPKI(t)
	r := verify(p.leaf, anchors(p.root), p.inter, p.root)
	assertResult(t, r, trustverify.Verified, trustverify.ReasonNone)
	assertChains(t, r, chainOf(p.leaf, p.inter, p.root))
}

// 6. An anchor need not be self-signed: Go accepts the intermediate itself as
// the anchor.
func TestNonSelfSignedAnchor(t *testing.T) {
	p := newPKI(t)
	r := verify(p.leaf, anchors(p.inter))
	assertResult(t, r, trustverify.Verified, trustverify.ReasonNone)
	assertChains(t, r, chainOf(p.leaf, p.inter))
}

// An anchor's own validity period is applied by Go's verifier.
func TestExpiredAnchorIsRejectedByGo(t *testing.T) {
	root := testpki.Issue(t, caTemplate("Root", 1, -1), testpki.ECDSAKey(t), nil)
	tpl := caTemplate("Expired Intermediate", 2, -1)
	tpl.NotBefore, tpl.NotAfter = date(2025, 1, 1), date(2026, 6, 1)
	inter := testpki.Issue(t, tpl, testpki.ECDSAKey(t), root)
	leaf := testpki.Issue(t, leafTemplate("api.example.test", 3), testpki.ECDSAKey(t), inter)
	assertResult(t, verify(leaf, anchors(inter)), trustverify.Failed, trustverify.ReasonExpired)
}

// A certificate that is itself a supplied anchor validates as a chain of one.
func TestTargetThatIsAnAnchor(t *testing.T) {
	p := newPKI(t)
	r := verify(p.root, anchors(p.root))
	assertResult(t, r, trustverify.Verified, trustverify.ReasonNone)
	assertChains(t, r, chainOf(p.root))
}

// 7. Several anchors, one of which succeeds.
func TestMultipleAnchorsOneSucceeds(t *testing.T) {
	p := newPKI(t)
	other := testpki.Issue(t, caTemplate("Other Root", 9, -1), testpki.ECDSAKey(t), nil)
	r := verify(p.leaf, anchors(other, p.root), p.inter)
	assertResult(t, r, trustverify.Verified, trustverify.ReasonNone)
	assertChains(t, r, chainOf(p.leaf, p.inter, p.root))
}

// 8. Every chain is kept, in the same order whatever the input order.
func TestMultipleChainsAreKeptDeterministically(t *testing.T) {
	keyA := testpki.ECDSAKey(t)
	rootA := testpki.Issue(t, caTemplate("Root A", 1, -1), keyA, nil)
	rootB := testpki.Issue(t, caTemplate("Root B", 2, -1), testpki.ECDSAKey(t), nil)
	crossA := testpki.Issue(t, caTemplate("Root A", 3, -1), keyA, rootB)
	inter := testpki.Issue(t, caTemplate("Intermediate", 4, -1), testpki.ECDSAKey(t), rootA)
	leaf := testpki.Issue(t, leafTemplate("api.example.test", 5), testpki.ECDSAKey(t), inter)

	r := verify(leaf, anchors(rootA, rootB), inter, crossA)
	assertResult(t, r, trustverify.Verified, trustverify.ReasonNone)
	assertChains(t, r, chainOf(leaf, inter, rootA), chainOf(leaf, inter, crossA, rootB))

	again := verify(leaf, anchors(rootB, rootA), crossA, inter)
	if !reflect.DeepEqual(r, again) {
		t.Errorf("order of anchors and intermediates changed the result:\n%v\n%v", r, again)
	}
}

// 9, 10, 11. Validity of the leaf, an intermediate, and not-yet-valid
// certificates.
func TestValidity(t *testing.T) {
	root := testpki.Issue(t, caTemplate("Root", 1, -1), testpki.ECDSAKey(t), nil)
	inter := testpki.Issue(t, caTemplate("Intermediate", 2, -1), testpki.ECDSAKey(t), root)

	expiredLeaf := leafTemplate("expired.example.test", 3)
	expiredLeaf.NotBefore, expiredLeaf.NotAfter = date(2025, 6, 1), date(2026, 6, 1)
	assertResult(t, verify(testpki.Issue(t, expiredLeaf, testpki.ECDSAKey(t), inter), anchors(root), inter),
		trustverify.Failed, trustverify.ReasonExpired)

	futureLeaf := leafTemplate("future.example.test", 4)
	futureLeaf.NotBefore = date(2026, 10, 1)
	assertResult(t, verify(testpki.Issue(t, futureLeaf, testpki.ECDSAKey(t), inter), anchors(root), inter),
		trustverify.Failed, trustverify.ReasonNotYetValid)

	expiredInterTpl := caTemplate("Expired Intermediate", 5, -1)
	expiredInterTpl.NotBefore, expiredInterTpl.NotAfter = date(2025, 1, 1), date(2026, 6, 1)
	expiredInter := testpki.Issue(t, expiredInterTpl, testpki.ECDSAKey(t), root)
	assertResult(t, verify(testpki.Issue(t, leafTemplate("a.example.test", 6), testpki.ECDSAKey(t), expiredInter), anchors(root), expiredInter),
		trustverify.Failed, trustverify.ReasonExpired)

	futureInterTpl := caTemplate("Future Intermediate", 7, -1)
	futureInterTpl.NotBefore = date(2026, 10, 1)
	futureInter := testpki.Issue(t, futureInterTpl, testpki.ECDSAKey(t), root)
	assertResult(t, verify(testpki.Issue(t, leafTemplate("b.example.test", 8), testpki.ECDSAKey(t), futureInter), anchors(root), futureInter),
		trustverify.Failed, trustverify.ReasonNotYetValid)
}

// 24. The injected time is used exactly; validity is inclusive at both ends.
func TestExactInjectedTime(t *testing.T) {
	p := newPKI(t)
	assertResult(t, verifyAt(leafUntil, p.leaf, anchors(p.root), p.inter), trustverify.Verified, trustverify.ReasonNone)
	assertResult(t, verifyAt(leafUntil.Add(time.Second), p.leaf, anchors(p.root), p.inter), trustverify.Failed, trustverify.ReasonExpired)
	assertResult(t, verifyAt(leafFrom, p.leaf, anchors(p.root), p.inter), trustverify.Verified, trustverify.ReasonNone)
	assertResult(t, verifyAt(leafFrom.Add(-time.Second), p.leaf, anchors(p.root), p.inter), trustverify.Failed, trustverify.ReasonNotYetValid)
}

// 12. Issuers that are not allowed to sign certificates.
func TestIssuerNotAuthorized(t *testing.T) {
	root := testpki.Issue(t, caTemplate("Root", 1, -1), testpki.ECDSAKey(t), nil)
	for name, mutate := range map[string]func(*testpki.Template){
		"CA false":                   func(tpl *testpki.Template) { tpl.IsCA, tpl.BasicConstraintsNotCA = false, true },
		"no basic constraints":       func(tpl *testpki.Template) { tpl.IsCA = false },
		"key usage without certSign": func(tpl *testpki.Template) { tpl.KeyUsage = x509.KeyUsageDigitalSignature },
	} {
		t.Run(name, func(t *testing.T) {
			tpl := caTemplate("Issuer", 2, -1)
			mutate(&tpl)
			issuer := testpki.Issue(t, tpl, testpki.ECDSAKey(t), root)
			leaf := testpki.Issue(t, leafTemplate("api.example.test", 3), testpki.ECDSAKey(t), issuer)
			assertResult(t, verify(leaf, anchors(root), issuer), trustverify.Failed, trustverify.ReasonIssuerNotAuthorized)
		})
	}
}

// 13. A path length violation.
func TestPathLength(t *testing.T) {
	root := testpki.Issue(t, caTemplate("Root", 1, 0), testpki.ECDSAKey(t), nil)
	inter := testpki.Issue(t, caTemplate("Intermediate", 2, -1), testpki.ECDSAKey(t), root)
	leaf := testpki.Issue(t, leafTemplate("api.example.test", 3), testpki.ECDSAKey(t), inter)
	assertResult(t, verify(leaf, anchors(root), inter), trustverify.Failed, trustverify.ReasonPathLength)
}

// Go counts every intermediate against pathLenConstraint, including a
// self-issued one that RFC 5280 does not count (and that the structural
// evaluator of ADR-0005 does not count). The verifier's result is reported
// as Go's, not rewritten.
func TestGoCountsSelfIssuedIntermediatesForPathLength(t *testing.T) {
	root := testpki.Issue(t, caTemplate("Self-Issued CA", 1, 0), testpki.ECDSAKey(t), nil)
	selfIssued := testpki.Issue(t, caTemplate("Self-Issued CA", 2, -1), testpki.ECDSAKey(t), root)
	leaf := testpki.Issue(t, leafTemplate("api.example.test", 3), testpki.ECDSAKey(t), selfIssued)
	r := verify(leaf, anchors(root), selfIssued)
	if r.State == trustverify.Verified {
		t.Fatalf("pinned Go 1.27 behaviour changed: a self-issued intermediate under pathLenConstraint 0 now verifies; update ADR-0006")
	}
	t.Logf("go-x509 result: %s/%s", r.State, r.Reason)
}

// 14. An unhandled critical extension, on an intermediate and on the leaf.
func TestUnhandledCriticalExtension(t *testing.T) {
	critical := []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Critical: true, Value: []byte{0x05, 0x00}}}
	root := testpki.Issue(t, caTemplate("Root", 1, -1), testpki.ECDSAKey(t), nil)

	interTpl := caTemplate("Intermediate", 2, -1)
	interTpl.ExtraExtensions = critical
	inter := testpki.Issue(t, interTpl, testpki.ECDSAKey(t), root)
	leaf := testpki.Issue(t, leafTemplate("api.example.test", 3), testpki.ECDSAKey(t), inter)
	assertResult(t, verify(leaf, anchors(root), inter), trustverify.Failed, trustverify.ReasonUnhandledCriticalExtension)

	plainInter := testpki.Issue(t, caTemplate("Plain Intermediate", 4, -1), testpki.ECDSAKey(t), root)
	leafTpl := leafTemplate("critical.example.test", 5)
	leafTpl.ExtraExtensions = critical
	criticalLeaf := testpki.Issue(t, leafTpl, testpki.ECDSAKey(t), plainInter)
	assertResult(t, verify(criticalLeaf, anchors(root), plainInter), trustverify.Failed, trustverify.ReasonUnhandledCriticalExtension)
}

// 15, 16. Go applies name constraints to every name in the chain, even though
// no host name is requested.
func TestNameConstraints(t *testing.T) {
	rootTpl := caTemplate("Constrained Root", 1, -1)
	rootTpl.PermittedDNSDomains = []string{"example.test"}
	root := testpki.Issue(t, rootTpl, testpki.ECDSAKey(t), nil)
	inter := testpki.Issue(t, caTemplate("Intermediate", 2, -1), testpki.ECDSAKey(t), root)

	permitted := testpki.Issue(t, leafTemplate("api.example.test", 3), testpki.ECDSAKey(t), inter)
	assertResult(t, verify(permitted, anchors(root), inter), trustverify.Verified, trustverify.ReasonNone)

	rejected := testpki.Issue(t, leafTemplate("api.other.test", 4), testpki.ECDSAKey(t), inter)
	assertResult(t, verify(rejected, anchors(root), inter), trustverify.Failed, trustverify.ReasonNameConstraints)
}

// 17. Generic inspection requests any extended key usage: a client-only leaf
// under a server-only intermediate still verifies. With Go's default (server
// authentication) neither would.
func TestAnyExtendedKeyUsageIsRequested(t *testing.T) {
	root := testpki.Issue(t, caTemplate("Root", 1, -1), testpki.ECDSAKey(t), nil)
	interTpl := caTemplate("Server Intermediate", 2, -1)
	interTpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	inter := testpki.Issue(t, interTpl, testpki.ECDSAKey(t), root)
	clientTpl := leafTemplate("client", 3)
	clientTpl.DNSNames, clientTpl.ExtKeyUsage = nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	client := testpki.Issue(t, clientTpl, testpki.ECDSAKey(t), inter)

	assertResult(t, verify(client, anchors(root), inter), trustverify.Verified, trustverify.ReasonNone)

	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	pool := x509.NewCertPool()
	pool.AddCert(inter.Cert)
	if _, err := client.Cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: pool, CurrentTime: now}); err == nil {
		t.Error("control: Go's default key usage (server authentication) was expected to reject a client certificate")
	}
}

// 18. The signer relationship layer (sigcheck, which uses CheckSignature)
// verifies a SHA-1 certificate signature, and Go's verifier rejects the
// algorithm. Both facts stand; neither rewrites the other. MD5 is refused by
// both layers.
func TestWeakSignatureVerifiesButVerifierRejectsIt(t *testing.T) {
	caKey := testpki.RSAKey(t, 2048)
	ca := testpki.Issue(t, caTemplate("Legacy RSA CA", 1, -1), caKey, nil)
	leaf := testpki.Issue(t, leafTemplate("legacy.example.test", 2), testpki.ECDSAKey(t), ca)
	for _, tc := range []struct {
		name   string
		alg    testpki.SigAlg
		signer sigcheck.State
	}{
		{"SHA-1", testpki.RSAWithSHA1, sigcheck.Verified},
		{"MD5", testpki.RSAWithMD5, sigcheck.Unverifiable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			weak, err := x509.ParseCertificate(testpki.Resign(t, leaf.DER, nil, tc.alg, caKey))
			if err != nil {
				t.Fatal(err)
			}
			if got := sigcheck.Certificate(weak, ca.Cert); got.State != tc.signer {
				t.Fatalf("signer relationship %s, want %s", got.State, tc.signer)
			}
			r := trustverify.Verify(weak, []*x509.Certificate{ca.Cert}, nil, now, purpose.Any)
			assertResult(t, r, trustverify.Failed, trustverify.ReasonInsecureSignatureAlgorithm)
		})
	}
}

// The package refuses to let Go substitute system roots or the system clock.
func TestRefusesImplicitDefaults(t *testing.T) {
	p := newPKI(t)
	assertResult(t, trustverify.Verify(p.leaf.Cert, nil, certs([]*testpki.Cert{p.inter}), now, purpose.Any), trustverify.Unverifiable, trustverify.ReasonEngineError)
	assertResult(t, trustverify.Verify(p.leaf.Cert, certs(anchors(p.root)), nil, time.Time{}, purpose.Any), trustverify.Unverifiable, trustverify.ReasonEngineError)
	assertResult(t, trustverify.Verify(nil, certs(anchors(p.root)), nil, now, purpose.Any), trustverify.Unverifiable, trustverify.ReasonEngineError)
	// An unknown purpose must not fall through to Go's default key usage.
	assertResult(t, trustverify.Verify(p.leaf.Cert, certs(anchors(p.root)), certs([]*testpki.Cert{p.inter}), now, purpose.Purpose("")), trustverify.Unverifiable, trustverify.ReasonEngineError)
}

// 15, 16. A requested purpose is enforced by Go along the chain. Generic
// success does not imply success for a specific purpose.
func TestRequestedPurposeIsEnforced(t *testing.T) {
	p := newPKI(t) // the leaf lists server authentication only
	assertResult(t, verifyFor(purpose.Any, p.leaf, anchors(p.root), p.inter), trustverify.Verified, trustverify.ReasonNone)
	assertResult(t, verifyFor(purpose.TLSServer, p.leaf, anchors(p.root), p.inter), trustverify.Verified, trustverify.ReasonNone)
	assertResult(t, verifyFor(purpose.TLSClient, p.leaf, anchors(p.root), p.inter), trustverify.Failed, trustverify.ReasonIncompatibleUsage)
	assertResult(t, verifyFor(purpose.CodeSigning, p.leaf, anchors(p.root), p.inter), trustverify.Failed, trustverify.ReasonIncompatibleUsage)
	assertResult(t, verifyFor(purpose.Email, p.leaf, anchors(p.root), p.inter), trustverify.Failed, trustverify.ReasonIncompatibleUsage)
}

// 14. An intermediate's extended key usage restricts the certificates below
// it: generic inspection verifies, a purpose the intermediate does not permit
// fails, even when the leaf itself permits it.
func TestIntermediateExtKeyUsageRestriction(t *testing.T) {
	root := testpki.Issue(t, caTemplate("Root", 1, -1), testpki.ECDSAKey(t), nil)
	interTpl := caTemplate("Server-Only Intermediate", 2, -1)
	interTpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	inter := testpki.Issue(t, interTpl, testpki.ECDSAKey(t), root)
	clientTpl := leafTemplate("client", 3)
	clientTpl.DNSNames, clientTpl.ExtKeyUsage = nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	client := testpki.Issue(t, clientTpl, testpki.ECDSAKey(t), inter)

	assertResult(t, verifyFor(purpose.Any, client, anchors(root), inter), trustverify.Verified, trustverify.ReasonNone)
	if leaf := purpose.Evaluate(client.Cert, purpose.TLSClient); leaf.State != purpose.Suitable {
		t.Fatalf("setup: the leaf itself permits tls-client: %+v", leaf)
	}
	assertResult(t, verifyFor(purpose.TLSClient, client, anchors(root), inter), trustverify.Failed, trustverify.ReasonIncompatibleUsage)
	assertResult(t, verifyFor(purpose.TLSServer, client, anchors(root), inter), trustverify.Failed, trustverify.ReasonIncompatibleUsage)

	server := testpki.Issue(t, leafTemplate("api.example.test", 4), testpki.ECDSAKey(t), inter)
	assertResult(t, verifyFor(purpose.TLSServer, server, anchors(root), inter), trustverify.Verified, trustverify.ReasonNone)
}

// 10, 11. Go's verifier treats a certificate without extended key usage as
// unrestricted, and passes anyExtendedKeyUsage for a requested usage (a Go
// verifier behaviour; see TestGoAcceptsAnyExtendedKeyUsage).
func TestGoExtKeyUsageSemantics(t *testing.T) {
	root := testpki.Issue(t, caTemplate("Root", 1, -1), testpki.ECDSAKey(t), nil)
	noEKUTpl := leafTemplate("no-eku.example.test", 2)
	noEKUTpl.ExtKeyUsage = nil
	noEKU := testpki.Issue(t, noEKUTpl, testpki.ECDSAKey(t), root)
	for _, p := range []purpose.Purpose{purpose.TLSServer, purpose.TLSClient, purpose.CodeSigning, purpose.Email} {
		assertResult(t, verifyFor(p, noEKU, anchors(root)), trustverify.Verified, trustverify.ReasonNone)
	}
	anyTpl := leafTemplate("any-eku.example.test", 3)
	anyTpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	anyEKU := testpki.Issue(t, anyTpl, testpki.ECDSAKey(t), root)
	assertResult(t, verifyFor(purpose.CodeSigning, anyEKU, anchors(root)), trustverify.Verified, trustverify.ReasonNone)
}

// Pinned Go 1.27.1 verifier behaviour, not an RFC 5280 requirement: a
// certificate listing anyExtendedKeyUsage, alone or next to a specific usage,
// passes Go's chain extended key usage check for every supported specific
// purpose. RFC 5280 lets an application that requires a specific usage reject
// such a certificate; Trustsmith reports Go's result as Go's.
func TestGoAcceptsAnyExtendedKeyUsage(t *testing.T) {
	root := testpki.Issue(t, caTemplate("Root", 1, -1), testpki.ECDSAKey(t), nil)
	specific := []purpose.Purpose{purpose.TLSServer, purpose.TLSClient, purpose.CodeSigning, purpose.Email}
	for i, tc := range []struct {
		name string
		ekus []x509.ExtKeyUsage
	}{
		{"any only", []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
		{"any and server auth", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageAny}},
		{"any and code signing", []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageAny}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tpl := leafTemplate("any.example.test", int64(10+i))
			tpl.ExtKeyUsage = tc.ekus
			cert := testpki.Issue(t, tpl, testpki.ECDSAKey(t), root)
			for _, p := range specific {
				if r := verifyFor(p, cert, anchors(root)); r.State != trustverify.Verified {
					t.Errorf("pinned Go behaviour changed: %s for %s: %s/%s", tc.name, p, r.State, r.Reason)
				}
			}
		})
	}
}

// Go's verifier ignores the leaf's key usage bits, so a certificate whose key
// usage does not permit code signing still verifies "for code signing". Leaf
// suitability and anchored-path validation are separate facts, and neither
// implies the other.
func TestGoIgnoresLeafKeyUsage(t *testing.T) {
	root := testpki.Issue(t, caTemplate("Root", 1, -1), testpki.ECDSAKey(t), nil)
	tpl := leafTemplate("signer.example.test", 2)
	tpl.ExtKeyUsage, tpl.KeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, x509.KeyUsageKeyEncipherment
	signer := testpki.Issue(t, tpl, testpki.ECDSAKey(t), root)

	if leaf := purpose.Evaluate(signer.Cert, purpose.CodeSigning); leaf.State != purpose.Unsuitable {
		t.Fatalf("leaf evaluation %+v", leaf)
	}
	assertResult(t, verifyFor(purpose.CodeSigning, signer, anchors(root)), trustverify.Verified, trustverify.ReasonNone)
}
