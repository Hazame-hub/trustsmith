package interpret_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/chainpath"
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/interpret"
	"github.com/Hazame-hub/trustsmith/internal/issuerlinks"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

// pathFindings builds paths for ders as one input and interprets them.
func pathFindings(t *testing.T, ders ...[]byte) []findings.Finding {
	t.Helper()
	var inputs []issuerlinks.Input
	first := map[fingerprint.Cert]int{}
	for i, der := range ders {
		p := x509facts.FromDER(der)
		if p.Certificate == nil {
			t.Fatalf("input %d does not parse", i)
		}
		inputs = append(inputs, issuerlinks.Input{Entry: i, Certificate: p.Certificate})
		if _, ok := first[p.Certificate.Fingerprint]; !ok {
			first[p.Certificate.Fingerprint] = i
		}
	}
	links := issuerlinks.Resolve(inputs, issuerlinks.DefaultLimits())
	result := chainpath.Build(inputs, links, notBefore.AddDate(0, 0, 1), chainpath.DefaultLimits())
	fs := interpret.Paths(result, first)
	assertCatalogued(t, fs)
	return fs
}

func TestNormalPathHasNoFindings(t *testing.T) {
	root := testpki.Issue(t, caTemplate("Root"), testpki.ECDSAKey(t), nil)
	inter := testpki.Issue(t, caTemplate("Intermediate"), testpki.ECDSAKey(t), root)
	leaf := testpki.Issue(t, serverTemplate("api.example.test"), testpki.ECDSAKey(t), inter)
	assertCodes(t, pathFindings(t, leaf.DER, inter.DER, root.DER))
}

// TestIssuerProblemIsReportedOncePerIssuer: two paths through the same non-CA
// issuer produce one finding on that issuer, not one per path.
func TestIssuerProblemIsReportedOncePerIssuer(t *testing.T) {
	root := testpki.Issue(t, caTemplate("Root"), testpki.ECDSAKey(t), nil)
	notCA := caTemplate("Not A CA")
	notCA.IsCA, notCA.BasicConstraintsNotCA = false, true
	inter := testpki.Issue(t, notCA, testpki.ECDSAKey(t), root)
	leafA := testpki.Issue(t, serverTemplate("a.example.test"), testpki.ECDSAKey(t), inter)
	leafB := testpki.Issue(t, serverTemplate("b.example.test"), testpki.ECDSAKey(t), inter)

	fs := pathFindings(t, leafA.DER, leafB.DER, inter.DER, root.DER)
	assertCodes(t, fs, "chain.issuer_not_ca:warning")
	if fs[0].Entry != 2 || evidence(fs[0], "basic_constraints") != "ca_false" {
		t.Errorf("finding %+v", fs[0])
	}
}

func TestKeyUsageAndPathLengthFindings(t *testing.T) {
	rootTpl := caTemplate("Root")
	rootTpl.MaxPathLen = 0
	root := testpki.Issue(t, rootTpl, testpki.ECDSAKey(t), nil)
	interTpl := caTemplate("Intermediate")
	interTpl.KeyUsage = x509.KeyUsageDigitalSignature
	inter := testpki.Issue(t, interTpl, testpki.ECDSAKey(t), root)
	leaf := testpki.Issue(t, serverTemplate("api.example.test"), testpki.ECDSAKey(t), inter)

	fs := pathFindings(t, leaf.DER, inter.DER, root.DER)
	assertCodes(t, fs, "chain.issuer_key_usage:warning", "chain.path_length_exceeded:warning")
	for _, f := range fs {
		if f.Code == findings.ChainPathLengthExceeded &&
			(f.Entry != 2 || evidence(f, "path_len_constraint") != "0" || evidence(f, "following_intermediates") != "1") {
			t.Errorf("path length finding %+v", f)
		}
	}
}

func TestNotEvaluatedStructureIsInformational(t *testing.T) {
	root := testpki.Issue(t, caTemplate("Root"), testpki.ECDSAKey(t), nil)
	tpl := caTemplate("Intermediate")
	tpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Critical: true, Value: []byte{0x05, 0x00}}}
	inter := testpki.Issue(t, tpl, testpki.ECDSAKey(t), root)
	leaf := testpki.Issue(t, serverTemplate("api.example.test"), testpki.ECDSAKey(t), inter)

	fs := pathFindings(t, leaf.DER, inter.DER, root.DER)
	assertCodes(t, fs, "chain.structure_unverifiable:info")
	if evidence(fs[0], "reason") != string(chainpath.IssueCriticalExtensionNotProcessed) || evidence(fs[0], "extension_oid") != "1.3.6.1.4.1.55555.1" {
		t.Errorf("evidence %+v", fs[0].Evidence)
	}
}

// TestValidityIsNotDuplicatedAsPathFindings: expired certificates already have
// cert.expired findings of their own.
func TestValidityIsNotDuplicatedAsPathFindings(t *testing.T) {
	root := testpki.Issue(t, caTemplate("Root"), testpki.ECDSAKey(t), nil)
	tpl := caTemplate("Intermediate")
	tpl.NotAfter = notBefore.Add(-1)
	tpl.NotBefore = notBefore.AddDate(-1, 0, 0)
	inter := testpki.Issue(t, tpl, testpki.ECDSAKey(t), root)
	leaf := testpki.Issue(t, serverTemplate("api.example.test"), testpki.ECDSAKey(t), inter)
	assertCodes(t, pathFindings(t, leaf.DER, inter.DER, root.DER))
}

func TestCycleAndLimitFindings(t *testing.T) {
	cycle := chainpath.Path{
		Certificates: []fingerprint.Cert{{1}, {2}},
		Entries:      [][]int{{0}, {1}},
		Completeness: chainpath.Cycle, End: chainpath.EndCycle, CycleTo: 0,
		Structure: chainpath.StructureSatisfied, Issues: []chainpath.Issue{},
		Validity: chainpath.ValiditySatisfied, NotValid: []chainpath.NotValid{},
	}
	fs := interpret.Paths(chainpath.Result{Paths: []chainpath.Path{cycle}, LimitReached: true}, map[fingerprint.Cert]int{{1}: 0, {2}: 1})
	assertCatalogued(t, fs)
	assertCodes(t, fs, "chain.cycle:info", "chain.path_limit_reached:info")
	for _, f := range fs {
		switch f.Code {
		case findings.ChainCycle:
			if f.Entry != 0 || evidence(f, "repeats_entry") != "0" {
				t.Errorf("cycle finding %+v", f)
			}
		case findings.ChainPathLimitReached:
			if f.Entry != findings.WholeInput {
				t.Errorf("limit finding must concern the whole input: %+v", f)
			}
		}
	}
}
