package chainpath_test

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/chainpath"
	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/issuerlinks"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

var (
	notBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	now       = time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
)

func caTemplate(cn string, serial int64) testpki.Template {
	return testpki.Template{
		CommonName: cn, Organization: "Tests", Serial: serial, NotBefore: notBefore, NotAfter: notAfter,
		IsCA: true, MaxPathLen: -1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

func leafTemplate(cn string) testpki.Template {
	return testpki.Template{
		CommonName: cn, Serial: 100, NotBefore: notBefore, NotAfter: notAfter,
		DNSNames: []string{cn}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

func issue(t *testing.T, tpl testpki.Template, key crypto.Signer, parent *testpki.Cert) *testpki.Cert {
	t.Helper()
	return testpki.Issue(t, tpl, key, parent)
}

func build(t *testing.T, limits chainpath.Limits, ders ...[]byte) chainpath.Result {
	t.Helper()
	var inputs []issuerlinks.Input
	for i, der := range ders {
		p := x509facts.FromDER(der)
		if p.Certificate == nil {
			t.Fatalf("input %d does not parse", i)
		}
		inputs = append(inputs, issuerlinks.Input{Entry: i, Certificate: p.Certificate})
	}
	links := issuerlinks.Resolve(inputs, issuerlinks.DefaultLimits())
	return chainpath.Build(inputs, links, now, limits)
}

func buildDefault(t *testing.T, ders ...[]byte) chainpath.Result {
	t.Helper()
	return build(t, chainpath.DefaultLimits(), ders...)
}

// describe renders each path as
// "entries completeness:end structure=... validity=... issues=kind@position,...".
func describe(r chainpath.Result) []string {
	out := []string{}
	for _, p := range r.Paths {
		entries := make([]string, len(p.Entries))
		for i, e := range p.Entries {
			entries[i] = strconv.Itoa(e[0])
		}
		issues := make([]string, len(p.Issues))
		for i, is := range p.Issues {
			issues[i] = fmt.Sprintf("%s@%d", is.Kind, is.Position)
		}
		out = append(out, fmt.Sprintf("%s %s:%s structure=%s validity=%s issues=%s",
			strings.Join(entries, ">"), p.Completeness, p.End, p.Structure, p.Validity, strings.Join(issues, ",")))
	}
	return out
}

func assertPaths(t *testing.T, r chainpath.Result, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if got := describe(r); !slices.Equal(got, want) {
		t.Errorf("paths\n got %q\nwant %q", got, want)
	}
}

type chain struct{ root, inter, leaf *testpki.Cert }

func newChain(t *testing.T) chain {
	t.Helper()
	root := issue(t, caTemplate("Root", 1), testpki.ECDSAKey(t), nil)
	inter := issue(t, caTemplate("Intermediate", 2), testpki.ECDSAKey(t), root)
	return chain{root: root, inter: inter, leaf: issue(t, leafTemplate("leaf.example.test"), testpki.ECDSAKey(t), inter)}
}

func TestCompletePathInInput(t *testing.T) {
	c := newChain(t)
	r := buildDefault(t, c.leaf.DER, c.inter.DER, c.root.DER)
	assertPaths(t, r, "0>1>2 complete_in_input:self_signed_terminal structure=satisfied validity=satisfied issues=")
	if r.LimitReached {
		t.Error("no limit was reached")
	}
}

func TestPartialPathWhenIssuerIsNotInInput(t *testing.T) {
	c := newChain(t)
	assertPaths(t, buildDefault(t, c.leaf.DER, c.inter.DER),
		"0>1 partial:no_issuer_candidate structure=satisfied validity=satisfied issues=")
}

func TestPartialPathWhenCandidateDoesNotVerify(t *testing.T) {
	c := newChain(t)
	impostor := issue(t, caTemplate("Intermediate", 9), testpki.ECDSAKey(t), nil)
	assertPaths(t, buildDefault(t, c.leaf.DER, impostor.DER),
		"0 partial:issuer_candidates_not_verified structure=not_applicable validity=satisfied issues=",
		"1 complete_in_input:self_signed_terminal structure=not_applicable validity=satisfied issues=")
}

func TestSingleCertificate(t *testing.T) {
	c := newChain(t)
	assertPaths(t, buildDefault(t, c.leaf.DER), "0 partial:no_issuer_candidate structure=not_applicable validity=satisfied issues=")
}

func TestIssuerWithBasicConstraintsCAFalse(t *testing.T) {
	root := issue(t, caTemplate("Root", 1), testpki.ECDSAKey(t), nil)
	notCA := caTemplate("Intermediate", 2)
	notCA.IsCA, notCA.BasicConstraintsNotCA = false, true
	inter := issue(t, notCA, testpki.ECDSAKey(t), root)
	leaf := issue(t, leafTemplate("leaf.example.test"), testpki.ECDSAKey(t), inter)

	r := buildDefault(t, leaf.DER, inter.DER, root.DER)
	assertPaths(t, r, "0>1>2 complete_in_input:self_signed_terminal structure=failed validity=satisfied issues=issuer_not_ca@1")
	if is := r.Paths[0].Issues[0]; !is.BasicConstraintsPresent || is.Outcome != chainpath.OutcomeViolation {
		t.Errorf("issue %+v", is)
	}
}

func TestIssuerWithoutBasicConstraints(t *testing.T) {
	root := issue(t, caTemplate("Root", 1), testpki.ECDSAKey(t), nil)
	noBC := caTemplate("Intermediate", 2)
	noBC.IsCA = false
	inter := issue(t, noBC, testpki.ECDSAKey(t), root)
	leaf := issue(t, leafTemplate("leaf.example.test"), testpki.ECDSAKey(t), inter)

	r := buildDefault(t, leaf.DER, inter.DER, root.DER)
	assertPaths(t, r, "0>1>2 complete_in_input:self_signed_terminal structure=failed validity=satisfied issues=issuer_not_ca@1")
	if r.Paths[0].Issues[0].BasicConstraintsPresent {
		t.Error("the extension is absent")
	}
}

func TestKeyUsage(t *testing.T) {
	for _, tc := range []struct {
		name  string
		usage x509.KeyUsage
		want  string
	}{
		{"present without keyCertSign", x509.KeyUsageDigitalSignature, "structure=failed validity=satisfied issues=issuer_key_usage_without_key_cert_sign@1"},
		{"present with keyCertSign", x509.KeyUsageCertSign, "structure=satisfied validity=satisfied issues="},
		{"absent", 0, "structure=satisfied validity=satisfied issues="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := issue(t, caTemplate("Root", 1), testpki.ECDSAKey(t), nil)
			tpl := caTemplate("Intermediate", 2)
			tpl.KeyUsage = tc.usage
			inter := issue(t, tpl, testpki.ECDSAKey(t), root)
			leaf := issue(t, leafTemplate("leaf.example.test"), testpki.ECDSAKey(t), inter)
			assertPaths(t, buildDefault(t, leaf.DER, inter.DER, root.DER), "0>1>2 complete_in_input:self_signed_terminal "+tc.want)
		})
	}
}

func TestPathLenZeroCountsNonSelfIssuedIntermediates(t *testing.T) {
	rootTpl := caTemplate("Root", 1)
	rootTpl.MaxPathLen = 0
	root := issue(t, rootTpl, testpki.ECDSAKey(t), nil)
	inter := issue(t, caTemplate("Intermediate", 2), testpki.ECDSAKey(t), root)
	leaf := issue(t, leafTemplate("leaf.example.test"), testpki.ECDSAKey(t), inter)

	r := buildDefault(t, leaf.DER, inter.DER, root.DER)
	assertPaths(t, r, "0>1>2 complete_in_input:self_signed_terminal structure=failed validity=satisfied issues=path_length_exceeded@2")
	if is := r.Paths[0].Issues[0]; is.PathLenConstraint != 0 || is.FollowingIntermediates != 1 {
		t.Errorf("issue %+v", is)
	}
}

// TestPathLenZeroIgnoresSelfIssuedIntermediates pins RFC 5280 semantics: a
// self-issued intermediate (for example a key rollover certificate) does not
// count against pathLenConstraint. Go's own verifier counts it.
func TestPathLenZeroIgnoresSelfIssuedIntermediates(t *testing.T) {
	rootTpl := caTemplate("Root", 1)
	rootTpl.MaxPathLen = 0
	root := issue(t, rootTpl, testpki.ECDSAKey(t), nil)
	rollover := issue(t, caTemplate("Root", 2), testpki.ECDSAKey(t), root) // same name, new key
	leaf := issue(t, leafTemplate("leaf.example.test"), testpki.ECDSAKey(t), rollover)

	facts := x509facts.FromDER(rollover.DER).Certificate
	if !facts.SelfIssued || facts.SelfSignature != x509facts.SignatureDoesNotVerify {
		t.Fatalf("rollover certificate must be self-issued but not self-signed: %v %s", facts.SelfIssued, facts.SelfSignature)
	}
	assertPaths(t, buildDefault(t, leaf.DER, rollover.DER, root.DER),
		"0>1>2 complete_in_input:self_signed_terminal structure=satisfied validity=satisfied issues=")
}

func TestPathLenOneBoundaries(t *testing.T) {
	rootTpl := caTemplate("Root", 1)
	rootTpl.MaxPathLen = 1
	root := issue(t, rootTpl, testpki.ECDSAKey(t), nil)
	i1 := issue(t, caTemplate("Intermediate 1", 2), testpki.ECDSAKey(t), root)
	i2 := issue(t, caTemplate("Intermediate 2", 3), testpki.ECDSAKey(t), i1)

	oneBelow := issue(t, leafTemplate("one.example.test"), testpki.ECDSAKey(t), i1)
	assertPaths(t, buildDefault(t, oneBelow.DER, i1.DER, root.DER),
		"0>1>2 complete_in_input:self_signed_terminal structure=satisfied validity=satisfied issues=")

	twoBelow := issue(t, leafTemplate("two.example.test"), testpki.ECDSAKey(t), i2)
	r := buildDefault(t, twoBelow.DER, i2.DER, i1.DER, root.DER)
	assertPaths(t, r, "0>1>2>3 complete_in_input:self_signed_terminal structure=failed validity=satisfied issues=path_length_exceeded@3")
	if is := r.Paths[0].Issues[0]; is.PathLenConstraint != 1 || is.FollowingIntermediates != 2 {
		t.Errorf("issue %+v", is)
	}

	zeroTpl := caTemplate("Intermediate 0", 4)
	zeroTpl.MaxPathLen = 0
	i0 := issue(t, zeroTpl, testpki.ECDSAKey(t), root)
	directLeaf := issue(t, leafTemplate("direct.example.test"), testpki.ECDSAKey(t), i0)
	assertPaths(t, buildDefault(t, directLeaf.DER, i0.DER, root.DER),
		"0>1>2 complete_in_input:self_signed_terminal structure=satisfied validity=satisfied issues=")
}

func TestValidityOfEveryCertificateOnThePath(t *testing.T) {
	root := issue(t, caTemplate("Root", 1), testpki.ECDSAKey(t), nil)
	leafFor := func(parent *testpki.Cert) *testpki.Cert {
		return issue(t, leafTemplate("leaf.example.test"), testpki.ECDSAKey(t), parent)
	}

	t.Run("expired intermediate", func(t *testing.T) {
		tpl := caTemplate("Intermediate", 2)
		tpl.NotAfter = now.Add(-time.Hour)
		inter := issue(t, tpl, testpki.ECDSAKey(t), root)
		r := buildDefault(t, leafFor(inter).DER, inter.DER, root.DER)
		assertPaths(t, r, "0>1>2 complete_in_input:self_signed_terminal structure=satisfied validity=failed issues=")
		if nv := r.Paths[0].NotValid; len(nv) != 1 || nv[0].Position != 1 || !nv[0].Expired {
			t.Errorf("not valid %+v", nv)
		}
	})
	t.Run("not yet valid intermediate", func(t *testing.T) {
		tpl := caTemplate("Intermediate", 3)
		tpl.NotBefore = now.Add(time.Hour)
		inter := issue(t, tpl, testpki.ECDSAKey(t), root)
		r := buildDefault(t, leafFor(inter).DER, inter.DER, root.DER)
		if nv := r.Paths[0].NotValid; r.Paths[0].Validity != chainpath.ValidityFailed || len(nv) != 1 || nv[0].Position != 1 || nv[0].Expired {
			t.Errorf("validity %s not valid %+v", r.Paths[0].Validity, nv)
		}
	})
	t.Run("expired self-signed terminal", func(t *testing.T) {
		tpl := caTemplate("Old Root", 4)
		tpl.NotBefore, tpl.NotAfter = now.AddDate(-5, 0, 0), now.Add(-time.Minute)
		oldRoot := issue(t, tpl, testpki.ECDSAKey(t), nil)
		inter := issue(t, caTemplate("Intermediate", 5), testpki.ECDSAKey(t), oldRoot)
		r := buildDefault(t, leafFor(inter).DER, inter.DER, oldRoot.DER)
		if nv := r.Paths[0].NotValid; len(nv) != 1 || nv[0].Position != 2 || !nv[0].Expired {
			t.Errorf("not valid %+v", nv)
		}
		if r.Paths[0].Completeness != chainpath.CompleteInInput {
			t.Error("an expired terminal still completes the path in the input; validity is reported separately")
		}
	})
}

func TestAllPathsAreKept(t *testing.T) {
	root := issue(t, caTemplate("Root", 1), testpki.ECDSAKey(t), nil)
	interKey := testpki.ECDSAKey(t)
	first := issue(t, caTemplate("Intermediate", 2), interKey, root)
	second := issue(t, caTemplate("Intermediate", 3), interKey, root) // reissued, same key
	leaf := issue(t, leafTemplate("leaf.example.test"), testpki.ECDSAKey(t), first)

	assertPaths(t, buildDefault(t, leaf.DER, first.DER, second.DER, root.DER),
		"0>1>3 complete_in_input:self_signed_terminal structure=satisfied validity=satisfied issues=",
		"0>2>3 complete_in_input:self_signed_terminal structure=satisfied validity=satisfied issues=")
}

func TestCrossSignedShape(t *testing.T) {
	keyA := testpki.ECDSAKey(t)
	rootA := issue(t, caTemplate("Root A", 1), keyA, nil)
	rootB := issue(t, caTemplate("Root B", 2), testpki.ECDSAKey(t), nil)
	crossA := issue(t, caTemplate("Root A", 3), keyA, rootB) // Root A's key certified by Root B
	inter := issue(t, caTemplate("Intermediate", 4), testpki.ECDSAKey(t), rootA)
	leaf := issue(t, leafTemplate("leaf.example.test"), testpki.ECDSAKey(t), inter)

	assertPaths(t, buildDefault(t, leaf.DER, inter.DER, rootA.DER, crossA.DER, rootB.DER),
		"0>1>2 complete_in_input:self_signed_terminal structure=satisfied validity=satisfied issues=",
		"0>1>3>4 complete_in_input:self_signed_terminal structure=satisfied validity=satisfied issues=")
}

func TestCycleStopsConstruction(t *testing.T) {
	keyX, keyY := testpki.ECDSAKey(t), testpki.ECDSAKey(t)
	seedY := issue(t, caTemplate("Y", 1), keyY, nil)
	x := issue(t, caTemplate("X", 2), keyX, seedY)                                  // X issued by Y
	y := issue(t, caTemplate("Y", 3), keyY, &testpki.Cert{Cert: x.Cert, Key: keyX}) // Y issued by X

	r := buildDefault(t, x.DER, y.DER)
	assertPaths(t, r, "0>1 cycle:cycle structure=satisfied validity=satisfied issues=")
	if r.Paths[0].CycleTo != 0 {
		t.Errorf("cycle to %d", r.Paths[0].CycleTo)
	}
}

func TestLimitsAreReportedNotSilent(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		root := issue(t, caTemplate("Root", 1), testpki.ECDSAKey(t), nil)
		i1 := issue(t, caTemplate("I1", 2), testpki.ECDSAKey(t), root)
		i2 := issue(t, caTemplate("I2", 3), testpki.ECDSAKey(t), i1)
		i3 := issue(t, caTemplate("I3", 4), testpki.ECDSAKey(t), i2)
		leaf := issue(t, leafTemplate("leaf.example.test"), testpki.ECDSAKey(t), i3)
		r := build(t, chainpath.Limits{MaxDepth: 3, MaxPathsPerStart: 8, MaxExpansions: 100}, leaf.DER, i3.DER, i2.DER, i1.DER, root.DER)
		assertPaths(t, r, "0>1>2 limit_reached:depth_limit structure=satisfied validity=satisfied issues=")
		if !r.LimitReached {
			t.Error("LimitReached must be set")
		}
	})
	t.Run("paths per start", func(t *testing.T) {
		root := issue(t, caTemplate("Root", 1), testpki.ECDSAKey(t), nil)
		key := testpki.ECDSAKey(t)
		ders := [][]byte{nil}
		var first *testpki.Cert
		for i := range 3 {
			c := issue(t, caTemplate("Intermediate", int64(10+i)), key, root)
			if first == nil {
				first = c
			}
			ders = append(ders, c.DER)
		}
		ders[0] = issue(t, leafTemplate("leaf.example.test"), testpki.ECDSAKey(t), first).DER
		ders = append(ders, root.DER)
		r := build(t, chainpath.Limits{MaxDepth: 8, MaxPathsPerStart: 2, MaxExpansions: 100}, ders...)
		if len(r.Paths) != 2 || !r.LimitReached {
			t.Errorf("%d paths, limit reached %v", len(r.Paths), r.LimitReached)
		}
	})
	t.Run("expansions", func(t *testing.T) {
		c := newChain(t)
		r := build(t, chainpath.Limits{MaxDepth: 8, MaxPathsPerStart: 8, MaxExpansions: 1}, c.leaf.DER, c.inter.DER, c.root.DER)
		if !r.LimitReached || r.Expansions > 1 {
			t.Errorf("limit reached %v expansions %d", r.LimitReached, r.Expansions)
		}
	})
}

func TestDuplicatesDoNotCreateDuplicatePaths(t *testing.T) {
	c := newChain(t)
	r := buildDefault(t, c.leaf.DER, c.inter.DER, c.leaf.DER, c.root.DER, c.inter.DER)
	if len(r.Paths) != 1 {
		t.Fatalf("%d paths", len(r.Paths))
	}
	if got := fmt.Sprint(r.Paths[0].Entries); got != "[[0 2] [1 4] [3]]" {
		t.Errorf("entries %s", got)
	}
}

func fingerprints(r chainpath.Result) []string {
	out := []string{}
	for _, p := range r.Paths {
		parts := make([]string, len(p.Certificates))
		for i, fp := range p.Certificates {
			parts[i] = fp.Hex()[:12]
		}
		out = append(out, strings.Join(parts, ">")+" "+string(p.Completeness))
	}
	return out
}

func TestInputOrderDoesNotChangePaths(t *testing.T) {
	c := newChain(t)
	forward := buildDefault(t, c.leaf.DER, c.inter.DER, c.root.DER)
	reversed := buildDefault(t, c.root.DER, c.inter.DER, c.leaf.DER)
	if !slices.Equal(fingerprints(forward), fingerprints(reversed)) {
		t.Errorf("forward %v\nreversed %v", fingerprints(forward), fingerprints(reversed))
	}
}

var unknownCritical = pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Critical: true, Value: []byte{0x05, 0x00}}

func TestUnprocessedCriticalExtensionIsNeverSatisfied(t *testing.T) {
	root := issue(t, caTemplate("Root", 1), testpki.ECDSAKey(t), nil)
	tpl := caTemplate("Intermediate", 2)
	tpl.ExtraExtensions = []pkix.Extension{unknownCritical}
	inter := issue(t, tpl, testpki.ECDSAKey(t), root)
	leaf := issue(t, leafTemplate("leaf.example.test"), testpki.ECDSAKey(t), inter)

	r := buildDefault(t, leaf.DER, inter.DER, root.DER)
	assertPaths(t, r, "0>1>2 complete_in_input:self_signed_terminal structure=structurally_unverifiable validity=satisfied issues=critical_extension_not_processed@1")
	if is := r.Paths[0].Issues[0]; is.ExtensionOID != "1.3.6.1.4.1.55555.1" || is.Outcome != chainpath.OutcomeNotEvaluated {
		t.Errorf("issue %+v", is)
	}

	leafTpl := leafTemplate("critical.example.test")
	leafTpl.ExtraExtensions = []pkix.Extension{unknownCritical}
	criticalLeaf := issue(t, leafTpl, testpki.ECDSAKey(t), root)
	assertPaths(t, buildDefault(t, criticalLeaf.DER, root.DER),
		"0>1 complete_in_input:self_signed_terminal structure=structurally_unverifiable validity=satisfied issues=critical_extension_not_processed@0")
}

func TestNameConstraintsOnAnIssuerAreNotEvaluated(t *testing.T) {
	root := issue(t, caTemplate("Root", 1), testpki.ECDSAKey(t), nil)
	tpl := caTemplate("Constrained", 2)
	tpl.PermittedDNSDomains = []string{"example.test"}
	constrained := issue(t, tpl, testpki.ECDSAKey(t), root)
	leaf := issue(t, leafTemplate("leaf.example.test"), testpki.ECDSAKey(t), constrained)

	assertPaths(t, buildDefault(t, leaf.DER, constrained.DER, root.DER),
		"0>1>2 complete_in_input:self_signed_terminal structure=structurally_unverifiable validity=satisfied issues=name_constraints_not_evaluated@1")

	// The same certificate at the start of a path constrains nothing on it.
	assertPaths(t, buildDefault(t, constrained.DER, root.DER),
		"0>1 complete_in_input:self_signed_terminal structure=satisfied validity=satisfied issues=")
}

func TestViolationOutranksNotEvaluated(t *testing.T) {
	root := issue(t, caTemplate("Root", 1), testpki.ECDSAKey(t), nil)
	tpl := caTemplate("Intermediate", 2)
	tpl.KeyUsage = x509.KeyUsageDigitalSignature
	tpl.ExtraExtensions = []pkix.Extension{unknownCritical}
	inter := issue(t, tpl, testpki.ECDSAKey(t), root)
	leaf := issue(t, leafTemplate("leaf.example.test"), testpki.ECDSAKey(t), inter)
	r := buildDefault(t, leaf.DER, inter.DER, root.DER)
	if r.Paths[0].Structure != chainpath.StructureFailed {
		t.Errorf("structure %s", r.Paths[0].Structure)
	}
}

// TestCompleteInInputIsNotTrust makes sure nothing in the path model can be
// read as a trust or validity verdict: no field is named that way and no
// value says so.
func TestCompleteInInputIsNotTrust(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(chainpath.Result{}), reflect.TypeOf(chainpath.Path{}), reflect.TypeOf(chainpath.Issue{}), reflect.TypeOf(chainpath.NotValid{})} {
		for i := range typ.NumField() {
			name := strings.ToLower(typ.Field(i).Name)
			if strings.Contains(name, "trust") || name == "valid" || name == "isvalid" || strings.HasSuffix(name, "valid") && name != "notvalid" {
				t.Errorf("%s.%s reads as a trust or validity verdict", typ.Name(), typ.Field(i).Name)
			}
		}
	}
	values := []string{
		string(chainpath.CompleteInInput), string(chainpath.Partial), string(chainpath.Cycle), string(chainpath.LimitReached),
		string(chainpath.EndSelfSignedTerminal), string(chainpath.EndNoIssuerCandidate), string(chainpath.EndIssuerCandidatesNotVerify),
		string(chainpath.EndIssuerCandidatesUnchecked), string(chainpath.EndCycle), string(chainpath.EndDepthLimit),
		string(chainpath.StructureSatisfied), string(chainpath.StructureFailed), string(chainpath.StructureUnverifiable), string(chainpath.StructureNotApplicable),
		string(chainpath.ValiditySatisfied), string(chainpath.ValidityFailed),
		string(chainpath.OutcomeViolation), string(chainpath.OutcomeNotEvaluated),
	}
	for _, v := range values {
		if strings.Contains(v, "trust") || v == "valid" || v == "trusted" || strings.Contains(v, "root") {
			t.Errorf("value %q reads as a trust verdict", v)
		}
	}

	c := newChain(t)
	p := buildDefault(t, c.leaf.DER, c.inter.DER, c.root.DER).Paths[0]
	if p.Completeness != chainpath.CompleteInInput || p.End != chainpath.EndSelfSignedTerminal {
		t.Fatalf("setup: %s %s", p.Completeness, p.End)
	}
}

var _ fingerprint.Cert
