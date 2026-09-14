package inspectsvc_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/interpret"
	"github.com/Hazame-hub/trustsmith/internal/issuerlinks"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
	"github.com/Hazame-hub/trustsmith/internal/trustverify"
)

var rootsDir = filepath.Join("..", "..", "..", "testdata", "roots")

func loadRoots(t *testing.T, names ...string) inspectsvc.Roots {
	t.Helper()
	paths := make([]string, len(names))
	for i, n := range names {
		paths[i] = filepath.Join(rootsDir, n)
	}
	r, err := inspectsvc.LoadRoots(paths)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func inspectWithRoots(t *testing.T, fixture string, roots inspectsvc.Roots, at time.Time) inspectsvc.Result {
	t.Helper()
	res, err := inspectsvc.New(func() time.Time { return at }, inspectsvc.WithRoots(roots)).InspectFile(filepath.Join(corpus, fixture))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func withoutFixtureRoot(t *testing.T) inspectsvc.Result {
	t.Helper()
	res, err := service().InspectFile(filepath.Join(corpus, "bundle.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func testNow() time.Time { return testpki.Now }

// 2. Without roots, trust is not evaluated, and no certificate — not even the
// bundle's own self-signed root — is treated as an anchor.
func TestTrustNotEvaluatedWithoutRoots(t *testing.T) {
	res := withoutFixtureRoot(t)
	if res.Trust.State != inspectsvc.TrustNotEvaluated || len(res.Trust.Targets) != 0 || len(res.Trust.Roots.Anchors) != 0 {
		t.Errorf("trust %+v", res.Trust)
	}
	for _, a := range res.Artifacts {
		if a.Summary.Chain != interpret.ChainNotChecked {
			t.Errorf("entry %d chain %s", a.Entry, a.Summary.Chain)
		}
	}
	for _, f := range res.Findings {
		if strings.HasPrefix(string(f.Code), "trust.") {
			t.Errorf("finding %s without roots", f.Code)
		}
	}
}

// 1, 5. The bundle validates to the explicitly supplied root; the root is
// also in the input, and is one anchor identity.
func TestTrustVerifiedAgainstSuppliedRoot(t *testing.T) {
	res := inspectWithRoots(t, "bundle.pem", loadRoots(t, "test-root.pem"), testNow())
	tr := res.Trust
	if tr.State != inspectsvc.TrustEvaluated || tr.Source != inspectsvc.TrustSourceSuppliedRoots || tr.Engine != trustverify.Engine || tr.EngineVersion == "" {
		t.Fatalf("trust %+v", tr)
	}
	if len(tr.Roots.Anchors) != 1 || len(tr.Targets) != 1 {
		t.Fatalf("anchors %d targets %d", len(tr.Roots.Anchors), len(tr.Targets))
	}
	target := tr.Targets[0]
	if !slices.Equal(target.Entries, []int{0}) || target.Result.State != trustverify.Verified || len(target.Result.Chains) != 1 {
		t.Fatalf("target %+v", target)
	}
	chain := target.Result.Chains[0]
	want := []fingerprint.Cert{res.Artifacts[0].Certificate.Fingerprint, res.Artifacts[1].Certificate.Fingerprint, res.Artifacts[2].Certificate.Fingerprint}
	if !slices.Equal(chain.Certificates, want) || chain.Anchor() != tr.Roots.Anchors[0].Certificate.Fingerprint {
		t.Errorf("chain %v, want %v ending at the anchor", chain.Certificates, want)
	}
	if res.Artifacts[0].Summary.Chain != interpret.ChainVerifiedToSuppliedRoots || res.Artifacts[1].Summary.Chain != interpret.ChainNotChecked {
		t.Errorf("summary chains %s / %s", res.Artifacts[0].Summary.Chain, res.Artifacts[1].Summary.Chain)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings %v", findingKeys(res.Findings))
	}
}

// 3, 4. The bundle's own self-signed root is not an anchor: with an
// unrelated root supplied, there is no path to an explicit anchor.
func TestInputRootIsNeverAnAnchor(t *testing.T) {
	res := inspectWithRoots(t, "bundle.pem", loadRoots(t, "unrelated-root.pem"), testNow())
	if len(res.Trust.Targets) != 1 {
		t.Fatalf("targets %+v", res.Trust.Targets)
	}
	if r := res.Trust.Targets[0].Result; r.State != trustverify.Failed || r.Reason != trustverify.ReasonNoAnchorPath {
		t.Errorf("result %+v", r)
	}
	if got := findingKeys(res.Findings); !slices.Equal(got, []string{"0:trust.failed:critical"}) {
		t.Errorf("findings %v", got)
	}
	if res.Artifacts[0].Summary.Chain != interpret.ChainFailedAgainstSuppliedRoots {
		t.Errorf("summary chain %s", res.Artifacts[0].Summary.Chain)
	}
}

// 7. Several anchors across files, one of which validates.
func TestMultipleRootsFilesOneAnchorSucceeds(t *testing.T) {
	res := inspectWithRoots(t, "bundle.pem", loadRoots(t, "unrelated-root.pem", "test-root.pem"), testNow())
	if len(res.Trust.Roots.Files) != 2 || len(res.Trust.Roots.Anchors) != 2 {
		t.Fatalf("roots %+v", res.Trust.Roots)
	}
	if r := res.Trust.Targets[0].Result; r.State != trustverify.Verified || r.Chains[0].Anchor() != res.Trust.Roots.Anchors[1].Certificate.Fingerprint {
		t.Errorf("result %+v", r)
	}
}

// 8. Every chain is kept: path-cross-signed validates through root A and,
// via the cross certificate, through root B.
func TestMultipleChainsAreReported(t *testing.T) {
	res := inspectWithRoots(t, "path-cross-signed.pem", loadRoots(t, "path-cross-roots.pem"), testNow())
	r := res.Trust.Targets[0].Result
	if r.State != trustverify.Verified || len(r.Chains) != 2 || len(r.Chains[0].Certificates) != 3 || len(r.Chains[1].Certificates) != 4 {
		t.Fatalf("result %+v", r)
	}
}

// 18. SHA-1: the signer relationship verifies and the included path is
// complete, while Go's verifier rejects the algorithm. Each layer reports its
// own fact.
func TestSHA1LayersDoNotContradict(t *testing.T) {
	res := inspectWithRoots(t, "sha1-with-issuer.pem", loadRoots(t, "legacy-signing-ca.pem"), testNow())
	if len(res.Relationships) != 1 || res.Relationships[0].State != issuerlinks.Verified {
		t.Errorf("relationships %+v", res.Relationships)
	}
	if len(res.Paths) != 1 || res.Paths[0].Completeness != "complete_in_input" {
		t.Errorf("paths %+v", res.Paths)
	}
	if r := res.Trust.Targets[0].Result; r.State != trustverify.Failed || r.Reason != trustverify.ReasonInsecureSignatureAlgorithm {
		t.Errorf("trust %+v", r)
	}
}

// Trust evaluation never changes what the earlier layers report.
func TestTrustDoesNotChangeRelationshipsOrPaths(t *testing.T) {
	for fixture, roots := range map[string]string{
		"bundle.pem":                    "unrelated-root.pem",
		"path-cross-signed.pem":         "path-cross-roots.pem",
		"path-expired-intermediate.pem": "path-expired-root.pem",
		"sha1-with-issuer.pem":          "legacy-signing-ca.pem",
	} {
		plain, err := service().InspectFile(filepath.Join(corpus, fixture))
		if err != nil {
			t.Fatal(err)
		}
		with := inspectWithRoots(t, fixture, loadRoots(t, roots), testNow())
		if !reflect.DeepEqual(plain.Relationships, with.Relationships) || !reflect.DeepEqual(plain.Paths, with.Paths) {
			t.Errorf("%s: roots changed relationships or paths", fixture)
		}
	}
}

// 10, 24. The injected clock drives validation: an expired intermediate
// fails, and at a later inspection time so does the whole bundle.
func TestTrustUsesTheInjectedClock(t *testing.T) {
	res := inspectWithRoots(t, "path-expired-intermediate.pem", loadRoots(t, "path-expired-root.pem"), testNow())
	if r := res.Trust.Targets[0].Result; r.State != trustverify.Failed || r.Reason != trustverify.ReasonExpired {
		t.Errorf("expired intermediate: %+v", r)
	}
	later := inspectWithRoots(t, "bundle.pem", loadRoots(t, "test-root.pem"), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	if r := later.Trust.Targets[0].Result; r.State != trustverify.Failed || r.Reason != trustverify.ReasonExpired {
		t.Errorf("bundle in 2030: %+v", r)
	}
}

// 19, 20, 21. Unusable roots files are refused as a whole.
func TestLoadRootsRefusesUnusableFiles(t *testing.T) {
	for name, wantMsg := range map[string]string{
		"empty.pem":            "empty",
		"malformed.pem":        "entry 0 is malformed",
		"with-private-key.pem": `entry 1 is a "PRIVATE KEY" PEM block`,
	} {
		_, err := inspectsvc.LoadRoots([]string{filepath.Join(rootsDir, name)})
		if !errors.Is(err, inspectsvc.ErrRoots) || !strings.Contains(err.Error(), wantMsg) {
			t.Errorf("%s: %v", name, err)
		}
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"text.txt": "not a certificate\n",
		"csr.pem":  "-----BEGIN CERTIFICATE REQUEST-----\nMAA=\n-----END CERTIFICATE REQUEST-----\n",
		"key.pem":  "-----BEGIN EC PRIVATE KEY-----\nMAA=\n-----END EC PRIVATE KEY-----\n",
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectsvc.LoadRoots([]string{p}); !errors.Is(err, inspectsvc.ErrRoots) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := inspectsvc.LoadRoots([]string{filepath.Join(dir, "missing.pem")}); err == nil || errors.Is(err, inspectsvc.ErrRoots) {
		t.Errorf("missing file: %v", err)
	}
	if _, err := inspectsvc.LoadRoots([]string{dir}); err == nil {
		t.Error("a directory must be refused")
	}
}

func TestLoadRootsDeduplicatesAnchors(t *testing.T) {
	data := mustReadRoots(t, "test-root.pem")
	p := filepath.Join(t.TempDir(), "twice.pem")
	if err := os.WriteFile(p, append(append([]byte{}, data...), data...), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := inspectsvc.LoadRoots([]string{p, filepath.Join(rootsDir, "test-root.pem")})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Anchors) != 1 || len(r.Anchors[0].Sources) != 3 || r.Files[0].Certificates != 2 {
		t.Errorf("roots %+v", r)
	}
}

func mustReadRoots(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(rootsDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
