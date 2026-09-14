package inspectsvc_test

import (
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/purpose"
	"github.com/Hazame-hub/trustsmith/internal/trustverify"
)

func inspectPurpose(t *testing.T, fixture string, p purpose.Purpose, roots ...string) inspectsvc.Result {
	t.Helper()
	opts := []inspectsvc.Option{inspectsvc.WithPurpose(p)}
	if len(roots) > 0 {
		opts = append(opts, inspectsvc.WithRoots(loadRoots(t, roots...)))
	}
	res, err := inspectsvc.New(testNow, opts...).InspectFile(filepath.Join(corpus, fixture))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func onlyTarget(t *testing.T, res inspectsvc.Result) inspectsvc.PurposeTarget {
	t.Helper()
	if res.Purpose.State != inspectsvc.PurposeEvaluated || len(res.Purpose.Targets) != 1 {
		t.Fatalf("purpose evaluation %+v", res.Purpose)
	}
	return res.Purpose.Targets[0]
}

// 1, 2. The default purpose is any, and asking for any changes nothing.
func TestDefaultPurposeIsAny(t *testing.T) {
	plain, err := service().InspectFile(filepath.Join(corpus, "bundle.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if plain.Purpose.Requested != purpose.Any || plain.Purpose.State != inspectsvc.PurposeNotEvaluated || len(plain.Purpose.Targets) != 0 {
		t.Errorf("default purpose %+v", plain.Purpose)
	}
	if explicit := inspectPurpose(t, "bundle.pem", purpose.Any); !reflect.DeepEqual(plain, explicit) {
		t.Error("--purpose any must equal the default")
	}
	withRoots := inspectWithRoots(t, "bundle.pem", loadRoots(t, "test-root.pem"), testNow())
	if explicit := inspectPurpose(t, "bundle.pem", purpose.Any, "test-root.pem"); !reflect.DeepEqual(withRoots, explicit) {
		t.Error("--purpose any with roots must equal the default with roots")
	}
	if withRoots.Trust.Purpose != purpose.Any {
		t.Errorf("trust purpose %q", withRoots.Trust.Purpose)
	}
}

// 17. Without roots the certificate's own usage is still evaluated; trust is
// not.
func TestPurposeWithoutRoots(t *testing.T) {
	res := inspectPurpose(t, "leaf.pem", purpose.TLSServer)
	target := onlyTarget(t, res)
	if target.Usage.State != purpose.Suitable || target.AnchoredPath != trustverify.NotEvaluated || res.Trust.State != inspectsvc.TrustNotEvaluated {
		t.Errorf("leaf.pem for tls-server: %+v, trust %s", target, res.Trust.State)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings %v", findingKeys(res.Findings))
	}

	client := inspectPurpose(t, "client.pem", purpose.TLSServer)
	if u := onlyTarget(t, client).Usage; u.State != purpose.Unsuitable || !slices.Equal(u.Reasons, []purpose.Reason{purpose.ReasonExtKeyUsage}) {
		t.Errorf("client.pem for tls-server: %+v", u)
	}
	if got := findingKeys(client.Findings); !slices.Equal(got, []string{"0:purpose.eku_disallows_usage:critical"}) {
		t.Errorf("findings %v", got)
	}
}

// 15, 16. With roots, Go validates the chain for the requested purpose. A
// certificate that validates generically does not thereby validate for every
// purpose, and the earlier layers never change.
func TestPurposeWithRoots(t *testing.T) {
	generic := inspectWithRoots(t, "bundle.pem", loadRoots(t, "test-root.pem"), testNow())
	if r := generic.Trust.Targets[0].Result; r.State != trustverify.Verified {
		t.Fatalf("generic trust %+v", r)
	}

	server := inspectPurpose(t, "bundle.pem", purpose.TLSServer, "test-root.pem")
	if target := onlyTarget(t, server); target.Usage.State != purpose.Suitable || target.AnchoredPath != trustverify.Verified {
		t.Errorf("tls-server %+v", target)
	}
	if server.Trust.Purpose != purpose.TLSServer || server.Trust.Targets[0].Result.State != trustverify.Verified {
		t.Errorf("tls-server trust %+v", server.Trust)
	}

	client := inspectPurpose(t, "bundle.pem", purpose.TLSClient, "test-root.pem")
	target := onlyTarget(t, client)
	if target.Usage.State != purpose.Unsuitable || target.AnchoredPath != trustverify.Failed || target.AnchoredPathReason != trustverify.ReasonIncompatibleUsage {
		t.Errorf("tls-client %+v", target)
	}
	if r := client.Trust.Targets[0].Result; r.State != trustverify.Failed || r.Reason != trustverify.ReasonIncompatibleUsage {
		t.Errorf("tls-client trust %+v", r)
	}
	if got := findingKeys(client.Findings); !slices.Equal(got, []string{"0:purpose.eku_disallows_usage:critical", "0:trust.failed:critical"}) {
		t.Errorf("findings %v", got)
	}
	if !reflect.DeepEqual(generic.Relationships, client.Relationships) || !reflect.DeepEqual(generic.Paths, client.Paths) {
		t.Error("a purpose changed relationships or paths")
	}
}

// 14. An intermediate restricted to server authentication: generic trust
// verifies, the leaf itself permits tls-client, and Go rejects the chain for
// tls-client. Leaf suitability does not imply anchored-path validation.
func TestIntermediateRestrictionIsAnAnchoredPathFact(t *testing.T) {
	generic := inspectWithRoots(t, "purpose-server-only-intermediate.pem", loadRoots(t, "purpose-root.pem"), testNow())
	if r := generic.Trust.Targets[0].Result; r.State != trustverify.Verified {
		t.Errorf("generic trust %+v", r)
	}
	target := onlyTarget(t, inspectPurpose(t, "purpose-server-only-intermediate.pem", purpose.TLSClient, "purpose-root.pem"))
	if target.Usage.State != purpose.Suitable || target.AnchoredPath != trustverify.Failed || target.AnchoredPathReason != trustverify.ReasonIncompatibleUsage {
		t.Errorf("tls-client under a server-only intermediate: %+v", target)
	}
}

// Go's verifier ignores leaf key usage: the anchored path verifies while the
// certificate's own key usage does not permit code signing. Anchored-path
// validation does not imply leaf suitability either.
func TestKeyUsageConflictIsALeafFact(t *testing.T) {
	target := onlyTarget(t, inspectPurpose(t, "purpose-key-usage-conflict.pem", purpose.CodeSigning, "purpose-root.pem"))
	if target.Usage.State != purpose.Unsuitable || !slices.Equal(target.Usage.Reasons, []purpose.Reason{purpose.ReasonKeyUsage}) ||
		target.AnchoredPath != trustverify.Verified {
		t.Errorf("%+v", target)
	}
}

// 7, 9, 10, 11 through the corpus.
func TestPurposeFixtures(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		purpose purpose.Purpose
		state   purpose.State
	}{
		{"purpose-code-signing.pem", purpose.CodeSigning, purpose.Suitable},
		{"purpose-code-signing.pem", purpose.TLSServer, purpose.Unsuitable},
		{"purpose-email.pem", purpose.Email, purpose.Suitable},
		{"purpose-email.pem", purpose.TLSClient, purpose.Unsuitable},
		{"purpose-no-eku.pem", purpose.TLSServer, purpose.Suitable},
		{"purpose-no-eku.pem", purpose.CodeSigning, purpose.Suitable},
		{"purpose-any-eku.pem", purpose.Email, purpose.Suitable},
		{"leaf.pem", purpose.CodeSigning, purpose.Unsuitable},
	} {
		if u := onlyTarget(t, inspectPurpose(t, tc.fixture, tc.purpose)).Usage; u.State != tc.state {
			t.Errorf("%s for %s: %s %v", tc.fixture, tc.purpose, u.State, u.Reasons)
		}
	}
}
