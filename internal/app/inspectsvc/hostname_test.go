package inspectsvc_test

import (
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/hostname"
	"github.com/Hazame-hub/trustsmith/internal/purpose"
	"github.com/Hazame-hub/trustsmith/internal/trustverify"
)

func inspectHost(t *testing.T, fixture, name string, opts ...inspectsvc.Option) inspectsvc.Result {
	t.Helper()
	if name != "" {
		req, err := hostname.ParseRequest(name)
		if err != nil {
			t.Fatal(err)
		}
		opts = append(opts, inspectsvc.WithHostname(req))
	}
	res, err := inspectsvc.New(testNow, opts...).InspectFile(filepath.Join(corpus, fixture))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func onlyHostTarget(t *testing.T, res inspectsvc.Result) hostname.Result {
	t.Helper()
	if res.Hostname.State != inspectsvc.HostnameEvaluated || len(res.Hostname.Targets) != 1 {
		t.Fatalf("hostname evaluation %+v", res.Hostname)
	}
	return res.Hostname.Targets[0].Result
}

func TestHostnameNotEvaluatedByDefault(t *testing.T) {
	res := inspectHost(t, "leaf.pem", "")
	if res.Hostname.State != inspectsvc.HostnameNotEvaluated || len(res.Hostname.Targets) != 0 || res.Hostname.Request != (hostname.Request{}) {
		t.Errorf("%+v", res.Hostname)
	}
}

// 21. A match without roots: identity matched, trust not evaluated, purpose
// not asserted.
func TestHostnameMatchWithoutRoots(t *testing.T) {
	res := inspectHost(t, "leaf.pem", "API.Example.TEST.")
	if r := onlyHostTarget(t, res); r.State != hostname.Matched {
		t.Errorf("result %+v", r)
	}
	if res.Hostname.Request.Normalized != "api.example.test" || res.Hostname.Request.Input != "API.Example.TEST." || res.Hostname.Matcher != inspectsvc.HostnameMatcher {
		t.Errorf("request %+v", res.Hostname)
	}
	if res.Trust.State != inspectsvc.TrustNotEvaluated || res.Purpose.State != inspectsvc.PurposeNotEvaluated || len(res.Findings) != 0 {
		t.Errorf("trust %s purpose %s findings %v", res.Trust.State, res.Purpose.State, findingKeys(res.Findings))
	}
	if r := onlyHostTarget(t, inspectHost(t, "leaf.pem", "192.0.2.10")); r.State != hostname.Matched {
		t.Errorf("IP address %+v", r)
	}
}

// 22. A certificate that validates to the supplied roots for TLS server use
// can still fail to identify the requested host: each fact stands.
func TestHostnameMismatchWithSuccessfulTrust(t *testing.T) {
	plain := inspectWithRoots(t, "bundle.pem", loadRoots(t, "test-root.pem"), testNow())
	res := inspectHost(t, "bundle.pem", "other.example.test",
		inspectsvc.WithRoots(loadRoots(t, "test-root.pem")), inspectsvc.WithPurpose(purpose.TLSServer))
	if r := res.Trust.Targets[0].Result; r.State != trustverify.Verified {
		t.Errorf("trust %+v", r)
	}
	if u := res.Purpose.Targets[0].Usage; u.State != purpose.Suitable {
		t.Errorf("purpose %+v", u)
	}
	r := onlyHostTarget(t, res)
	if r.State != hostname.Mismatch || !slices.Equal(r.DNSNames, []string{"api.example.test", "www.example.test"}) {
		t.Errorf("hostname %+v", r)
	}
	if got := findingKeys(res.Findings); !slices.Equal(got, []string{"0:name.hostname_mismatch:critical"}) {
		t.Errorf("findings %v", got)
	}
	if !reflect.DeepEqual(plain.Relationships, res.Relationships) || !reflect.DeepEqual(plain.Paths, res.Paths) {
		t.Error("a host name request changed relationships or paths")
	}
}

// 23. A host name match with a purpose the certificate does not permit.
func TestHostnameMatchWithPurposeMismatch(t *testing.T) {
	res := inspectHost(t, "leaf.pem", "www.example.test", inspectsvc.WithPurpose(purpose.TLSClient))
	if r := onlyHostTarget(t, res); r.State != hostname.Matched {
		t.Errorf("hostname %+v", r)
	}
	if u := res.Purpose.Targets[0].Usage; u.State != purpose.Unsuitable {
		t.Errorf("purpose %+v", u)
	}
	if got := findingKeys(res.Findings); !slices.Equal(got, []string{"0:purpose.eku_disallows_usage:critical"}) {
		t.Errorf("findings %v", got)
	}
}

// 24, 25. Neither layer implies the other.
func TestHostnameAndPurposeAreIndependent(t *testing.T) {
	if res := inspectPurpose(t, "leaf.pem", purpose.TLSServer); res.Hostname.State != inspectsvc.HostnameNotEvaluated {
		t.Errorf("--purpose evaluated host names: %+v", res.Hostname)
	}
	if res := inspectHost(t, "leaf.pem", "api.example.test"); res.Purpose.Requested != purpose.Any || res.Purpose.State != inspectsvc.PurposeNotEvaluated {
		t.Errorf("--hostname implied a purpose: %+v", res.Purpose)
	}
}

// 12. A CN-only certificate does not identify its Common Name; the existing
// CN-only finding and the mismatch are separate findings.
func TestHostnameCommonNameOnly(t *testing.T) {
	res := inspectHost(t, "cn-only.pem", "cn-only.example.test")
	if r := onlyHostTarget(t, res); r.State != hostname.Mismatch || !r.CommonNameIgnored || len(r.DNSNames) != 0 {
		t.Errorf("%+v", r)
	}
	if got := findingKeys(res.Findings); !slices.Equal(got, []string{"0:name.hostname_mismatch:critical", "0:name.cn_only_no_san:warning"}) {
		t.Errorf("findings %v", got)
	}
	// The mismatch finding carries structured evidence, never Go's message.
	for _, f := range res.Findings {
		if f.Code != "name.hostname_mismatch" {
			continue
		}
		want := map[string]string{"requested": "cn-only.example.test", "normalized": "cn-only.example.test", "kind": "dns", "certificate_dns_names": "", "common_name_ignored": "true"}
		got := map[string]string{}
		for _, e := range f.Evidence {
			got[e.Key] = e.Value
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("evidence %v, want %v", got, want)
		}
	}
}
