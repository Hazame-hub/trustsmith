package inspectsvc_test

import (
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/artifact"
	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/hostname"
	"github.com/Hazame-hub/trustsmith/internal/purpose"
)

// TestRequestFormsShareIdentity: the same request in PEM, DER and under the
// legacy label has the same facts and interpretation.
func TestRequestFormsShareIdentity(t *testing.T) {
	var results []inspectsvc.Result
	for _, name := range []string{"csr.pem", "csr.der", "csr-legacy-label.pem"} {
		res, err := service().InspectFile(filepath.Join(corpus, name))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Artifacts) != 1 || res.Artifacts[0].Request == nil || res.Artifacts[0].RequestSummary == nil {
			t.Fatalf("%s: artifacts %+v", name, res.Artifacts)
		}
		results = append(results, res)
	}
	first := results[0].Artifacts[0]
	for i, res := range results[1:] {
		a := res.Artifacts[0]
		if a.Request.KeyID != first.Request.KeyID || a.Request.EncodedSPKI != first.Request.EncodedSPKI {
			t.Errorf("form %d: key fingerprints differ", i+1)
		}
		if !reflect.DeepEqual(a.RequestSummary, first.RequestSummary) || !reflect.DeepEqual(res.Findings, results[0].Findings) {
			t.Errorf("form %d: interpretation differs", i+1)
		}
	}
	if results[1].Format != artifact.FormatDER || results[2].Artifacts[0].Label != "NEW CERTIFICATE REQUEST" {
		t.Errorf("format %s label %q", results[1].Format, results[2].Artifacts[0].Label)
	}
	if first.Request.KeyIdentity != "canonical" || first.Request.KeyID == (fingerprint.KeyID{}) {
		t.Errorf("key identity %s", first.Request.KeyIdentity)
	}
}

// TestRequestIsNeverACertificate: next to a certificate, a request is never an
// issuer candidate, path member or target of trust, purpose or host name
// evaluation, whatever is requested.
func TestRequestIsNeverACertificate(t *testing.T) {
	req, err := hostname.ParseRequest("api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	res, err := inspectsvc.New(testNow,
		inspectsvc.WithRoots(loadRoots(t, "test-root.pem")),
		inspectsvc.WithPurpose(purpose.TLSServer),
		inspectsvc.WithHostname(req),
	).InspectFile(filepath.Join(corpus, "csr-with-leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Relationships) != 0 || len(res.Paths) != 1 || !reflect.DeepEqual(res.Paths[0].Entries, [][]int{{0}}) {
		t.Errorf("relationships %v paths %v", relationshipKeys(res), pathKeys(res))
	}
	leaf := res.Artifacts[0].Certificate.Fingerprint
	for name, targets := range map[string]int{
		"trust": len(res.Trust.Targets), "purpose": len(res.Purpose.Targets), "hostname": len(res.Hostname.Targets),
	} {
		if targets != 1 {
			t.Errorf("%s: %d targets, want only the certificate", name, targets)
		}
	}
	if res.Trust.Targets[0].Certificate != leaf || res.Purpose.Targets[0].Certificate != leaf || res.Hostname.Targets[0].Certificate != leaf {
		t.Error("every target must be the certificate")
	}
	for _, f := range res.Findings {
		if f.Entry == 1 {
			t.Errorf("the request got an evaluation finding: %+v", f)
		}
	}
}

// TestRequestOnlyInputIsInspected: an input of requests only does not get
// input.no_certificates, and evaluations have nothing to evaluate.
func TestRequestOnlyInputIsInspected(t *testing.T) {
	req, err := hostname.ParseRequest("api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	res, err := inspectsvc.New(testNow, inspectsvc.WithHostname(req), inspectsvc.WithPurpose(purpose.TLSServer)).
		InspectFile(filepath.Join(corpus, "csr.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.Highest != "" {
		t.Errorf("findings %v", findingKeys(res.Findings))
	}
	if res.Hostname.State != inspectsvc.HostnameEvaluated || len(res.Hostname.Targets) != 0 || len(res.Purpose.Targets) != 0 {
		t.Errorf("hostname %+v purpose %+v", res.Hostname, res.Purpose)
	}

	// A request label around bytes that are not a request is still a
	// request entry: unparseable, critical, and not "no certificates".
	res, err = service().InspectBytes(inspectsvc.Source{Kind: inspectsvc.SourceStdin, Locator: "-"},
		[]byte("-----BEGIN CERTIFICATE REQUEST-----\nMAA=\n-----END CERTIFICATE REQUEST-----\n"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Artifacts[0].Type != inspectsvc.TypeUnparseableCertificateRequest || res.Artifacts[0].UnparseableRequest == nil {
		t.Errorf("artifact %+v", res.Artifacts[0])
	}
	if got := findingKeys(res.Findings); !slices.Equal(got, []string{"0:input.unparseable_certificate_request:critical"}) {
		t.Errorf("findings %v", got)
	}
}

// TestRootsRefuseRequests: a certificate signing request is never a trust
// anchor, in whatever form it appears in a roots file.
func TestRootsRefuseRequests(t *testing.T) {
	for name, entry := range map[string]string{
		"csr.pem": "entry 0", "csr.der": "entry 0", "csr-legacy-label.pem": "entry 0", "csr-with-leaf.pem": "entry 1",
	} {
		_, err := inspectsvc.LoadRoots([]string{filepath.Join(corpus, name)})
		if !errors.Is(err, inspectsvc.ErrRoots) || !strings.Contains(err.Error(), entry+" is a certificate request, not a certificate") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
