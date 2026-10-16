package cli_test

import (
	"encoding/json"
	"strings"
	"testing"
)

// Certificate signing requests (ADR-0011): advanced text, and evaluations
// requested next to a request, which never include it as a target.
func TestRequestGoldens(t *testing.T) {
	chdirRoot(t)
	for _, name := range []string{"csr.pem", "csr-ca.pem", "csr-md5.pem"} {
		t.Run(name+" advanced", func(t *testing.T) {
			_, text, _ := run(t, nil, "inspect", "--fail-on", "never", "--advanced", "testdata/certs/"+name)
			golden(t, name+".advanced.txt", text)
		})
	}
	args := []string{"inspect", "--fail-on", "never", "--roots", "testdata/roots/test-root.pem",
		"--purpose", "tls-server", "--hostname", "api.example.test", "testdata/certs/csr-with-leaf.pem"}
	_, text, stderr := run(t, nil, args...)
	if stderr != "" {
		t.Fatalf("stderr: %s", stderr)
	}
	golden(t, "csr-with-leaf-evaluations.txt", text)
	_, js, _ := run(t, nil, append(args, "--output", "json")...)
	golden(t, "csr-with-leaf-evaluations.json", js)
}

type jsonRequestDoc struct {
	Overview struct {
		Certificates        int `json:"certificates"`
		CertificateRequests int `json:"certificate_requests"`
	} `json:"overview"`
	Artifacts []struct {
		Type         string             `json:"type"`
		Fingerprints map[string]*string `json:"fingerprints"`
		KeyIdentity  struct {
			Status string `json:"status"`
		} `json:"key_identity"`
		Summary *json.RawMessage `json:"summary"`
		Request *struct {
			Requests             []string `json:"requests"`
			Signature            string   `json:"signature"`
			SignatureCheck       string   `json:"signature_check"`
			SignatureCheckReason string   `json:"signature_check_reason"`
			KeyUsage             []string `json:"key_usage"`
			ExtendedKeyUsage     []string `json:"extended_key_usage"`
			Attributes           []struct {
				OID string `json:"oid"`
			} `json:"attributes"`
		} `json:"request"`
	} `json:"artifacts"`
	Findings []struct {
		Code string `json:"code"`
	} `json:"findings"`
}

func decodeRequest(t *testing.T, path string) jsonRequestDoc {
	t.Helper()
	_, out, _ := run(t, nil, "inspect", "--output", "json", "--fail-on", "never", path)
	var d jsonRequestDoc
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return d
}

func TestRequestJSONContract(t *testing.T) {
	chdirRoot(t)
	d := decodeRequest(t, "testdata/certs/csr.pem")
	if d.Overview.Certificates != 0 || d.Overview.CertificateRequests != 1 || len(d.Artifacts) != 1 || len(d.Findings) != 0 {
		t.Fatalf("overview %+v artifacts %d findings %+v", d.Overview, len(d.Artifacts), d.Findings)
	}
	a := d.Artifacts[0]
	if a.Type != "certificate_request" || a.Summary != nil || a.Request == nil {
		t.Fatalf("artifact %+v", a)
	}
	// A request has the two key schemes only: x509-cert-sha256 identifies
	// certificates.
	if _, ok := a.Fingerprints["x509-cert-sha256"]; ok {
		t.Error("a request must not carry x509-cert-sha256")
	}
	for _, scheme := range []string{"x509-spki-sha256", "x509-spki-encoded-sha256"} {
		if v := a.Fingerprints[scheme]; v == nil || len(*v) != 64 {
			t.Errorf("fingerprint %s: %v", scheme, v)
		}
	}
	r := a.Request
	if r.SignatureCheck != "verified" || r.SignatureCheckReason != "" || r.Signature != "ECDSA-SHA256" ||
		strings.Join(r.Requests, ",") != "api.example.test,www.example.test,192.0.2.10" ||
		strings.Join(r.KeyUsage, ",") != "digitalSignature" || strings.Join(r.ExtendedKeyUsage, ",") != "serverAuth" ||
		len(r.Attributes) != 1 || a.KeyIdentity.Status != "canonical" {
		t.Errorf("request %+v", r)
	}

	if d := decodeRequest(t, "testdata/certs/csr-bad-signature.pem"); d.Artifacts[0].Request.SignatureCheck != "does_not_verify" ||
		d.Artifacts[0].Request.SignatureCheckReason != "signature_mismatch" {
		t.Errorf("corrupt signature: %+v", d.Artifacts[0].Request)
	}

	// A certificate next to a request is counted apart from it.
	if d := decodeRequest(t, "testdata/certs/csr-with-leaf.pem"); d.Overview.Certificates != 1 || d.Overview.CertificateRequests != 1 {
		t.Errorf("overview %+v", d.Overview)
	}
}

func TestRequestExitCodes(t *testing.T) {
	chdirRoot(t)
	for path, want := range map[string]int{
		"testdata/certs/csr.pem":               0,
		"testdata/certs/csr-bad-signature.pem": 3,
		"testdata/certs/csr-rsa-1024.pem":      3,
	} {
		if code, _, stderr := run(t, nil, "inspect", path); code != want {
			t.Errorf("%s: exit %d, want %d (%s)", path, code, want, stderr)
		}
	}
	code, _, stderr := run(t, nil, "inspect", "--roots", "testdata/certs/csr.pem", "testdata/certs/leaf.pem")
	if code != 1 || !strings.Contains(stderr, "certificate request, not a certificate") {
		t.Errorf("a request as --roots: exit %d, stderr %q", code, stderr)
	}
}
