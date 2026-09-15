package cli_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/cli"
	"github.com/Hazame-hub/trustsmith/internal/probe"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
)

// Endpoint tests reach in-process servers only: the dialer ignores the
// address asked for, records it, and connects to a loopback listener.

type endpointServer struct {
	mu      sync.Mutex
	dialled []string
	sni     []string
}

func (s *endpointServer) record(list *[]string, v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	*list = append(*list, v)
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func (s *endpointServer) dialTo(addr string) probe.DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		s.record(&s.dialled, address)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
}

// endpointChainDER is tls-endpoint.pem: leaf (RFC 9500 key), intermediate, root.
func endpointChainDER(t *testing.T) [][]byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "certs", "tls-endpoint.pem"))
	if err != nil {
		t.Fatal(err)
	}
	var ders [][]byte
	for b, rest := pem.Decode(data); b != nil; b, rest = pem.Decode(rest) {
		ders = append(ders, b.Bytes)
	}
	return ders
}

// serveTLSEndpoint serves the leaf and intermediate of tls-endpoint.pem.
func serveTLSEndpoint(t *testing.T) (*endpointServer, probe.DialFunc) {
	t.Helper()
	s := &endpointServer{}
	ln := listen(t)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: endpointChainDER(t)[:2], PrivateKey: testpki.RFC9500P256Key(t)}},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			s.record(&s.sni, h.ServerName)
			return nil, nil
		},
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				tc := tls.Server(conn, cfg)
				if tc.Handshake() == nil {
					_, _ = tc.Read(make([]byte, 1))
				}
			}()
		}
	}()
	return s, s.dialTo(ln.Addr().String())
}

// refusedDial connects to a loopback port nothing listens on.
func refusedDial(t *testing.T) probe.DialFunc {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return (&endpointServer{}).dialTo(addr)
}

// plainDial connects to a server that answers with an SSH banner.
func plainDial(t *testing.T) probe.DialFunc {
	t.Helper()
	ln := listen(t)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Read(make([]byte, 1024))
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.9\r\n"))
		time.Sleep(200 * time.Millisecond)
	}()
	return (&endpointServer{}).dialTo(ln.Addr().String())
}

func runDial(t *testing.T, dial probe.DialFunc, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := cli.Run(args, bytes.NewReader(nil), &out, &errOut, cli.Env{
		Now:     func() time.Time { return testpki.Now },
		Version: "v0.0.0-test",
		Dial:    dial,
	})
	return code, out.String(), errOut.String()
}

var endpointGoldens = []struct {
	name   string
	dial   func(t *testing.T) probe.DialFunc
	args   []string
	code   int
	stderr string
}{
	{"endpoint-complete", tlsDial, []string{"inspect", "api.example.test:443"}, 0, ""},
	{"endpoint-roots", tlsDial, []string{"inspect", "--roots", "testdata/roots/tls-endpoint-root.pem", "tls://api.example.test"}, 0, ""},
	{"endpoint-wrong-roots", tlsDial, []string{"inspect", "--roots", "testdata/roots/unrelated-root.pem", "api.example.test:443"}, 3, ""},
	{"endpoint-hostname-mismatch", tlsDial, []string{"inspect", "other.example.test:443"}, 3, ""},
	{"endpoint-ip", tlsDial, []string{"inspect", "192.0.2.10:443"}, 0, ""},
	{"endpoint-refused", refusedDial, []string{"inspect", "api.example.test:443"}, 1, "connect_refused"},
	{"endpoint-not-tls", plainDial, []string{"inspect", "api.example.test:443"}, 1, "not_tls"},
}

func tlsDial(t *testing.T) probe.DialFunc {
	_, dial := serveTLSEndpoint(t)
	return dial
}

func TestEndpointGoldens(t *testing.T) {
	chdirRoot(t)
	for _, tc := range endpointGoldens {
		t.Run(tc.name, func(t *testing.T) {
			for _, output := range []string{"text", "json"} {
				code, out, stderr := runDial(t, tc.dial(t), append([]string{"--output", output}, tc.args...)...)
				if code != tc.code {
					t.Errorf("%s: exit %d, want %d (stderr %q)", output, code, tc.code, stderr)
				}
				if (tc.stderr == "") != (stderr == "") || !strings.Contains(stderr, tc.stderr) {
					t.Errorf("%s: stderr %q, want it to mention %q", output, stderr, tc.stderr)
				}
				if output == "json" {
					if !json.Valid([]byte(out)) {
						t.Fatalf("invalid JSON:\n%s", out)
					}
					golden(t, tc.name+".json", out)
				} else {
					golden(t, tc.name+".txt", out)
				}
			}
		})
	}
}

type jsonEndpointDoc struct {
	Input struct {
		Kind    string `json:"kind"`
		Locator string `json:"locator"`
		Format  string `json:"format"`
	} `json:"input"`
	Probe *struct {
		Kind     string `json:"kind"`
		Endpoint struct {
			Host string `json:"host"`
			Port int    `json:"port"`
			Kind string `json:"kind"`
		} `json:"endpoint"`
		State                  string  `json:"state"`
		Stage                  string  `json:"stage"`
		Reason                 *string `json:"reason"`
		CertificateAcquisition string  `json:"certificate_acquisition"`
		Policy                 struct {
			Name              string   `json:"name"`
			Version           int      `json:"version"`
			MinVersion        string   `json:"min_version"`
			MaxVersion        string   `json:"max_version"`
			TLS12CipherSuites []string `json:"tls12_cipher_suites"`
			TLS13CipherSuites string   `json:"tls13_cipher_suites"`
			SignatureSchemes  string   `json:"signature_schemes"`
			Groups            []string `json:"groups"`
			ALPN              []string `json:"alpn"`
		} `json:"policy"`
		Engine struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"engine"`
		SNI        *string `json:"sni"`
		Negotiated *struct {
			Version          string  `json:"version"`
			CipherSuite      string  `json:"cipher_suite"`
			KeyExchangeGroup *string `json:"key_exchange_group"`
			ALPN             *string `json:"alpn"`
		} `json:"negotiated"`
		PeerCertificateCount int `json:"peer_certificate_count"`
	} `json:"probe"`
	Artifacts []struct {
		Entry   int    `json:"entry"`
		Locator string `json:"locator"`
	} `json:"artifacts"`
	PurposeEvaluation struct {
		Requested string `json:"requested"`
		Source    string `json:"source"`
		State     string `json:"state"`
	} `json:"purpose_evaluation"`
	HostnameEvaluation struct {
		State      string  `json:"state"`
		Source     *string `json:"source"`
		Requested  *string `json:"requested"`
		Normalized *string `json:"normalized"`
		Targets    []struct {
			State string `json:"state"`
		} `json:"targets"`
	} `json:"hostname_evaluation"`
	TrustEvaluation struct {
		State string `json:"state"`
	} `json:"trust_evaluation"`
	Findings []struct {
		Code string `json:"code"`
	} `json:"findings"`
}

func decodeEndpoint(t *testing.T, out string) jsonEndpointDoc {
	t.Helper()
	var d jsonEndpointDoc
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return d
}

func TestEndpointJSONContract(t *testing.T) {
	chdirRoot(t)
	srv, dial := serveTLSEndpoint(t)
	code, out, stderr := runDial(t, dial, "inspect", "--output", "json", "api.example.test:443")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	d := decodeEndpoint(t, out)
	p := d.Probe
	if d.Input.Kind != "endpoint" || d.Input.Locator != "tls://api.example.test:443" || d.Input.Format != "tls_peer_certificates" || p == nil {
		t.Fatalf("input %+v probe %v", d.Input, p)
	}
	if p.Kind != "tls" || p.Endpoint.Host != "api.example.test" || p.Endpoint.Port != 443 || p.Endpoint.Kind != "dns" ||
		p.State != "complete" || p.Stage != "complete" || p.Reason != nil || p.CertificateAcquisition != "acquired" {
		t.Errorf("probe %+v", p)
	}
	pol := p.Policy
	if pol.Name != "modern" || pol.Version != 1 || pol.MinVersion != "TLS 1.2" || pol.MaxVersion != "TLS 1.3" ||
		pol.TLS13CipherSuites != "engine_managed" || pol.SignatureSchemes != "engine_managed" || len(pol.ALPN) != 0 ||
		!slices.Equal(pol.Groups, []string{"X25519MLKEM768", "X25519", "CurveP256", "CurveP384"}) || len(pol.TLS12CipherSuites) != 6 {
		t.Errorf("policy %+v", pol)
	}
	for _, s := range pol.TLS12CipherSuites {
		aead := strings.Contains(s, "_GCM_") || strings.Contains(s, "CHACHA20_POLY1305")
		if !strings.HasPrefix(s, "TLS_ECDHE_") || !aead {
			t.Errorf("suite %s", s)
		}
	}
	if p.Engine.Name != "go" || !strings.HasPrefix(p.Engine.Version, "go") {
		t.Errorf("engine %+v", p.Engine)
	}
	if p.SNI == nil || *p.SNI != "api.example.test" || p.Negotiated == nil || p.Negotiated.Version != "TLS 1.3" || p.Negotiated.ALPN != nil || p.PeerCertificateCount != 2 {
		t.Errorf("negotiated %+v sni %v count %d", p.Negotiated, p.SNI, p.PeerCertificateCount)
	}
	if len(d.Artifacts) != 2 || d.Artifacts[1].Locator != "tls://api.example.test:443#peer-1" {
		t.Errorf("artifacts %+v", d.Artifacts)
	}
	if d.PurposeEvaluation.Requested != "tls-server" || d.PurposeEvaluation.Source != "endpoint" ||
		d.HostnameEvaluation.Source == nil || *d.HostnameEvaluation.Source != "endpoint" || d.TrustEvaluation.State != "not_evaluated" {
		t.Errorf("evaluations %+v %+v", d.PurposeEvaluation, d.HostnameEvaluation)
	}
	if srv.sni[0] != "api.example.test" {
		t.Errorf("sni %q", srv.sni)
	}

	var raw map[string]any
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatal(err)
	}
	for k := range raw["probe"].(map[string]any) {
		for _, verdict := range []string{"secure", "valid", "trusted", "verified", "ok", "success"} {
			if strings.Contains(k, verdict) {
				t.Errorf("probe key %q reads as a verdict", k)
			}
		}
	}
}

func TestEndpointDerivedIntentAndOverrides(t *testing.T) {
	chdirRoot(t)
	_, dial := serveTLSEndpoint(t)

	_, out, _ := runDial(t, dial, "inspect", "--output", "json", "--fail-on", "never", "--purpose", "tls-client", "api.example.test:443")
	d := decodeEndpoint(t, out)
	if d.PurposeEvaluation.Requested != "tls-client" || d.PurposeEvaluation.Source != "explicit" || d.Probe.State != "complete" {
		t.Errorf("--purpose override: %+v", d.PurposeEvaluation)
	}

	_, out, _ = runDial(t, dial, "inspect", "--output", "json", "--fail-on", "never", "--hostname", "other.example.test", "api.example.test:443")
	d = decodeEndpoint(t, out)
	if h := d.HostnameEvaluation; *h.Source != "explicit" || *h.Requested != "other.example.test" || h.Targets[0].State != "mismatch" {
		t.Errorf("--hostname override: %+v", h)
	}
	if d.PurposeEvaluation.Source != "endpoint" || d.Probe.SNI == nil || *d.Probe.SNI != "api.example.test" {
		t.Error("--hostname must not change the purpose or the SNI sent")
	}

	// A file keeps the file defaults.
	_, out, _ = run(t, nil, "inspect", "--output", "json", "testdata/certs/leaf.pem")
	d = decodeEndpoint(t, out)
	if d.Probe != nil || d.PurposeEvaluation.Source != "default" || d.PurposeEvaluation.Requested != "any" || d.HostnameEvaluation.Source != nil {
		t.Errorf("file inspection: probe %v purpose %+v hostname %+v", d.Probe, d.PurposeEvaluation, d.HostnameEvaluation)
	}
}

func TestEndpointUnicodeAndIP(t *testing.T) {
	chdirRoot(t)
	srv, dial := serveTLSEndpoint(t)
	code, out, _ := runDial(t, dial, "inspect", "--output", "json", "tls://Bücher.example")
	d := decodeEndpoint(t, out)
	if code != 0 || srv.dialled[0] != "xn--bcher-kva.example:443" || srv.sni[0] != "xn--bcher-kva.example" ||
		*d.Probe.SNI != "xn--bcher-kva.example" || d.HostnameEvaluation.Targets[0].State != "matched" {
		t.Errorf("unicode endpoint: exit %d dialled %q sni %q", code, srv.dialled, srv.sni)
	}

	code, out, _ = runDial(t, dial, "inspect", "--output", "json", "[2001:db8::1]:8443")
	d = decodeEndpoint(t, out)
	if srv.dialled[1] != "[2001:db8::1]:8443" || srv.sni[1] != "" || d.Probe.SNI != nil || d.Probe.Endpoint.Kind != "ip" {
		t.Errorf("IPv6 endpoint: dialled %q sni %q", srv.dialled, srv.sni)
	}
	if code != 3 || d.HostnameEvaluation.Targets[0].State != "mismatch" {
		t.Errorf("an IP address not in the certificate is a finding (exit 3), got exit %d", code)
	}
}

// An existing file always wins over an endpoint reading of the same argument.
func TestExistingFileWinsOverEndpoint(t *testing.T) {
	leaf, err := os.ReadFile(filepath.Join("..", "..", "testdata", "certs", "leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	if err := os.WriteFile("api.example.test", leaf, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := run(t, nil, "inspect", "--output", "json", "api.example.test")
	if d := decodeEndpoint(t, out); code != 0 || stderr != "" || d.Input.Kind != "file" || d.Probe != nil {
		t.Errorf("exit %d stderr %q input %+v", code, stderr, d.Input)
	}
}
