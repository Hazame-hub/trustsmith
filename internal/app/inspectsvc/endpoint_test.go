package inspectsvc_test

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/endpoint"
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/hostname"
	"github.com/Hazame-hub/trustsmith/internal/probe"
	"github.com/Hazame-hub/trustsmith/internal/purpose"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
	"github.com/Hazame-hub/trustsmith/internal/trustverify"
)

// endpointChain is tls-endpoint.pem: leaf, intermediate, root.
func endpointChain(t *testing.T) [][]byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(corpus, "tls-endpoint.pem"))
	if err != nil {
		t.Fatal(err)
	}
	var ders [][]byte
	for {
		var b *pem.Block
		if b, data = pem.Decode(data); b == nil {
			break
		}
		ders = append(ders, b.Bytes)
	}
	if len(ders) != 3 {
		t.Fatalf("tls-endpoint.pem holds %d certificates", len(ders))
	}
	return ders
}

// tlsEndpoint serves chain on loopback and returns a dialer that reaches it
// whatever address is dialled, the addresses dialled and the SNI received.
type tlsEndpoint struct {
	mu      sync.Mutex
	dialled []string
	sni     []string
}

func serveEndpoint(t *testing.T, chain [][]byte) (*tlsEndpoint, probe.DialFunc) {
	t.Helper()
	return serveEndpointWith(t, chain, nil)
}

// serveEndpointWith is serveEndpoint with the server configuration adjusted by
// configure, e.g. to accept only some cipher suites.
func serveEndpointWith(t *testing.T, chain [][]byte, configure func(*tls.Config)) (*tlsEndpoint, probe.DialFunc) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	e := &tlsEndpoint{}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: testpki.RFC9500P256Key(t)}},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			e.mu.Lock()
			e.sni = append(e.sni, h.ServerName)
			e.mu.Unlock()
			return nil, nil
		},
	}
	if configure != nil {
		configure(cfg)
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
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		e.mu.Lock()
		e.dialled = append(e.dialled, address)
		e.mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}
	return e, dial
}

func inspectEndpoint(t *testing.T, target string, dial probe.DialFunc, opts ...inspectsvc.Option) inspectsvc.Result {
	t.Helper()
	ep, err := endpoint.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	settings := inspectsvc.DefaultProbeSettings()
	settings.Dial = dial
	opts = append([]inspectsvc.Option{inspectsvc.WithProbeSettings(settings)}, opts...)
	return inspectsvc.New(testNow, opts...).InspectEndpoint(context.Background(), ep)
}

func rootsFile(t *testing.T, name string) inspectsvc.Option {
	t.Helper()
	roots, err := inspectsvc.LoadRoots([]string{filepath.Join("..", "..", "..", "testdata", "roots", name)})
	if err != nil {
		t.Fatal(err)
	}
	return inspectsvc.WithRoots(roots)
}

func wantAcquired(t *testing.T, res inspectsvc.Result, certificates int) {
	t.Helper()
	if res.Probe == nil || res.Probe.State != probe.StateComplete || res.Probe.Acquisition != probe.AcquisitionAcquired {
		t.Fatalf("probe %+v", res.Probe)
	}
	if res.Source.Kind != inspectsvc.SourceEndpoint || res.Format != inspectsvc.FormatTLSPeerCertificates || len(res.Artifacts) != certificates {
		t.Fatalf("source %+v format %q, %d artifacts", res.Source, res.Format, len(res.Artifacts))
	}
	for i, a := range res.Artifacts {
		if want := res.Source.Locator + "#peer-" + string(rune('0'+i)); a.Locator != want || a.Entry != i || a.Type != inspectsvc.TypeCertificate {
			t.Errorf("artifact %d: locator %q entry %d type %q", i, a.Locator, a.Entry, a.Type)
		}
	}
	if res.RecoveredPanics != 0 {
		t.Error("recovered panics")
	}
}

func onlyHostnameResult(t *testing.T, res inspectsvc.Result) hostname.Result {
	t.Helper()
	if res.Hostname.State != inspectsvc.HostnameEvaluated || len(res.Hostname.Targets) != 1 {
		t.Fatalf("hostname evaluation %+v", res.Hostname)
	}
	return res.Hostname.Targets[0].Result
}

func TestEndpointDerivesPurposeAndHostname(t *testing.T) {
	chain := endpointChain(t)
	srv, dial := serveEndpoint(t, chain[:2])
	res := inspectEndpoint(t, "api.example.test:443", dial)
	wantAcquired(t, res, 2)

	if res.Source.Locator != "tls://api.example.test:443" || res.Artifacts[0].Locator != "tls://api.example.test:443#peer-0" {
		t.Errorf("locators %q %q", res.Source.Locator, res.Artifacts[0].Locator)
	}
	if res.Purpose.Requested != purpose.TLSServer || res.Purpose.Source != inspectsvc.PurposeSourceEndpoint || res.Purpose.State != inspectsvc.PurposeEvaluated {
		t.Errorf("purpose %+v", res.Purpose)
	}
	if res.Hostname.Source != inspectsvc.HostnameSourceEndpoint || res.Hostname.Request.Normalized != "api.example.test" {
		t.Errorf("hostname %+v", res.Hostname)
	}
	if r := onlyHostnameResult(t, res); r.State != hostname.Matched {
		t.Errorf("hostname result %+v", r)
	}
	if res.Trust.State != inspectsvc.TrustNotEvaluated {
		t.Errorf("trust evaluated without roots: %+v", res.Trust)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings %v", findingKeys(res.Findings))
	}
	if srv.sni[0] != "api.example.test" || srv.dialled[0] != "api.example.test:443" {
		t.Errorf("sni %q dialled %q", srv.sni, srv.dialled)
	}
}

func TestEndpointExplicitPurposeOverridesDerived(t *testing.T) {
	chain := endpointChain(t)
	_, dial := serveEndpoint(t, chain[:2])
	base := inspectEndpoint(t, "api.example.test:443", dial)
	for _, p := range []purpose.Purpose{purpose.TLSClient, purpose.Any} {
		res := inspectEndpoint(t, "api.example.test:443", dial, inspectsvc.WithPurpose(p))
		wantAcquired(t, res, 2)
		if res.Purpose.Requested != p || res.Purpose.Source != inspectsvc.PurposeSourceExplicit {
			t.Errorf("--purpose %s: %+v", p, res.Purpose)
		}
		// A purpose never changes how certificates are acquired.
		if *res.Probe.Negotiated != *base.Probe.Negotiated || res.Probe.Policy.Name != base.Probe.Policy.Name {
			t.Errorf("--purpose %s changed the handshake: %+v vs %+v", p, res.Probe.Negotiated, base.Probe.Negotiated)
		}
	}
	res := inspectEndpoint(t, "api.example.test:443", dial, inspectsvc.WithPurpose(purpose.TLSClient))
	if codes := findingKeys(res.Findings); !slices.Contains(codes, "0:purpose.eku_disallows_usage:critical") {
		t.Errorf("tls-client findings %v", codes)
	}
	if res = inspectEndpoint(t, "api.example.test:443", dial, inspectsvc.WithPurpose(purpose.Any)); res.Purpose.State != inspectsvc.PurposeNotEvaluated {
		t.Errorf("explicit any: %+v", res.Purpose)
	}
}

func TestEndpointExplicitHostnameOverridesDerived(t *testing.T) {
	chain := endpointChain(t)
	srv, dial := serveEndpoint(t, chain[:2])
	req, err := hostname.ParseRequest("other.example.test")
	if err != nil {
		t.Fatal(err)
	}
	res := inspectEndpoint(t, "api.example.test:443", dial, inspectsvc.WithHostname(req))
	wantAcquired(t, res, 2)
	if res.Hostname.Source != inspectsvc.HostnameSourceExplicit || onlyHostnameResult(t, res).State != hostname.Mismatch {
		t.Errorf("hostname %+v", res.Hostname)
	}
	// The host name to check is separate from where the probe connects and
	// what it sends as SNI.
	if srv.sni[0] != "api.example.test" || srv.dialled[0] != "api.example.test:443" {
		t.Errorf("sni %q dialled %q", srv.sni, srv.dialled)
	}
}

func TestEndpointHostnameMismatchIsAFindingNotAFailure(t *testing.T) {
	chain := endpointChain(t)
	_, dial := serveEndpoint(t, chain[:2])
	res := inspectEndpoint(t, "other.example.test:443", dial)
	wantAcquired(t, res, 2)
	if onlyHostnameResult(t, res).State != hostname.Mismatch {
		t.Error("expected a mismatch")
	}
	if codes := findingKeys(res.Findings); !slices.Equal(codes, []string{"0:name.hostname_mismatch:critical"}) {
		t.Errorf("findings %v", codes)
	}
}

func TestEndpointIPAddress(t *testing.T) {
	chain := endpointChain(t)
	srv, dial := serveEndpoint(t, chain[:2])
	res := inspectEndpoint(t, "192.0.2.10:8443", dial)
	wantAcquired(t, res, 2)
	if r := onlyHostnameResult(t, res); r.State != hostname.Matched || res.Hostname.Request.Kind != hostname.KindIP {
		t.Errorf("hostname %+v", res.Hostname)
	}
	if srv.sni[0] != "" || srv.dialled[0] != "192.0.2.10:8443" || res.Probe.Target.ServerName != "" {
		t.Errorf("an IP endpoint must send no SNI: sni %q dialled %q", srv.sni, srv.dialled)
	}
}

func TestEndpointUnicodeHostUsesIDNABeforeSNI(t *testing.T) {
	chain := endpointChain(t)
	srv, dial := serveEndpoint(t, chain[:2])
	res := inspectEndpoint(t, "tls://Bücher.example:443", dial)
	wantAcquired(t, res, 2)
	if srv.sni[0] != "xn--bcher-kva.example" || srv.dialled[0] != "xn--bcher-kva.example:443" {
		t.Errorf("sni %q dialled %q", srv.sni, srv.dialled)
	}
	if r := onlyHostnameResult(t, res); r.State != hostname.Matched || res.Hostname.Request.Input != "Bücher.example" {
		t.Errorf("hostname %+v", res.Hostname)
	}
}

func TestEndpointTrustUsesOnlySuppliedRoots(t *testing.T) {
	chain := endpointChain(t)
	_, dial := serveEndpoint(t, chain[:2])

	res := inspectEndpoint(t, "api.example.test:443", dial, rootsFile(t, "tls-endpoint-root.pem"))
	wantAcquired(t, res, 2)
	if res.Trust.State != inspectsvc.TrustEvaluated || res.Trust.Purpose != purpose.TLSServer || len(res.Trust.Targets) != 1 ||
		res.Trust.Targets[0].Result.State != trustverify.Verified {
		t.Fatalf("correct roots: %+v", res.Trust)
	}

	res = inspectEndpoint(t, "api.example.test:443", dial, rootsFile(t, "unrelated-root.pem"))
	wantAcquired(t, res, 2) // the handshake succeeds regardless of trust
	if len(res.Trust.Targets) != 1 || res.Trust.Targets[0].Result.State != trustverify.Failed {
		t.Fatalf("wrong roots: %+v", res.Trust)
	}
	if res.Highest != findings.SeverityCritical {
		t.Errorf("highest %q", res.Highest)
	}
}

func TestEndpointPeerCertificatesKeepOrderAndDuplicates(t *testing.T) {
	chain := endpointChain(t)
	_, dial := serveEndpoint(t, [][]byte{chain[0], chain[1], chain[1], chain[2]})
	res := inspectEndpoint(t, "api.example.test:443", dial)
	wantAcquired(t, res, 4)
	for i, want := range [][]byte{chain[0], chain[1], chain[1], chain[2]} {
		if string(res.Probe.PeerCertificates[i]) != string(want) {
			t.Errorf("peer certificate %d out of order", i)
		}
	}
	if got := relationshipKeys(res); !slices.Equal(got, []string{"[0]->[1 2]:verified", "[1 2]->[3]:verified"}) {
		t.Errorf("relationships %v", got)
	}
}

func TestEndpointFailureInspectsNothing(t *testing.T) {
	refused := func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("unexpected")}
	}
	res := inspectEndpoint(t, "api.example.test:443", refused, rootsFile(t, "tls-endpoint-root.pem"))
	if res.Probe == nil || res.Probe.State != probe.StateFailed || res.Probe.Acquisition != probe.AcquisitionNone {
		t.Fatalf("probe %+v", res.Probe)
	}
	if len(res.Artifacts) != 0 || len(res.Findings) != 0 || res.Highest != "" || len(res.Relationships) != 0 || len(res.Paths) != 0 {
		t.Errorf("a failed acquisition must inspect nothing: %+v", res)
	}
	if len(res.Trust.Targets) != 0 || len(res.Purpose.Targets) != 0 || len(res.Hostname.Targets) != 0 {
		t.Error("evaluations without certificates must have no targets")
	}
	if res.Purpose.Source != inspectsvc.PurposeSourceEndpoint || res.Hostname.Source != inspectsvc.HostnameSourceEndpoint {
		t.Error("derived sources are recorded even when acquisition fails")
	}
}

func TestFileInspectionHasNoProbeOrDerivedIntent(t *testing.T) {
	res := inspectHost(t, "leaf.pem", "")
	if res.Probe != nil || res.Purpose.Source != inspectsvc.PurposeSourceDefault || res.Purpose.Requested != purpose.Any ||
		res.Hostname.State != inspectsvc.HostnameNotEvaluated || res.Hostname.Source != "" || res.Artifacts[0].Locator != "" {
		t.Errorf("file inspection changed: probe %v purpose %+v hostname %+v", res.Probe, res.Purpose, res.Hostname)
	}
	res = inspectHost(t, "leaf.pem", "api.example.test", inspectsvc.WithPurpose(purpose.TLSServer))
	if res.Purpose.Source != inspectsvc.PurposeSourceExplicit || res.Hostname.Source != inspectsvc.HostnameSourceExplicit {
		t.Errorf("explicit sources: %+v %+v", res.Purpose, res.Hostname)
	}
}
