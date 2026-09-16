package probe_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/probe"
)

// --- in-process servers -----------------------------------------------------

type serverSide struct {
	hello     *tls.ClientHelloInfo // nil when the handshake never reached ClientHello processing
	appData   []byte               // decrypted bytes the client sent after the handshake
	raw       []byte               // every byte the client sent on the wire
	handshake error
}

type recordingConn struct {
	net.Conn
	raw *bytes.Buffer
}

func (c recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.raw.Write(p[:n])
	return n, err
}

// serve accepts one connection on a loopback listener and hands it to handle.
func serve(t *testing.T, handle func(conn net.Conn, raw *bytes.Buffer) serverSide) (string, <-chan serverSide) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	out := make(chan serverSide, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			out <- serverSide{handshake: err}
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		raw := &bytes.Buffer{}
		s := handle(recordingConn{conn, raw}, raw)
		s.raw = raw.Bytes()
		out <- s
	}()
	return ln.Addr().String(), out
}

// serveTLS runs a TLS server with cfg, records the ClientHello and reads
// whatever application data the client sends until it closes.
func serveTLS(t *testing.T, cfg *tls.Config) (string, <-chan serverSide) {
	t.Helper()
	return serve(t, func(conn net.Conn, _ *bytes.Buffer) serverSide {
		var s serverSide
		c := cfg.Clone()
		c.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			s.hello = h
			return nil, nil
		}
		tc := tls.Server(conn, c)
		if s.handshake = tc.Handshake(); s.handshake != nil {
			return s
		}
		s.appData, _ = io.ReadAll(tc)
		return s
	})
}

func receive(t *testing.T, ch <-chan serverSide) serverSide {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(15 * time.Second):
		t.Fatal("server did not finish")
		return serverSide{}
	}
}

// --- certificates -----------------------------------------------------------

type issued struct {
	der  []byte
	cert *x509.Certificate
	key  any
}

func issue(t *testing.T, cn string, parent *issued, ca bool, key any) *issued {
	t.Helper()
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if ca {
		tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, x509.KeyUsageCertSign
	} else {
		tmpl.DNSNames = []string{"api.example.test"}
		tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	pub := key.(crypto.Signer).Public()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, pub, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &issued{der: der, cert: c, key: key}
}

func leafCertificate(t *testing.T) (tls.Certificate, *issued) {
	t.Helper()
	leaf := issue(t, "api.example.test", nil, false, nil)
	return tls.Certificate{Certificate: [][]byte{leaf.der}, PrivateKey: leaf.key}, leaf
}

// --- probe helpers ----------------------------------------------------------

func options() probe.Options {
	return probe.Options{
		Policy:           probe.ModernV1(),
		ConnectTimeout:   5 * time.Second,
		HandshakeTimeout: 5 * time.Second,
		Now:              time.Now,
	}
}

func run(t *testing.T, addr, serverName string, o probe.Options) probe.Result {
	t.Helper()
	return probe.Run(context.Background(), probe.Target{Address: addr, ServerName: serverName}, o)
}

func wantFailure(t *testing.T, r probe.Result, stage probe.Stage, reason probe.Reason) {
	t.Helper()
	if r.State != probe.StateFailed || r.Stage != stage || r.Reason != reason {
		t.Fatalf("got state %q stage %q reason %q, want failed at %q with %q", r.State, r.Stage, r.Reason, stage, reason)
	}
	if r.Negotiated != nil {
		t.Errorf("a failed probe must not report negotiated parameters: %+v", r.Negotiated)
	}
	if r.Reason != probe.ReasonCertificateUnparseable {
		if r.Acquisition != probe.AcquisitionNone || len(r.PeerCertificates) != 0 {
			t.Errorf("no certificate was received, got acquisition %q with %d certificates", r.Acquisition, len(r.PeerCertificates))
		}
	}
}

func wantComplete(t *testing.T, r probe.Result) {
	t.Helper()
	if r.State != probe.StateComplete || r.Stage != probe.StageComplete || r.Reason != probe.ReasonNone || r.Negotiated == nil {
		t.Fatalf("probe did not complete: %+v", r)
	}
}

// --- tests ------------------------------------------------------------------

func TestTLS13Handshake(t *testing.T) {
	cert, leaf := leafCertificate(t)
	addr, srv := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	r := run(t, addr, "api.example.test", options())
	wantComplete(t, r)
	if r.Negotiated.Version != tls.VersionTLS13 {
		t.Errorf("version %s, want TLS 1.3", tls.VersionName(r.Negotiated.Version))
	}
	if !slices.Contains(probe.ModernV1().CurvePreferences, r.Negotiated.Group) {
		t.Errorf("group %v is not in the modern policy", r.Negotiated.Group)
	}
	if r.Acquisition != probe.AcquisitionAcquired || len(r.PeerCertificates) != 1 || !bytes.Equal(r.PeerCertificates[0], leaf.der) {
		t.Errorf("peer certificate not acquired: %q %d", r.Acquisition, len(r.PeerCertificates))
	}
	if r.Policy.Name != "modern" || r.Policy.Version != 1 || !strings.HasPrefix(r.EngineVersion, "go") {
		t.Errorf("policy %s v%d engine %q", r.Policy.Name, r.Policy.Version, r.EngineVersion)
	}
	receive(t, srv)
}

func TestTLS12ECDHEGCMHandshake(t *testing.T) {
	cert, _ := leafCertificate(t)
	addr, srv := serveTLS(t, &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
	})
	r := run(t, addr, "api.example.test", options())
	wantComplete(t, r)
	if r.Negotiated.Version != tls.VersionTLS12 || r.Negotiated.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {
		t.Errorf("negotiated %s %s", tls.VersionName(r.Negotiated.Version), tls.CipherSuiteName(r.Negotiated.CipherSuite))
	}
	receive(t, srv)
}

// Servers that only accept what the modern policy refuses to offer fail the
// handshake; the probe never retries with a weaker policy.
func TestModernPolicyRefusesLegacyServers(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaLeaf := issue(t, "api.example.test", nil, false, rsaKey)
	rsaCert := tls.Certificate{Certificate: [][]byte{rsaLeaf.der}, PrivateKey: rsaKey}
	for name, cfg := range map[string]*tls.Config{
		"tls1.0 only": {MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10},
		"rsa key exchange only": {MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_128_CBC_SHA}},
		"cbc only": {MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}},
		"3des only": {MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg.Certificates = []tls.Certificate{rsaCert}
			addr, srv := serveTLS(t, cfg)
			r := run(t, addr, "api.example.test", options())
			wantFailure(t, r, probe.StageHandshake, probe.ReasonTLSNegotiationFailed)
			if s := receive(t, srv); s.handshake == nil {
				t.Error("the server completed a handshake it should have refused")
			}
		})
	}
}

func TestServerNameIndication(t *testing.T) {
	cert, _ := leafCertificate(t)
	for _, tc := range []struct{ name, serverName string }{
		{"dns name", "api.example.test"},
		{"idna a-label", "xn--bcher-kva.example"},
		{"ip address sends none", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, srv := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}})
			r := run(t, addr, tc.serverName, options())
			wantComplete(t, r)
			s := receive(t, srv)
			if s.hello == nil || s.hello.ServerName != tc.serverName {
				t.Fatalf("server saw SNI %q, want %q", s.hello.ServerName, tc.serverName)
			}
			if r.Target.ServerName != tc.serverName {
				t.Errorf("result records SNI %q, want %q", r.Target.ServerName, tc.serverName)
			}
		})
	}
}

func TestNoALPNAndNoApplicationData(t *testing.T) {
	cert, _ := leafCertificate(t)
	addr, srv := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
	r := run(t, addr, "api.example.test", options())
	wantComplete(t, r)
	if r.Negotiated.ALPN != "" {
		t.Errorf("ALPN %q negotiated", r.Negotiated.ALPN)
	}
	s := receive(t, srv)
	if len(s.hello.SupportedProtos) != 0 {
		t.Errorf("client offered ALPN %q", s.hello.SupportedProtos)
	}
	if len(s.appData) != 0 {
		t.Errorf("client sent %d bytes of application data: %q", len(s.appData), s.appData)
	}
	for _, http := range []string{"GET ", "HEAD ", "HTTP/", "PRI * HTTP/2"} {
		if bytes.Contains(s.raw, []byte(http)) {
			t.Errorf("client sent %q on the wire", http)
		}
	}
}

func TestPeerCertificatesKeepServerOrder(t *testing.T) {
	root := issue(t, "Root", nil, true, nil)
	inter := issue(t, "Intermediate", root, true, nil)
	leaf := issue(t, "api.example.test", inter, false, nil)
	for name, chain := range map[string][][]byte{
		"leaf intermediate root": {leaf.der, inter.der, root.der},
		"unusual order":          {leaf.der, root.der, inter.der},
		"duplicates":             {leaf.der, inter.der, inter.der},
	} {
		t.Run(name, func(t *testing.T) {
			addr, srv := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: leaf.key}}})
			r := run(t, addr, "api.example.test", options())
			wantComplete(t, r)
			if !slices.EqualFunc(r.PeerCertificates, chain, bytes.Equal) {
				t.Errorf("peer certificates differ from what the server sent, in content or order")
			}
			receive(t, srv)
		})
	}
}

// The probe completes against a server whose certificate nobody trusts: no
// verification, and so no system roots, is involved in acquisition.
func TestAcquisitionDoesNotVerify(t *testing.T) {
	cert, _ := leafCertificate(t)
	addr, srv := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	r := run(t, addr, "not-the-certificate-name.example", options())
	wantComplete(t, r)
	receive(t, srv)
}

func TestClientCertificateRequestIsRecorded(t *testing.T) {
	cert, _ := leafCertificate(t)
	for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(v), func(t *testing.T) {
			addr, srv := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequestClientCert, MaxVersion: v})
			r := run(t, addr, "api.example.test", options())
			wantComplete(t, r)
			if !r.ClientCertificateRequested {
				t.Error("certificate request not recorded")
			}
			if s := receive(t, srv); s.handshake == nil {
				// The client presented no certificate.
				if len(s.appData) != 0 {
					t.Error("application data sent")
				}
			}
		})
	}
}

func TestConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	r := run(t, addr, "", options())
	wantFailure(t, r, probe.StageConnect, probe.ReasonConnectRefused)
}

func TestConnectTimeout(t *testing.T) {
	o := options()
	o.ConnectTimeout = 50 * time.Millisecond
	var deadlineSet bool
	o.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		_, deadlineSet = ctx.Deadline()
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: ctx.Err()}
	}
	r := run(t, "192.0.2.1:443", "", o)
	wantFailure(t, r, probe.StageConnect, probe.ReasonConnectTimeout)
	if !deadlineSet {
		t.Error("the connect context carries no deadline")
	}
}

func TestDialFailuresAreClassifiedNarrowly(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		stage  probe.Stage
		reason probe.Reason
	}{
		"dns":     {&net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "x.invalid", IsNotFound: true}}, probe.StageResolve, probe.ReasonDNSError},
		"unknown": {errors.New("something unexpected"), probe.StageConnect, probe.ReasonEngineError},
	} {
		t.Run(name, func(t *testing.T) {
			o := options()
			o.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, tc.err }
			wantFailure(t, run(t, "x.invalid:443", "x.invalid", o), tc.stage, tc.reason)
		})
	}
}

func TestHandshakeTimeout(t *testing.T) {
	addr, srv := serve(t, func(conn net.Conn, _ *bytes.Buffer) serverSide {
		_, _ = io.Copy(io.Discard, conn) // read the ClientHello and never answer
		return serverSide{}
	})
	o := options()
	o.HandshakeTimeout = 200 * time.Millisecond
	r := run(t, addr, "api.example.test", o)
	wantFailure(t, r, probe.StageHandshake, probe.ReasonHandshakeTimeout)
	receive(t, srv)
}

func TestPlainTCPServerIsNotTLS(t *testing.T) {
	addr, srv := serve(t, func(conn net.Conn, raw *bytes.Buffer) serverSide {
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.9\r\n"))
		time.Sleep(100 * time.Millisecond)
		return serverSide{}
	})
	r := run(t, addr, "api.example.test", options())
	wantFailure(t, r, probe.StageHandshake, probe.ReasonNotTLS)
	s := receive(t, srv)
	if len(s.raw) == 0 || s.raw[0] != 0x16 {
		t.Errorf("the client's first bytes are not a TLS handshake record: % x", s.raw[:min(len(s.raw), 8)])
	}
	if bytes.Contains(s.raw, []byte("HTTP")) {
		t.Error("the client sent HTTP bytes")
	}
}

func TestServerClosesDuringHandshake(t *testing.T) {
	addr, srv := serve(t, func(conn net.Conn, _ *bytes.Buffer) serverSide {
		buf := make([]byte, 5) // part of the ClientHello record header, then hang up
		_, _ = io.ReadFull(conn, buf)
		return serverSide{}
	})
	r := run(t, addr, "api.example.test", options())
	wantFailure(t, r, probe.StageHandshake, probe.ReasonConnectionClosed)
	receive(t, srv)
}

// A server certificate that Go's parser rejects ends the handshake inside
// crypto/tls. Nothing can be acquired, and that is reported as unverifiable
// acquisition, not as a bad certificate.
func TestEngineRejectedCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	malformed := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	addr, srv := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{malformed}, PrivateKey: key}}})
	r := run(t, addr, "api.example.test", options())
	if r.State != probe.StateFailed || r.Stage != probe.StageHandshake || r.Reason != probe.ReasonCertificateUnparseable {
		t.Fatalf("got %q %q %q", r.State, r.Stage, r.Reason)
	}
	if r.Acquisition != probe.AcquisitionUnverifiable || len(r.PeerCertificates) != 0 {
		t.Errorf("acquisition %q with %d certificates", r.Acquisition, len(r.PeerCertificates))
	}
	receive(t, srv)
}

func TestElapsedUsesInjectedClock(t *testing.T) {
	cert, _ := leafCertificate(t)
	addr, srv := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	o := options()
	fixed := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	o.Now = func() time.Time { return fixed }
	r := run(t, addr, "api.example.test", o)
	wantComplete(t, r)
	if r.Elapsed != 0 || r.HandshakeElapsed != 0 {
		t.Errorf("elapsed %v / %v with a fixed clock", r.Elapsed, r.HandshakeElapsed)
	}
	receive(t, srv)
}

func TestPolicyByName(t *testing.T) {
	if p, err := probe.PolicyByName("modern"); err != nil || p.Name != "modern" || p.Version != 1 {
		t.Fatalf("modern: %+v %v", p, err)
	}
	for _, name := range []string{"", "Modern", "legacy", "legacy-diagnostic", "modern-v1"} {
		if _, err := probe.PolicyByName(name); !errors.Is(err, probe.ErrUnknownPolicy) {
			t.Errorf("PolicyByName(%q) = %v", name, err)
		}
	}
}
