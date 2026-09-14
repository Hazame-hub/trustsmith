// Package probe acquires a TLS server's certificates and negotiated connection
// facts.
//
// It is a diagnostic acquisition layer. It completes a TLS handshake with
// InsecureSkipVerify set, so that Go's own verifier does not end the handshake
// before Trustsmith can inspect what the server presented. InsecureSkipVerify
// is used only to collect peer certificate material for diagnostics:
// Trustsmith evaluates trust and host name identity separately, in the
// inspection pipeline, and reports them independently. A completed handshake
// says nothing about trust, identity or suitability.
//
// The probe sends no application data and makes no HTTP request: it closes
// the connection as soon as the handshake completes. It uses no system roots
// and no GODEBUG settings, and it makes no certificate-policy decisions.
package probe

import (
	"context"
	"crypto/tls"
	"net"
	"runtime"
	"slices"
	"time"
)

// Default timeouts. Every network stage is bounded.
const (
	DefaultConnectTimeout   = 10 * time.Second
	DefaultHandshakeTimeout = 10 * time.Second
)

// DialFunc opens the TCP connection. Tests replace it; nil uses a net.Dialer.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Target is where to connect and what to send.
type Target struct {
	// Address is the host and port to connect to.
	Address string
	// ServerName is the TLS server name indication to send. It is empty for
	// an IP address: no SNI is sent then.
	ServerName string
}

// Options configure a probe.
type Options struct {
	Policy           Policy
	ConnectTimeout   time.Duration
	HandshakeTimeout time.Duration
	// Now is the clock, used for elapsed time and tls.Config.Time. Required.
	Now  func() time.Time
	Dial DialFunc
}

// Stage is how far a probe got.
type Stage string

const (
	StageResolve   Stage = "resolve"
	StageConnect   Stage = "connect"
	StageHandshake Stage = "handshake"
	StageComplete  Stage = "complete"
)

// State is the probe outcome.
type State string

const (
	StateComplete State = "complete"
	StateFailed   State = "failed"
)

// Acquisition says whether peer certificates were obtained.
type Acquisition string

const (
	AcquisitionAcquired Acquisition = "acquired"
	// AcquisitionNone: no certificate was received.
	AcquisitionNone Acquisition = "not_acquired"
	// AcquisitionUnverifiable: the server sent certificates, but Go's TLS
	// engine could not parse them, so none could be acquired for inspection.
	AcquisitionUnverifiable Acquisition = "unverifiable"
)

// Negotiated are the connection facts of a completed handshake.
type Negotiated struct {
	Version           uint16
	CipherSuite       uint16
	Group             tls.CurveID // key exchange group, as reported by crypto/tls
	ALPN              string
	HelloRetryRequest bool
	DidResume         bool
}

// Result of Run.
type Result struct {
	Target        Target
	Policy        Policy
	EngineVersion string
	State         State
	Stage         Stage
	Reason        Reason // ReasonNone when complete
	Acquisition   Acquisition
	// PeerCertificates are the certificates the server sent, as DER, in the
	// order it sent them. Empty unless acquired.
	PeerCertificates [][]byte
	Negotiated       *Negotiated // nil unless complete
	// ClientCertificateRequested: the server asked for a client certificate.
	// None was sent.
	ClientCertificateRequested bool
	Elapsed                    time.Duration
	HandshakeElapsed           time.Duration
}

// Run connects to t and completes one TLS handshake under o.Policy.
func Run(ctx context.Context, t Target, o Options) Result {
	res := Result{
		Target: t, Policy: o.Policy, EngineVersion: runtime.Version(),
		Acquisition: AcquisitionNone, PeerCertificates: [][]byte{},
	}
	start := o.Now()
	finish := func() Result {
		res.Elapsed = o.Now().Sub(start)
		return res
	}

	dial := o.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	connectCtx, cancelConnect := context.WithTimeout(ctx, o.ConnectTimeout)
	raw, err := dial(connectCtx, "tcp", t.Address)
	cancelConnect()
	if err != nil {
		res.State = StateFailed
		res.Stage, res.Reason = classifyDial(err)
		return finish()
	}
	defer func() { _ = raw.Close() }()

	requested := false
	conn := tls.Client(raw, clientConfig(o.Policy, t.ServerName, o.Now, &requested))
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, o.HandshakeTimeout)
	handshakeStart := o.Now()
	err = conn.HandshakeContext(handshakeCtx)
	cancelHandshake()
	res.HandshakeElapsed = o.Now().Sub(handshakeStart)
	res.ClientCertificateRequested = requested
	if err != nil {
		res.State, res.Stage = StateFailed, StageHandshake
		res.Reason, res.Acquisition = classifyHandshake(err)
		return finish()
	}

	cs := conn.ConnectionState()
	for _, c := range cs.PeerCertificates {
		res.PeerCertificates = append(res.PeerCertificates, slices.Clone(c.Raw))
	}
	res.Negotiated = &Negotiated{
		Version: cs.Version, CipherSuite: cs.CipherSuite, Group: cs.CurveID,
		ALPN: cs.NegotiatedProtocol, HelloRetryRequest: cs.HelloRetryRequest, DidResume: cs.DidResume,
	}
	res.State, res.Stage, res.Reason = StateComplete, StageComplete, ReasonNone
	if len(res.PeerCertificates) > 0 {
		res.Acquisition = AcquisitionAcquired
	}
	// No application data is sent: Close sends only the close_notify alert.
	_ = conn.Close()
	return finish()
}
