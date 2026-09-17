package inspectsvc

import (
	"context"
	"fmt"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/artifact"
	"github.com/Hazame-hub/trustsmith/internal/endpoint"
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/interpret"
	"github.com/Hazame-hub/trustsmith/internal/probe"
	"github.com/Hazame-hub/trustsmith/internal/purpose"
)

// FormatTLSPeerCertificates is the input format of an endpoint inspection:
// the certificates a TLS server presented, as DER, in the order it sent them.
// Offsets are positions in their concatenation.
const FormatTLSPeerCertificates artifact.Format = "tls_peer_certificates"

// ProbeSettings configure how endpoint certificates are acquired.
type ProbeSettings struct {
	Policy           probe.Policy
	ConnectTimeout   time.Duration
	HandshakeTimeout time.Duration
	// Dial replaces the TCP dialer; nil dials the endpoint. Tests use it to
	// reach in-process servers.
	Dial probe.DialFunc
}

// DefaultProbeSettings are the modern policy and the default timeouts.
func DefaultProbeSettings() ProbeSettings {
	return ProbeSettings{
		Policy:           probe.ModernV1(),
		ConnectTimeout:   probe.DefaultConnectTimeout,
		HandshakeTimeout: probe.DefaultHandshakeTimeout,
	}
}

// WithProbeSettings sets how endpoint certificates are acquired.
func WithProbeSettings(p ProbeSettings) Option {
	return func(s *Service) { s.probe = p }
}

// InspectEndpoint acquires the certificates a TLS endpoint presents and
// inspects them with the same pipeline as a file.
//
// Unless requested explicitly, the purpose is tls-server and the host name is
// the endpoint's host; the evaluations record which applied. Acquisition uses
// no trust decision of its own: trust, purpose and host name identity are
// evaluated afterwards, by the same layers as for files.
//
// When no certificate was acquired, nothing is inspected and no certificate
// finding is made: Result.Probe says why. Otherwise the negotiated transport
// parameters are interpreted too (interpret.Transport).
//
// The probe makes exactly one handshake, under the configured policy. A
// failure is reported as it is and never retried with another policy.
func (s *Service) InspectEndpoint(ctx context.Context, e endpoint.Endpoint) Result {
	derived := *s
	if derived.purposeSource != PurposeSourceExplicit {
		derived.purpose, derived.purposeSource = purpose.TLSServer, PurposeSourceEndpoint
	}
	if derived.hostnameSource != HostnameSourceExplicit {
		host := e.Host
		derived.hostname, derived.hostnameSource = &host, HostnameSourceEndpoint
	}

	acquired := probe.Run(ctx, probe.Target{Address: e.Address(), ServerName: e.ServerName()}, probe.Options{
		Policy:           s.probe.Policy,
		ConnectTimeout:   s.probe.ConnectTimeout,
		HandshakeTimeout: s.probe.HandshakeTimeout,
		Now:              s.now,
		Dial:             s.probe.Dial,
	})
	locator := e.Locator()
	decoded := artifact.Decoded{Format: FormatTLSPeerCertificates, Blocks: []artifact.Block{}}
	size := 0
	for i, der := range acquired.PeerCertificates {
		decoded.Blocks = append(decoded.Blocks, artifact.Block{Entry: i, Kind: artifact.KindCertificate, Offset: size, DER: der})
		size += len(der)
	}
	res := Result{
		Source:      Source{Kind: SourceEndpoint, Locator: locator},
		Size:        size,
		Format:      FormatTLSPeerCertificates,
		InspectedAt: s.now().UTC(),
		Probe:       &acquired,
		Endpoint:    &e,
	}

	if acquired.Acquisition != probe.AcquisitionAcquired {
		res.Artifacts, res.Findings = []Artifact{}, []findings.Finding{}
		res.Trust = derived.evaluateTrust(nil, nil, res.InspectedAt)
		res.Purpose = derived.evaluatePurpose(nil, res.Trust)
		res.Hostname = derived.evaluateHostname(nil)
		return res
	}
	res = derived.inspectDecoded(res, decoded)
	for i := range res.Artifacts {
		res.Artifacts[i].Locator = fmt.Sprintf("%s#peer-%d", locator, res.Artifacts[i].Entry)
	}
	res.Findings = append(res.Findings, interpret.Transport(transportFacts(acquired))...)
	finishFindings(&res)
	return res
}

// transportFacts hands interpretation the negotiated parameters as plain
// values.
func transportFacts(r probe.Result) interpret.TransportFacts {
	t := interpret.TransportFacts{Policy: r.Policy.ID(), Features: []string{}}
	if n := r.Negotiated; n != nil {
		t.Negotiated, t.Version, t.CipherSuite = true, n.VersionName(), n.CipherSuiteName()
		for _, f := range n.CompatibilityFeatures() {
			t.Features = append(t.Features, string(f))
		}
	}
	return t
}
