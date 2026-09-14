package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strings"
)

// Reason is a stable code for a failed probe. Raw engine errors are never
// part of the contract.
type Reason string

const (
	ReasonNone                   Reason = ""
	ReasonDNSError               Reason = "dns_error"
	ReasonConnectRefused         Reason = "connect_refused"
	ReasonConnectTimeout         Reason = "connect_timeout"
	ReasonHandshakeTimeout       Reason = "handshake_timeout"
	ReasonTLSNegotiationFailed   Reason = "tls_negotiation_failed"
	ReasonNotTLS                 Reason = "not_tls"
	ReasonConnectionClosed       Reason = "connection_closed"
	ReasonCertificateUnparseable Reason = "certificate_unparseable_by_engine"
	ReasonEngineError            Reason = "engine_error"
)

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
		(errors.As(err, &netErr) && netErr.Timeout())
}

// classifyDial maps a dial error to a stage and reason. Only reliably
// identifiable failures are named; anything else is engine_error.
func classifyDial(err error) (Stage, Reason) {
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr):
		return StageResolve, ReasonDNSError
	case isTimeout(err):
		return StageConnect, ReasonConnectTimeout
	case isRefused(err):
		return StageConnect, ReasonConnectRefused
	}
	return StageConnect, ReasonEngineError
}

// peerCertificateParseError is how crypto/tls reports a server certificate
// its parser rejected. It is the only engine message this package reads, and
// probe_test.go pins it.
const peerCertificateParseError = "tls: failed to parse certificate from server"

// classifyHandshake maps a handshake error to a reason and acquisition state.
func classifyHandshake(err error) (Reason, Acquisition) {
	var header tls.RecordHeaderError
	var op *net.OpError
	switch {
	case isTimeout(err):
		return ReasonHandshakeTimeout, AcquisitionNone
	case errors.As(err, &header):
		return ReasonNotTLS, AcquisitionNone
	case errors.As(err, &op) && op.Op == "remote error":
		// The server sent a TLS alert: it refused what the policy offered.
		return ReasonTLSNegotiationFailed, AcquisitionNone
	case strings.HasPrefix(err.Error(), peerCertificateParseError):
		return ReasonCertificateUnparseable, AcquisitionUnverifiable
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), isReset(err):
		return ReasonConnectionClosed, AcquisitionNone
	}
	return ReasonEngineError, AcquisitionNone
}
