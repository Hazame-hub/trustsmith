// Package hostname answers one question: does a certificate identify the host
// name or IP address the user explicitly supplied?
//
// That is separate from signer relationships, included paths, trust
// evaluation and purpose evaluation. A certificate may match a host name and
// still fail any of those, and the reverse.
//
// Matching is delegated entirely to Go's (*x509.Certificate).VerifyHostname:
//   - only subject alternative names are used, never the Common Name;
//   - an IP address request matches only IP address SANs;
//   - a DNS request matches DNS SANs case-insensitively (ASCII);
//   - a wildcard matches only as the complete left-most label of a SAN.
//
// This package validates and normalises the requested name, and turns Go's
// answer into a stable result. It implements no matching of its own.
package hostname

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// MaxInputLength bounds a requested name in bytes. A DNS name is at most 253
// bytes, plus an optional root dot.
const MaxInputLength = 255

// Kind is what the request names.
type Kind string

const (
	KindDNS Kind = "dns"
	KindIP  Kind = "ip"
)

// Request is a validated host name or IP address to match.
type Request struct {
	Input      string // exactly as supplied, for display
	Normalized string // what is matched
	Kind       Kind
}

// ErrInvalid marks a requested name that is not a host name or IP address.
var ErrInvalid = errors.New("invalid host name")

// ParseRequest validates s and normalises it for matching.
//
//   - Components are refused, never stripped: a URL scheme, path, query,
//     user information or port is an error.
//   - IP addresses are recognised first. Plain or bracketed IPv6 and IPv4 are
//     normalised to their canonical text form. Zones are refused.
//   - A DNS name loses one terminal root dot and is lower-cased (ASCII).
//     Labels must be non-empty, at most 63 bytes, made of letters, digits,
//     hyphens and underscores (Go's matcher accepts underscores), and must not
//     start or end with a hyphen. The whole name is at most 253 bytes. A
//     wildcard is not a host name, and an all-numeric last label is refused
//     because it is neither a DNS name nor a valid IP address.
//   - Non-ASCII names are refused until internationalised host names are
//     supported.
func ParseRequest(s string) (Request, error) {
	fail := func(format string, args ...any) (Request, error) {
		return Request{}, fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
	}
	switch {
	case s == "":
		return fail("empty")
	case len(s) > MaxInputLength:
		return fail("longer than %d bytes", MaxInputLength)
	case strings.Contains(s, "://"):
		return fail("%q contains a URL scheme; give only the host name or IP address", s)
	case strings.ContainsAny(s, "/?#@"):
		return fail("%q contains a path or other URL component; give only the host name or IP address", s)
	case strings.IndexFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f }) >= 0:
		return fail("%q contains whitespace or control characters", s)
	}

	if strings.HasPrefix(s, "[") {
		if !strings.HasSuffix(s, "]") {
			return fail("%q: a bracketed address must end with ']' and carry no port", s)
		}
		addr, err := netip.ParseAddr(s[1 : len(s)-1])
		if err != nil || !addr.Is6() {
			return fail("%q: only an IPv6 address may be written in brackets", s)
		}
		return ipRequest(s, addr)
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return ipRequest(s, addr)
	}
	if strings.Contains(s, ":") {
		return fail("%q contains a port or is not a valid IP address; give only the host name or IP address", s)
	}

	name := strings.TrimSuffix(s, ".")
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			// Pending decision: internationalised names need IDNA (UTS #46)
			// conversion, which Go's matcher does not perform.
			return fail("%q is not ASCII: internationalised host names are not supported yet; give the A-label (xn--) form", s)
		}
	}
	name = strings.ToLower(name)
	if err := checkDNSName(name); err != nil {
		return fail("%q: %v", s, err)
	}
	return Request{Input: s, Normalized: name, Kind: KindDNS}, nil
}

func ipRequest(input string, addr netip.Addr) (Request, error) {
	if addr.Zone() != "" {
		return Request{}, fmt.Errorf("%w: %q has an IPv6 zone, which no certificate can identify", ErrInvalid, input)
	}
	return Request{Input: input, Normalized: addr.String(), Kind: KindIP}, nil
}

func checkDNSName(name string) error {
	if name == "" {
		return errors.New("empty")
	}
	if len(name) > 253 {
		return errors.New("longer than 253 bytes")
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		switch {
		case label == "":
			return errors.New("empty label")
		case len(label) > 63:
			return errors.New("label longer than 63 bytes")
		case strings.Contains(label, "*"):
			return errors.New("a wildcard is not a host name")
		case label[0] == '-' || label[len(label)-1] == '-':
			return errors.New("label starts or ends with a hyphen")
		}
		for _, c := range label {
			if !isLabelChar(c) {
				return fmt.Errorf("label %q contains %q", label, c)
			}
		}
	}
	if last := labels[len(labels)-1]; strings.Trim(last, "0123456789") == "" {
		return errors.New("an all-numeric last label is neither a DNS name nor a valid IP address")
	}
	return nil
}

// State is the outcome of matching one certificate.
type State string

const (
	// NotEvaluated: no host name was requested.
	NotEvaluated State = "not_evaluated"
	// Matched: Go's matcher found a subject alternative name for the request.
	Matched State = "matched"
	// Mismatch: no subject alternative name identifies the request.
	Mismatch State = "mismatch"
	// Unverifiable: the certificate could not be matched at all.
	Unverifiable State = "unverifiable"
)

// Reason is a stable code for an unverifiable result.
type Reason string

const (
	ReasonNone           Reason = ""
	ReasonNotParsed      Reason = "certificate_not_parsed"
	ReasonInvalidRequest Reason = "invalid_request"
	ReasonEngineError    Reason = "engine_error"
)

// Result of Evaluate. Lists are never nil.
type Result struct {
	State  State
	Reason Reason
	// DNSNames and IPAddresses are the certificate's subject alternative
	// names as encoded (IP addresses in text form); they are never rewritten.
	DNSNames    []string
	IPAddresses []string
	// CommonNameIgnored: a DNS request did not match, and the certificate's
	// Common Name equals the requested name. The Common Name is never used to
	// identify a host.
	CommonNameIgnored bool
}

// Evaluate matches c against r with Go's VerifyHostname.
func Evaluate(c *x509.Certificate, r Request) Result {
	res := Result{DNSNames: []string{}, IPAddresses: []string{}}
	switch {
	case c == nil:
		res.State, res.Reason = Unverifiable, ReasonNotParsed
		return res
	case r.Normalized == "" || (r.Kind != KindDNS && r.Kind != KindIP):
		res.State, res.Reason = Unverifiable, ReasonInvalidRequest
		return res
	}
	res.DNSNames = append(res.DNSNames, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		res.IPAddresses = append(res.IPAddresses, ip.String())
	}

	var mismatch x509.HostnameError
	switch err := c.VerifyHostname(r.Normalized); {
	case err == nil:
		res.State = Matched
	case errors.As(err, &mismatch):
		res.State = Mismatch
		res.CommonNameIgnored = r.Kind == KindDNS && c.Subject.CommonName != "" && strings.EqualFold(c.Subject.CommonName, r.Normalized)
	default:
		res.State, res.Reason = Unverifiable, ReasonEngineError
	}
	return res
}

// isLabelChar reports a byte allowed in a normalised DNS label: lower-case
// letters, digits, hyphens and underscores.
func isLabelChar(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}
