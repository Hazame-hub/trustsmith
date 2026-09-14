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
// This package validates and normalises the requested name, including IDNA
// conversion of internationalised names, and turns Go's answer into a stable
// result. It implements no matching of its own and never rewrites names taken
// from a certificate.
package hostname

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// MaxRawInputBytes is a safety bound on the raw requested value, checked
// before any normalisation. It is deliberately generous and is not the DNS
// length limit: IDNA conversion can lengthen or shorten a name, so the DNS
// limits (63 bytes per label, 253 bytes for the name) are enforced on the ASCII
// result by the profile's VerifyDNSLength.
const MaxRawInputBytes = 1024

// dnsProfile is Trustsmith's IDNA profile for requested DNS names. It is spelled
// out option by option instead of using idna.Lookup, whose configuration may
// change between releases, because host name normalisation is part of
// Trustsmith's stable behaviour. In golang.org/x/net v0.59.0:
//   - MapForLookup: UTS #46 mapping for lookup (case folding, width and
//     compatibility mappings, NFC). It also enables StrictDomainName and
//     ValidateLabels, which are listed again below to make the profile
//     explicit;
//   - BidiRule: the RFC 5893 Bidi rule, applied when a name has right-to-left
//     labels;
//   - Transitional(false): deviation characters (ß, ς, ZWJ, ZWNJ) are kept and
//     encoded, never mapped (ß is not mapped to "ss");
//   - StrictDomainName(true): STD3 ASCII rules (letters, digits and hyphens
//     only; no underscore, no "*");
//   - ValidateLabels(true): label validity, including hyphen positions (no
//     leading or trailing hyphen, no "--" in positions 3 and 4 outside valid
//     A-labels) and the CONTEXTJ rules for joiners;
//   - VerifyDNSLength(true): after conversion, labels are 1 to 63 bytes and
//     the name at most 253 bytes; empty labels are errors, and so is a
//     terminal root dot.
//
// The behaviour is pinned by profile_internal_test.go.
var dnsProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.Transitional(false),
	idna.StrictDomainName(true),
	idna.ValidateLabels(true),
	idna.VerifyDNSLength(true),
)

// Kind is what the request names.
type Kind string

const (
	KindDNS Kind = "dns"
	KindIP  Kind = "ip"
)

// Request is a validated host name or IP address to match.
type Request struct {
	Input      string // exactly as supplied, for display
	Normalized string // what is matched: canonical IP text or an ASCII DNS name
	Kind       Kind
}

// ErrInvalid marks a requested name that is not a host name or IP address.
var ErrInvalid = errors.New("invalid host name")

// ParseRequest validates s and normalises it for matching, in this order:
//
//  1. Syntactic refusal of the raw value: empty, longer than MaxRawInputBytes,
//     invalid UTF-8, whitespace or control characters, a URL scheme, path,
//     query, fragment, user information, or a wildcard. Components are never
//     stripped.
//  2. IP literals are recognised on the raw value: IPv4, IPv6, or IPv6 in
//     brackets, normalised to canonical text. Zones are refused. IP literals
//     never go through IDNA.
//  3. Anything else with a colon is refused (a port, or a malformed address).
//  4. A DNS name loses one terminal root dot and is converted by dnsProfile.ToASCII,
//     which maps, validates and length-checks it. The result is lower-case
//     ASCII; for example "Bücher.example." becomes "xn--bcher-kva.example".
//  5. A result whose last label is all digits is refused: it is neither a DNS
//     name nor an IP literal (for example full-width digits that map to
//     "192.0.2.10").
func ParseRequest(s string) (Request, error) {
	fail := func(format string, args ...any) (Request, error) {
		return Request{}, fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
	}
	switch {
	case s == "":
		return fail("empty")
	case len(s) > MaxRawInputBytes:
		return fail("longer than %d bytes", MaxRawInputBytes)
	case !utf8.ValidString(s):
		return fail("not valid UTF-8")
	case strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0:
		return fail("%q contains whitespace or control characters", s)
	case strings.Contains(s, "://"):
		return fail("%q contains a URL scheme; give only the host name or IP address", s)
	case strings.ContainsAny(s, `/\?#@`):
		return fail("%q contains a path or other URL component; give only the host name or IP address", s)
	case strings.Contains(s, "*"):
		return fail("%q: a wildcard is not a host name", s)
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

	// The profile's VerifyDNSLength treats a terminal root dot as an error, so
	// one is removed first: "api.example.com." requests "api.example.com".
	name := strings.TrimSuffix(s, ".")
	if name == "" {
		return fail("%q has no labels", s)
	}
	ascii, err := dnsProfile.ToASCII(name)
	if err != nil {
		return fail("%q is not a valid host name (%v)", s, err)
	}
	if last := ascii[strings.LastIndexByte(ascii, '.')+1:]; strings.Trim(last, "0123456789") == "" {
		return fail("%q: an all-numeric last label is neither a DNS name nor a valid IP address", s)
	}
	return Request{Input: s, Normalized: ascii, Kind: KindDNS}, nil
}

func ipRequest(input string, addr netip.Addr) (Request, error) {
	if addr.Zone() != "" {
		return Request{}, fmt.Errorf("%w: %q has an IPv6 zone, which no certificate can identify", ErrInvalid, input)
	}
	return Request{Input: input, Normalized: addr.String(), Kind: KindIP}, nil
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
		res.CommonNameIgnored = r.Kind == KindDNS && c.Subject.CommonName != "" &&
			(strings.EqualFold(c.Subject.CommonName, r.Normalized) || strings.EqualFold(c.Subject.CommonName, r.Input))
	default:
		res.State, res.Reason = Unverifiable, ReasonEngineError
	}
	return res
}
