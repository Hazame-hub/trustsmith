// Package endpoint parses a TLS endpoint named on the command line. It only
// parses: it resolves nothing and connects to nothing.
//
// Accepted forms are host:port, [IPv6]:port and tls://host:port, and the same
// without a port, which defaults to 443. The host is validated and normalised
// by the hostname package, so an internationalised name becomes the same
// ASCII identity that host name evaluation uses.
package endpoint

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Hazame-hub/trustsmith/internal/hostname"
)

// DefaultPort is used when an endpoint names no port.
const DefaultPort = 443

// ErrInvalid marks an argument that is not a supported TLS endpoint.
var ErrInvalid = errors.New("invalid endpoint")

// Endpoint is a parsed TLS endpoint.
type Endpoint struct {
	Input string           // exactly as supplied
	Host  hostname.Request // validated host: normalised DNS name or canonical IP address
	Port  int
}

// Address is the host and port to connect to, with IPv6 addresses bracketed.
func (e Endpoint) Address() string {
	host := e.Host.Normalized
	if e.Host.Kind == hostname.KindIP && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(e.Port)
}

// ServerName is the TLS server name to send (SNI): the normalised ASCII DNS
// name, or empty for an IP address, which is never sent as SNI.
func (e Endpoint) ServerName() string {
	if e.Host.Kind != hostname.KindDNS {
		return ""
	}
	return e.Host.Normalized
}

// Locator is the endpoint in the canonical tls://host:port form.
func (e Endpoint) Locator() string { return "tls://" + e.Address() }

// Parse parses s as a TLS endpoint.
//
//   - The only scheme is tls://. Any other scheme (https:// included) is
//     refused: Trustsmith speaks no application protocol.
//   - User information, paths, queries and fragments are refused, never
//     stripped.
//   - An IPv6 address must be bracketed when a port follows.
//   - The port is decimal, 1 to 65535; without one, DefaultPort applies.
//   - The host must pass hostname.ParseRequest.
func Parse(s string) (Endpoint, error) {
	fail := func(format string, args ...any) (Endpoint, error) {
		return Endpoint{}, fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
	}
	rest := s
	if i := strings.Index(s, "://"); i >= 0 {
		if !strings.EqualFold(s[:i], "tls") {
			return fail("%q: unsupported scheme %q; use tls://host:port (Trustsmith sends no application protocol)", s, s[:i])
		}
		rest = s[i+len("://"):]
	}
	switch {
	case rest == "":
		return fail("%q names no host", s)
	case strings.ContainsAny(rest, "/?#@"):
		return fail("%q contains user information, a path, a query or a fragment; give only host and port", s)
	}

	host, port := rest, DefaultPort
	switch {
	case strings.HasPrefix(rest, "["):
		end := strings.Index(rest, "]")
		if end < 0 {
			return fail("%q: missing ']' after an IPv6 address", s)
		}
		host = rest[:end+1]
		if after := rest[end+1:]; after != "" {
			if !strings.HasPrefix(after, ":") {
				return fail("%q: unexpected text after ']'", s)
			}
			p, err := parsePort(after[1:])
			if err != nil {
				return fail("%q: %v", s, err)
			}
			port = p
		}
	case strings.Count(rest, ":") == 1:
		i := strings.LastIndex(rest, ":")
		p, err := parsePort(rest[i+1:])
		if err != nil {
			return fail("%q: %v", s, err)
		}
		host, port = rest[:i], p
	case strings.Count(rest, ":") > 1:
		return fail("%q: write an IPv6 endpoint as [address]:port", s)
	}

	req, err := hostname.ParseRequest(host)
	if err != nil {
		return fail("%q: %v", s, err)
	}
	return Endpoint{Input: s, Host: req, Port: port}, nil
}

func parsePort(p string) (int, error) {
	if p == "" || len(p) > 5 || strings.Trim(p, "0123456789") != "" {
		return 0, fmt.Errorf("port %q is not a number from 1 to 65535", p)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %q is not a number from 1 to 65535", p)
	}
	return n, nil
}
