package cli

import (
	"net"
	"net/netip"
	"path/filepath"
	"strings"
)

type targetKind string

const (
	targetStdin    targetKind = "stdin"
	targetFile     targetKind = "file"
	targetEndpoint targetKind = "endpoint"
)

var certificateFileExtensions = map[string]bool{
	".pem": true, ".crt": true, ".cer": true, ".cert": true, ".der": true,
	".key": true, ".csr": true, ".p7b": true, ".p12": true, ".pfx": true, ".txt": true,
}

// resolveTarget decides whether an inspect argument names standard input, a
// file or a network endpoint. In order:
//  1. "-" is standard input;
//  2. an existing path is a file;
//  3. Windows drive paths and anything containing a path separator are files;
//  4. a scheme ("://") makes an endpoint;
//  5. a name with a certificate file extension is a file;
//  6. an argument shaped like an endpoint is an endpoint, even when its port
//     or address is malformed, so that endpoint parsing reports a usage error
//     instead of the argument becoming a missing file;
//  7. a bare dotted DNS name is an endpoint; anything else is a file.
func resolveTarget(arg string, exists func(string) bool) targetKind {
	switch {
	case arg == "-":
		return targetStdin
	case exists(arg):
		return targetFile
	case isWindowsDrivePath(arg):
		return targetFile
	case strings.Contains(arg, "://"):
		return targetEndpoint
	case strings.ContainsAny(arg, `/\`):
		return targetFile
	case certificateFileExtensions[strings.ToLower(filepath.Ext(arg))]:
		return targetFile
	case isEndpointShaped(arg), isHostname(arg):
		return targetEndpoint
	}
	return targetFile
}

// isWindowsDrivePath matches "C:" followed by anything, including a
// single-letter "host" such as "a:b".
func isWindowsDrivePath(s string) bool {
	return len(s) >= 2 && s[1] == ':' && (s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z')
}

// isEndpointShaped matches arguments written as an endpoint, whether or not
// they are valid ones. It decides only where an argument goes; endpoint.Parse
// decides whether it is acceptable. It matches:
//   - host:port, where host is a dotted DNS name, localhost or an IPv4
//     address and port is anything (including empty, "0", "-1" or "abc");
//   - a bracketed IPv6 form, "[" followed by text containing a colon, closed
//     or not;
//   - an unbracketed IPv6 address, optionally followed by :port, which
//     endpoint.Parse refuses explicitly.
func isEndpointShaped(s string) bool {
	if rest, ok := strings.CutPrefix(s, "["); ok {
		inside, _, _ := strings.Cut(rest, "]")
		return strings.Contains(inside, ":")
	}
	switch colons := strings.Count(s, ":"); {
	case colons == 1:
		host := s[:strings.Index(s, ":")]
		return host == "localhost" || isHostname(host) || net.ParseIP(host) != nil
	case colons > 1:
		if _, err := netip.ParseAddr(s); err == nil {
			return true
		}
		_, err := netip.ParseAddr(s[:strings.LastIndex(s, ":")])
		return err == nil
	}
	return false
}

// isHostname matches dotted DNS names whose last label is alphabetic, such as
// api.example.com.
func isHostname(s string) bool {
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || strings.IndexFunc(l, notLabelChar) >= 0 {
			return false
		}
	}
	tld := labels[len(labels)-1]
	return len(tld) >= 2 && strings.IndexFunc(tld, notLetter) < 0
}

func notLetter(c rune) bool { return (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') }

func notLabelChar(c rune) bool { return notLetter(c) && (c < '0' || c > '9') && c != '-' }
