package cli

import (
	"net"
	"path/filepath"
	"strconv"
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
// file or a network endpoint. An existing path always wins; a Windows drive
// path is always a file.
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
	case isHostPort(arg), isHostname(arg):
		return targetEndpoint
	}
	return targetFile
}

// isWindowsDrivePath matches "C:" followed by anything, including a
// single-letter "host" such as "a:b".
func isWindowsDrivePath(s string) bool {
	return len(s) >= 2 && s[1] == ':' && (s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z')
}

func isHostPort(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	return net.ParseIP(host) != nil || host == "localhost" || isHostname(host)
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
