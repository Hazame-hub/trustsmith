package endpoint_test

import (
	"errors"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/endpoint"
	"github.com/Hazame-hub/trustsmith/internal/hostname"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		in, address, serverName, locator string
		kind                             hostname.Kind
	}{
		{"example.com:443", "example.com:443", "example.com", "tls://example.com:443", hostname.KindDNS},
		{"tls://example.com:8443", "example.com:8443", "example.com", "tls://example.com:8443", hostname.KindDNS},
		{"TLS://Example.COM:443", "example.com:443", "example.com", "tls://example.com:443", hostname.KindDNS},
		{"example.com", "example.com:443", "example.com", "tls://example.com:443", hostname.KindDNS},
		{"tls://example.com", "example.com:443", "example.com", "tls://example.com:443", hostname.KindDNS},
		{"example.com.:443", "example.com:443", "example.com", "tls://example.com:443", hostname.KindDNS},
		{"bücher.example:443", "xn--bcher-kva.example:443", "xn--bcher-kva.example", "tls://xn--bcher-kva.example:443", hostname.KindDNS},
		{"192.0.2.10:443", "192.0.2.10:443", "", "tls://192.0.2.10:443", hostname.KindIP},
		{"tls://192.0.2.10", "192.0.2.10:443", "", "tls://192.0.2.10:443", hostname.KindIP},
		{"[2001:db8::1]:443", "[2001:db8::1]:443", "", "tls://[2001:db8::1]:443", hostname.KindIP},
		{"[2001:0DB8::0001]", "[2001:db8::1]:443", "", "tls://[2001:db8::1]:443", hostname.KindIP},
		{"localhost:65535", "localhost:65535", "localhost", "tls://localhost:65535", hostname.KindDNS},
	} {
		e, err := endpoint.Parse(tc.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", tc.in, err)
			continue
		}
		if e.Address() != tc.address || e.ServerName() != tc.serverName || e.Locator() != tc.locator || e.Host.Kind != tc.kind || e.Input != tc.in {
			t.Errorf("Parse(%q) = %+v: address %q server name %q locator %q", tc.in, e, e.Address(), e.ServerName(), e.Locator())
		}
	}
}

func TestParseRefuses(t *testing.T) {
	for _, in := range []string{
		"", "tls://", ":443",
		"https://example.com", "http://example.com:80", "ftp://example.com", "starttls://example.com:25",
		"user@example.com:443", "tls://user:pass@example.com:443",
		"example.com:443/path", "tls://example.com/", "example.com:443?x=1", "example.com:443#frag",
		"example.com:0", "example.com:65536", "example.com:-1", "example.com:+443", "example.com:44a", "example.com:",
		"2001:db8::1:443", "[2001:db8::1", "[2001:db8::1]443", "[2001:db8::1]:", "[192.0.2.10]:443",
		"*.example.com:443", "exa mple.com:443", "_service.example.com:443",
	} {
		if _, err := endpoint.Parse(in); !errors.Is(err, endpoint.ErrInvalid) {
			t.Errorf("Parse(%q) must be refused, got %v", in, err)
		}
	}
}
