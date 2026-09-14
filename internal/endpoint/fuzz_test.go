package endpoint_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/endpoint"
	"github.com/Hazame-hub/trustsmith/internal/hostname"
)

// FuzzParse: Parse never panics, and whatever it accepts round-trips through
// its canonical locator to the same endpoint.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"example.com:443", "tls://example.com", "[2001:db8::1]:443", "192.0.2.10", "bücher.example:8443",
		"https://example.com", "user@host:1", "host:0", "[::1", "a:b:c", "tls://", "", ".", "example.com.:443",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e, err := endpoint.Parse(s)
		if err != nil {
			if !errors.Is(err, endpoint.ErrInvalid) {
				t.Fatalf("Parse(%q) error %v is not ErrInvalid", s, err)
			}
			return
		}
		if e.Port < 1 || e.Port > 65535 {
			t.Fatalf("Parse(%q) port %d", s, e.Port)
		}
		if (e.ServerName() == "") != (e.Host.Kind == hostname.KindIP) || strings.ContainsAny(e.ServerName(), ":[]/") {
			t.Fatalf("Parse(%q) server name %q for kind %q", s, e.ServerName(), e.Host.Kind)
		}
		again, err := endpoint.Parse(e.Locator())
		if err != nil || again.Address() != e.Address() || again.Host.Normalized != e.Host.Normalized {
			t.Fatalf("Parse(%q) locator %q does not round-trip: %+v, %v", s, e.Locator(), again, err)
		}
	})
}
