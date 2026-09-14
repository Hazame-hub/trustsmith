package hostname_test

import (
	"crypto/x509"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/hostname"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
)

func cert(t *testing.T, cn string, dns []string, ips []string) *x509.Certificate {
	t.Helper()
	return testpki.Issue(t, testpki.Template{
		CommonName: cn, Serial: 2,
		NotBefore: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 9, 1, 0, 0, 0, 0, time.UTC),
		DNSNames: dns, IPAddresses: ips, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, testpki.ECDSAKey(t), nil).Cert
}

func request(t *testing.T, s string) hostname.Request {
	t.Helper()
	r, err := hostname.ParseRequest(s)
	if err != nil {
		t.Fatalf("ParseRequest(%q): %v", s, err)
	}
	return r
}

func match(t *testing.T, c *x509.Certificate, s string) hostname.Result {
	t.Helper()
	return hostname.Evaluate(c, request(t, s))
}

func assertState(t *testing.T, r hostname.Result, want hostname.State) {
	t.Helper()
	if r.State != want {
		t.Errorf("state %s, want %s (%+v)", r.State, want, r)
	}
}

func TestParseRequestNormalisation(t *testing.T) {
	for _, tc := range []struct {
		in, normalized string
		kind           hostname.Kind
	}{
		{"api.example.com", "api.example.com", hostname.KindDNS},
		{"API.Example.COM", "api.example.com", hostname.KindDNS},
		{"api.example.com.", "api.example.com", hostname.KindDNS}, // one root dot is removed
		{"localhost", "localhost", hostname.KindDNS},
		{"_service.example.com", "_service.example.com", hostname.KindDNS},
		{"xn--bcher-kva.example", "xn--bcher-kva.example", hostname.KindDNS},
		{"192.0.2.10", "192.0.2.10", hostname.KindIP},
		{"2001:db8::1", "2001:db8::1", hostname.KindIP},
		{"2001:0DB8:0:0::1", "2001:db8::1", hostname.KindIP},
		{"[2001:db8::1]", "2001:db8::1", hostname.KindIP},
		{"::ffff:192.0.2.10", "::ffff:192.0.2.10", hostname.KindIP},
	} {
		r, err := hostname.ParseRequest(tc.in)
		if err != nil || r.Normalized != tc.normalized || r.Kind != tc.kind || r.Input != tc.in {
			t.Errorf("ParseRequest(%q) = %+v, %v; want %q %s", tc.in, r, err, tc.normalized, tc.kind)
		}
	}
}

// 18, 19, 20. Anything that is not a bare host name or IP address is refused;
// components are never silently stripped.
func TestParseRequestRefuses(t *testing.T) {
	for _, in := range []string{
		"",
		"https://api.example.com", "api.example.com/path", "user@api.example.com", "api.example.com?x", // scheme, path, user info
		"api.example.com:443", "192.0.2.10:443", "[2001:db8::1]:443", "[2001:db8::1", "[192.0.2.10]", // ports and brackets
		"fe80::1%eth0",                                                         // zone
		"api..example.com", ".api.example.com", "api.example.com..", ".", "..", // empty labels
		"-api.example.com", "api-.example.com", "api example.com", "api\texample.com",
		"*.example.com", "api*.example.com", "*",
		"256.1.1.1", "192.0.2", "192.0.2.010", "1.2.3.4.5", // not IP addresses, not DNS names
		strings.Repeat("a", 64) + ".example.com",
		strings.Repeat("a.", 127) + "com",
		strings.Repeat("a", 256),
		"bücher.example", // internationalised names are not supported yet
	} {
		if _, err := hostname.ParseRequest(in); !errors.Is(err, hostname.ErrInvalid) {
			t.Errorf("ParseRequest(%q) must be refused, got %v", in, err)
		}
	}
}

// 1, 2, 3, 14. DNS names: exact, case-insensitive, mismatch, several SANs.
func TestDNSNames(t *testing.T) {
	c := cert(t, "api.example.test", []string{"www.example.test", "API.example.test", "internal.example.test"}, nil)
	assertState(t, match(t, c, "api.example.test"), hostname.Matched)
	assertState(t, match(t, c, "Api.EXAMPLE.test"), hostname.Matched)
	assertState(t, match(t, c, "internal.example.test"), hostname.Matched)
	r := match(t, c, "other.example.test")
	assertState(t, r, hostname.Mismatch)
	if !slices.Equal(r.DNSNames, []string{"www.example.test", "API.example.test", "internal.example.test"}) || r.CommonNameIgnored {
		t.Errorf("facts must be the SANs as encoded: %+v", r)
	}
}

// 4, 5, 6, 7. Wildcards, delegated to Go.
func TestWildcards(t *testing.T) {
	c := cert(t, "", []string{"*.example.test"}, nil)
	assertState(t, match(t, c, "api.example.test"), hostname.Matched)
	assertState(t, match(t, c, "example.test"), hostname.Mismatch)
	assertState(t, match(t, c, "a.b.example.test"), hostname.Mismatch)

	partial := cert(t, "", []string{"api*.example.test"}, nil)
	assertState(t, match(t, partial, "api1.example.test"), hostname.Mismatch)
	assertState(t, match(t, partial, "api.example.test"), hostname.Mismatch)
}

// 8, 9, 10, 11. IP addresses match IP SANs only.
func TestIPAddresses(t *testing.T) {
	c := cert(t, "", []string{"192.0.2.99"}, []string{"192.0.2.10", "2001:db8::1"})
	assertState(t, match(t, c, "192.0.2.10"), hostname.Matched)
	assertState(t, match(t, c, "2001:db8::1"), hostname.Matched)
	assertState(t, match(t, c, "2001:0db8::0001"), hostname.Matched)
	assertState(t, match(t, c, "[2001:db8::1]"), hostname.Matched)
	// A DNS SAN holding digits does not satisfy an IP request.
	if r := match(t, c, "192.0.2.99"); r.State != hostname.Mismatch || !slices.Equal(r.IPAddresses, []string{"192.0.2.10", "2001:db8::1"}) {
		t.Errorf("textual DNS SAN matched an IP request: %+v", r)
	}
	// Pinned Go 1.27.1: an IPv4-mapped IPv6 request equals the IPv4 SAN.
	assertState(t, match(t, c, "::ffff:192.0.2.10"), hostname.Matched)
}

// 12, 13. The Common Name is never used.
func TestCommonNameIsNotUsed(t *testing.T) {
	cnOnly := cert(t, "api.example.test", nil, nil)
	r := match(t, cnOnly, "api.example.test")
	if r.State != hostname.Mismatch || !r.CommonNameIgnored {
		t.Errorf("CN-only certificate: %+v", r)
	}

	sanWins := cert(t, "api.example.test", []string{"www.example.test"}, nil)
	if r := match(t, sanWins, "api.example.test"); r.State != hostname.Mismatch || !r.CommonNameIgnored {
		t.Errorf("Common Name must be ignored when SANs exist: %+v", r)
	}
	assertState(t, match(t, sanWins, "www.example.test"), hostname.Matched)
	if r := match(t, sanWins, "other.example.test"); r.CommonNameIgnored {
		t.Errorf("Common Name flag set without a Common Name equal to the request: %+v", r)
	}
}

// 15, 16. Internationalised names: requests are refused until IDNA
// conversion is supported; an A-label request matches an A-label SAN, as the
// certificate encodes it.
func TestInternationalisedNames(t *testing.T) {
	c := cert(t, "", []string{"xn--bcher-kva.example"}, nil)
	assertState(t, match(t, c, "xn--bcher-kva.example"), hostname.Matched)
	assertState(t, match(t, c, "XN--BCHER-KVA.example"), hostname.Matched)
	if _, err := hostname.ParseRequest("bücher.example"); !errors.Is(err, hostname.ErrInvalid) {
		t.Errorf("a Unicode request must be refused for now: %v", err)
	}
	// Pinned Go 1.27.1: VerifyHostname performs no IDNA conversion, so the
	// Unicode form never matches the A-label SAN.
	if err := c.VerifyHostname("bücher.example"); err == nil {
		t.Error("pinned Go behaviour changed: VerifyHostname now converts Unicode names")
	}
}

// 17. Trailing dots.
func TestTrailingDot(t *testing.T) {
	c := cert(t, "", []string{"api.example.test"}, nil)
	// Trustsmith removes one root dot from the request.
	assertState(t, match(t, c, "api.example.test."), hostname.Matched)
	// Pinned Go 1.27.1: VerifyHostname also ignores a request's terminal dot.
	if err := c.VerifyHostname("api.example.test."); err != nil {
		t.Errorf("pinned Go behaviour changed: %v", err)
	}
	// Pinned Go 1.27.1: a SAN with a terminal dot is not a valid pattern and is
	// matched only exactly, so it does not match the request without the dot.
	dotted := cert(t, "", []string{"api.example.test."}, nil)
	assertState(t, match(t, dotted, "api.example.test"), hostname.Mismatch)
}

func TestUnverifiable(t *testing.T) {
	if r := hostname.Evaluate(nil, request(t, "api.example.test")); r.State != hostname.Unverifiable || r.Reason != hostname.ReasonNotParsed {
		t.Errorf("nil certificate %+v", r)
	}
	c := cert(t, "", []string{"api.example.test"}, nil)
	if r := hostname.Evaluate(c, hostname.Request{}); r.State != hostname.Unverifiable || r.Reason != hostname.ReasonInvalidRequest {
		t.Errorf("empty request %+v", r)
	}
}
