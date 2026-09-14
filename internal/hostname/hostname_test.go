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

func assertRefused(t *testing.T, inputs ...string) {
	t.Helper()
	for _, in := range inputs {
		if r, err := hostname.ParseRequest(in); !errors.Is(err, hostname.ErrInvalid) {
			t.Errorf("ParseRequest(%q) must be refused, got %+v, %v", in, r, err)
		}
	}
}

// 13 and IDNA cases 1, 3, 11. Normalisation of accepted requests.
func TestParseRequestNormalisation(t *testing.T) {
	for _, tc := range []struct {
		in, normalized string
		kind           hostname.Kind
	}{
		// ASCII names behave as before IDNA was added.
		{"api.example.com", "api.example.com", hostname.KindDNS},
		{"API.Example.COM", "api.example.com", hostname.KindDNS},
		{"api.example.com.", "api.example.com", hostname.KindDNS}, // one root dot is removed
		{"localhost", "localhost", hostname.KindDNS},
		{"xn--bcher-kva.example", "xn--bcher-kva.example", hostname.KindDNS},
		{"XN--BCHER-KVA.example", "xn--bcher-kva.example", hostname.KindDNS},
		// 1, 3. Unicode names become lower-case A-labels.
		{"bücher.example", "xn--bcher-kva.example", hostname.KindDNS},
		{"BÜCHER.EXAMPLE", "xn--bcher-kva.example", hostname.KindDNS},
		{"Bücher.example.", "xn--bcher-kva.example", hostname.KindDNS},
		// 4. Non-transitional: ß is encoded, not mapped to "ss".
		{"straße.example", "xn--strae-oqa.example", hostname.KindDNS},
		// 11. Raw UTF-8 far longer than the ASCII result: full-width letters and dots.
		{"ＡＰＩ．ＥＸＡＭＰＬＥ．ＣＯＭ", "api.example.com", hostname.KindDNS},
		// 12. IP literals never go through IDNA.
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
	if len("ＡＰＩ．ＥＸＡＭＰＬＥ．ＣＯＭ") <= 2*len("api.example.com") {
		t.Fatal("test 11 setup: the raw input must be materially longer than its ASCII form")
	}
}

// 18, 19, 20. Anything that is not a bare host name or IP address is refused;
// components are never silently stripped.
func TestParseRequestRefusesSyntax(t *testing.T) {
	assertRefused(t,
		"", strings.Repeat("a", hostname.MaxRawInputBytes+1), "\xff.example",
		"https://api.example.com", "api.example.com/path", `api.example.com\path`, "user@api.example.com", "api.example.com?x", "api.example.com#x",
		"api.example.com:443", "192.0.2.10:443", "[2001:db8::1]:443", "[2001:db8::1", "[192.0.2.10]",
		"fe80::1%eth0",
		"api example.com", "api\texample.com", "api\x00.example.com", "api example.com",
		"*.example.com", "api*.example.com", "*",
		".", "..", "api..example.com", ".api.example.com", "api.example.com..",
		"-api.example.com", "api-.example.com",
		"256.1.1.1", "192.0.2", "192.0.2.010", "1.2.3.4.5", // not IP addresses, and not DNS names
	)
}

// IDNA cases 5, 7, 8, 9, 10, 12, 14: refused by the explicit profile.
func TestParseRequestRefusesByProfile(t *testing.T) {
	// 14. Underscores are not allowed under strict (STD3) host name rules.
	assertRefused(t, "_service.example.com", "api_1.example.com")
	// 5. Disallowed code points (private use, noncharacter).
	assertRefused(t, "\ue000.example", "a\ufdd0b.example")
	// 7. The Bidi rule: a right-to-left label may not contain a left-to-right letter.
	assertRefused(t, "אa.example")
	// 8. Joiners outside their CONTEXTJ context.
	assertRefused(t, "a\u200db.example", "a\u200cb.example")
	// Hyphens in positions 3 and 4 are reserved outside valid A-labels.
	assertRefused(t, "ab--cd.example")
	// An A-label that decodes to ASCII only (GO-2026-5026) or is not valid Punycode.
	assertRefused(t, "xn--example-.com", "xn--a.example")
	// 9. Per-label DNS length after conversion: 63 raw characters, but more than
	// 63 bytes once encoded.
	longLabel := strings.Repeat("a", 60) + "üüü"
	if n := len([]rune(longLabel)); n != 63 {
		t.Fatalf("setup: label has %d characters", n)
	}
	assertRefused(t, longLabel+".example")
	request(t, strings.Repeat("a", 63)+".example") // the ASCII limit itself is accepted
	// 10. Whole-name DNS length after conversion: 200 bytes of UTF-8 that
	// become more than 253 bytes of ASCII.
	longName := strings.Repeat("bücherei.", 20) + "example"
	if len(longName) > 253 {
		t.Fatalf("setup: raw name is %d bytes", len(longName))
	}
	assertRefused(t, longName)
	assertRefused(t, strings.Repeat("a", 64)+".example.com", strings.Repeat("a.", 127)+"com")
	// 12. Full-width digits map to an IP-looking DNS name, which is refused:
	// IP literals are recognised only on the raw input, never after IDNA.
	assertRefused(t, "１９２．０．２．１０")
}

// 6. A valid internationalised name with a right-to-left label.
func TestBidiValidName(t *testing.T) {
	r := request(t, "שלום.example")
	if r.Kind != hostname.KindDNS || !strings.HasPrefix(r.Normalized, "xn--") || !strings.HasSuffix(r.Normalized, ".example") {
		t.Errorf("%+v", r)
	}
	// A joiner in a valid CONTEXTJ position (after a virama) is accepted.
	if _, err := hostname.ParseRequest("क्\u200dष.example"); err != nil {
		t.Errorf("valid ZWJ after virama refused: %v", err)
	}
}

// 1, 2, 3, 14 (matching). DNS names: exact, case-insensitive, mismatch, several SANs.
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
	// A wildcard SAN matches an internationalised name through its A-label.
	assertState(t, match(t, c, "bücher.example.test"), hostname.Matched)

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

// IDNA cases 2, 4, 15. Internationalised requests match the equivalent
// A-label SAN; certificate facts are never rewritten.
func TestInternationalisedNames(t *testing.T) {
	c := cert(t, "", []string{"xn--bcher-kva.example", "API.example.test"}, nil)
	for _, in := range []string{"bücher.example", "BÜCHER.example", "xn--bcher-kva.example", "XN--BCHER-KVA.example"} {
		assertState(t, match(t, c, in), hostname.Matched)
	}
	r := match(t, c, "Bücher.example")
	if !slices.Equal(r.DNSNames, []string{"xn--bcher-kva.example", "API.example.test"}) {
		t.Errorf("certificate SAN facts changed: %v", r.DNSNames)
	}
	// Pinned Go 1.27.1: VerifyHostname performs no IDNA conversion itself, so
	// only the normalised request can match.
	if err := c.VerifyHostname("bücher.example"); err == nil {
		t.Error("pinned Go behaviour changed: VerifyHostname now converts Unicode names")
	}

	// 4. Non-transitional ß: the request is xn--strae-oqa, not strasse.
	strasse := cert(t, "", []string{"strasse.example"}, nil)
	assertState(t, match(t, strasse, "straße.example"), hostname.Mismatch)
	encoded := cert(t, "", []string{"xn--strae-oqa.example"}, nil)
	assertState(t, match(t, encoded, "straße.example"), hostname.Matched)
}

// 17. Trailing dots.
func TestTrailingDot(t *testing.T) {
	c := cert(t, "", []string{"api.example.test"}, nil)
	// Trustsmith removes one root dot from the request before IDNA.
	assertState(t, match(t, c, "api.example.test."), hostname.Matched)
	assertState(t, match(t, cert(t, "", []string{"xn--bcher-kva.example"}, nil), "bücher.example."), hostname.Matched)
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

// The raw input bound is a defensive limit on input size, not a DNS length
// rule: DNS length is checked on the ASCII result of IDNA conversion.
func TestRawInputBoundIsNotDNSLength(t *testing.T) {
	if hostname.MaxRawInputBytes != 4096 {
		t.Errorf("raw input bound %d, want 4096", hostname.MaxRawInputBytes)
	}
	// 723 bytes of UTF-8 (full-width letters) that normalise to a 243-byte name.
	fullWidth := strings.Repeat("ａ", 60)
	raw := strings.Join([]string{fullWidth, fullWidth, fullWidth, fullWidth}, ".")
	ascii := strings.Join([]string{strings.Repeat("a", 60), strings.Repeat("a", 60), strings.Repeat("a", 60), strings.Repeat("a", 60)}, ".")
	if len(raw) <= 253 || len(ascii) > 253 {
		t.Fatalf("setup: raw %d bytes, ascii %d bytes", len(raw), len(ascii))
	}
	if r := request(t, raw); r.Normalized != ascii {
		t.Errorf("normalised %q", r.Normalized)
	}
	// The reverse: fewer than 253 bytes of UTF-8 that exceed 253 bytes once encoded.
	encodedTooLong := strings.Repeat("bücherei.", 20) + "example"
	if len(encodedTooLong) > 253 {
		t.Fatalf("setup: raw %d bytes", len(encodedTooLong))
	}
	assertRefused(t, encodedTooLong)
	// Only input beyond the defensive bound gets the safety-limit error.
	_, err := hostname.ParseRequest(strings.Repeat("a", hostname.MaxRawInputBytes+1))
	if !errors.Is(err, hostname.ErrInvalid) || !strings.Contains(err.Error(), "input safety limit") {
		t.Errorf("oversized input: %v", err)
	}
	if _, err := hostname.ParseRequest(strings.Repeat("a", 300)); err == nil || strings.Contains(err.Error(), "input safety limit") {
		t.Errorf("a 300-byte label must fail the DNS length rule, not the safety limit: %v", err)
	}
}

// A single terminal root dot is the absolute form of the same DNS name: it is
// kept in the request as given and removed before IDNA and matching.
func TestRootDotIsNormalised(t *testing.T) {
	plain, dotted := request(t, "api.example.test"), request(t, "api.example.test.")
	if plain.Normalized != dotted.Normalized || dotted.Normalized != "api.example.test" || dotted.Input != "api.example.test." || dotted.Kind != hostname.KindDNS {
		t.Errorf("plain %+v dotted %+v", plain, dotted)
	}
	c := cert(t, "", []string{"api.example.test"}, nil)
	assertState(t, hostname.Evaluate(c, plain), hostname.Matched)
	assertState(t, hostname.Evaluate(c, dotted), hostname.Matched)

	wildcard := cert(t, "", []string{"*.example.test"}, nil)
	assertState(t, match(t, wildcard, "api.example.test."), hostname.Matched)
	assertState(t, match(t, wildcard, "example.test."), hostname.Mismatch)
	assertState(t, match(t, wildcard, "a.b.example.test."), hostname.Mismatch)

	if u := request(t, "BÜCHER.example."); u.Normalized != "xn--bcher-kva.example" || u.Input != "BÜCHER.example." {
		t.Errorf("unicode with root dot %+v", u)
	}

	// Only one root dot; empty labels anywhere else are refused.
	assertRefused(t, "api.example.test..", ".", "..", "api..example.test.", ".api.example.test.")

	// Length is checked after the root dot is removed and the name converted:
	// a 253-byte name with its root dot is accepted, a 254-byte one is not.
	name253 := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(name253) != 253 {
		t.Fatalf("setup: %d bytes", len(name253))
	}
	if r := request(t, name253+"."); r.Normalized != name253 {
		t.Errorf("253-byte name with root dot: %+v", r)
	}
	assertRefused(t, name253+"d.")

	// IP literals never lose a dot: these are not IP literals, and are refused.
	assertRefused(t, "192.0.2.10.", "2001:db8::1.", "[2001:db8::1].")
}
