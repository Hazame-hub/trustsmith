package hostname

import (
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
)

// TestIDNAProfileIsPinned records exactly what the explicit IDNA profile does
// with golang.org/x/net v0.59.0. An x/net upgrade that changes any of these
// outcomes fails here instead of silently changing Trustsmith's host name
// semantics.
func TestIDNAProfileIsPinned(t *testing.T) {
	// String covers the option flags; the mapping (MapForLookup) and the Bidi
	// rule are pinned by the behaviour table below.
	if got, want := dnsProfile.String(), "NonTransitional:UseSTD3Rules:CheckHyphens:CheckJoiners:VerifyDNSLength"; got != want {
		t.Errorf("profile options %q, want %q", got, want)
	}
	for _, tc := range []struct {
		in, out string // out "" means an error is required
	}{
		{"bücher.example", "xn--bcher-kva.example"},
		{"BÜCHER.EXAMPLE", "xn--bcher-kva.example"},
		{"api.example.com", "api.example.com"},
		{"API.Example.COM", "api.example.com"},
		{"xn--bcher-kva.example", "xn--bcher-kva.example"},
		{"straße.example", "xn--strae-oqa.example"}, // non-transitional: no ß -> ss
		{"ＡＰＩ．ＥＸＡＭＰＬＥ．ＣＯＭ", "api.example.com"},      // width mapping and ideographic full stops
		{"１９２．０．２．１０", "192.0.2.10"},                // the profile itself allows this; ParseRequest refuses it
		{strings.Repeat("a", 63) + ".example", strings.Repeat("a", 63) + ".example"},
		{"api.example.com.", ""},     // VerifyDNSLength: a terminal root dot is an error
		{"_service.example.com", ""}, // StrictDomainName: underscore
		{"*.example.com", ""},        // StrictDomainName: wildcard
		{"ab--cd.example", ""},       // ValidateLabels: hyphens in positions 3 and 4
		{"-api.example.com", ""},     // ValidateLabels: leading hyphen
		{"a\u200db.example", ""},     // ValidateLabels: CONTEXTJ for ZWJ
		{"a\u200cb.example", ""},     // ValidateLabels: CONTEXTJ for ZWNJ
		{"אa.example", ""},           // BidiRule
		{"\ue000.example", ""},       // disallowed code point
		{"xn--example-.com", ""},     // A-label decoding to ASCII only (GO-2026-5026)
		{"api..example.com", ""},     // VerifyDNSLength: empty label
		{strings.Repeat("a", 64) + ".example", ""},
		{strings.Repeat("a", 60) + "üüü.example", ""},     // label longer than 63 bytes once encoded
		{strings.Repeat("bücherei.", 20) + "example", ""}, // name longer than 253 bytes once encoded
	} {
		got, err := dnsProfile.ToASCII(tc.in)
		switch {
		case tc.out == "" && err == nil:
			t.Errorf("ToASCII(%q) = %q, want an error", tc.in, got)
		case tc.out != "" && (err != nil || got != tc.out):
			t.Errorf("ToASCII(%q) = %q, %v; want %q", tc.in, got, err, tc.out)
		}
	}
}

// TestIDNAModuleVersion refuses a build with a golang.org/x/net release older
// than v0.55.0, which is affected by GO-2026-5026.
func TestIDNAModuleVersion(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("no build information")
	}
	for _, dep := range info.Deps {
		if dep.Path != "golang.org/x/net" {
			continue
		}
		version := dep.Version
		if dep.Replace != nil {
			version = dep.Replace.Version
		}
		parts := strings.SplitN(strings.TrimPrefix(version, "v"), ".", 3)
		if len(parts) < 2 {
			t.Fatalf("unparseable golang.org/x/net version %q", version)
		}
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])
		if major == 0 && minor < 55 {
			t.Fatalf("golang.org/x/net %s is older than v0.55.0 (GO-2026-5026)", version)
		}
		return
	}
	t.Fatal("golang.org/x/net is not in the build")
}
