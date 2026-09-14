# ADR-0008: Explicit host name identity

- Status: accepted
- Date: 2026-09-14
- Implemented in: `internal/hostname`, `internal/app/inspectsvc`, `internal/interpret`, `internal/cli`

## Context

Users ask whether a certificate identifies the host name or IP address they
have in mind. That question is separate from:
- signer relationships (ADR-0004);
- included paths (ADR-0005);
- trust evaluation (ADR-0006);
- purpose evaluation (ADR-0007).

These combinations must all stay representable:
- validated to the supplied roots, suitable for TLS server use, but not
  identifying the requested host;
- identifying the host with no trust anchors supplied;
- identifying the host while unsuitable for the requested purpose.

## Decision

### Dependency

`golang.org/x/net` **v0.59.0** is added, approved for
`golang.org/x/net/idna` only. Go's `VerifyHostname` performs no IDNA
conversion, so an internationalised name must be converted before matching.

- **Security.** Releases before v0.55.0 are affected by GO-2026-5026
  (CVE-2026-39821): Punycode labels that decode to ASCII only were
  accepted. `TestIDNAModuleVersion` fails a build with an older release.
- **Transitive module.** `golang.org/x/text` v0.42.0 is compiled because
  `idna` imports `x/text/transform`, `unicode/bidi`, `secure/bidirule` and
  `unicode/norm`. No other x/net package is imported.
- **Allow-list.** Both modules are on the `internal/archtest` module
  allow-list.

### The IDNA profile

`idna.Lookup` is not used: its documented configuration may change between
releases, and host name normalisation is part of Trustsmith's stable
behaviour. The profile is explicit:

```go
idna.New(
    idna.MapForLookup(),
    idna.BidiRule(),
    idna.Transitional(false),
    idna.StrictDomainName(true),
    idna.ValidateLabels(true),
    idna.VerifyDNSLength(true),
)
```

Option interactions, confirmed in the v0.59.0 source (Go 1.27 builds the
Unicode 17 tables):

| Option | Effect |
|---|---|
| `MapForLookup` | UTS #46 mapping for lookup: case folding, width and compatibility mappings, NFC. It also enables `StrictDomainName` and `ValidateLabels`; they are listed again to keep the profile explicit. |
| `BidiRule` | The RFC 5893 Bidi rule, applied when a name has right-to-left labels. |
| `Transitional(false)` | Deviation characters (ß, ς, ZWJ, ZWNJ) are kept and encoded. `straße.example` becomes `xn--strae-oqa.example`, never `strasse.example`. |
| `StrictDomainName(true)` | STD3 ASCII rules: letters, digits and hyphens only. No underscore, no `*`. |
| `ValidateLabels(true)` | Label validity. It also enables hyphen checks (no leading or trailing hyphen, no `--` in positions 3 and 4 outside valid A-labels) and the CONTEXTJ joiner rules. |
| `VerifyDNSLength(true)` | After conversion, labels are 1–63 bytes and the name at most 253 bytes. Empty labels, and a terminal root dot, are errors. |

`dnsProfile.String()` is
`NonTransitional:UseSTD3Rules:CheckHyphens:CheckJoiners:VerifyDNSLength`.
`profile_internal_test.go` pins that value and a behaviour table covering
every option, so an x/net upgrade cannot change Trustsmith silently.

### The request

`internal/hostname.ParseRequest` processes `trustsmith inspect <input>
--hostname <name>` in this order:

1. **Syntactic refusal of the raw value** (usage error, exit 2). Components are
   never stripped. Refused:
   - an empty value, more than `MaxRawInputBytes` (1024), or invalid UTF-8;
   - whitespace or control characters, including NUL;
   - a URL scheme, path (`/` or `\`), query, fragment or user information;
   - a wildcard.
2. **IP literals, on the raw value.**
   - IPv4 and IPv6 are parsed with `netip.ParseAddr` and normalised to
     canonical text (`2001:0DB8:0:0::1` becomes `2001:db8::1`).
   - Bracketed IPv6 is accepted; bracketed IPv4 and IPv6 zones are refused.
   - IP literals never go through IDNA.
3. **Any other colon** is refused: a port, including `[v6]:port`, or a
   malformed address.
4. **DNS names.** One terminal root dot is removed, because the profile rejects
   it, and the rest is converted with `dnsProfile.ToASCII`. The result is
   lower-case ASCII: `Bücher.example.` becomes `xn--bcher-kva.example`. Any
   profile error is a usage error, for example a disallowed code point, a
   Bidi or joiner violation, an invalid A-label, or a length violation.
5. **An all-numeric last label** after conversion is refused. It is neither a
   DNS name nor an IP literal, and this stops full-width digits
   (`１９２．０．２．１０`) from becoming a DNS request for `192.0.2.10`.

**Two separate length concepts:**
- `MaxRawInputBytes` is a generous safety bound on the raw value.
- DNS length is enforced only on the ASCII result, by `VerifyDNSLength`,
  because IDNA can lengthen a name (`bücherei` ×20 is 180 bytes of UTF-8 but
  more than 253 bytes of ASCII) or shorten it (full-width text).

The request keeps `Input` (as supplied, for display), `Normalized` (what is
matched) and `Kind` (`dns` or `ip`). Names taken from certificates are never
rewritten: IDNA applies only to the user's DNS request.

**Changes from the first draft of this PR,** which used ASCII-only rules
before IDNA was approved:
- underscores are now refused, under STD3;
- labels with `--` in positions 3 and 4 (other than valid A-labels) are now
  refused, by the hyphen check `ValidateLabels` enables.

### Matching

`hostname.Evaluate` calls `(*x509.Certificate).VerifyHostname(normalized)`
and implements no matching of its own. Go 1.27.1 semantics, pinned by tests:

- **Identity sources:** only subject alternative names; the Common Name is
  never used.
  - A CN-only certificate does not identify its Common Name.
  - A certificate with SANs is judged only by them.
- **IP requests** match IP address SANs only.
  - A DNS SAN `192.0.2.99` does not match the IP request `192.0.2.99`.
  - An IPv4-mapped IPv6 request (`::ffff:192.0.2.10`) equals the IPv4 SAN.
- **DNS requests** match DNS SANs, ignoring ASCII case. An internationalised
  request matches the SAN holding its A-label; Go does not convert Unicode
  itself.
- **Wildcards** match only as the complete left-most label of a SAN, exactly
  one label deep:
  - `*.example.com` matches `api.example.com` and `bücher.example.com`, the
    latter through its A-label;
  - it does not match `example.com` or `a.b.example.com`;
  - `api*.example.com` is never a wildcard.
- **Trailing dots:**
  - Trustsmith removes one root dot from the request.
  - Go also ignores a request's terminal dot.
  - x/net's profile rejects one.
  - A SAN with a terminal dot is not a valid pattern for Go and is matched
    only exactly, so `api.example.com.` in a SAN does not match
    `api.example.com`.
- **Result states:**
  - `matched`;
  - `mismatch`, when Go returns a `HostnameError`;
  - `unverifiable`, when the certificate was not parsed, the request is
    invalid, or Go returns any other error. Engine inability is never a
    mismatch.

Go's `HostnameError` message is never part of the output. The result carries
structured facts instead:
- the certificate's DNS and IP address SANs, as encoded;
- `common_name_ignored`: a DNS request did not match, and the certificate's
  Common Name equals the request.

Matching runs on Go 1.27.1 (the toolchain is pinned), which includes the fix
for the `VerifyHostname` complexity issue in earlier releases. No Trustsmith
loop iterates over patterns.

### Targets

The same certificates as trust and purpose evaluation: those that issued no
other certificate in the input. That is a graph heuristic for likely end
certificates, not proof of end-entity status, so the contract calls them
targets, never leaves.

### Independence

- `--hostname` implies no purpose, and `--purpose` evaluates no host name.
- `trustverify` never sets `VerifyOptions.DNSName` (`internal/archtest`).
  Trust validation may still apply CA name constraints to names in a chain;
  that is reported by trust evaluation.
- `purpose_evaluation.hostname_evaluated` was removed before any release.
  Keeping it would have created a second, always-false source of truth for
  identity, which now has its own layer.

### Findings

| Code | Severity | Evidence |
|---|---|---|
| `name.hostname_mismatch` | critical | `requested`, `normalized`, `kind`, `certificate_dns_names` or `certificate_ip_addresses`, and `common_name_ignored` when set |

A match is not a finding. A CN-only certificate keeps its
`name.cn_only_no_san` warning alongside the mismatch.

### Output

**JSON.** `trustsmith.inspect/v1` gains `hostname_evaluation`, additively:
- `state`: `not_evaluated` or `evaluated`;
- `requested` (as given), `normalized` (for example the A-label), `kind`,
  `matcher` (`go-x509-verifyhostname`) and `engine_version`, each null when
  not evaluated;
- `targets`, each with `certificate`, `state`, `reason`,
  `certificate_dns_names`, `certificate_ip_addresses` and
  `common_name_ignored`.

**Text.** A "Hostname" section always appears:
- without a request: "Not evaluated (use --hostname)";
- otherwise: the request, and its normalised form when that differs; the
  matcher; and for each target "Match: yes" or "Match: no" with the
  certificate's names of the requested kind. A note appears when the Common
  Name equals the request but was not used.

## Consequences

- TLS endpoint probing can later combine explicit trust, `tls-server` purpose
  and host name identity, and still say which condition failed.
- Any change to IDNA behaviour is a deliberate profile change that fails the
  pinned tests first.
