# ADR-0008: Explicit host name identity

- Status: accepted (internationalised names pending an owner decision, see below)
- Date: 2026-09-14
- Implemented in: `internal/hostname`, `internal/app/inspectsvc`, `internal/interpret`, `internal/cli`

## Context

Users ask whether a certificate identifies the host name or IP address they
have in mind. That question is separate from signer relationships
(ADR-0004), included paths (ADR-0005), trust evaluation (ADR-0006) and purpose
evaluation (ADR-0007).

These combinations must all stay representable:
- validated to the supplied roots, suitable for TLS server use, but not
  identifying the requested host;
- identifying the host with no trust anchors supplied;
- identifying the host while unsuitable for the requested purpose.

## Decision

### The request

`trustsmith inspect <input> --hostname <name>`. `internal/hostname.ParseRequest`
validates and normalises the name before any matching.

**Refused as usage errors (exit 2).** Components are never stripped. The
following are refused:
- an empty value, or one longer than 255 bytes;
- a URL scheme, path, query, fragment or user information;
- a port, including a bracketed IPv6 address with a port;
- whitespace or control characters;
- an IPv6 zone;
- a wildcard (`*`), which is not a host name;
- empty labels, labels over 63 bytes, and names over 253 bytes;
- a label starting or ending with a hyphen;
- characters other than letters, digits, hyphens and underscores;
- an all-numeric last label (for example `256.1.1.1` or `192.0.2.010`), which
  is neither a DNS name nor a valid IP address.

**IP addresses are recognised first.**
- IPv4 and IPv6 are parsed with `netip.ParseAddr` and normalised to canonical
  text (`2001:0DB8:0:0::1` becomes `2001:db8::1`).
- A bracketed IPv6 address (`[2001:db8::1]`) is accepted and normalised the
  same way. A bracketed IPv4 address is refused.

**DNS names.**
- One terminal root dot is removed (`api.example.com.` becomes
  `api.example.com`).
- The name is lower-cased (ASCII).
- Underscores are accepted, because Go's matcher accepts them.

**Internationalised names are pending.** Go's `VerifyHostname` performs no
IDNA conversion: a Unicode request never matches its A-label SAN (pinned).
The approved plan normalises user input with `idna.Lookup.ToASCII`, which
would add the module `golang.org/x/net`.
- Until the owner decides, a non-ASCII request is refused as a usage error,
  and the message points to the A-label (`xn--`) form.
- An A-label request matches an A-label SAN, compared as ASCII.

The request keeps `Input` (as supplied, for display), `Normalized` (what is
matched) and `Kind` (`dns` or `ip`). Names taken from certificates are never
rewritten.

### Matching

`hostname.Evaluate` calls `(*x509.Certificate).VerifyHostname(normalized)`
and implements no matching of its own. Go 1.27.1 semantics, pinned by tests:

- **Identity sources:** only subject alternative names; the Common Name is
  never used. A CN-only certificate does not identify its Common Name, and a
  certificate with SANs is judged only by them.
- **IP requests** match IP address SANs only. A DNS SAN spelling
  `192.0.2.10` does not match the IP request `192.0.2.10`. An IPv4-mapped
  IPv6 request (`::ffff:192.0.2.10`) equals the IPv4 SAN.
- **DNS requests** match DNS SANs, ignoring ASCII case in both the request and
  the SAN.
- **Wildcards** match only as the complete left-most label of a SAN, and
  exactly one label deep:
  - `*.example.com` matches `api.example.com`;
  - it does not match `example.com` or `a.b.example.com`;
  - a partial-label pattern such as `api*.example.com` is never a wildcard.
- **Trailing dots.** Go ignores a request's terminal dot. A SAN with a
  terminal dot is not a valid pattern and is matched only exactly, so
  `api.example.com.` in a SAN does not match `api.example.com`.
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
  Common Name equals it.

Requests are bounded (255 bytes) and matched by Go 1.27.1 (the toolchain is
pinned), which includes the fix for the `VerifyHostname` complexity issue in
earlier releases. No Trustsmith loop iterates over patterns.

### Targets

The same certificates as trust and purpose evaluation: those that issued no
other certificate in the input. That is a graph heuristic for likely end
certificates, not proof of end-entity status, so the contract calls them
targets, never leaves.

### Independence

- `--hostname` implies no purpose, and `--purpose` evaluates no host name.
- `trustverify` still never sets `VerifyOptions.DNSName` (`internal/archtest`).
  Trust validation may still apply CA name constraints to the names in a
  chain; that is reported by trust evaluation, not here.
- `purpose_evaluation.hostname_evaluated` was removed before any release.
  Keeping it would have created a second, always-false source of truth for
  identity, which now has its own layer. The purpose text section likewise no
  longer mentions host names.

### Findings

| Code | Severity | Evidence |
|---|---|---|
| `name.hostname_mismatch` | critical | `requested`, `normalized`, `kind`, `certificate_dns_names` or `certificate_ip_addresses`, and `common_name_ignored` when set |

A match is not a finding. A CN-only certificate keeps its existing
`name.cn_only_no_san` warning alongside the mismatch.

### Output

**JSON.** `trustsmith.inspect/v1` gains `hostname_evaluation`, additively:
- `state`: `not_evaluated` or `evaluated`;
- `requested`, `normalized`, `kind`, `matcher` (`go-x509-verifyhostname`) and
  `engine_version`, each null when not evaluated;
- `targets`, each with `certificate`, `state`, `reason`,
  `certificate_dns_names`, `certificate_ip_addresses` and
  `common_name_ignored`.

**Text.** A "Hostname" section always appears:
- without a request: "Not evaluated (use --hostname)";
- otherwise: the request (with its normalised form when that differs), the
  matcher, and for each target "Match: yes" or "Match: no" with the
  certificate's names of the requested kind. A note appears when the Common
  Name equals the request but was not used.

## Consequences

- TLS endpoint probing can later combine explicit trust, `tls-server` purpose
  and host name identity, and still say which condition failed.
- Internationalised names need only a change to `ParseRequest` once the IDNA
  decision is made. Matching and the contract stay the same.
