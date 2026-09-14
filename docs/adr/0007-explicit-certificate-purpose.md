# ADR-0007: Explicit certificate-purpose validation

- Status: accepted
- Date: 2026-09-14
- Implemented in: `internal/purpose`, `internal/trustverify`, `internal/app/inspectsvc`, `internal/interpret`, `internal/cli`

## Context

Users ask: "is this certificate suitable for the purpose I have in mind?"
That question is separate from the ones earlier layers answer:

| Question | Layer |
|---|---|
| Who signed it, and does the signature verify? | ADR-0004 |
| Is its included path structurally plausible? | ADR-0005 |
| Does it validate to explicitly supplied trust anchors? | ADR-0006 |
| Does it match a host name? | not implemented |

A certificate can be:
- signature-verified, structurally complete and validated to the supplied
  roots, yet unsuitable for TLS server use;
- suitable for TLS server use by its own fields, yet not validated to the
  supplied roots.

Both must stay representable, so no layer may be collapsed into a single
verdict.

## Decision

### Purposes

`trustsmith inspect --purpose <purpose>`. Spellings are exact: an unknown value,
including different case or separators, is a usage error (exit 2). There are
no aliases.

| Purpose | Meaning | Go `ExtKeyUsage` passed to the verifier |
|---|---|---|
| `any` (default) | no application purpose is asserted | `ExtKeyUsageAny` |
| `tls-server` | TLS server authentication | `ExtKeyUsageServerAuth` |
| `tls-client` | TLS client authentication | `ExtKeyUsageClientAuth` |
| `code-signing` | code signing | `ExtKeyUsageCodeSigning` |
| `email` | email protection (S/MIME) | `ExtKeyUsageEmailProtection` |

- **`any`** means no application-specific suitability is asserted. It does not
  switch off any other layer. Leaving out `--purpose` gives byte-identical
  output to `--purpose any`.
- **OCSP signing** is not included: the rest of the model has no use for it
  yet.

The mapping exists once, in `purpose.Purpose.ExtKeyUsage`. The CLI parses
the flag, the application service passes a `purpose.Purpose` value, and
`trustverify` asks the purpose package for the usage. No flag string reaches
the verifier.

### Two facts for every target

Targets are the same certificates trust evaluation uses: those that issued no
other certificate in the input.

**1. Certificate usage.** `internal/purpose` reports what the certificate's own
fields permit. It is always evaluated when a purpose other than `any` is
requested, with or without roots.

- **Extended key usage** (RFC 5280 section 4.2.1.12):
  - An absent extension places no restriction.
  - `anyExtendedKeyUsage` means the extension does not restrict the
    certificate to other purposes, so this evaluator treats it as not
    restricted by extended key usage. That is Trustsmith's generic
    interpretation, not a claim that every application accepts the
    certificate: RFC 5280 allows an application that requires a specific
    usage to reject a certificate listing `anyExtendedKeyUsage` without that
    usage. `certificate_usage.ext_key_usage_basis` records which case applied
    (`not_present`, `listed`, `any_extended_key_usage`, `not_listed`).
  - Otherwise the purpose's usage must be listed. Unrecognised usage OIDs
    restrict like any other listed usage.
- **Key usage:**
  - An absent extension places no restriction.
  - Otherwise at least one bit that RFC 5280 section 4.2.1.12 names as
    consistent with the purpose's extended key usage must be set:

    | Purpose | Consistent key usage bits |
    |---|---|
    | `tls-server` | digitalSignature, keyEncipherment, keyAgreement |
    | `tls-client` | digitalSignature, keyAgreement |
    | `code-signing` | digitalSignature |
    | `email` | digitalSignature, nonRepudiation (contentCommitment), keyEncipherment, keyAgreement |

    These are certificate semantics, not TLS cipher-suite policy. There is no
    universal "TLS server requires digitalSignature" rule.
- **BasicConstraints CA:TRUE** is reported (`ca_certificate`) but decides
  nothing: RFC 5280 does not make a CA certificate unsuitable for these
  purposes on that ground.
- **States:** `suitable`, `unsuitable` (reasons `ext_key_usage_disallows_usage`
  and/or `key_usage_disallows_usage`), `unverifiable`, and `not_evaluated` for
  `any`.

**2. Anchored path.** With `--roots`, `trustverify.Verify` runs with
`KeyUsages` set to the purpose's extended key usage.

- Go's `checkChainForKeyUsage` then enforces that usage along the whole chain:
  - every certificate is checked, the root included;
  - a certificate without extended key usage is unrestricted;
  - a certificate listing `anyExtendedKeyUsage` passes for any requested usage
    (Go verifier behaviour, below).
- A chain that does not permit the purpose gives
  `failed / incompatible_usage`.
- `purpose_evaluation.targets[].anchored_path` mirrors the trust evaluation
  result for the same certificate and purpose. Without roots it is
  `not_evaluated`.

### Go 1.27.1 behaviour pinned by tests

- **Leaf key usage is not checked by Go's verifier.** Its only key usage check
  is keyCertSign on issuers, through `CheckSignatureFrom`. A code-signing
  certificate whose key usage is keyEncipherment alone is therefore:
  - `certificate_usage: unsuitable (key_usage_disallows_usage)`;
  - `anchored_path: verified`.

  Neither fact implies the other.
- **Intermediate extended key usage restrictions** are enforced only on the
  anchored path. A client certificate under a server-only intermediate is:
  - `certificate_usage: suitable` for `tls-client`;
  - `anchored_path: failed (incompatible_usage)`.

  With `any`, the same chain verifies.
- **No EKU.** A certificate without extended key usage verifies for every
  requested purpose.
- **`anyExtendedKeyUsage` is a Go verifier behaviour, not an RFC 5280 rule.**
  - A certificate listing `anyExtendedKeyUsage`, alone or together with a
    specific usage, passes Go's chain check for every supported purpose.
  - This records what Go 1.27.1 does. An application that requires the
    specific usage may still reject such a certificate.
- **Without roots, intermediate restrictions are not evaluated.** Trustsmith
  does not claim a purpose-valid path in that case.

### Trust evaluation

- `trust_evaluation` gains `requested_purpose`.
- `requested_extended_key_usages` names the usage actually requested:
  `["any"]` by default, or for example `["server_auth"]`.
- Results for different purposes are different results. Generic success does
  not imply success for a specific purpose.
- `summary.chain` refers to the requested purpose.
- `trust.failed` and `trust.unverifiable` carry `purpose` evidence when a
  specific purpose was requested.

### Host names and TLS

- No purpose evaluates host names, and `DNSName` stays unset
  (`internal/archtest`). Host name identity is its own layer (ADR-0008); the
  former `purpose_evaluation.hostname_evaluated` flag was removed before any
  release.
- There is no endpoint probing, cipher-suite, protocol-version,
  signature-scheme, key-exchange, ALPN, SNI or client-certificate negotiation
  logic.

### Findings

| Code | Severity | Evidence |
|---|---|---|
| `purpose.eku_disallows_usage` | critical | `requested`, `required_ext_key_usage`, `ext_key_usage` |
| `purpose.key_usage_disallows_usage` | critical | `requested`, `key_usage`, `consistent_key_usage` |

- **Not findings:**
  - an absent extended key usage or key usage extension, which is not an error;
  - a CA certificate.
- **Anchored-path failures** keep their own trust-layer finding
  (`trust.failed`, reason `incompatible_usage`, with `purpose` evidence).

### Output

**JSON.** `trustsmith.inspect/v1` gains, additively, a top-level
`purpose_evaluation`:
- `requested` and `state` (`not_evaluated` or `evaluated`);
- `targets`, each with:
  - `certificate`;
  - `certificate_usage`: `state`, `reasons`, `required_ext_key_usage`,
    `ext_key_usage_present`, `ext_key_usage_basis`, `ext_key_usage`,
    `key_usage_present`, `key_usage`, `consistent_key_usage` and
    `ca_certificate`;
  - `anchored_path`: `state` and `reason`.

Usage names are stable snake_case, such as `server_auth` and
`digital_signature`. They are Trustsmith's own names, not Go's `String()`
output. `summary.purposes` keeps its existing meaning: purposes derived from a
certificate's extended key usage, not the requested purpose.

**Text.**
- A "Purpose" section always appears. For `any` it reads "Not evaluated for a
  specific application".
- Otherwise it gives the requested purpose and, for each target, its usage, extended key usage, key usage and anchored path.
- The trust section names the extended key usage the verifier was asked for,
  and qualifies each result with the purpose, for example "verified for TLS
  server use against the explicitly supplied roots".

### Architecture

- `internal/purpose` is a domain package, so it has no filesystem, network or
  CLI access.
- There is no general policy engine.
- The architecture rules for the verifier are unchanged: `KeyUsages` must be
  set and non-nil at the single call site.

## Consequences

- Host name validation can be added later as its own explicit layer, for
  example with endpoint probing, without changing purpose semantics.
- Further purposes can be added without changing the meaning of existing ones.
