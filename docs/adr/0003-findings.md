# ADR-0003: Findings, inspect output and exit codes

- Status: accepted
- Date: 2026-09-14
- Implemented in: `internal/findings`, `internal/interpret`, `internal/cli`

## Context

Inspection must explain problems to people who are not PKI experts, and stay
machine-readable for scripts and future integrations. Free-form diagnostic
strings cannot be relied on by either audience.

## Decision

### Raw facts and interpretation stay separate

- **Raw facts:** `x509facts` (what a certificate contains) and `artifact` (how
  the input is framed) never judge.
- **Interpretation:** `interpret` is a pure function of those facts, the
  inspection time and expiry thresholds. It produces a friendly summary and
  findings.

### Finding

A finding carries:
- a **stable code**, such as `cert.expired`;
- a **severity**: `info`, `warning` or `critical`;
- an **entry**: the block index, or the whole input;
- **typed evidence**: key/value pairs.

Human text (title, explanation, remediation actions with their own codes) lives
in the embedded `catalog.json`. The text may be improved freely without changing
codes.

Codes are an external contract:

- `internal/findings/testdata/codes.golden` is **append-only**. A removed or
  renamed code fails the tests even with `UPDATE_GOLDEN=1`. Removing one needs a
  hand edit plus an amendment to this ADR.
- The tests read `codes.go` and fail if a declared code has no catalog entry, or
  the catalog has an entry no code declares.
- Evidence keys are stable `snake_case`. Fingerprint evidence uses the scheme
  names from ADR-0002 as keys.

Codes in this revision:

| Code | Severity | Emitted when |
|---|---|---|
| `input.empty` | critical | no data |
| `input.unsupported_format` | critical (whole input) / warning (block) | neither PEM nor DER; a non-certificate PEM block (reported by label, not decoded); DER that is not a certificate; a CSR |
| `input.no_certificates` | critical | input framed, but no certificate in it |
| `input.malformed_pem` | critical | bad armour, missing END, undecodable block |
| `input.malformed_der` | critical | invalid DER |
| `input.trailing_data` | info (PEM) / warning (DER) | data outside any block |
| `input.unparseable_certificate` | critical | Go's X.509 parser rejected a certificate |
| `input.malformed_spki` | warning | the certificate's public key is malformed |
| `cert.expired` / `cert.not_yet_valid` | critical | inspection time after `notAfter` / before `notBefore` |
| `cert.expiring_soon` | warning at ≤ 30 days, critical at ≤ 7 days | still valid, expiring |
| `cert.self_signed_leaf` | warning | non-CA certificate whose self-signature verifies |
| `sig.sha1` / `sig.md5` | critical; info on a self-issued CA | weak signature algorithm |
| `key.rsa_under_2048` | critical | RSA modulus shorter than 2048 bits |
| `key.noncanonical_spki` | warning | KeyID exists but the key is encoded non-canonically |
| `key.unsupported_for_identity` | info | the key has no ADR-0002 identity |
| `name.cn_only_no_san` | warning | non-CA certificate named only by Common Name |
| `issuer.candidate_unverifiable` | info | a matching certificate in the input could not check this signature, and none verified (ADR-0004) |
| `issuer.candidates_not_checked` | info | issuer-candidate limits were reached; issuer information is incomplete (ADR-0004) |
| `chain.issuer_not_ca` | warning | an issuer on an included path is not a CA certificate (ADR-0005) |
| `chain.issuer_key_usage` | warning | an issuer's key usage lacks keyCertSign (ADR-0005) |
| `chain.path_length_exceeded` | warning | a CA's pathLenConstraint is exceeded (ADR-0005) |
| `chain.structure_unverifiable` | info | no structural violation, but part of a path's structure could not be evaluated (ADR-0005) |
| `chain.cycle` | info | verified issuer relationships form a cycle (ADR-0005) |
| `chain.path_limit_reached` | info | path construction limits were reached; paths are incomplete (ADR-0005) |
| `trust.failed` | critical | validation against explicitly supplied roots failed; evidence `reason` (ADR-0006) |
| `trust.unverifiable` | warning | validation against explicitly supplied roots was inconclusive; evidence `reason` (ADR-0006) |

### Semantics this revision commits to

- **Validity:** a certificate is valid from `notBefore` through `notAfter`
  inclusive, at the injected inspection time.
- **Generic interpretation only.** No CA/Browser Forum or other public-WebPKI
  limit is applied to any certificate. A later WebPKI policy uses its own
  `webpki.*` codes, driven by effective-date data, and only when requested
  explicitly.
- **Issuer relationships are signature checks inside the input only**
  (ADR-0004).
  - The summary reports the issuer name as stated in the certificate, plus what
    the input shows about it (`issuer_in_input`).
  - Relationships assert no trust, CA validity or chain validity.
- **Trust is evaluated only against explicitly supplied roots** (ADR-0006).
  The summary's `chain` is `not_checked` unless the certificate was validated;
  otherwise it is `verified_to_supplied_roots`, `failed_against_supplied_roots`
  or `unverifiable_against_supplied_roots`, each naming its trust source.
- **Certification paths are structural and inside the input only**
  (ADR-0005). A path's `trust` is always `not_evaluated`, and path findings
  never repeat a certificate's own validity findings.
- **Self-signature is a cryptographic fact.** It is computed with
  `Certificate.CheckSignature` over the certificate's own key:
  - The result is `verified`, `does_not_verify` or `unverifiable`.
  - Go still accepts SHA-1 signatures in `CheckSignature`, so a SHA-1
    self-signature can be `verified`; `sig.sha1` flags the algorithm.
  - Go refuses MD5, so an MD5 self-signature is `unverifiable`, never `does_not_verify`.

### JSON output: `trustsmith.inspect/v1`

- **The schema is its own set of types in `internal/cli/render_json.go`.**
  Internal structs are never serialised.
- **Top-level fields:** `schema`, `inspected_at`, `input`, `overview`,
  `artifacts`, `relationships`, `paths`, `trust_evaluation`, `findings`. `relationships` and the
  summary fields `issuer_in_input`, `verified_issuer_entries` and
  `candidate_issuer_entries` were added compatibly within v1 (ADR-0004), as
  were `paths`, `overview.included_paths` and `overview.path_limit_reached`
  (ADR-0005). `trust_evaluation` and the qualified summary `chain` values
  were added within v1 (ADR-0006).
- **Fingerprints** are keyed by ADR-0002 scheme name. A missing key identity is
  `null`.
- **Findings** include the rendered catalog text and codes. Their `entry` is
  `null` for whole-input findings.
- **Arrays** are always arrays, never `null`.
- **Pre-release rename:** `chain.structure_not_evaluated` was renamed to
  `chain.structure_unverifiable` before any release, to match the
  `structurally_unverifiable` state and avoid implying nothing was evaluated.
  After the first release, codes are never renamed.
- **Compatibility:** within `v1`, fields may be added. Renaming, removing or
  changing the meaning of a field requires `v2`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success; no finding at or above `--fail-on` (default `critical`) |
| 1 | operational error (unreadable, missing or oversized input, directory given, unusable `--roots` file) |
| 2 | usage error (flags, arguments, unknown command, endpoint argument while probing is unimplemented) |
| 3 | inspection completed and the highest finding reached `--fail-on` |

`--fail-on never` disables 3. The output format does not affect the exit code.

## Consequences

- Scripts can rely on codes, severities, evidence keys, the JSON schema and exit
  codes.
- Improving explanations never breaks consumers.
- Policy-specific diagnostics can be added without making generic output wrong
  for private PKI.
