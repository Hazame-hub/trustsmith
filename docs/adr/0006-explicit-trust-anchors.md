# ADR-0006: Explicitly supplied trust anchors

- Status: accepted
- Date: 2026-09-14
- Implemented in: `internal/trustverify`, `internal/app/inspectsvc`, `internal/interpret`, `internal/cli`

## Context

ADR-0004 and ADR-0005 report facts found inside one input:
- which key verifies which signature;
- which certification paths those relationships form;
- whether the issuers along those paths are structurally allowed to sign.

None of that is trust. Trust needs a source.

The fundamental rule of this slice is: **a certificate becomes a trust anchor
only because the user explicitly supplied it as one.** Being present in the
inspected input is never enough, and neither is being self-signed.

## Decision

### The trust source

- **Option:** `trustsmith inspect <input> --roots <file>`. It can be
  repeated.
- **What a roots file holds:** certificates only, as PEM, DER or a PEM bundle.
- **All or nothing:** the whole file is refused with an operational error
  (exit 1), and nothing is inspected, when it contains:
  - any other block, such as a private key (reported by label, never decoded);
  - a malformed or unparseable block;
  - a certificate request;
  - trailing data after DER;
  - no certificate at all, including an empty file.

  No other trust source is ever used instead.
- **No `--roots system`.** System and platform trust stores are not used in
  this version.
- **No `--roots none`.** Leaving the option out already evaluates nothing, and
  a file literally named `none` must stay unambiguous.

**Anchors:**
- An anchor is a supplied certificate, deduplicated by `x509-cert-sha256`,
  with every roots-file occurrence recorded.
- It need not be self-signed. Its self-signature is reported only as a fact
  about the certificate, never as the reason it is an anchor.
- A certificate that is both in the input and in the roots is an anchor only,
  and is not also offered as an intermediate.
- Every other input certificate is at most a candidate intermediate.

**Targets:**
- The certificates validated are those that issued no other certificate in the
  input: end entities, and the ends of partial bundles.
- If every certificate issues another (a cycle), all of them are validated.

### The verifier

`trustverify.Verify` is the only call to `x509.Certificate.Verify` in
Trustsmith. It builds its options at the call site, and every field that
matters is set deliberately:

| Option | Value | Why it is explicit |
|---|---|---|
| `Roots` | a pool of the supplied anchors, never nil | nil Roots load the system store (the platform verifier on Windows and macOS) |
| `Intermediates` | the input's certificates that are not anchors | nothing fetched, no system pool |
| `CurrentTime` | the injected inspection time | a zero time reads the system clock |
| `KeyUsages` | the requested purpose's extended key usage: `[ExtKeyUsageAny]` for `any` (the default), otherwise per ADR-0007 | an empty list means server authentication; generic inspection is not purpose validation |
| `MaxConstraintComparisions` | 250000 | Go 1.27.1 does not read this field; it is set anyway so that no bound is ever implicit |
| `DNSName` | not set | host name validation is a later slice |
| `CertificatePolicies` | not set | Go's default: any valid policy is acceptable |

**Guards:**
- Verify refuses a nil target, an empty anchor set or a zero time, returning
  `unverifiable/engine_error` without calling Go.
- `internal/archtest` enforces the call-site shape.

### What Go 1.27.1 evaluates here

Results are reported as engine `go-x509`, with `engine_version` taken from
`runtime.Version()`. Trustsmith does not claim an independent RFC 5280
implementation. Behaviour pinned by tests:

- **Validity** of every certificate, at the injected time, inclusive at both
  ends. This includes the anchor: an expired anchor fails.
- **Issuer authority.**
  - An intermediate needs BasicConstraints CA:TRUE.
  - Every issuer, anchor included, must pass `CheckSignatureFrom`, which also
    requires CA status and, when KeyUsage is present, keyCertSign.
- **Path length.** Go counts **every** intermediate against
  `pathLenConstraint`, self-issued ones included. RFC 5280 and ADR-0005's
  structural evaluator do not count self-issued intermediates. Trustsmith
  reports Go's result as Go's, and keeps both views.
- **Name constraints** apply to every name in the chain, even though no host
  name is requested. Go does not support DirectoryName constraints.
- **Unhandled critical extensions** are rejected.
- **Certificate policies** are processed (RFC 5280 as updated by RFC 9618),
  with any policy acceptable.
- **Signature algorithms.** SHA-1 and MD5 certificate signatures are rejected.
  Go's `CheckSignature` still verifies SHA-1, which is what ADR-0004 relies
  on.
- **Not evaluated:** revocation, host names, and AIA fetching. Extended key
  usage is enforced only for a purpose requested with `--purpose` (ADR-0007);
  by default any usage is requested.

### States and reasons

| State | Meaning |
|---|---|
| `not_evaluated` | no roots supplied (the whole evaluation) |
| `verified` | Go built at least one chain to a supplied anchor |
| `failed` | Go rejected the certificate, for the stated reason |
| `unverifiable` | Go reached no conclusion Trustsmith can classify |

**Stable reasons:**
- `no_explicit_anchor_path`
- `certificate_expired`, `certificate_not_yet_valid`
- `issuer_not_authorized`, `name_constraints`, `path_length`
- `unhandled_critical_extension`, `incompatible_usage`
- `insecure_signature_algorithm`, `policy`
- `engine_limit`, `engine_error`

`no_explicit_anchor_path` says exactly what was checked: only the supplied
anchors. It never says "untrusted".

**How errors are classified:**
- Typed errors are classified by type and reason. That covers
  `CertificateInvalidError`, `UnhandledCriticalExtension` and
  `InsecureAlgorithmError`. For expiry, the certificate's own dates decide
  between expired and not yet valid.
- Most chain-building failures reach callers only as an
  `UnknownAuthorityError`. Its message carries the error that rejected **one**
  candidate issuer. `trustverify.classifyHint` is the only code that reads
  verifier message text, and real-chain tests pin every hint it recognises.
  With several candidates, the reason describes a rejected candidate, not
  necessarily every reason.
- A candidate that matched by name but did not sign the certificate gives
  `no_explicit_anchor_path`.
- Anything unrecognised becomes `unverifiable/engine_error`, never a guessed
  failure.
- Raw verifier messages are never part of the JSON contract.

### Chains

- Every chain the verifier returns is kept.
- Chains are normalised to certificate fingerprints, from the target to the
  anchor.
- They are ordered shortest first, then by fingerprint bytes. The ordering is
  for presentation only and does not depend on input order.

### Layers stay separate

| Layer | Question | Engine |
|---|---|---|
| Issuer relationships (ADR-0004) | does this key verify that signature? | `CheckSignature` |
| Included paths (ADR-0005) | what paths do those relationships form, and are the issuers structurally allowed to sign? | Trustsmith |
| Trust evaluation (this ADR) | does Go validate this certificate to the supplied anchors? | `go-x509` |

No layer rewrites another. A SHA-1 chain, for example, shows:
- the relationship as `verified`;
- the path as `complete_in_input`;
- trust as `failed / insecure_signature_algorithm`.

A path's `trust` field remains `not_evaluated`: that layer never evaluates
trust.

### Findings

| Code | Severity | Emitted when |
|---|---|---|
| `trust.failed` | critical | a target failed validation; evidence `reason` |
| `trust.unverifiable` | warning | the verifier was inconclusive; evidence `reason` |

- A verified target produces no finding.
- The reason is evidence on one code rather than a code per reason. Facts that
  certificates already report, such as `cert.expired` or `sig.sha1`, keep
  their own findings.
- `trust.failed` is critical, so with `--roots` a failed validation reaches
  exit code 3 under the default `--fail-on critical`.

### Output

**JSON.** `trustsmith.inspect/v1` gains a top-level `trust_evaluation`,
additively:
- `state`;
- `source` (`supplied_roots`), `engine` (`go-x509`) and `engine_version`,
  each null when not evaluated;
- `requested_purpose` and `requested_extended_key_usages` (`["any"]` by default; ADR-0007);
- `roots_files`;
- `anchors`, each with its fingerprint, subject, `self_signature` fact, roots
  sources and the input entries holding the same certificate;
- `targets`, each with its certificate, `state`, `reason`, and `chains`
  (certificate references plus `anchor`).

`summary.chain` keeps `not_checked` and gains values that name their source:
- `verified_to_supplied_roots`
- `failed_against_supplied_roots`
- `unverifiable_against_supplied_roots`

There is no `valid` or `trusted` key or value. A test scans every golden for
them.

**Text.**
- A "Trust evaluation" section is always present.
- Without roots it reads: "Not evaluated: no trust anchors were supplied".
- With roots it names the source files, the verifier and its version, and each
  anchor, then gives each target's result, chains or reason.
- The per-certificate Chain line names the supplied roots whenever it reports
  a result.

### Architecture

`internal/archtest`:
- allows `Certificate.Verify`, `x509.VerifyOptions` and certificate pools only
  in `internal/trustverify`;
- requires each Verify call there to take a `VerifyOptions` literal that sets
  `Roots`, `Intermediates`, `CurrentTime`, `KeyUsages` and
  `MaxConstraintComparisions`, none of them to nil, and does not set
  `DNSName`;
- forbids `x509.SystemCertPool` and `SetFallbackRoots` everywhere, tests
  included.

`trustverify` is a domain package, so it cannot import the network, the
filesystem or processes. Roots files are read by the application service.

## Consequences

- Later slices can add, each as an explicit and separately reported choice:
  - purpose validation, with key usages taken from user intent;
  - host name validation;
  - system or platform roots.
- The Go-specific behaviours pinned here are regression tests. A Go release
  that changes them fails the suite instead of silently changing results.
