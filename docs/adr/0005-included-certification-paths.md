# ADR-0005: Structural certification paths inside one input

- Status: accepted
- Date: 2026-09-14
- Implemented in: `internal/chainpath`, `internal/interpret`, `internal/app/inspectsvc`, `internal/cli`

## Context

ADR-0004 establishes which certificate of an input verifies which certificate's
signature. Users with a bundle next want to see the paths those relationships
form, and whether the issuers along them are structurally allowed to issue
certificates: CA status, key usage, path length, and validity at the
inspection time.

That is still not chain validation. Validation needs trust anchors, which this
version does not have, plus name constraints, policies, purpose and revocation.
The standard verifier cannot be used here either: `x509.Certificate.Verify`
takes its trust anchors in `VerifyOptions.Roots`. Putting a self-signed
certificate from the input there would declare it trusted, which is exactly
the conclusion this slice must not reach.

## Decision

### What a path is

An **included certification path** is a sequence of distinct certificates from
one input. It starts at the certificate furthest from any issuer, and each
certificate is followed by one whose key verifies its signature (a `verified`
relationship, ADR-0004).

- **Completeness** says how far construction got:

| Completeness | End | Meaning |
|---|---|---|
| `complete_in_input` | `self_signed_terminal` | The path reaches a certificate with a verified self-signature. **Not a trust decision.** |
| `partial` | `no_issuer_candidate` | The last certificate has no issuer candidate in the input. Matching is by exact name and key identifier, so this does not prove absence. |
| `partial` | `issuer_candidates_not_verified` | Candidates exist, but none verified (they do not verify, or were unverifiable). |
| `limit_reached` | `issuer_candidates_not_checked` | Issuer-link limits left candidates unchecked. Unknown, not absent. |
| `limit_reached` | `depth_limit` | The path reached `MaxDepth`; it may continue. |
| `cycle` | `cycle` | The next issuer is already on the path; `CycleTo` names its position. |

- **A self-signed certificate ends a path. It is never a trust anchor.** The
  JSON calls it `self_signed_terminal`; there is no `root` or `trusted_root`
  value.
- **Signatures** along a path are verified by construction. Nothing is
  re-verified, and no other signature check exists.
- **Trust** is always `not_evaluated`. No path field is named or valued as a
  validity or trust verdict, and tests enforce that on both the Go types and
  every golden output.

### Construction

`chainpath.Build(inputs, relationships, now, limits)` works in memory:

1. **Deduplicate** certificates by `x509-cert-sha256`, as ADR-0004 does.
2. **Start** at every certificate that issued no other certificate in the
   input, in order of first appearance.
3. **Extend** a path through each verified issuer in relationship order. Every
   alternative becomes its own path (cross-signing, reissued intermediates), and
   no "best" parent is chosen.
4. **Stop** at a self-signed certificate, at a certificate with no verified
   issuer, at an issuer already on the path (a cycle), or at a limit.
5. **Also start** from any certificate not reachable from those starts, which
   can only happen inside a cycle. Reachability follows the relationships
   themselves, not what construction visited, so a certificate cut off by a
   limit is reported through the limit rather than as a new start.

**Work limits** (`DefaultLimits`) are centralised:

| Limit | Default |
|---|---|
| `MaxDepth` | 16 certificates on one path |
| `MaxPathsPerStart` | 32 |
| `MaxExpansions` | 4096 extension steps for the whole input |

- Reaching any limit sets `Result.LimitReached`. The service copies it to
  `path_limit_reached` and emits `chain.path_limit_reached`.
- Additional paths are never silently discarded while the rest is called
  complete.

### Structural checks

For each certificate at position *j* ≥ 1 (an issuer of the certificate before
it), `evaluateStructure` checks:

- **CA status** (RFC 5280 6.1.4(k)):
  - BasicConstraints absent or CA:FALSE → `issuer_not_ca` (violation).
  - A version 1 or 2 issuer, whose CA status can only be established out of
    band → `issuer_ca_status_not_evaluated` (not evaluated).
- **Key usage** (6.1.4(n)): the KeyUsage extension present without
  keyCertSign → `issuer_key_usage_without_key_cert_sign` (violation). An
  absent extension places no restriction.
- **Path length** (4.2.1.9, 6.1.4(l)(m)): for a CA with `pathLenConstraint`
  *n*, count the certificates at positions 1…*j*−1 that are **not
  self-issued**. The start of the path is not an intermediate and does not
  count. More than *n* → `path_length_exceeded` (violation), with the constraint
  and the count as evidence.
- **Constraints this version does not evaluate:** name constraints, policy
  constraints, policy mappings or inhibitAnyPolicy on an issuer →
  `…_not_evaluated`.
- **Critical extensions:** any critical extension on any certificate of the
  path, other than basic constraints, key usage, extended key usage, subject
  alternative names and key identifiers → `critical_extension_not_processed`.

**Structure state:**

| State | When |
|---|---|
| `failed` | Any violation. A violation outranks anything not evaluated. |
| `structurally_unverifiable` | No violation, but something was not evaluated. |
| `satisfied` | Every check passed and nothing relevant was left unevaluated. |
| `not_applicable` | A one-certificate path, which has no issuer. |

A structure is therefore never `satisfied` by omission.

**Validity:** every certificate on the path is checked at the injected
inspection time. Any certificate outside its period makes the path's validity
`failed` and is listed, as `expired` or `not_yet_valid`.

This is deliberately **not** RFC 5280 path validation: no names such as
`RFC5280Valid`, `ValidChain` or `TrustedChain` exist.

### No standard verifier

- `internal/chainpath` does not call `Certificate.Verify` and builds no
  `VerifyOptions` or `CertPool`.
- `internal/archtest` forbids `x509.VerifyOptions`, `x509.CertPool`,
  `x509.NewCertPool`, `x509.SystemCertPool`, and any `.Verify(` call, in all
  production code.
- None of the structural checks needed the verifier.
- Trust anchors, when they arrive, will be an explicit input and will lift this
  rule deliberately.

### Findings

Findings stay sparse and avoid duplicates:

| Code | Severity | Reported on |
|---|---|---|
| `chain.issuer_not_ca` | warning | The issuer, once, however many paths pass through it; evidence `basic_constraints` = `absent` or `ca_false`. |
| `chain.issuer_key_usage` | warning | The issuer, once. |
| `chain.path_length_exceeded` | warning | The constrained CA, once, with the largest excess seen. |
| `chain.structure_not_evaluated` | info | The certificate, once per reason and extension. |
| `chain.cycle` | info | The certificate that would repeat. |
| `chain.path_limit_reached` | info | The whole input. |

- **Not findings:**
  - a partial path, because a missing issuer is ordinary for a leaf file;
  - a complete path, because it is not an achievement;
  - validity, because every certificate already has its own `cert.expired` /
    `cert.not_yet_valid` finding and a path finding would duplicate it.

### Output

**JSON.** `trustsmith.inspect/v1` gains, additively:
- `overview.included_paths` and `overview.path_limit_reached`;
- a top-level `paths` array.

Each path has:
- `type` `included_certification_path`;
- `certificates` (fingerprint and entries);
- `completeness`, `end`, and `cycle_to_position` (null unless a cycle);
- `signatures`: `verified` when the path has issuer links, otherwise
  `not_applicable`;
- `structure` {`state`, `issues`};
- `validity` {`state`, `outside_validity_period`};
- `trust`: always `not_evaluated`.

**Text.**
- An "Included certification paths" section appears when some path links
  certificates, cycles or hits a limit.
- Each path shows its end, completeness, signatures, CA constraints with one
  line per issue, validity, and "Trust: not evaluated".
- A one-certificate path is described by its own entry, so it gets no section.
- The per-certificate Chain line reads "not validated against trust anchors".

## Consequences

- Trust-anchor-based validation can later consume these paths and add anchors,
  name constraints, policies, purpose and revocation, reporting against the
  same structure.
- The trust field and the verifier ban make any later trust decision an
  explicit, reviewable change rather than a side effect.
