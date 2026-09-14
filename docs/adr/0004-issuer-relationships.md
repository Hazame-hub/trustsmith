# ADR-0004: Issuer relationships inside one input

- Status: accepted
- Date: 2026-09-14
- Implemented in: `internal/sigcheck`, `internal/issuerlinks`, `internal/interpret`, `internal/cli`

## Context

An inspection input often contains several certificates, such as a bundle
with a leaf, an intermediate and a root. Users want to know which certificate
signed which.

That is a narrow cryptographic question. It is not the same as "is this chain
trusted", "is the issuer a valid CA" or "is the chain valid". Those need trust
anchors, BasicConstraints, KeyUsage, path length, validity, name constraints,
purpose and policy, and later chain validation will answer them.

## Decision

### What a relationship means

A `certificate_issuer` relationship links a **child** certificate to a
**candidate** issuer from the same input.

- **Evidence** says why the candidate was considered. Evidence is heuristic
  and never makes a relationship verified:
  - `issuer_dn_match`: the child's issuer name is byte-identical to the
    candidate's subject name.
  - `authority_key_id_match`: the child's Authority Key Identifier equals the
    candidate's Subject Key Identifier.
- **State** is the result of checking the child's signature with the
  candidate's public key:

| State | Meaning |
|---|---|
| `verified` | The candidate's key verifies the child's signature over its exact TBSCertificate bytes. |
| `invalid` | The engine evaluated the signature under that key and it does not verify, or that key type cannot have produced it. |
| `unverifiable` | The engine could not decide (for example an algorithm it refuses). Never treated as invalid. |
| `not_checked` | A work limit was reached before this candidate was checked. Unknown, not absent. |

- **Reason** is a stable code for non-verified states:

| Reason | State |
|---|---|
| `signature_mismatch` | invalid |
| `key_algorithm_mismatch` | invalid |
| `insecure_algorithm` | unverifiable |
| `unsupported_algorithm` | unverifiable |
| `engine_error` | unverifiable |
| `engine_panic` | unverifiable |

A verified relationship means only that the signature is cryptographically
valid under that key. No trust, CA validity, chain validity or acceptability of
the algorithm is implied. A verified SHA-1 signature still carries the
`sig.sha1` finding.

### Verification

- **API.** `internal/sigcheck` calls
  `signer.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)`
  on the standard-library parse of both certificates. It uses the exact signed
  bytes and signature from the child; nothing is reconstructed.
- **`CheckSignatureFrom` is deliberately not used.** In Go 1.27.1 it also:
  - rejects a signer without CA:TRUE or without the certSign key usage;
  - passes `allowSHA1=false`.
  Those are chain-validation policies, not facts about a signature. Tests pin
  both differences.
- **Classifier.** `sigcheck.classify` maps errors to states:
  - `InsecureAlgorithmError` becomes `unverifiable/insecure_algorithm`.
  - `ErrUnsupportedAlgorithm` becomes `unverifiable/unsupported_algorithm`.
  - `rsa.ErrVerification` becomes `invalid/signature_mismatch`.
  - For failures crypto/x509 reports as untyped errors, the classifier is the
    only code that matches Go's message text: the ECDSA, Ed25519 and ML-DSA
    verification-failure messages, and the key-algorithm and ML-DSA-parameter
    mismatch messages.
  - Anything unrecognised is `unverifiable/engine_error`, never `invalid`.
  - Real-signature tests across RSA, ECDSA, Ed25519 and ML-DSA detect if Go
    changes its messages.
- **Pinned Go 1.27.1 behaviour.**
  - RSA and ECDSA SHA-1 certificate signatures verify with `CheckSignature`,
    and `CheckSignatureFrom` refuses them.
  - MD5 is refused by both. That is `unverifiable`, even with an unrelated key,
    because Go never evaluates the signature.
  - A signer holding an X25519 key gives `unverifiable/unsupported_algorithm`.
  - A signer that is not a CA still verifies.

### Self-issued and self-signed

- **Self-issued** (`SelfIssued`, an x509facts field): subject and issuer names
  are byte-identical. It is a naming fact only.
- **Self-signed:** a self-issued certificate whose own public key verifies its
  signature. This follows RFC 5280 and uses the same `sigcheck` call.
  - x509facts records it as `SelfSignature` with the values `verified`,
    `failed`, `unverifiable` or `not_applicable`. `failed` is the
    self-signature spelling of `invalid`, and is kept for v1 compatibility.
- **A certificate is never its own relationship candidate.**
- `cert.self_signed_leaf` and the `self_signed` issuer state both require a
  verified self-signature. A self-issued certificate signed by another key is
  neither.

### Candidate discovery and complexity

`internal/issuerlinks.Resolve` works in memory over the parsed certificates of
one input:

1. **Deduplicate** certificates by `x509-cert-sha256`. A certificate appearing
   several times is one certificate listing all its entries.
2. **Index** by raw subject name and by Subject Key Identifier.
3. **Gather candidates** for each certificate: those matching its Authority Key
   Identifier first, then those matching its issuer name. At most
   `MaxCandidatesPerCertificate` (32) are kept; any beyond that set
   `CandidatesOmitted` and the `issuer.candidates_not_checked` finding.
4. **Verify once per distinct candidate key** (encoded SPKI) per child, within a
   global budget of `MaxVerifications` (4096). Past the budget, relationships
   are recorded as `not_checked`.

Unrelated certificates cost no signature checks, and ordinary inputs cost about
one check per issued certificate. Every verified relationship is kept; no parent
is chosen. Several certificates for the same key all verify. Unparseable
certificates and CSRs take no part.

### Output

- **Findings.** Only two, both `info`:
  - `issuer.candidate_unverifiable`: matching certificates exist, none verified,
    and at least one could not be checked.
  - `issuer.candidates_not_checked`: limits were reached.
  A missing issuer, several candidates, or a candidate whose key does not verify
  produce no finding.
- **Summary.** `issuer_in_input` takes, in precedence order: `verified`,
  `self_signed`, `candidate_unverifiable`, `candidate_not_checked`,
  `candidate_invalid`, `not_present`. It comes with `verified_issuer_entries`
  and `candidate_issuer_entries`.
- **JSON.** `trustsmith.inspect/v1` gains a top-level `relationships` array and
  these summary fields. Both are additive, so the schema version is unchanged.
- **Text.** Under the stated issuer name, a second line states what the input
  shows. An "Issuer relationships" section lists every relationship and says a
  verified signature is not a trust decision. The word "trusted" is never used.

### Panic boundaries

`recover` is allowed only at the two untrusted-input boundaries:
- the standard-library X.509 parser in `x509facts`, reported as
  `Parsed.ParserPanicked`;
- the signature engine in `sigcheck`, reported as `engine_panic`.

The inspect service counts both in `Result.RecoveredPanics`, which the tests and
fuzzing assert is zero. Interpretation, relationship resolution, rendering and
application logic do not recover, so a bug there fails loudly instead of
becoming a finding about the input. `internal/archtest` enforces this.

## Consequences

- Chain building can later start from verified relationships, choosing paths
  among several verified issuers and adding trust anchors and policy.
- Relationship state is a cryptographic fact that stays independent of the
  policy findings.
