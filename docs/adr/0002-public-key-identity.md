# ADR-0002: Certificate and public-key identity

- Status: accepted
- Date: 2026-09-14
- Implemented in: `internal/fingerprint` (vectors in `internal/fingerprint/testdata`)

## Context

A certificate's identity and a public key's identity must be deterministic.
They have to join the same key across certificates, CSRs, public keys, private
keys and, later, other systems (Sybil/Aegis/Quasar).

An identity that depends on how bytes happen to be encoded, or on how strict a
given Go release is, would silently split one key into several identities.
Aegis's own credential fingerprint is an OPRF over secret material. It is the
wrong tool for public data, and Trustsmith never presents its fingerprints as
Aegis fingerprints.

## Decision

Three schemes. Each is a distinct Go type, so they cannot be confused:

| Scheme | Go type | Definition | Use |
|---|---|---|---|
| `x509-cert-sha256` | `fingerprint.Cert` | SHA-256 of the certificate DER exactly as encoded | certificate identity |
| `x509-spki-sha256` | `fingerprint.KeyID` | SHA-256 of the **canonical** SubjectPublicKeyInfo defined below | the only cross-artifact and cross-system key identity |
| `x509-spki-encoded-sha256` | `fingerprint.EncodedSPKI` | SHA-256 of the SPKI bytes exactly as present in an artifact | provenance, diagnostics, RFC 7469 pins; **never a join key** |

- **Wire form:** 64 lowercase hex characters, labelled by scheme.
- **Human form:** `sha256:<hex>`.
- **RFC 7469 pin:** `pin-sha256` is base64 of the `x509-spki-encoded-sha256`
  digest.
- **OpenSSL-style form:** the uppercase colon-separated certificate fingerprint
  is display only.

### Canonical SPKI

The canonical SPKI is DER as defined in RFC 5280. The BIT STRING must have
0 unused bits.

| Family | AlgorithmIdentifier | subjectPublicKey | Accepted non-canonical input, canonicalised |
|---|---|---|---|
| RSA | `rsaEncryption` 1.2.840.113549.1.1.1, parameters **explicit NULL** | DER `RSAPublicKey{n, e}`, minimal positive INTEGERs | parameters absent |
| ECDSA | `id-ecPublicKey` 1.2.840.10045.2.1, `namedCurve` P-256 1.2.840.10045.3.1.7 / P-384 1.3.132.0.34 / P-521 1.3.132.0.35 | uncompressed point `04‖X‖Y` | compressed point `02/03‖X` (decompressed, checked on-curve) |
| Ed25519 | `id-Ed25519` 1.3.101.112, parameters absent | 32 bytes | none |
| ML-DSA | `id-ml-dsa-44/65/87` 2.16.840.1.101.3.4.3.17 / .18 / .19, parameters absent | 1312 / 1952 / 2592 bytes | none |

**Unsupported, so no KeyID** (`fingerprint.ErrUnsupported`):
- RSASSA-PSS-OID keys.
- `implicitCurve` / `specifiedCurve` parameters, and curves other than the three
  above.
- DSA, X25519, X448, Ed448 and unknown OIDs.

**Malformed, so no KeyID** (`fingerprint.ErrMalformed`):
- Structural errors and trailing data.
- Non-zero unused bits.
- RSA parameters other than NULL or absent.
- Non-minimal or non-positive RSA integers.
- Missing EC parameters, and off-curve or wrongly sized points.
- Ed25519 or ML-DSA with parameters present, or with the wrong length.

Adding support for an algorithm later only **adds** identities; it never
changes an existing one.

### Implementation rules

- **Trustsmith's own `cryptobyte` encoder is the definition.** It does not use
  `x509.ParsePKIXPublicKey`/`MarshalPKIXPublicKey`, because their strictness
  varies across Go releases. For example, Go rejects RSA keys without NULL
  parameters. A test asserts that `MarshalPKIXPublicKey` equals the canonical
  bytes for every positive vector, so drift is detected, but the spec wins.
- **Validation depth.** Point decompression uses
  `crypto/elliptic.UnmarshalCompressed`, and uncompressed points are validated
  with `ecdsa.ParseUncompressedPublicKey`. Ed25519 and ML-DSA keys are checked
  for length only.
- **No substitution.** A KeyID is never derived from bytes that could not be
  canonicalised: there is no fallback to the encoded hash. In the JSON output, a
  missing identity is `null`.
- **Certificates Go cannot parse** still get both fingerprints when their SPKI
  can be located structurally (`x509facts`).
- **Non-canonical keys.** When a KeyID exists but the encoded bytes differ from
  canonical, both values are reported and `key.noncanonical_spki` is emitted.

## Vectors

Computed on 2026-09-14 with OpenSSL 3.5.7
(`openssl pkey -pubout -outform DER | sha256sum`). The tests reproduce every
positive vector from every input form: SPKI PEM/DER, PKCS#8, PKCS#1/SEC1 where
applicable, a self-signed certificate and a CSR.

| Vector | Input key | Canonical SPKI | `x509-spki-sha256` |
|---|---|---|---|
| rsa-2048 | RFC 9500 `testRSA2048` | 294 B, `30820122300d06092a864886f70d0101010500…` | `8fb6bad671cfe698393c453357da61b56d757ab8c0f3fb9c87f2849e63131878` |
| ecdsa-p256 | RFC 9500 `testECCP256` | 91 B, `3059301306072a8648ce3d020106082a8648ce3d030107034200…` | `b2b04340cfaee616ec9c2c62d261b208e54bb197498df52e8cadede23ac0ba5e` |
| ed25519 | RFC 8410 §10.3 | 44 B, `302a300506032b6570032100…` | `a1e9156054e04fac899ae9f275132cdc07a5dbc4ea2c2ad3a1ffc6e0d253681f` |
| ml-dsa-44 | seed `000102…1e1f` | 1334 B, `30820532300b06096086480165030403110382052100…` | `837832708c5236d951581f1fddf2b79991b3424a0486d16da1ddad0fd69701be` |
| ml-dsa-65 | seed `000102…1e1f` | 1974 B, `308207b2300b0609608648016503040312038207a100…` | `b8b62131bfbe84433efb2273d7f5b87f7a22854a2cfd366fc2aead86d837c52d` |
| ml-dsa-87 | seed `000102…1e1f` | 2614 B, `30820a32300b060960864801650304031303820a2100…` | `07e57c4f14dbad1267f621ec3777b4e2e6c4fbc4c22fbb87510ff8e0b3c6a642` |

Two-scheme vectors (non-canonical encodings of the same keys):

| Vector | Encoded SPKI | `x509-spki-encoded-sha256` | `x509-spki-sha256` |
|---|---|---|---|
| rsa-2048, NULL parameters missing | 292 B | `675e4501dfdc6442006534585c91eff10fb1da755f8a2dcbe5c434655423ad34` | `8fb6bad6…63131878` (same as rsa-2048) |
| ecdsa-p256, compressed point | 59 B | `b9fd8f074598636ae25ab3f96311e48bc2c602bd6397aad28c74eb0e7f9bf546` | `b2b04340…3ac0ba5e` (same as ecdsa-p256) |

OpenSSL 3.5.7 re-emits the compressed point unchanged. That is concrete
evidence that "whatever a library re-marshals" is not a stable identity.

## Consequences

- Correlation with other systems uses `x509-spki-sha256` only. A future
  Quasar/Aegis proposal must emit that scheme, derived from the parsed key.
- `x509-spki-encoded-sha256` may be displayed and exported only under its own
  scheme name.
- Changing the canonical encoding of an already supported family would change
  identities, so it would need a new scheme name, not an edit here.
