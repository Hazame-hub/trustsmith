# ADR-0010: Explicit compatible TLS probe policy

- Status: accepted
- Date: 2026-09-16
- Implemented in: `internal/probe`, `internal/interpret`, `internal/app/inspectsvc`, `internal/cli`

## Context

`modern-v1` (ADR-0009) offers TLS 1.2 with ECDHE AEAD suites and TLS 1.3. A
server that accepts only older TLS 1.2 suites fails that handshake, and
Trustsmith then acquires no certificate from it. Users need a way to inspect
such endpoints without Trustsmith quietly lowering what it offers.

A probe policy answers one question: what TLS capabilities is Trustsmith
willing to offer during this diagnostic handshake? It does not mean secure,
insecure, trusted, vulnerable, or compatible with every legacy system.
Certificate trust, host name identity, purpose and transport stay separate.

## Decision

### Two explicit, versioned policies

| Identifier | Name | Selected by |
|---|---|---|
| `modern-v1` | `modern` | default, or `--probe-policy modern` |
| `compatible-v1` | `compatible` | `--probe-policy compatible` only |

- **Unchanged modern.** `modern-v1` is unchanged; a test pins it.
- **No silent changes.** A published policy version never changes meaning: a different offer is a new version.
- **One attempt.** The user chooses the policy before the handshake, and the probe makes exactly one attempt. There is no automatic fallback from `modern` to `compatible`.
  - A modern failure says only that the modern handshake failed, never that the server requires `compatible`.
  - Tests count connection attempts.
- **Usage errors (exit 2).** An unknown `--probe-policy` value, or the flag with a file input, is a usage error.

### compatible-v1

`compatible-v1` is `modern-v1` plus a small, named set of additions.

**Versions:** TLS 1.2 to TLS 1.3, the same as modern. TLS 1.0 and 1.1 belong
to a later, explicit legacy diagnostic policy.

**TLS 1.2 suites:** every modern-v1 suite, plus the four suites below. Their
constants were verified against Go 1.27.1.

| Suite | ID |
|---|---|
| `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` | 0xc009 |
| `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` | 0xc013 |
| `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA` | 0xc00a |
| `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` | 0xc014 |

These keep ephemeral ECDH key exchange but use AES-CBC with HMAC-SHA1. Go
1.27.1 neither lists them in `tls.InsecureCipherSuites()` nor disables them,
so an explicit client suite list offers them without GODEBUG.

**Deliberately excluded:**
- **Static RSA key exchange** (`TLS_RSA_WITH_*`): no forward secrecy. It belongs to explicit legacy diagnostics.
- **3DES and RC4:** out entirely.
- **ECDHE CBC-SHA256 suites:** Go lists them among its insecure suites, and they add little compatibility beyond CBC-SHA1.
- **Everything else Go still implements.** `compatible-v1` broadens interoperability by a named amount; it is not an "enable everything" mode.

**Groups:** every modern-v1 group (X25519MLKEM768, X25519, P-256, P-384), plus
P-521. Go 1.27.1 supports it through the same public `CurvePreferences`
mechanism.

### Sets, not preferences

Go 1.27.1 ignores the order of `Config.CipherSuites` and
`Config.CurvePreferences`: it applies its own fixed preference order and uses
the configured lists only as filters. So:
- a policy defines allowed **sets**;
- output lists suites and groups sorted by name, which also changes the listed order for `modern-v1`, without changing what it offers;
- Trustsmith never presents list order as negotiation priority.

TLS 1.3 suites and signature schemes remain engine-managed.

### Negotiated key exchange group

`key_exchange_group` is `tls.ConnectionState.CurveID`, as Go names it. It is
never inferred from suite names.

`CurveID == 0` means Go reports no ECDHE or hybrid group, as with RSA key
exchange, which no current policy offers. An ECDHE handshake reporting 0 would
be unexpected engine behaviour. It is represented diagnostically, without a
panic:
- JSON `null`;
- text "key exchange group not reported by the engine".

### What was actually negotiated

`compatible` succeeding does not mean weaker parameters were used. The probe
records `compatibility_features_used`: the negotiated parameters that
`modern-v1` does not offer.

| Feature | Negotiated |
|---|---|
| `tls12_aes_cbc_sha1` | a TLS 1.2 ECDHE AES-CBC-SHA suite |
| `ecdhe_p521` | the P-521 group |

- **How it's computed.** From the negotiated values alone, whatever the policy, so it is `[]` whenever every negotiated parameter is also in `modern-v1`'s offer.
- **What it never claims.** It never claims a modern handshake would have failed: the server might have accepted a modern offer too.

### Finding

`tls.cbc_cipher_negotiated` (warning, whole input) is emitted only when a TLS
1.2 AES-CBC-SHA suite was actually negotiated. It states:
- that fact;
- that the modern policy does not offer the suite;
- that it was available only because `compatible` was selected.

Evidence: `tls_version`, `cipher_suite`, `policy`. A `compatible` handshake
that negotiated modern parameters, or only P-521, produces no finding. There
is no score or grade, and the endpoint is not called insecure.

### One probe implementation

Policies are immutable data consumed by the existing probe. The single
`tls.Config` literal and its architecture test are unchanged, and
`CompatibleV1()` is built from `ModernV1()` plus the named additions.

## Consequences

- `probe.policy` gains `id`, and `probe` gains `compatibility_features_used`, additively within `trustsmith.inspect/v1`. Policy suite and group lists are now sorted.
- **Text output.** It shows a "Compatibility" line for non-modern policies.
- **Deferred:**
  - a `legacy-diagnostic` policy (TLS 1.0/1.1, RSA key exchange, and whatever GODEBUG-free Go allows);
  - post-handshake alerts;
  - any per-endpoint rating.
