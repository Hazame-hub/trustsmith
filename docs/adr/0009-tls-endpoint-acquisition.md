# ADR-0009: Minimal TLS endpoint acquisition

- Status: accepted
- Date: 2026-09-14
- Implemented in: `internal/endpoint`, `internal/probe`, `internal/app/inspectsvc`, `internal/cli`

## Context

Users want to inspect the certificates a server actually presents, not only
files. Acquiring them needs a TLS handshake, and a handshake is where most
tools quietly mix acquisition with judgement:
- Go's default verification ends the handshake before an untrusted or
  mismatched chain can be seen;
- library defaults decide which versions and suites are offered, and change
  between releases;
- a failed connection is easily reported as a bad certificate.

This slice adds acquisition only. Every judgement stays in the existing layers
(ADR-0004 to ADR-0008), unchanged.

## Decision

### Targets

`trustsmith inspect` accepts `host:port`, `[IPv6]:port` and `tls://host:port`.
Without a port, 443 is used.

- **Existing files win.** An existing file with the same name is always
  inspected as a file, and a Windows drive path is always a file (the
  existing target resolver).
- **Refused, never stripped:**
  - any scheme other than `tls://`, including `https://`, since Trustsmith
    speaks no application protocol;
  - user information, paths, queries and fragments;
  - an unbracketed IPv6 address with a port;
  - a port outside 1 to 65535.
- **Host validation.** The host is validated by the hostname layer (ADR-0008).
  A DNS name therefore becomes the same IDNA A-label identity that host name
  evaluation uses, and an IP address its canonical form.

Three concepts stay separate:
- **Connect address:** the normalised host and port.
- **SNI:** the normalised ASCII DNS name, never an IP address. Go also omits
  IP literals.
- **Host name identity:** the endpoint host, or `--hostname` when given.

There is no `--server-name` flag, but `probe.Target` already carries the
server name separately from the address.

### Policy `modern`, version 1

Every field bearing on what is offered is set explicitly in one `tls.Config`
literal. An architecture test pins the required and forbidden fields.

| Field | Value |
|---|---|
| `MinVersion` / `MaxVersion` | TLS 1.2 / TLS 1.3 |
| `CipherSuites` (TLS 1.2 only) | ECDHE_ECDSA and ECDHE_RSA with AES_128_GCM_SHA256, AES_256_GCM_SHA384, CHACHA20_POLY1305_SHA256 |
| `CurvePreferences` | X25519MLKEM768, X25519, P-256, P-384 |
| `Renegotiation` | `RenegotiateNever` |
| `ClientSessionCache` / `SessionTicketsDisabled` | nil / true (no resumption) |
| `NextProtos` | nil (no ALPN offered) |
| `ServerName` | the SNI described above |
| `InsecureSkipVerify` | true (below) |
| `Time` | the injected clock |
| `GetClientCertificate` | records a request and returns an empty certificate |
| Never set | `RootCAs`, `VerifyPeerCertificate`, `VerifyConnection`, `KeyLogWriter`, `Certificates` |

There is no CBC, no RSA key exchange, no 3DES and no TLS 1.0/1.1. There is no
GODEBUG setting (an architecture test forbids `godebug` in go.mod,
`//go:debug` and GODEBUG literals), and no retry with a weaker policy. Changing
any value makes a new policy version.

**Engine-managed.** Go's public API does not let a client choose:
- the TLS 1.3 cipher suites;
- the signature schemes it offers;
- its handshake message size bounds.

Results record `tls13_cipher_suites` and `signature_schemes` as
`engine_managed` and name the engine (`go`, with the Go version), rather than
claiming the policy determines them.

### Diagnostic handshake

`InsecureSkipVerify` is used only to collect peer certificate material for
diagnostics. Trustsmith performs trust and hostname evaluation separately and
reports them independently.

It is confined to `internal/probe`, which depends on no other Trustsmith
package. Architecture tests enforce this, and also confine `crypto/tls` and
network dialing to that package.

- **Where certificates come from.** After the handshake the probe copies
  `ConnectionState().PeerCertificates` in the server's order and closes the
  connection. It sends no application data, only the TLS close_notify, and
  makes no HTTP request.
- **What is never done.** No `VerifyPeerCertificate` or `VerifyConnection`
  callback exists, `RootCAs` is never set, and no system roots are consulted.
- **What completion means.** A completed handshake is reported as acquisition,
  never as trust.

### Timeouts, stages and reasons

The connect timeout bounds the dial, and the handshake timeout bounds the
handshake. Both are context deadlines, 10 seconds each by default.

- **State:** `complete` or `failed`.
- **Stage:** how far the probe got: `resolve`, `connect`, `handshake` or
  `complete`.
- **Reasons** are stable codes; raw engine error text never reaches the
  output:

| Reason | Stage | Classified from |
|---|---|---|
| `dns_error` | resolve | `*net.DNSError` |
| `connect_timeout` | connect | deadline exceeded |
| `connect_refused` | connect | `ECONNREFUSED` / `WSAECONNREFUSED` |
| `handshake_timeout` | handshake | deadline exceeded |
| `not_tls` | handshake | `tls.RecordHeaderError` |
| `tls_negotiation_failed` | handshake | a remote alert (`*net.OpError` with `Op == "remote error"`) |
| `connection_closed` | handshake | EOF or reset during the handshake |
| `certificate_unparseable_by_engine` | handshake | crypto/tls's `failed to parse certificate from server` (pinned by a test) |
| `engine_error` | either | anything else |

Certificate acquisition is `acquired`, `not_acquired`, or `unverifiable`: the
server sent certificates Go's TLS engine could not parse. Only
acquired certificates are inspected. When none were acquired, no certificate
finding is made. Output says "No peer certificate was acquired", and the exit
code is 1. `connection_closed` and `certificate_unparseable_by_engine` extend
the reason list proposed for this slice: EOF and an engine-rejected
certificate are common and distinct, and folding them into `engine_error` would
hide them.

### Integration

`inspectsvc.InspectEndpoint` probes, then frames the acquired DER as input of
format `tls_peer_certificates`. Entry *N* is the *N*th certificate the server
sent, with locator `tls://host:port#peer-N`. The unchanged pipeline then runs:
facts, fingerprints, relationships (duplicates keep their existing treatment),
paths, trust, purpose and host name identity.

**Derived intent.** An endpoint implies purpose `tls-server` and host name the
endpoint host, unless `--purpose` or `--hostname` is given explicitly.

- **Recorded sources.** `purpose_evaluation.source` is `default`, `explicit` or
  `endpoint`; `hostname_evaluation.source` is `explicit`, `endpoint` or null.
- **Transport is unaffected.** An explicit purpose never changes how the
  handshake is made, and an explicit `--hostname` never changes the SNI.
- **Trust.** `--roots` works as for files, through `trustverify` only, for the
  requested purpose.
- **File inspection is unchanged.** Default purpose `any`, no host name,
  `probe: null`.

### Output and exit codes

**JSON** gains a top-level `probe` object, additive within
`trustsmith.inspect/v1` (null for files):
- `kind`, `endpoint{host, port, kind}`, `state`, `stage`, `reason`,
  `certificate_acquisition`;
- `policy{name, version, min_version, max_version, tls12_cipher_suites,
  tls13_cipher_suites, signature_schemes, groups, alpn}`;
- `engine{name, version}`, `sni`, `negotiated{version, cipher_suite,
  key_exchange_group, alpn}`;
- `peer_certificate_count`, `client_certificate_requested`, `elapsed_ms`,
  `handshake_ms`.

No key reads as a verdict. There is no `secure`, `valid`, `trusted` or
`verified`.

**Text** gains a "TLS probe" section.

**Exit codes:**

| Outcome | Exit code |
|---|---|
| No certificate acquired | 1 |
| Usage error (bad endpoint, unknown policy, `--probe-policy` for a file) | 2 |
| Findings about acquired certificates reach `--fail-on` | 3 |

A host name mismatch is therefore a finding (exit 3), never a network failure.

### Tests

Tests use in-process loopback servers only, never the public Internet. CLI
tests fail on any dial they did not arrange.

- **Golden endpoints.** They serve committed certificates on the published
  RFC 9500 testECCP256 key (`testpki.RFC9500TestECCP256`, pinned to the
  fingerprint vector), so no new private key enters the repository.
- **Negative servers.** TLS 1.0-only, RSA-key-exchange-only, CBC-only and
  3DES-only servers are built by listing those settings explicitly in the
  test server's own config. Go permits this there without GODEBUG.

## Consequences

- Inspecting an endpoint can now reach the network, and only the endpoint
  named on the command line. Everything else stays offline.
- **Machine-dependent negotiation.** The negotiated TLS 1.3 suite depends on
  Go's hardware-dependent preference (AES-GCM with AES hardware, otherwise
  ChaCha20-Poly1305). Goldens assume AES hardware, which all release and CI
  platforms have.
- **Deferred:**
  - compatible and legacy diagnostic policies;
  - STARTTLS and ALPN probing;
  - post-handshake alerts (a TLS 1.3 client-certificate requirement surfaces
    only on the first read, which this slice never performs);
  - OCSP stapling, SCTs, AIA fetching and system roots.
