# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's "Report a
vulnerability" (private security advisories) on this repository. Do not open a
public issue.

## What the current version does

This describes the implementation today: `trustsmith inspect`, the local CA
(`trustsmith ca`), `trustsmith match` and `trustsmith scan`.

- **Reads only what you ask.** It reads the file named on the command line,
  or standard input, and the `--roots` files you name. Only `trustsmith scan`
  reads a directory, the one you name: it never follows a symbolic link out of
  it, never decodes a private key, and skips files over 8 MiB
  ([ADR-0014](docs/adr/0014-directory-scan.md)). It opens no other files and
  sends no telemetry. The only network connection it makes is to a TLS
  endpoint named on the command line.
- **Probes endpoints without judging them.** Inspecting a TLS endpoint
  completes an unauthenticated TLS handshake.
  - Go's verification is skipped (`InsecureSkipVerify`) only to collect the
    certificates the server presents.
  - A completed handshake does not mean the certificates are trusted, match the
    host name, are appropriate for any purpose, or that the server is secure.
  - Trust, host name identity and purpose are evaluated afterwards, separately,
    by the same code as for files. No system roots are used, and the handshake
    never uses `RootCAs` or verification callbacks.
  - By default the probe offers only TLS 1.2 (ECDHE with AEAD suites) and
    TLS 1.3. `--probe-policy compatible` also offers the TLS 1.2 ECDHE
    AES-CBC-SHA suites and the P-521 group; it never offers TLS 1.0/1.1, RSA
    key exchange, 3DES, RC4 or CBC-SHA256. A policy is chosen before
    connecting and a failed handshake is never retried with another policy.
    It uses no GODEBUG settings.
  - A policy describes what Trustsmith offers, not whether a server is secure.
    A negotiated CBC suite is reported as a warning about that handshake, not
    as a grade of the endpoint.
  - It sends no application payload (only the TLS close_notify alert), speaks
    no HTTP, and bounds the connection and the handshake with timeouts.
  - Skipping verification and speaking TLS are confined by architecture tests
    to one package, which depends on no evaluation code.
- **Handles no private keys when inspecting.** PEM blocks other than
  `CERTIFICATE` are reported by label and never decoded; only `trustsmith
  match` reads a key (below). `inspect` stores nothing and writes nothing
  except its output; only `trustsmith ca` writes files (below).
- **Treats input as hostile.**
  - Input is limited to 8 MiB and 10,000 PEM blocks.
  - One malformed block is reported without stopping the others.
  - The decoder, key canonicaliser, certificate reader and whole inspection
    pipeline are fuzz-tested.
  - Panics are recovered only at the standard-library X.509 parser and the
    signature-verification engine, and are counted. Tests and fuzzing fail if
    any occur. A panic in Trustsmith's own logic is not recovered, so it cannot
    masquerade as a problem with the input.
- **Claims only what it checked.**
  - An issuer relationship between certificates of the same input is reported
    as verified only when the candidate's key cryptographically verifies the
    signature. An algorithm the engine refuses is reported as unverifiable,
    never as a signature mismatch.
  - A verified signature is not a trust decision.
  - Certification paths are built only from certificates in the input. A
    self-signed certificate ends a path but is never used as a trust anchor,
    and a path's trust is always reported as "not evaluated".
  - Structural issuer checks report anything they do not evaluate, such as an
    unknown critical extension or name constraints. A path structure is
    therefore never reported as satisfied by omission.
  - Trust is evaluated only against trust anchors you supply with `--roots`.
    A roots file may contain only certificates: a private key or any other
    block refuses the whole file without being decoded, and nothing falls back
    to a system or platform trust store. Go's verifier runs in one package,
    with its roots, intermediates, time and key usages set explicitly; an
    architecture test enforces this and forbids `SystemCertPool` everywhere.
  - Trust results name their source and engine (`supplied_roots`, `go-x509`).
    Failure reasons are stable codes; verifier messages are not part of the
    output.
  - Purpose results keep two facts apart: what the certificate's own fields
    permit, and whether Go validates the chain for that purpose to roots you
    supply. A purpose never checks host names, and generic validation is
    never reported as validation for a specific purpose.
  - Host name identity uses only subject alternative names, through Go's
    `VerifyHostname`; the Common Name is never used. A requested name with a
    scheme, path or port is refused rather than stripped, and requests are
    bounded in length. Internationalised names are converted with an explicit
    IDNA profile (`golang.org/x/net/idna`, v0.59.0; releases before v0.55.0,
    affected by GO-2026-5026, fail the tests), and only the user's DNS request
    is converted: IP addresses and certificate names never are.
  - A self-signature is reported as verified only when it verifies
    cryptographically.

## The local CA

`trustsmith ca` ([ADR-0012](docs/adr/0012-local-private-ca.md)) is the only
part of Trustsmith that creates or stores secret material.

- **What it writes.** `ca init` writes `ca.pem` and `ca.key` into a directory
  it creates with mode 0700; `ca issue` writes `<out>.pem` and `<out>.key`.
  Keys are unencrypted PKCS #8 PEM with mode 0600. On Windows the mode bits
  only toggle read-only and the key inherits the directory's ACL, so put the
  CA directory somewhere only you can read.
- **What it never does.** It never overwrites a file, never installs the root
  into a system or browser trust store, and never sends anything anywhere.
- **Name constraints.** With `--permit-dns`/`--permit-ip` the root carries
  critical name constraints, and naming one type closes the other, so a stolen
  CA key cannot produce a certificate that validates for another name wherever
  constraints are enforced. Without them, the root can certify any name: the
  CLI says so when it creates one.
- **Proof before writing.** Every issued certificate is validated against its
  CA, for its purpose and every requested name, by the same code as
  `trustsmith inspect`, before its key is written.
- Key creation and file writing are each confined to one package by
  architecture tests.
## Matching keys to certificates

`trustsmith match` ([ADR-0013](docs/adr/0013-key-certificate-match.md)) reads
a private key file, which `inspect` never does.

- It reads exactly one **unencrypted** key and refuses encrypted ones; it
  never asks for a passphrase.
- The private value is used only to derive the public key. Only the public key
  identity (`x509-spki-sha256`) is printed; a test checks that no part of the
  key appears in the output.
- Go cannot reliably zero key material, so the private value stays in process
  memory until it is garbage-collected. The process exits right after.
- Private key decoding is confined by an architecture test to this package
  (and, for its own key, the local CA).

## Limitations

- **Endpoint results are one handshake's view.** A probe sees the chain the
  server sent to this client, with this SNI, under the modern policy, at that
  moment. A server may present other certificates to other clients. Revocation
  status, stapled OCSP responses and certificate transparency are not
  examined, and protocol support beyond what the policy offers is not measured.

- **Trust only from what you supply.** Without `--roots`, inspection does not
  tell you whether to trust a certificate. With it, the result is what Go's
  crypto/x509 verifier concludes against those roots, not an independent
  RFC 5280 implementation, and there is no revocation checking yet.
- **Parser-dependent fields.** Findings based on Go's X.509 parser inherit its
  behaviour. Certificates it rejects are reported as unparseable, with
  fingerprints computed from their bytes where possible.
