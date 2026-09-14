# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's "Report a
vulnerability" (private security advisories) on this repository. Do not open a
public issue.

## What the current version does

This describes the implementation today, which offers only
`trustsmith inspect`.

- **Reads only what you ask.** It reads the file named on the command line,
  or standard input, and the `--roots` files you name. It does not scan directories, open other files, make
  network connections or send telemetry.
- **Handles no private keys.** PEM blocks other than `CERTIFICATE` are reported
  by label and never decoded. The tool stores nothing and writes nothing except
  its output.
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
  - A self-signature is reported as verified only when it verifies
    cryptographically.

## Limitations

- **Trust only from what you supply.** Without `--roots`, inspection does not
  tell you whether to trust a certificate. With it, the result is what Go's
  crypto/x509 verifier concludes against those roots, not an independent
  RFC 5280 implementation, and there is no revocation checking yet.
- **Parser-dependent fields.** Findings based on Go's X.509 parser inherit its
  behaviour. Certificates it rejects are reported as unparseable, with
  fingerprints computed from their bytes where possible.
