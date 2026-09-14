# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's "Report a
vulnerability" (private security advisories) on this repository. Do not open a
public issue.

## What the current version does

This describes the implementation today, which offers only
`trustsmith inspect`.

- **Reads only what you ask.** It reads the single file named on the command
  line, or standard input. It does not scan directories, open other files, make
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
    and a path's trust is always reported as "not evaluated". The standard
    verifier (`Certificate.Verify`, `VerifyOptions`, certificate pools) is
    not used anywhere, and an architecture test enforces this, so no included
    certificate can become trusted as a side effect.
  - Structural issuer checks report anything they do not evaluate, such as an
    unknown critical extension or name constraints. A path structure is
    therefore never reported as satisfied by omission.
  - A self-signature is reported as verified only when it verifies
    cryptographically.

## Limitations

- **No trust judgement.** Inspection does not tell you whether to trust a
  certificate. It has no trust store, trust anchors, name or policy constraint
  processing, or revocation checking yet.
- **Parser-dependent fields.** Findings based on Go's X.509 parser inherit its
  behaviour. Certificates it rejects are reported as unparseable, with
  fingerprints computed from their bytes where possible.
