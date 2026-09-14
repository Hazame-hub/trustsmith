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
  - A panic while inspecting one entry is contained and reported as an internal
    error on that entry. Tests fail if this ever happens.
- **Claims only what it checked.**
  - The issuer is shown as stated in the certificate; no issuer relationship is
    verified.
  - Chain verification is not implemented and is reported as "not checked".
  - A self-signature is reported as verified only when it verifies
    cryptographically.

## Limitations

- **No trust judgement.** Inspection does not tell you whether to trust a
  certificate. It has no trust store, revocation checking or chain building
  yet.
- **Parser-dependent fields.** Findings based on Go's X.509 parser inherit its
  behaviour. Certificates it rejects are reported as unparseable, with
  fingerprints computed from their bytes where possible.
