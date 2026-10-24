# ADR-0001: Stack, repository layout and boundaries

- Status: accepted
- Date: 2026-09-14
- Scope: the whole repository; this revision records what the first inspection slice implements

## Context

Trustsmith is a local-first certificate and private-PKI workbench, built as
an independent product. Sybil/Aegis may later consume its public facts through
an optional adapter. The approved v0.1 plan calls for a Go core shared by every
interface, with the CLI first. A hardened local browser UI comes later, and a
Wails desktop build is optional and must never block a release.

The first slice implements only `trustsmith inspect` for PEM, DER and PEM
certificate bundles.

## Decisions

### Language, toolchain, dependencies

- **Go 1.27**, with `toolchain go1.27.3` in `go.mod` (1.27.2 fixed GO-2026-6607 in crypto/tls; 1.27.3 fixes GO-2026-6809 in crypto/x509). No GODEBUG settings are
  used: `internal/archtest` forbids a `godebug` block in `go.mod`, `//go:debug`
  directives and GODEBUG literals (ADR-0009).
- **Standard-library cryptography first.** `crypto/x509` parses certificates.
  `golang.org/x/crypto/cryptobyte` handles DER where Trustsmith must be stricter
  or more lenient than `crypto/x509`: canonical key identity, PEM-independent
  framing, and salvaging certificates Go rejects.
- **Cobra** provides the CLI.
- **The build compiles only these third-party modules**: `golang.org/x/crypto`,
  `golang.org/x/net` (for `golang.org/x/net/idna` only, ADR-0008),
  `golang.org/x/text` (required by `idna`), `github.com/spf13/cobra`,
  `github.com/spf13/pflag` and
  `github.com/inconshreveable/mousetrap`. `internal/archtest` fails the build on
  any other module. Adding one is a reviewed change to the allow-list.
- **Apache-2.0**; module path `github.com/Hazame-hub/trustsmith`.

### Layout and dependency direction

```
cmd/trustsmith          composition root; the only place the real clock is read
internal/cli            argument parsing, text and JSON rendering, exit codes
internal/app/inspectsvc the inspect application service (one code path for every interface)
internal/app/casvc      the local CA service: CA directories, issuance proven by inspectsvc, the only file writer (ADR-0012)
internal/issuance       certificate and key creation for the local CA; pure, the only CreateCertificate call (ADR-0012)
internal/probe          TLS endpoint acquisition: the only network and crypto/tls code; no certificate decisions (ADR-0009)
internal/endpoint       parsing of TLS endpoint arguments (ADR-0009)
internal/interpret      facts + relationships + paths + time → friendly summary and findings (pure)
internal/chainpath      certification paths and structural issuer checks inside one input (ADR-0005)
internal/trustverify    validation against explicitly supplied trust anchors; the only Go verifier call (ADR-0006)
internal/purpose        what a certificate's own fields permit for an explicitly requested purpose (ADR-0007)
internal/hostname       whether a certificate identifies an explicitly requested host name or IP address (ADR-0008)
internal/issuerlinks    issuer relationships between the certificates of one input (ADR-0004)
internal/sigcheck       does one certificate's key verify another's signature (no policy)
internal/findings       stable codes, severities, evidence, catalog
internal/x509facts      what a certificate contains (no judgement)
internal/artifact       framing of untrusted input into ordered blocks
internal/fingerprint    ADR-0002 identities
internal/testpki        test-only certificate builders and the fixture generator
internal/archtest       architecture tests
testdata/certs          committed inspection corpus
```

Dependencies point inward only: `cmd → cli → app → interpret → {chainpath →
issuerlinks, trustverify → purpose, hostname} → {x509facts → sigcheck,
artifact, findings} → fingerprint`. `app` also composes `endpoint → hostname`
and `probe`; `probe` depends on no other Trustsmith package, so acquisition
cannot reach an evaluation layer.
`internal/archtest` enforces:

- **Domain packages** (`fingerprint`, `artifact`, `x509facts`, `findings`,
  `interpret`, `sigcheck`, `issuerlinks`, `chainpath`, `trustverify`, `purpose`, `hostname`):
  - do not import `os`, `os/exec`, `net`, `net/http`, `database/sql`,
    `syscall` or `io/fs` directly;
  - do not depend on cobra, the CLI, application services, `cmd` or `testpki`.
- **Application services** do not depend on the CLI, cobra or `cmd`.
- **No production package** depends on `testpki`.
- **Nothing under `internal/`** refers to `time.Now`. The time is always an
  input, which is what makes validity boundaries testable exactly.
- **`recover()`** appears only at the two untrusted-input boundaries: the
  standard-library X.509 parser in `x509facts` and the signature engine in
  `sigcheck` (ADR-0004). A panic anywhere else surfaces as a bug.
- **The Go verifier** (`Certificate.Verify`, `x509.VerifyOptions`,
  certificate pools) is used only in `internal/trustverify`, where every Verify
  call takes a `VerifyOptions` literal setting non-nil `Roots`,
  `Intermediates`, `CurrentTime`, `KeyUsages` and `MaxConstraintComparisions`,
  and no `DNSName`. `x509.SystemCertPool` is forbidden everywhere, tests
  included. Trust anchors never enter implicitly (ADR-0006).

Application-service packages use a `svc` suffix. This avoids name collisions
with domain packages that later slices add (for example `inventory` and
`inventorysvc`).

### Interfaces

- **The CLI is the authoritative interface** for secret-bearing and destructive
  operations whenever those exist.
- **Later interfaces** (the local browser UI, then an optional Wails build)
  call the same application services. A Wails build that fails its gate does
  not block a release.
- **No interface contains domain logic.** The CLI's JSON types are its own
  versioned contract (ADR-0003), and internal Go structures are never
  serialised directly.

### Testing conventions

- **Standard library `testing` only.**
- **Golden files** are refreshed with `UPDATE_GOLDEN=1`.
- **Fixtures are committed, never generated in CI.** Go ignores the randomness
  source in key generation and signing, so regenerating changes fingerprints.
  `internal/testpki/genfixtures` and `internal/fingerprint/testdata/gen.sh`
  document their provenance.
- **Fuzz targets sit at every parser boundary.** Their seed corpora run in
  ordinary `go test`, and CI fuzzes each target briefly.

## Consequences

- No SQLite, UI, Wails, key storage, CA or network code exists yet, and the
  module allow-list keeps it out until a slice introduces it deliberately.
- Future interfaces reuse `inspectsvc` unchanged.

## Deviations from the approved plan in this slice

- **Corpus location:** the inspection corpus lives at `testdata/certs`, not
  `internal/testpki/testdata`, so the service and CLI tests share one path.
- **No `ignore` directive for `frontend/node_modules`** yet: no frontend exists.
- **No `PolicyContext` type yet.** Only generic interpretation exists, and the
  type arrives with the first non-generic policy.
- **`time.Now` rule:** the architecture test forbids `time.Now` across all of
  `internal/`, which is stricter than the plan's list of domain packages. The
  `VerifyOptions.CurrentTime` check applies to the single verifier call
  site (ADR-0006); the `tls.Config.Time` check waits until TLS probing exists.
