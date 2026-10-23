# ADR-0015: Public packages for the JSON contracts

- Status: accepted
- Date: 2026-10-23
- Implemented in: `pkg/scan`, `pkg/inspect`, `pkg/internal/runcli`

## Context

Every Trustsmith package lives under `internal/`, so another Go module cannot
import any of it. Sybil's agent, Quasar, needs to run a scan on each host it
manages and report the result (docs/integrations/sybil.md). It could ship the
`trustsmith` binary beside itself and run it as a process, but then every host
needs a second binary at a matching version, and the agent has to find it,
check it and parse exit codes.

What an integration needs is already stable: the `trustsmith.scan/v1` and
`trustsmith.inspect/v1` documents, their JSON Schema and the append-only
finding codes. The Go types that build those documents are not stable and
should not become a promise.

## Decision

Two public packages, each one function, each returning the JSON document as
bytes:

- `pkg/scan`: `Directory(path, Options) ([]byte, error)` returns
  `trustsmith.scan/v1`, exactly what `trustsmith scan --output json
  --fail-on never` prints.
- `pkg/inspect`: `Target(target, Options) ([]byte, error)` returns
  `trustsmith.inspect/v1`, exactly what `trustsmith inspect --output json
  --fail-on never` prints, for a file or a TLS endpoint.

`Options` holds only a clock today. New fields are added only when a CLI flag
already exists for them, so the library never does something the command
cannot.

Both run the command in process through `pkg/internal/runcli`, so the output
is the CLI's byte for byte. Tests compare each against the CLI's own golden
files, which keeps the library from drifting from the binary.

Findings never make a call fail (`--fail-on never`). An error means the scan
or inspection could not run at all, and carries the command's message.

### Compatibility

The Go API (two functions, two `Options` structs, two `Schema` constants) is
covered by semantic versioning from v0.2.0. The documents follow their own
rules (ADR-0003): fields are only added within v1, so callers decode with
their own types and ignore what they do not know.

No Go type from `internal/` appears in the public API. The packages that
build the documents can be restructured without a breaking release.

## Alternatives considered

- **Promote `internal/x509facts` and its dependencies** (the sybil-dev
  `certificate-discovery` draft). It gives callers certificate facts but no
  walk, no limits and no contract; every caller would write its own scanner
  and its own JSON, the duplication this tool exists to avoid.
- **Export the contract types** (`jsonScan`, `jsonInspect`) as Go structs. It
  would freeze roughly fifty structs as public API on top of the JSON
  promise. Possible later, if a caller needs typed access; nothing needs it
  now.
- **Run the binary as a process.** Still possible for non-Go callers, and
  unchanged by this decision.

## Consequences

- Importing either package compiles the CLI into the caller, including
  `github.com/spf13/cobra`. Quasar already uses cobra.
- Callers need Go 1.27, the version in `go.mod`.
- The library runs with no injected dialer, so `inspect.Target` on an
  endpoint uses the network, as the CLI does.
