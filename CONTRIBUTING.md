# Contributing to Trustsmith

Thank you for helping. Trustsmith's value is that it says exactly what it
checked, so the bar for a change is less "does it work" than "does it claim
only what it proves". This page is how to get a change in.

## Reporting a problem

- **A certificate Trustsmith misreads** is the most useful report there is.
  Open an issue with the certificate (public certificates only, never a
  private key), the command you ran, what it printed and what you expected.
- **A vulnerability**: do not open an issue. Follow [SECURITY.md](SECURITY.md).

## Before writing code

- Read [ADR-0001](docs/adr/0001-stack-and-boundaries.md). It fixes the layout,
  the dependency direction and the rules `internal/archtest` enforces. A change
  that needs to break one of those rules needs an ADR amendment first.
- A new behaviour (a new input type, a new evaluation, a new command) starts
  with a short ADR in `docs/adr/`, numbered after the last one. It says what is
  decided, what is deliberately not, and what the output contract gains.
- New third-party modules are a reviewed change to the allow-list in
  `internal/archtest`; prefer the standard library.

## The rules the tests enforce

- **Time is an input.** Nothing under `internal/` calls `time.Now`.
- **Trust is explicit.** No system trust store, ever; only `--roots`.
- **Finding codes are append-only.** `internal/findings/testdata/codes.golden`
  must never lose a line. Every code has a catalog entry with a title, an
  explanation and a fix.
- **The JSON contract is versioned.** Fields may be added to
  `trustsmith.inspect/v1`; renaming, removing or changing the meaning of one
  needs v2. The schema in `docs/schema/` is regenerated from the contract types.
- **Fixtures are committed, not generated in CI.** Regenerate them with
  `task fixtures` and commit the result together with the updated goldens.

## Making the change

```console
$ go test -count=1 ./...            # everything, including architecture tests
$ UPDATE_GOLDEN=1 go test ./internal/cli ./internal/findings   # after an intended output change
$ golangci-lint run ./...
$ task fuzz:short                   # if you touched a parser
```

Review the golden diff as carefully as the code diff: it is the user-visible
change.

## Pull requests

- One behaviour per pull request, with its ADR, tests and goldens.
- The description says what a user sees before and after.
- CI runs build, vet, tests, the race detector, lint, govulncheck, short
  fuzzing, a smoke test of the real binary and a cross-compile of every release
  target. All of it must be green.

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
