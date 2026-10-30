# Trustsmith and Sybil

Trustsmith is an independent, open-source tool. Sybil is an infrastructure
platform (intent → verified live state → drift detection) whose secrets
service, Aegis, stores and audits credentials per host. This page says how the
two relate, what exists today and what does not, in the same "claims only what
it checked" spirit as the rest of Trustsmith.

## The boundary

| | Trustsmith | Sybil / Aegis |
|---|---|---|
| Certificates: parse, explain, validate, find problems | yes | no |
| Private CA, issuance, renewal (roadmap) | yes | no: PKI is an explicit Aegis non-goal |
| Secrets: versioned KV, envelope encryption, owner binding, audit | no | yes |
| Fleet: which host runs what, agents, drift, timeline | no | yes |

Neither depends on the other. Trustsmith never phones home, has no account and
no telemetry, and every feature works offline from the command line. Aegis
keeps its own internal CA for its mutual-TLS listener; it does not need, and
does not call, Trustsmith.

ADR-0001 records the direction: "Sybil/Aegis may later consume its public
facts through an optional adapter." The adapter lives on the Sybil side. On the
Trustsmith side the only thing it needs is a stable, documented output, and
that is the part that exists.

## What exists today

- **A versioned JSON contract.** `trustsmith inspect --output json` emits
  `trustsmith.inspect/v1` ([ADR-0003](../adr/0003-findings.md)).
- **A JSON Schema for it**, generated from the CLI's contract types:
  [`docs/schema/trustsmith.inspect.v1.schema.json`](../schema/trustsmith.inspect.v1.schema.json).
  Every JSON golden file in the test suite is validated against it, so the
  schema cannot drift from the binary.
- **Stable finding codes.** Codes are append-only; an integration can map
  `cert.expired`, `cert.expiring_soon`, `name.hostname_mismatch` or
  `trust.failed` to alerts without parsing human text.
- **Go packages** for the agent side: `pkg/scan` and `pkg/inspect` return
  those documents, byte for byte what the CLI prints, so Quasar can scan a
  host without a second binary ([ADR-0015](../adr/0015-public-packages.md)).
- **Exit codes** that make inspection a gate: 0 clean, 3 findings at or above
  `--fail-on`, 1 operational error, 2 usage error.

## How Sybil uses it

1. **Certificate lens on the asset page.** The Sybil agent runs `pkg/scan` on
   each host and sends the `trustsmith.scan/v1` document; the Sybil server
   stores it against the asset, and the asset page lists what the host holds.
2. **Expiry on the timeline.** The server turns the scan's expiry into
   timeline events beside the deployments and drift that explain them.
3. **Renewal with verification.** When a runbook renews a certificate, the
   server re-inspects what the service now serves with `pkg/inspect`, against
   the name it serves and the `tls-server` purpose, and the renewal fails on
   any critical finding. This is Sybil's Act → Verify loop applied to
   certificates. Issuing the new certificate from Trustsmith's private CA is
   not wired yet; the renewal takes a bundle from the secrets store.

Each of those is Sybil work. Trustsmith's commitment is to keep the contract
above stable, and to add fields within v1 only additively.

## Consuming the JSON

- Check `schema` equals `trustsmith.inspect/v1` before reading anything else.
- Ignore properties you do not know: they may be added within v1.
- Key on finding `code` and evidence `key`, never on `title`, `explanation`
  or remediation text, which may be reworded at any time.
- Treat `trust_evaluation.state == "not_evaluated"` as "not checked", never as
  "trusted". Trust is only ever evaluated against roots the caller supplied.
