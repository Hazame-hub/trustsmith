# ADR-0011: Certificate signing requests

- Status: accepted
- Date: 2026-10-16
- Implemented in: `internal/artifact`, `internal/x509facts`, `internal/sigcheck`, `internal/interpret`, `internal/app/inspectsvc`, `internal/cli`, `internal/testpki`

## Context

A certificate signing request (CSR, PKCS #10, RFC 2986) is what someone sends
a CA to ask for a certificate. People are routinely handed one and asked to
check it before it is submitted, or to find which certificate was issued for
it. Until now Trustsmith did not explain them:

- a PEM `CERTIFICATE REQUEST` block was reported by label as
  `input.unsupported_format`;
- a DER request was recognised by `x509facts.FromDER`, but carried no facts and
  got the same finding;
- an input of requests only also got the critical `input.no_certificates`,
  although the user had asked about exactly what the file contained.

A request is not a certificate. It is signed by the key it asks to have
certified, not by an issuer. It has no serial number, issuer, validity period,
chain or trust, and nothing in it is in force until a CA decides what to
issue. Treating it as a certificate in any layer would invent facts.

## Decision

### Framing

- **PEM labels.** `CERTIFICATE REQUEST` and the legacy `NEW CERTIFICATE
  REQUEST` (written by older Netscape, Windows and Java tools for the same
  structure) are framed as `artifact.KindCertificateRequest` and their contents
  decoded.
  - A block that is not valid base64 is `input.malformed_pem`, as for
    certificates.
  - Every other label, private keys included, is still reported by label and
    never decoded.
- **The label decides the parser.** A request-labelled block is parsed only as
  a request (`x509facts.FromRequestDER`). A certificate inside one is an
  unparseable request, never silently a certificate.
- **DER and `CERTIFICATE` blocks.** A request has the outer shape of a
  certificate, so DER input and `CERTIFICATE` blocks keep going to
  `x509facts.FromDER`. When Go rejects the bytes as a certificate but parses
  them as a request, they are described as a request.

### Facts

`x509facts.CertificateRequest` holds what the request asks for:
- the subject name;
- the requested subject alternative names (DNS, IP, email, URI), as Go parses
  them from the requested `subjectAltName` extension;
- the public key (algorithm, curve or parameter set, bits);
- the signature algorithm, by name and OID;
- every requested extension (OID, critical, the name from the same table as
  certificates);
- the attribute types;
- the result of checking its signature.

**Requested extensions.** Go's request parser does not decode key usage,
extended key usage or basic constraints, so `x509facts` decodes them from the
requested extensions with `cryptobyte`:
- `keyUsage`, as a BIT STRING;
- `extKeyUsage`, as a SEQUENCE of OIDs;
- `basicConstraints`, with `cA` defaulting to FALSE and a path length reported
  only for a CA.

Names match certificates' (`digitalSignature`, `serverAuth`; unknown usages by
OID). A requested extension whose value cannot be decoded is listed in
`UndecodedExtensions`. It is never reported as absent.

**Attributes** are listed by type only. Their values are never decoded or
shown: a `challengePassword` is a shared secret.

**Key identity.** The ADR-0002 identities are computed from the request's
`RawSubjectPublicKeyInfo` by the same `identify` helper as certificates. They
now live in `x509facts.SPKIIdentity`, which `x509facts.Identity` embeds next
to the certificate fingerprint.
- `x509-spki-sha256` is what joins a request to the certificate issued for
  it. A test pins that a certificate for the requested key has the same value.
- A request has no `x509-cert-sha256`: that scheme identifies certificates.
  No digest of the request's own bytes is published, since ADR-0002 defines no
  scheme for one.

**Unparseable requests.** When Go rejects a request-labelled block:
- the SubjectPublicKeyInfo is located structurally
  (`CertificationRequestInfo`: version, subject, SPKI);
- both public-key fingerprints are reported where possible;
- `key.noncanonical_spki` or `input.malformed_spki` follow as for
  certificates, and the parse error is recorded.

This mirrors unparseable certificates. Non-canonical keys always land here,
because Go rejects RSA keys without NULL parameters and compressed EC points.

### The signature check

`sigcheck.Request` calls `CertificateRequest.CheckSignature`, which verifies
the signature over the exact `RawTBSCertificateRequest` bytes with the
request's own public key.
- **Shared boundary.** It shares `sigcheck`'s classifier and its panic
  boundary with `sigcheck.Certificate`, so `recover` still appears only in the
  two files `internal/archtest` allows. The inspect service counts an
  `engine_panic` here in `RecoveredPanics`, like any other.
- **States** are `verified`, `does_not_verify` (`signature_mismatch`,
  `key_algorithm_mismatch`) and `unverifiable` (`insecure_algorithm`,
  `unsupported_algorithm`, `engine_error`, `engine_panic`), with the same
  meaning as in ADR-0004.
- **What it proves.** A verified signature proves only that whoever made the
  request held the private key of the key it asks to have certified. It says
  nothing about whether the subject or names are the requester's to ask for.
- **Pinned Go 1.27.1 behaviour.**
  - `CheckSignature` accepts SHA-1 request signatures and refuses MD5.
  - `CreateCertificateRequest` still creates SHA-1 requests but refuses MD5;
    the MD5 fixture is re-signed with `testpki.ResignRequest`.
  - A request for an X25519 key, which cannot sign, is
    `unverifiable/unsupported_algorithm`.

### Findings

| Code | Severity | Emitted when | Evidence |
|---|---|---|---|
| `csr.signature_invalid` | critical | the signature does not verify with the request's own key: the request is corrupt or was altered | `reason`, `signature_algorithm` |
| `csr.signature_unverifiable` | warning | the engine could not decide; never claimed invalid | `reason`, `signature_algorithm` |
| `input.unparseable_certificate_request` | critical | Go's parser rejected a request-labelled block | `parse_error` |
| `sig.sha1` / `sig.md5` | critical | weak signature algorithm. Always critical for a request: a CA always checks it, so the trust-anchor exception for certificates never applies | `signature_algorithm` |
| `key.rsa_under_2048` | critical | RSA modulus shorter than 2048 bits; a CA should refuse it | `key_bits` |
| `name.cn_only_no_san` | warning | a request for a non-CA certificate names its host only in the Common Name and asks for no subject alternative names | `common_name` |
| `key.noncanonical_spki` / `key.unsupported_for_identity` / `input.malformed_spki` | as for certificates | as for certificates | as for certificates |

- **One request can carry both.** An MD5-signed request gets `sig.md5`
  (critical) and `csr.signature_unverifiable` (warning): one is about the
  algorithm, the other about what could be checked.
- **Catalog text.** The catalog text of the reused codes now mentions requests;
  their codes and evidence keys are unchanged.
- **No validity findings.** A request has no validity period, so it never gets
  `cert.expired`, `cert.not_yet_valid` or `cert.expiring_soon`. Nor does it get
  `cert.self_signed_leaf`: a request is always signed by its own key, and that
  is the point of it.

### `input.no_certificates`

`interpret.Input` now takes the number of certificates and the number of
requests (each parseable or not). `input.no_certificates` (critical) is
emitted only when both are zero.
- **Requests only.** An input holding only requests was inspected and answered.
  Each request has its own findings, including a critical one when it cannot be
  parsed or its signature is invalid.
- **Nothing inspectable** (private keys only, only malformed blocks) still gets
  it, as before.
- The catalog explanation says "no certificate or certificate signing
  request". The code is unchanged.

### Requests take no part in relationships or evaluations

Only certificates are inputs to issuer relationships (ADR-0004), included paths
(ADR-0005), and the targets of trust (ADR-0006), purpose (ADR-0007) and host
name (ADR-0008) evaluation.
- **Never an issuer candidate.** A request is never an issuer candidate or a
  child, never on a path, and never a target. That holds even when it requests
  CA:TRUE, or names the host given with `--hostname`.
- **What a request asks for is not evaluated.** Whether it would suit a
  purpose, or identify a host, would be a judgement of a certificate that does
  not exist.
- **Text output.** When an evaluation runs over an input that holds requests,
  its section says that certificate signing requests are not evaluated because
  they are not certificates. In JSON, the targets simply do not include them.
- **Roots files.** `--roots` files still refuse requests, in PEM (both labels)
  and DER, with "entry N is a certificate request, not a certificate". A
  request is never a trust anchor.

### Output

**Text.** An entry headed "Certificate signing request", or "Certificate
signing request for a CA certificate" when CA:TRUE is requested. Its lines
follow the certificate entry:

| Line | Content |
|---|---|
| Requests | the requested subject alternative names, or `CN=` when none |
| Subject | the requested subject name |
| Key | algorithm and curve or size |
| Signature | algorithm, and whether it verifies with the requested key |
| Certificate | none: a CA issues one, and nothing in the request is in force |
| Key identity | `x509-spki-sha256` |

`--advanced` adds "Technical details (as requested)":
- subject, public key and signature algorithm;
- the requested key usage, extended key usage and basic constraints;
- the subject alternative names;
- the extensions, with any not decoded;
- the attribute types (with a note that values are not shown);
- the encoded SPKI fingerprint and `pin-sha256`.

### JSON additions within `trustsmith.inspect/v1`

All additive; no field is renamed or removed.
- **`overview.certificate_requests`** counts requests, parseable or not.
  `overview.certificates` keeps counting certificates only.
- **`artifacts[].type`** stays `certificate_request` for a parsed request, and
  gains `unparseable_certificate_request`.
- **`artifacts[].fingerprints`** carries `x509-spki-sha256` (null without an
  ADR-0002 identity) and `x509-spki-encoded-sha256` for a request.
  `x509-cert-sha256` is absent: it is a certificate identity.
  `artifacts[].key_identity` is as for certificates.
- **`artifacts[].parse_error`** is set for an unparseable request.
- **`artifacts[].request`** (omitted for anything else) is its own contract
  type, `jsonRequest`; no internal structure is serialised. Its fields:

| Field | Content |
|---|---|
| `kind`, `requests`, `subject`, `key` | as in the text entry |
| `public_key` | `algorithm`, `detail`, `bits` |
| `signature` | the algorithm name, as `summary.signature` for a certificate |
| `signature_algorithm` | `name` and `oid` |
| `signature_check` | `verified`, `does_not_verify` or `unverifiable` |
| `signature_check_reason` | stable code, omitted when verified |
| `subject_alt_names` | `dns`, `ip`, `email`, `uri` |
| `key_usage`, `extended_key_usage`, `basic_constraints` | decoded from the requested extensions |
| `extensions` | `oid`, `critical`, `name` |
| `undecoded_extensions` | OIDs |
| `attributes` | `oid`, `name`; never a value |
| `pin_sha256` | RFC 7469 pin of the encoded SPKI |

A request has no `summary` or `technical` object. Arrays are always arrays.

### Deliberately not done

- **No CA acceptance policy.** There is no check of what a CA would accept
  beyond the findings above: no CA/Browser Forum rules, allowed subject
  attributes, name-ownership checks, required extensions, key-usage
  consistency or maximum names.
- **No checks on what was requested.** A request for CA:TRUE, an odd key
  usage or a wildcard name is reported, not judged.
- **No challenge passwords.** They are not checked, decoded or shown, and no
  other attribute value is either.
- **No request-to-certificate matching.** Requests and certificates are not yet
  matched inside one input. The shared `x509-spki-sha256` makes that a later,
  additive step.
- **No request identity.** No identity is defined for the request's own bytes.
- **No other request formats.** CRMF (RFC 4211), SPKAC (Netscape
  `SignedPublicKeyAndChallenge`) and PKCS #7-wrapped requests are not
  supported; they remain reported by label.
- **No unparseable salvage.** No fields of an unparseable request other than
  the key fingerprints are salvaged.

## Consequences

- `trustsmith inspect request.csr` explains a request: what it asks for, its
  key and key identity, and whether its signature verifies. It exits 3 only
  for a critical finding: an invalid signature, a weak algorithm or key, or a
  request that cannot be parsed.
- **Matching.** A user can match a request to the certificate later issued for
  it by comparing `x509-spki-sha256`.
- **Golden changes.** Every JSON output gains `overview.certificate_requests`.
  Outputs containing the reused codes show the updated catalog text.
- **Fixtures.** The fixture corpus gains ten request fixtures, generated
  without touching existing files.
- **Isolation.** Relationship, path, trust, purpose and host name behaviour for
  certificates is unchanged, and requests cannot leak into it: the service
  passes only certificates to those layers.
