# RFC Coverage Matrix

Each row maps an RFC section to the test that exercises it. A **Conformance**
test asserts the requirement as stated in the RFC text — the assertion is
derived from the spec, never from what the implementation happens to do — and
quotes the governing sentence with a file:line into the source fetched from
rfc-editor.org. The conformance rows are what `make conformance-gate` enforces.

This matrix exists because the audit in
[rfc-analysis/HTTP1_SERVER_RECONCILIATION.md](rfc-analysis/HTTP1_SERVER_RECONCILIATION.md)
found 24 MUST-level failures and traced every one to the same root cause: there
was no way in this repository to say "the RFC requires X" such that CI could
fail on it. Adding a row here is how a normative requirement becomes enforceable.

## RFC 7540 — HTTP/2 (h2c Upgrade only)

RFC 9113 obsoletes RFC 7540 and marks the h2c upgrade token and the
HTTP2-Settings header field as obsolete (`rfc9113.txt:3613`). RFC 7540 §3.2
nevertheless remains the governing text for `server/h2c.go`, which implements
that mechanism.

| Section | Type | Test |
|---------|------|------|
| §3.2 (`rfc7540.txt:464`) | Conformance | `TestConformance_RFC7540_Sec32_ServerIgnoresH2UpgradeToken` |
| §3.2 (`rfc7540.txt:471`, `:487-492`) | Conformance | `TestConformance_RFC7540_Sec32_ResponseToUpgradingRequestOnStream1` |
| §3.2.1 (`rfc7540.txt:511`) | Conformance | `TestConformance_RFC7540_Sec321_NoUpgradeWithoutHTTP2Settings` |
| §3.2.1 (`rfc7540.txt:511`) | Conformance | `TestConformance_RFC7540_Sec321_NoUpgradeWithDuplicateHTTP2Settings` |
| §3.2 / §3.4 | Integration | `TestH2C_Upgrade`, `TestH2C_PriorKnowledge`, `TestTransport_H2C_Upgrade_Fallback` |

## RFC 9110 — HTTP Semantics

| Section | Type | Test |
|---------|------|------|
| §7.8, §15.2 (`rfc9110.txt:2880`) | Conformance | `TestConformance_RFC9110_Sec78_IgnoreUpgradeInHTTP10Request` |
| §5.5 (`rfc9110.txt:1606`) | Conformance | `TestConformance_RFC9110_Sec55_FieldValueCRLFNUL_StreamError` |
| §5.5 (`rfc9110.txt:1611`) | Conformance | `TestConformance_RFC9110_Sec55_CleanFieldValueAccepted` |

## RFC 9112 — HTTP/1.1 Message Syntax

Applies only to the h2c Upgrade probe in `server/h2c.go`; this server does not
serve HTTP/1.1.

| Section | Type | Test |
|---------|------|------|
| §2.2 (`rfc9112.txt:445`) | Conformance | `TestConformance_RFC9112_Sec22_RejectRequestWithoutHost` |

## RFC 9113 — HTTP/2

No `TestConformance_RFC9113_*` suites yet: the HTTP/2 conformance audit has not
been run. `scripts/rfc-coverage-gate.sh` deliberately omits the `RFC9113` tag
until the first one lands — and its self-check will fail the build if a suite
appears without the tag being added.

## Known gaps

The HTTP/1.1 audit confirmed 24 MUST-level failures. The rows above close the
h2c Upgrade cluster and the field-value injection gap. The remaining confirmed
gaps — inbound request validation (target-URI validation, empty `:authority`,
raw `:path` in `grpc-message`), response correctness (HEAD body suppression,
`Date`, trailer/header separation, gzip `Content-Encoding`) and server push
(`:authority` on PUSH_PROMISE) — are listed with per-item evidence in
[rfc-analysis/HTTP1_SERVER_RECONCILIATION_TABLES.md](rfc-analysis/HTTP1_SERVER_RECONCILIATION_TABLES.md).
Each should arrive as a new row here plus the test that proves it.
