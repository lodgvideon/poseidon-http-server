---
name: validate-rfc-conformance
description: Audit poseidon-http-server against the HTTP RFCs it implements (9113, 7541, 9110) by reusing the verified fact catalogs from the sibling poseidon-http-client repo. Use for "is the server RFC-conformant", "what does RFC 9113 require of a server", building a server conformance checklist, or reconciling conn/ + server/ + grpcserver/ against normative text.
---

# Validate RFC Conformance (server)

Server-side runbook on top of [auditing-rfc-conformance](../auditing-rfc-conformance/SKILL.md),
which owns the methodology. **Read that first for the iron rules.** This file
answers only: what is already done, what is reusable, and what still has to run.

## The shortcut this repo gets

The expensive half of an RFC audit — extracting every normative fact from raw
spec bytes and double-verifying each one — was already paid for in the sibling
`poseidon-http-client` repo. Those catalogs are **role-neutral where it
matters**: every fact carries a verbatim quote, a normative level, and an
`applies_to` audience list. Filtering them for the server role is a filter, not
a re-extraction.

Source of truth — a sibling checkout, path relative to **this repo's root**
(read-only; never edit in place):

```
../poseidon-http-client/docs/rfc-analysis/      # committed on origin/main
```

If the sibling checkout is absent, the catalogs are still reachable without a
working tree:

```bash
git -C ../poseidon-http-client show origin/main:docs/rfc-analysis/RFC9113_FACTS.md > /tmp/RFC9113_FACTS.md
```

Do not re-extract a spec that has a catalog. If you disagree with a catalog
fact, that is a finding to raise against the catalog, not a reason to start over.

## Scope map — what the server implements

| RFC | Catalog | Facts | Server target |
|-----|---------|-------|---------------|
| **9113** HTTP/2 (current) | `RFC9113_FACTS.md` | 594 | `conn/` frame loop, streams, flow control, SETTINGS, GOAWAY, §8 request/response mapping, §8.4 push; `server/` handler + h2c |
| **7541** HPACK | `RFC7541_HPACK_FACTS.md` | 167 | decoder lives in the **client module** (`hpack/`) — audit for correct *use* (`conn/` HPACK sync, MAX_HEADER_LIST_SIZE); codec defects file against the client repo |
| **9110** HTTP semantics | `RFC9110_9112_FACTS.md` | 1208 (9110+9112 mixed) | `server/handler.go` status/field handling, `middleware/`. **9112 is HTTP/1.1 syntax — out of scope except `server/h2c.go`**, which really does speak HTTP/1.1 to do the Upgrade probe |
| **7540** HTTP/2 (obsolete) | `RFC7540_FACTS.md` + `HTTP2_RFC_DELTA.md` | 606 + 91 deltas | the delta doc is the cheapest high-value read: this server's code and ADRs cite **7540**, so every "removed"/"tightened" delta is a live suspect |
| 9114 / 9204 / 9000-9002 | present | 2698 | **not applicable** — no HTTP/3 or QUIC in this server |
| gRPC-over-HTTP/2 | *none* | — | `grpcserver/` — not an RFC, no catalog exists; needs a real extraction pass per the parent skill's §1–5 |

Measured reusable inventory (grep over the catalogs, `applies_to` ∩
`{server, origin, endpoint, receiver, sender, all}`):

- RFC 9113: ~498 of 594 facts touch the server role; ~200 are MUST/SHOULD-family.
- RFC 9110/9112: ~811 of 1208; ~264 normative (before dropping the 9112-only slice).
- RFC 7541: role-symmetric — treat all 167 as in scope for *usage*.

## The trap that decides whether this works

**Mine `*_FACTS.md`, never `*_CLIENT_CHECKLIST.md`.**

The checklists were distilled with `client_relevant` as the filter. The FACTS
catalogs kept every fact and tag the dropped ones `[not-client]`. Those dropped
facts are precisely the server's obligations: **35 normative RFC 9113 facts** and
**181 normative RFC 9110/9112 facts** are marked `[not-client]`. Start from a
client checklist and you silently lose the entire server-only surface — the part
you are auditing.

Second trap: the catalogs' **"Impl check / status" column is client-code
prose** (it names `client/`, `http1/`, `conn/` *of the client repo*). Quote,
level, and audience are reusable verbatim; that column is not. Re-derive it
against `conn/` + `server/` + `grpcserver/` here. Never let a reconciliation
agent treat it as an instruction about this repo.

## Pipeline

Phase 0 and 1 are cheap and must land before any agent fan-out.

**Phase 0 — delta triage (do this first, it may be the whole answer).**
Read `HTTP2_RFC_DELTA.md` (91 deltas, 7540→9113) and grep this repo for
7540-era assumptions. The prior is strong: the tree cites **RFC 7540 48 times**
against 8 files mentioning 9113. Known live suspects, already visible:

- `server/h2c.go` implements `Upgrade: h2c` + `101 Switching Protocols`,
  citing "RFC 7540 §3.2, §3.4". RFC 9113 **removed** in-band h2c upgrade —
  cleartext HTTP/2 is prior-knowledge only. ADR-0005 documents the choice;
  the audit's job is to say whether the ADR still holds under 9113.
- Priority (7540 §5.3) is deprecated wholesale in 9113. Check
  `conn/server_priority_test.go` and the PRIORITY handling path: a server
  still *enforcing* removed 7540 MUSTs (e.g. self-dependent stream →
  PROTOCOL_ERROR) now kills streams a 9113 peer considers legal.
- 9113 §8.2.1 added field validation; malformed requests are a **stream**
  error, not a connection error. Verify `conn/server_validation_test.go`
  matches the 9113 wording, not 7540's.

**Phase 1 — server checklist distillation.** Parse the FACTS tables, keep rows
whose audience intersects the server set (include `[not-client]` rows), keep
MUST/SHOULD-family levels, drop the 9112-only slice except the h2c probe path.
Bucket by subsystem (~10–40 items each): frame loop · streams/state machine ·
flow control · SETTINGS · GOAWAY/teardown · pseudo-headers and field validation
· push · h2c · handler/semantics. Write
`docs/rfc-analysis/HTTP2_SERVER_CHECKLIST.md` with the reconcile column
re-keyed to this repo's packages.

**Phase 2 — code reconciliation.** Parent skill §7, unchanged: judge +
2 adversarial verifiers per bucket, `real_gap=false` by default, splits go to
REVIEW. Standing out-of-scope set for principled N/A: HTTP/1.1 beyond the h2c
probe, caching (9111), proxy/intermediary roles, HTTP/3, and anything inside the
`poseidon-http-client` module. Output
`docs/rfc-analysis/HTTP2_SERVER_RECONCILIATION.md`.

**Phase 3 — close the loop in tests.** The server currently has **zero**
`TestConformance_*` tests and no `docs/RFC_COVERAGE.md`. Every confirmed gap
should land as a named `TestConformance_RFC9113_SecNN_*` test built from
hand-written wire bytes, mirroring the client's convention, plus a coverage
matrix and a `scripts/rfc-coverage-gate.sh` port (the client's version also
self-checks that every `TestConformance_RFCxxxx` suite in the tree is named in
its tag list — keep that property).

## Guardrails specific to this repo

- **Zero-allocation contract (ADR-0001).** A conformance fix on the native
  write path must ship with a benchmark; `make bench-gate` is the gate. Do not
  let a remediation agent "simplify" `statusBytes` or the gRPC header slices.
- **Verifier agents mutate the repo.** Observed in the client run: throwaway
  `_test.go` probes and, worse, edits to production constants left behind.
  `git status --porcelain` before every commit; stage by explicit path.
- **ADRs are authoritative here.** A finding that contradicts an ADR is not
  automatically a bug — it is a request to update or supersede that ADR. Say
  which one.
