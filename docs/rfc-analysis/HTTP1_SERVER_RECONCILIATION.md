# HTTP/1.1 conformance reconciliation — poseidon-http-server

Audit of this server against the **current HTTP/1.1 specification pair**
(RFC 9110 semantics + RFC 9112 message syntax) plus **RFC 7540 §3.2**, which
defines the h2c Upgrade mechanism `server/h2c.go` actually implements.

Per-item evidence: [HTTP1_SERVER_RECONCILIATION_TABLES.md](HTTP1_SERVER_RECONCILIATION_TABLES.md).

## Method

Normative facts were **not** re-extracted. They were reused from the verified
catalogs in the sibling `poseidon-http-client` repo (`docs/rfc-analysis/` on
`origin/main`), where every fact carries a verbatim quote, a normative level and
an `applies_to` audience list, and each survived two independent default-refute
verifiers. See [.claude/skills/validate-rfc-conformance](../../.claude/skills/validate-rfc-conformance/SKILL.md).

Server slice derived by re-filtering on audience (`server` ∪ `origin` ∪ `all` ∪
`endpoint` ∪ `receiver` ∪ `sender`), **not** on the catalogs' `client_relevant`
flag — 181 normative RFC 9110/9112 facts are tagged `[not-client]` and are
exactly this server's obligations.

| | |
|---|---|
| Obligations judged | **294** (30 × RFC 7540 §3.2, 63 × RFC 9112, 201 × RFC 9110) |
| Judges | 7 (one per bucket, high effort, read-only) |
| Adversarial verifiers | 14 (2 per bucket, `real_gap=false` by default, opposite lenses) |
| Confirmed MUST-family failures | **24** |
| Other confirmed gaps (SHOULD / PARTIAL / UNTESTED) | 35 |
| Split verdicts needing a human | 13 |
| Findings **overturned** by the verifier pair | 126 (60%) |
| N/A dismissals found to be wrong | 0 |

The 60% overturn rate is the load-bearing number: a verifier pair that confirms
everything is broken. Quotes acted on in this document were additionally
re-checked byte-for-byte against `rfc7540.txt` and `rfc9113.txt` fetched from
rfc-editor.org.

## Where the failures are

24 confirmed MUST-family failures, but they are not spread evenly:

| Cluster | MUSTs | Location | Status |
|---|---|---|---|
| **1. h2c Upgrade** | **11** | `server/h2c.go` — one 35-line function | ✅ **fixed** — see [ADR-0005 amendment](../adr/0005-h2c-prior-knowledge-and-upgrade.md) |
| 2. Inbound request validation | 6 | `conn/server_handler.go`, `server/server.go` | open |
| 3. Response correctness | 5 | `server/handler.go`, `middleware/gzip.go` | open |
| 4. Server push | 2 | `server/push.go` | open |

The 12 rows left unverified by the first pass (the judge had batched several ids
into one finding, so verifier verdicts did not key against them) were re-run
against a fresh independent pair: **11 dismissals upheld, 0 wrong, 1 split**.
No `NOT_APPLICABLE` call in this audit survives unchallenged.

### Cluster 1 — the h2c Upgrade path (11 MUSTs in 35 lines)

`handleHTTP1Upgrade` ([server/h2c.go:50](../../server/h2c.go)) is the server's
only HTTP/1.1 surface, and it fails almost every obligation that applies to it:

| Rule | Verbatim | Reality |
|---|---|---|
| 7540 §3.2 | *"A server MUST ignore an "h2" token in an Upgrade header field."* | `h2` is accepted as an upgrade token (`h2c.go:63-64`) |
| 7540 §3.2.1 | *"A server MUST NOT upgrade the connection to HTTP/2 if this header field is not present or if more than one is present."* | `HTTP2-Settings` is never read — repo-wide it appears only in two test files |
| 7540 §3.2 | *"These frames MUST include a response to the request that initiated the upgrade."* | the parsed request is discarded at `h2c.go:83`; `conn/` has no notion of an upgrade (zero grep hits) |
| 9112 §3.2 | *"A server MUST respond with a 400 (Bad Request) … to any HTTP/1.1 request message that lacks a Host header field"* | a Host-less upgrade request gets 101 |
| 9110 §7.8 | *"A server MUST NOT switch to a protocol that was not indicated by the client"* | a client offering only `h2` is switched to `h2c` |
| 9110 §7.8 | *"A server that receives an Upgrade header field in an HTTP/1.0 request MUST ignore that Upgrade field."* | version-blind; `GET / HTTP/1.0` + `Upgrade: h2c` → 101 |
| 9110 §15.2 | *"a server MUST NOT send a 1xx response to an HTTP/1.0 client."* | same root — `req.Proto` is never read |
| 9110 §10.1.1 | *"the server MUST send a 100 (Continue) response before sending a 101"* | `Expect` is never inspected |
| 9112 §9.6 | *"A server MUST read the entire request message body or close the connection after sending its response"* | **security**: `http.ReadRequest` leaves the body unread in the `bufio.Reader`, which is handed straight to `conn.NewServerConn` — leftover HTTP/1.1 body octets are then parsed as HTTP/2 frames |

That last row is a request-smuggling primitive, not a paperwork failure.

**The tests cannot catch any of this.** `TestH2C_Upgrade`
([server/h2c_test.go:118](../../server/h2c_test.go)) and
`TestTransport_H2C_Upgrade_Fallback` both send a *brand-new* `HEADERS` on
stream 1 after the 101. A conformant client cannot do that — stream 1 is already
assigned to the upgrading request and is half-closed from the client side
(RFC 7540 §3.2). The tests encode the same wrong model as
the code, so they are green.

#### 5 whys

1. **Why do 11 MUSTs fail in one function?** Only the *surface* of the upgrade is
   implemented — recognise a token, write 101, switch. The §3.2 machinery
   (stream 1, `HTTP2-Settings`, version gating) was never built.
2. **Why only the surface?** The acceptance test itself opens a fresh stream 1
   after the 101, so it never exercised the machinery and never missed it.
3. **Why is the test shaped that way?** It was written *from the implementation*
   rather than from the spec text — it records what the code does.
4. **Why was no test written from the spec?** There is no such test in this
   repository. Zero `TestConformance_*` functions, no `docs/RFC_COVERAGE.md`.
   The genre does not exist here.
5. **Why does the genre not exist?** **Root cause:** the server inherited the
   client's *codec* (`frame`, `hpack`) but not its *verification process*. The
   client has `conformance-gate.yml`, `RFC_COVERAGE.md` and
   `scripts/rfc-coverage-gate.sh`; this repo has none of them. A requirement that
   is written down nowhere cannot be failed — and
   [ADR-0005](../adr/0005-h2c-prior-knowledge-and-upgrade.md) cited §3.2 without
   a line-by-line reading, promoting the first MUST violation to a documented
   feature ("only `h2c`/`h2` upgrade tokens are honoured", line 59).

So the 11 failures are a symptom. The disease is the missing
normative-text → test → CI-gate chain.

#### The fork

`conn.registerStream` is unexported; there is no way for `server/h2c.go` to seed
stream 1 from outside the package. So this cannot be patched surgically:

- **A — implement §3.2 properly.** New exported `conn` API to seed stream 1 in
  half-closed(remote), translate `http.Request` → `Request`, decode
  `HTTP2-Settings` (base64url → SETTINGS) and apply it, gate on
  `req.ProtoMinor`, drain or reject bodies. ~150–250 lines through the core
  state machine; touches ADR-0001 (zero-alloc) and ADR-0003 (goroutine model).
- **B — remove the Upgrade path**, keep prior-knowledge h2c only. All 11 MUSTs
  disappear, the smuggling primitive disappears, ~40 lines are deleted.
  RFC 9113 — the current HTTP/2 spec — supports this: *"This revision of HTTP/2
  marks the HTTP2-Settings header field and the h2c upgrade token, both defined
  in [RFC7540], as obsolete"* (RFC 9113 §11), and *"never widely deployed
  and is deprecated by this document"* (RFC 9113 §3.1). Requires superseding
  ADR-0005 and is a **visible behaviour change** to `Options.H2C`.

B is what the current specification asks for; A implements a mechanism its
successor declared obsolete. **Not decided here — this is a product call.**

### Cluster 2 — inbound request validation (6 MUSTs)

The server accepts and forwards what the spec says to reject:

- `91105-21` — *"a recipient of CR, LF, or NUL within a field value MUST either
  reject the message or replace each of those characters with SP"*.
  `emitHeaderBlock` (`conn/server_handler.go:234-291`) copies decoded header
  fields verbatim; the value reaches `http.Header.Add` unchanged. **Header
  injection into any stdlib-compat handler.**
- `91102-3-9` — an attacker-chosen `:path` is interpolated raw into the
  `grpc-message` trailer (`grpcserver/service.go:160`, `:359-364`).
- `91107-12` — the target URI is reconstructed with no validation at all
  (`server/server.go:471-493`): empty/foreign `:scheme`, missing `:authority`,
  CTL bytes in `:path` all pass through.
- `91104-9` / `91104-13` — a request with no `:authority` is **repaired** with
  the literal `"localhost"` (`server/handler.go:447-450`) where the RFC says
  *"A recipient that processes such a URI reference MUST reject it as invalid."*
- `91107-13` — nothing compares `:authority` against the connection's
  certificate; there is no 421 (Misdirected Request) path anywhere (zero grep
  hits for `421`).

Same root cause as cluster 1: `conn/server_validation_test.go` tests the
validation that exists, and nothing enumerates the validation that should.

### Cluster 3 — response correctness (5 MUSTs)

- `91109-20` — **HEAD returns a body.** Nothing in `conn/`, `server/` or
  `middleware/` reads `req.Method == "HEAD"`; `WriteData`/`Write` emit DATA
  unconditionally. Zero occurrences of `MethodHead` in the repo. Note this bites
  hardest via `FromHTTPHandler`, because a stdlib handler *relies* on `net/http`
  suppressing the body for it.
- `91106-42` — no `Date` field on any framework-generated response, though
  *"An origin server with a clock … MUST generate a Date header field in all 2xx,
  3xx, and 4xx responses"*.
- `91106-34` — `bufferStreamWriter.sendHeaders` (`server/handler.go:421-427`)
  cannot distinguish a trailer callback from response headers, so
  `grpc-status`/`grpc-message` get merged into the header section.
- `91108-17` — `middleware/gzip.go:261` uses `Set("Content-Encoding","gzip")` on
  the stdlib path, erasing a coding the handler already applied. The native path
  (`:294-303`) does it correctly — the bug is only in the compat path.
- `911010-15` — `Expect: 100-continue` is never inspected (zero grep hits).

### Cluster 4 — server push (2 MUSTs)

`PushWithScheme` (`server/push.go:109-115`) promises `{:method, :path, :scheme}`
with no `:authority`, so the synthesized target URI has an empty host — *"A
sender MUST NOT generate an "http" URI with an empty host identifier."*

## Progress

**Done (2026-07-31):**

1. **Root cause closed.** [docs/RFC_COVERAGE.md](../RFC_COVERAGE.md),
   `scripts/rfc-coverage-gate.sh` (ported from the client, self-check intact),
   `make conformance-gate`, and a CI job. Both halves of the gate were
   negative-tested: a required tag with no passing suite fails, and an untagged
   `TestConformance_RFCxxxx` suite in the tree fails.
2. **Cluster 1 fixed** — six `TestConformance_*` tests written from the RFC text
   first (all six red against the old code, including a 5-second hang on the
   missing stream-1 response), then `server/h2c.go` + the new
   `conn.UpgradedRequest` seam made them green. The two pre-existing upgrade
   tests, which encoded a client behaviour §3.2 forbids, were corrected.

**Remaining, in order:**

3. **Security-bearing:** `91105-21` (CR/LF/NUL in field values), `91102-3-9`
   (grpc-message), then `91107-12` / `91104-9` (target-URI validation).
4. **Correctness:** `91109-20` (HEAD), `91106-42` (Date), `91108-17` (gzip
   Content-Encoding), `91106-34` (trailer merge).
5. **Server push:** `91104-8` / `91104-12` (`:authority` on PUSH_PROMISE).
6. The 13 split verdicts in the tables document need a human ruling each.

Every item above should arrive as a row in `docs/RFC_COVERAGE.md` plus the test
that proves it — that is what stops this audit from being re-needed.

## Scope note

RFC 9111 (caching), proxy/gateway/tunnel roles, HTTP/3, and application-level
semantics owned by the user's `http.Handler` (content negotiation, conditional
requests, range requests, authentication) were ruled `NOT_APPLICABLE`. Those
dismissals were themselves adversarially checked; none were found wrong.
