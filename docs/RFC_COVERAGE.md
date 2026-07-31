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
| §2.2 (`rfc9110.txt:572`) | Conformance | `TestConformance_RFC9110_Sec22_GRPCMessagePercentEncoded` |
| §2.2 (`rfc9110.txt:572`) | Conformance | `TestConformance_RFC9110_Sec22_GRPCMessageOmittedWhenEmpty` |
| §4.2.1, §4.2.2 (`rfc9110.txt:1106`, `:1135`) | Conformance | `TestConformance_RFC9110_Sec42_EmptyHostRejected` |
| §4.2 boundary (`rfc9113.txt:2643`) | Conformance | `TestConformance_RFC9110_Sec42_NonHTTPSchemeUnaffected` |
| §7.2 (`rfc9110.txt:2426`) | Conformance | `TestConformance_RFC9110_Sec72_HostSuppliesAuthority` |
| §7.2 / RFC 9113 §8.3.1 (`rfc9113.txt:2649`) | Conformance | `TestConformance_RFC9110_Sec72_AuthorityWinsOverHost` |
| §9.3.2 (`rfc9110.txt:3987`) | Conformance | `TestConformance_RFC9110_Sec932_HeadSendsNoContent` |
| §9.3.2 (`rfc9110.txt:3993`, `rfc9113.txt:2457`) | Conformance | `TestConformance_RFC9110_Sec932_HeadKeepsHeaderFields` |
| §9.3.2 control | Conformance | `TestConformance_RFC9110_Sec932_GetStillSendsContent` |
| §5.4 | Conformance | `TestConformance_RFC9110_Sec54_OversizedFieldsGet431` |
| §5.4 control | Conformance | `TestConformance_RFC9110_Sec54_WithinLimitUnaffected` |
| §5.4 / CVE-2024-27316 | Conformance | `TestConformance_RFC9110_Sec54_ContinuationFloodAnswers431` |
| §5.6.3, §5.6.1.2 (`rfc9110.txt:1774`, `:1695`) | Conformance | `TestConformance_RFC9110_Sec561_ListGrammar` |
| §8.6 (`rfc9110.txt:3226`) | Conformance | `TestConformance_RFC9110_Sec86_HeadContentLengthNotStale` |
| §6.6.1 (`rfc9110.txt:2313`) | Conformance | `TestConformance_RFC9110_Sec661_DateOnMustStatuses` |
| §6.6.1 (`rfc9110.txt:2313`) | Conformance | `TestConformance_RFC9110_Sec661_DateOnStdlibPath` |
| §6.6.1 (`rfc9110.txt:2313`) | Conformance | `TestConformance_RFC9110_Sec661_HandlerDateWins` |
| §8.4 (`rfc9110.txt:3059`) | Conformance | `TestConformance_RFC9110_Sec84_NativePreEncodedNotRecompressed` |
| §8.4 (`rfc9110.txt:3059`) | Conformance | `TestConformance_RFC9110_Sec84_HTTPPreEncodedNotRecompressed` |
| §8.4 control | Conformance | `TestConformance_RFC9110_Sec84_UnencodedStillCompressed` |
| §6.5.1 (`rfc9110.txt:2245`) | Conformance | `TestConformance_RFC9110_Sec651_TrailersNotMergedIntoHeaders` |
| §6.5.1 (`rfc9110.txt:2244`) | Conformance | `TestConformance_RFC9110_Sec651_TrailersForwardedAsTrailers` |
| §6.5.1 boundary | Conformance | `TestConformance_RFC9110_Sec651_HeaderOnlyResponseUnaffected` |
| §10.1.1 | Conformance | `TestConformance_RFC9110_Sec1011_ImmediateContinue` |
| §10.1.1 (no expectation) | Conformance | `TestConformance_RFC9110_Sec1011_NoExpectNoContinue` |
| §10.1.1 (no content) | Conformance | `TestConformance_RFC9110_Sec1011_NoContentNoContinue` |
| §7.4 (`rfc9110.txt:2510`) | Conformance | `TestConformance_RFC9110_Sec74_MisdirectedAuthorityRejected` |
| §7.4 control | Conformance | `TestConformance_RFC9110_Sec74_AuthorityInCertAccepted` |

RFC 9110 §2.2 — *"A sender MUST NOT generate protocol elements that do not
match the grammar defined by the corresponding ABNF rules"* — is the hook by
which non-RFC grammars become gate-enforceable here. The `grpc-message` ABNF
comes from the gRPC-over-HTTP/2 spec (`doc/PROTOCOL-HTTP2.md`), which has no
RFC number of its own; naming the tests after the RFC that makes the grammar
binding keeps them visible to `scripts/rfc-coverage-gate.sh`, whose self-check
only recognises `TestConformance_RFC<digits>_*`.

## RFC 9112 — HTTP/1.1 Message Syntax

Applies only to the h2c Upgrade probe in `server/h2c.go`; this server does not
serve HTTP/1.1.

| Section | Type | Test |
|---------|------|------|
| §2.2 (`rfc9112.txt:445`) | Conformance | `TestConformance_RFC9112_Sec22_RejectRequestWithoutHost` |
| §5.1 (`rfc9112.txt:716`) | Conformance | `TestConformance_RFC9112_Sec51_WhitespaceBeforeColonRejected` |
| §9.6 (`rfc9112.txt:1521`) | Conformance | `TestConformance_RFC9112_Sec96_CloseOptionDeclinesUpgrade` |
| §9.6 (`rfc9112.txt:1521`) | Conformance | `TestConformance_RFC9112_Sec96_SecondCloseFieldLineCounts` |
| §9.6 (`rfc9112.txt:1548`) | Regression | `TestH2CProbe_TearDownIsStaged`, `TestH2CProbe_BadRequestTearsDownStaged` |

## RFC 9113 — HTTP/2

The HTTP/2 conformance audit has not been run yet; these rows arrived via the
HTTP/1.1 audit, which found the target URI was reconstructed with no validation
at all and landed on §8.3 as the HTTP/2-native way to state the rule.

| Section | Type | Test |
|---------|------|------|
| §8.3 (`rfc9113.txt:2614`, `:2619`, `:2624`, `:2690`, `:2699`, `:2710`) | Conformance | `TestConformance_RFC9113_Sec83_MalformedPseudoHeaders_StreamError` |
| §8.3 (`rfc9113.txt:2643`, `:2703`, `:2710`) | Conformance | `TestConformance_RFC9113_Sec83_ValidRequestsAccepted` |
| §8.3 / RFC 9110 §4.2.3 (`rfc9110.txt:1179`) | Conformance | `TestConformance_RFC9113_Sec83_SchemeIsCaseInsensitive` |
| §6.5.2 (uncompressed list size) | Regression | `TestServerConn_Continuation_OversizedBlock_TearsDownConnection` |
| §8.1.1 (`rfc9113.txt:2463`) | Regression | `TestServerConnHandler_MalformedStream_KeepsHPACKDecoderSynced` |
| §8.4 (`rfc9113.txt:2811`) | Conformance | `TestConformance_RFC9113_Sec84_PushPromiseCarriesAuthority` |
| §8.4 / §8.3 (`rfc9113.txt:2624`) | Conformance | `TestConformance_RFC9113_Sec84_PushPromiseCallerAuthorityWins` |
| §8.4 (`rfc9113.txt:2815`) | Conformance | `TestConformance_RFC9113_Sec84_PushRefusedWithoutAuthority` |
| §8.4 (`rfc9113.txt:2811`) | Conformance | `TestConformance_RFC9113_Sec84_PushWithPriorityCarriesAuthority` |

The `MalformedStream_KeepsHPACKDecoderSynced` row is not a conformance test but
guards the trap that makes §8.3 validation safe to implement at all: a rejected
block must still be fed to the shared HPACK decoder, or its dynamic table
desyncs from the client's encoder and every later stream on the connection
decodes corrupt headers.

## Known gaps

The HTTP/1.1 audit confirmed 24 MUST-level failures. The rows above close the
h2c Upgrade cluster and the field-value injection gap. The remaining confirmed
MUST-level gaps are closed, and so are the audit's 13 **split verdicts** —
findings where the two adversarial verifiers disagreed. Each was re-judged
against the post-fix code and then challenged from the opposite position: six
had been made moot by the merged fixes, five were real and are fixed, one
(gRPC status in trailers, RFC 9110 §6.5.1) is a deliberate deviation now
recorded in [ADR-0004](adr/0004-grpc-framing-and-status-trailers.md), and one
flipped — the reviewer was right that a bug existed but wrong about the rule;
the binding one turned out to be §8.6, not §9.3.2.

The 421 check (RFC 9110 §7.4) enforces only where the presented certificate is
knowable without guessing: a TLS listener served through
`ListenAndServeTLS`/`ListenAndServeTLSConfig`/`ServeTLSConfig`, with exactly one
static certificate and no `GetCertificate`/`GetConfigForClient` callback. Every
other arrangement stands the check down rather than risk rejecting legitimate
traffic — see the rationale on `selectLeaf`.
