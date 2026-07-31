# HTTP/1.1 conformance reconciliation — evidence tables

Machine-generated companion to [HTTP1_SERVER_RECONCILIATION.md](HTTP1_SERVER_RECONCILIATION.md).
One row per non-PASS verdict that survived (or was killed by) adversarial verification.

**Totals** — 210 verdicts judged · **24 confirmed MUST-family FAIL** · 35 other confirmed gaps · 13 split (REVIEW) · 126 overturned by verifiers.

## 1. Confirmed MUST-family failures

Both adversarial verifiers, instructed to default to `real_gap=false`, failed to overturn these.

### RFC 7540 §3.2 h2c upgrade

| ID | Level | Verdict | Requirement | Evidence |
|----|-------|---------|-------------|----------|
| `1-3-19` | MUST | FAIL | After a 101 upgrade response, the HTTP/2 frames the server sends MUST include a response to the request that initiated the upgrade. | server/h2c.go:56-84 (handleHTTP1Upgrade); tests server/h2c_test.go:63 TestH2C_Upgrade and server/integration/transport_test.go:187 TestTransport_H2C_Upgrade_Fallback |
| `1-3-18` | MUST | FAIL | A server MUST ignore an "h2" token appearing in an Upgrade header field (h2 is only negotiated via TLS/ALPN). | server/h2c.go:63-64; docs/adr/0005-h2c-prior-knowledge-and-upgrade.md:61; no test exists (grep of *_test.go finds only 'Upgrade: h2c' at server/h2c_test.go:87 and server/integration/transport_test.go: |
| `1-3-27` | MUST NOT | FAIL | A server MUST NOT upgrade to HTTP/2 if the HTTP2-Settings header field is absent or occurs more than once. | server/h2c.go:50-84 (handleHTTP1Upgrade); repo-wide case-insensitive grep for HTTP2-Settings matches only server/h2c_test.go:88 and server/integration/transport_test.go:231 |

### RFC 9112 framing + parsing

| ID | Level | Verdict | Requirement | Evidence |
|----|-------|---------|-------------|----------|
| `91124-5-15` | MUST | FAIL | A server must reject with 400 (Bad Request) any request containing whitespace between a header field name and colon. | server/h2c.go:56 (http.ReadRequest) — GOROOT net/textproto/reader.go:760-765 deliberately ACCEPTS a space before the colon (go.dev/issue/34540, returns the key un-canonicalized, ok=true); the rejectin |
| `91123-16` | MUST | FAIL | A server must respond 400 to any HTTP/1.1 request lacking Host, containing more than one Host field line, or containing an invalid Host value. | server/h2c.go:56-84 — no Host validation anywhere in server/ (grep for "Host" in server/*.go yields only handler.go:488 and test files). GOROOT net/http/request.go:1138 rejects only >1 Host (and h2c.g |

### RFC 9112 transfer-coding / connection / security

| ID | Level | Verdict | Requirement | Evidence |
|----|-------|---------|-------------|----------|
| `91128-9-25` | MUST | FAIL | A server must read the entire request body or close the connection after responding. | server/h2c.go:56 (http.ReadRequest) + server/h2c.go:77-83 (101 write then serveConnReader); no test in server/h2c_test.go or server/integration/transport_test.go sends an Upgrade request carrying a bo |

### RFC 9110 fields + routing

| ID | Level | Verdict | Requirement | Evidence |
|----|-------|---------|-------------|----------|
| `91107-13` | MUST | FAIL | A request for an https resource must be rejected unless received over a connection secured via a certificate valid for the target URI's origin. | server/server.go:471-493 (buildRequest); server/tls.go:18-57 (ListenAndServeTLS/TLSConfig); no test — grep for "421"/"Misdirected" across the repo returns zero hits |
| `91107-12` | MUST | FAIL | Unless the connection is from a trusted gateway, an origin server must reject a request that fails any scheme-specific requirement of the target URI. | server/server.go:471-493 (buildRequest) and server/server.go:499-506 (splitPathQuery); server/fuzz_test.go FuzzRequestPath only asserts the split is lossless, never that bad targets are rejected |
| `91106-42` | MUST | FAIL | An origin server with a clock must generate a Date header field in all 2xx, 3xx, and 4xx responses. | server/handler.go:244-262 (WriteHeaders) and :307-336 (WriteHeader); server/server.go:427-432 (rejectTooLarge 413) and :434-469 (dispatchAndClose 200/500); grep for '"date"', 'http.TimeFormat', 'time. |
| `91105-21` | MUST | FAIL | A recipient of CR, LF, or NUL within a field value must either reject the message or replace each such character with SP before further processing/forwarding. | conn/server_handler.go:234-291 (emitHeaderBlock) and server/server.go:471-493 (buildRequest); server/handler.go:466-468 (NewHTTPRequest copies into http.Header). No validation test exists — conn/serve |
| `91107-67` | MUST NOT | FAIL | A server must not switch protocols unless the received message's semantics can be honored by the new protocol. | server/h2c.go:50-84 (handleHTTP1Upgrade); TestH2C_Upgrade (server/h2c_test.go:63-129) and server/integration/transport_test.go:228-284 both send a brand-new request on stream 1 after the 101, confirmi |
| `91107-71` | MUST | FAIL | If a server receives both Upgrade and Expect: 100-continue, it must send a 100 (Continue) response before sending 101 (Switching Protocols). | server/h2c.go:56-80 — between http.ReadRequest and the hand-written 101 there is no Expect inspection; grep for 'Expect' / '100-continue' across *.go returns no server-side hits (only server/integrati |
| `91107-69` | MUST | FAIL | A server receiving an Upgrade header field in an HTTP/1.0 request must ignore it. | server/h2c.go:56-80 — req.Proto/ProtoMajor/ProtoMinor are never read after http.ReadRequest; grep for 'ProtoMinor' shows hits only in server/integration tests asserting client-side ProtoMajor==2 |
| `91107-63` | MUST NOT | FAIL | A server must not switch to a protocol the client did not indicate in the corresponding request's Upgrade header field. | server/h2c.go:63-64 accepts EqualFold(Upgrade,"h2c") OR EqualFold(Upgrade,"h2"), then server/h2c.go:77-80 unconditionally replies "Upgrade: h2c"; no test exercises the "h2" branch (h2c_test.go and tra |
| `91106-34` | MUST NOT | FAIL | A recipient must not merge a trailer field into the header section unless it understands the field definition and that definition explicitly permits and defines safe merg | server/handler.go:421-427 (bufferStreamWriter.sendHeaders appends trailer fields to headerFields, comment claims it is "harmless") replayed at server/handler.go:395-406 via w.Header().Add before w.Wri |
| `91102-3-9` | MUST NOT | FAIL | A sender must not emit any protocol element that fails its ABNF grammar. | grpcserver/service.go:160 Statusf(Unimplemented, "unknown method %s", req.Path) and service.go:359-364 statusToHPack write st.Message raw into the grpc-message trailer; errToStatus (service.go:390) us |

### RFC 9110 representation + methods

| ID | Level | Verdict | Requirement | Evidence |
|----|-------|---------|-------------|----------|
| `91109-20` | MUST NOT | FAIL | A server must not send content in a response to HEAD. | server/handler.go:266 responseWriter.WriteData / server/handler.go:294 responseWriter.Write; server/server.go:434 dispatchAndClose — no test exists (grep for \"HEAD\"/MethodHead over all *.go returns  |
| `911010-15` | MUST | FAIL | An origin server receiving a request with a 100-continue expectation and an indication that request content will follow must immediately send either a final response or a | server/server.go:471-493 buildRequest (parses only :method/:path/:scheme/:authority); repo-wide grep for `100-continue`, `StatusContinue`, `"expect"` returns zero hits in any .go file |
| `91104-9` | MUST | FAIL | A recipient processing an http URI reference with an empty host must reject it as invalid. | server/handler.go:447-450 NewHTTPRequest (`host := req.Authority; if host == "" { host = "localhost" }`); server/server.go:486-489 buildRequest performs no pseudo-header validation; no test asserts re |
| `91104-13` | MUST | FAIL | A recipient processing an https URI reference with an empty host must reject it as invalid. | server/handler.go:447-450 NewHTTPRequest — the same substitution runs for scheme=="https"; server/server.go:471-493 has no authority check |
| `91104-8` | MUST NOT | FAIL | A sender must never generate an http URI whose host identifier is empty. | server/push.go:109-115 PushWithScheme and server/push.go:153-159 pushWithPriorityAndScheme — the PUSH_PROMISE field list is exactly {:method, :path, :scheme} plus caller extras; no *_test.go asserts a |
| `91104-12` | MUST NOT | FAIL | A sender must never generate an https URI whose host identifier is empty. | server/push.go:104-115 (default scheme is https, per server/push.go:46 schemeHTTPS) and server/push.go:150-159 |
| `91108-17` | MUST | FAIL | A sender that applied content codings MUST list them in Content-Encoding in application order. | middleware/gzip.go:261-273 flushHTTP — `h.Set("Content-Encoding", "gzip")`; contrast the correct native path middleware/gzip.go:294-303 withGzipEncoding, tested by middleware/gzip_wrapper_test.go:119; |

### RFC 9110 status codes

| ID | Level | Verdict | Requirement | Evidence |
|----|-------|---------|-------------|----------|
| `911015.1-15.3-12` | MUST NOT | FAIL | A server must not send a 1xx response to an HTTP/1.0 client. | server/h2c.go:50-84 handleHTTP1Upgrade (http.ReadRequest at :56, 101 written at :77-80); no test in server/h2c_test.go or server/integration/transport_test.go exercises an HTTP/1.0 upgrade request |

## 2. Confirmed SHOULD-family / PARTIAL / UNTESTED gaps

### RFC 7540 §3.2 h2c upgrade

| ID | Level | Verdict | Requirement | Evidence |
|----|-------|---------|-------------|----------|
| `1-3-26` | informative | FAIL | The HTTP2-Settings header field value is syntactically a token68 (ABNF: HTTP2-Settings = token68) and is a connection-specific header field. | server/h2c.go:50-84 — no base64url decode and no frame.SettingsParams construction anywhere in the h2c path; no test |
| `1-3-22` | informative | FAIL | The HTTP/1.1 request sent prior to upgrade is assigned stream identifier 1 with default priority values. | server/h2c.go:83 s.serveConnReader(ctx, nc, br) -> conn.NewServerConn (conn/server_conn.go:249); grep 'Upgrade' over conn/ returns no matches; no test |
| `1-3-23` | informative | FAIL | After upgrade, stream 1 is implicitly half-closed (local) from the client's perspective because the request was completed as HTTP/1.1. | conn/server_conn.go:249-354 NewServerConn (no upgrade parameter, no pre-seeded stream); server/h2c_test.go:118 TestH2C_Upgrade |
| `1-3-24` | informative | FAIL | After commencing the HTTP/2 connection, the response to the upgrading request is delivered on stream 1. | server/h2c.go:76-83; server/server.go:287 acceptLoop only serves client-initiated streams from sc.AcceptStream; no test |

### RFC 9112 framing + parsing

| ID | Level | Verdict | Requirement | Evidence |
|----|-------|---------|-------------|----------|
| `91126-30` | MUST | PARTIAL | Rule 4: if Transfer-Encoding is present in a request and chunked is not the final encoding, the length is unreliable and the server must respond 400 and close the connect | server/h2c.go:57-60 — the *unsupportedTEError returned by GOROOT net/http/transfer.go:648/651 is discarded and the connection is closed with no bytes written. No test. |
| `91126-32` | MUST | PARTIAL | Rule 5: if the unrecoverable Content-Length error is in a request, the server must respond 400 and close the connection. | server/h2c.go:57-60 — the error from GOROOT net/http/transfer.go:661-690 (fixLength) / :1050-1069 (parseContentLength) is discarded and nc.Close() is called with no response written. No test sends a b |
| `91121-2-23` | SHOULD | FAIL | A server receiving octets not matching the HTTP-message grammar should respond 400 and close the connection. | server/h2c.go:56-60: `req, err := http.ReadRequest(br); if err != nil { _ = nc.Close(); return }`. The only 400 (h2c.go:66-71) is emitted for a *well-formed* non-upgrade request. TestH2C_RejectHTTP1 ( |
| `91123-11` | SHOULD | FAIL | Recipients of an invalid request-line should respond 400 or a 301 redirect with the target properly encoded. | server/h2c.go:57-60 — parseRequestLine/validMethod/url.ParseRequestURI errors (GOROOT net/http/request.go:1097-1125) all funnel into the same silent nc.Close(). No test sends an invalid request-line. |
| `91121-2-20` | SHOULD | FAIL | A server expecting a request-line should ignore at least one empty line (CRLF) received before it. | server/h2c.go:30-44 (Peek(14) fails the preface compare on a leading CRLF) then h2c.go:56 http.ReadRequest → GOROOT net/http/request.go:1086-1100 parseRequestLine("") → error. The stdlib's leading-CR/ |
| `91126-14` | SHOULD | FAIL | A server receiving a request with a transfer coding it does not understand should respond 501. | server/h2c.go:57-60 discards the *unsupportedTEError from GOROOT net/http/transfer.go:648-652; net/http's own server maps that error to "501 Unsupported Transfer-Encoding" in (*conn).serve, a path thi |

### RFC 9112 transfer-coding / connection / security

| ID | Level | Verdict | Requirement | Evidence |
|----|-------|---------|-------------|----------|
| `91128-9-42` | SHOULD | FAIL | A client or server wishing to time out should issue a graceful close on the connection. | server/server.go:270-284 (serveConn) and server/server.go:287-310 (acceptLoop); the only conn.ServerConn.Close() call sites are server/server.go:638/699/709 (Close/Shutdown). Test server/idle_timeout_ |
| `91128-9-43` | SHOULD | PARTIAL | Implementations should constantly monitor open connections for a received closure signal and respond appropriately. | conn/server_conn.go:666-687 (readerLoop) + conn/server_conn.go:710-720 (shutdownStreams); conn/server_ops.go:67 is the only send on acceptCh and nothing ever closes it (grep acceptCh → conn/server_con |
| `91128-9-22` | MUST | UNTESTED | A server that does not support persistence must send "close" in every non-1xx response. | server/h2c.go:66-70 (the only non-1xx HTTP/1.1 response the server emits) ; TestH2C_RejectHTTP1 (server/h2c_test.go:132-162) |
| `91128-9-49` | SHOULD | UNTESTED | A sender should send a Connection header with the "close" option when it intends to close the connection. | server/h2c.go:68 ("Connection: close\r\n" in the 400) ; TestH2C_RejectHTTP1 (server/h2c_test.go:132-162) asserts only the status line |
| `91128-9-56` | MUST | UNTESTED | A server that sends "close" must initiate closure after sending the response containing it. | server/h2c.go:71-72 (nc.Write(resp) then nc.Close()) ; TestH2C_RejectHTTP1 (server/h2c_test.go:132-162) |
| `91128-9-73` | SHOULD | UNTESTED | Servers should be prepared to receive an incomplete close from the client. | conn/server_conn.go:672-684 (any read error, including unexpected EOF / RST, is handled uniformly) ; no test in server/, server/integration/, or conn/ closes the client transport abruptly and then ass |

### RFC 9110 fields + routing

| ID | Level | Verdict | Requirement | Evidence |
|----|-------|---------|-------------|----------|
| `91105-35` | MUST | PARTIAL | A recipient must parse for bad whitespace and remove it before interpreting the protocol element. | grpcserver/service.go:328-336 isGRPCContentType compares with == against "application/grpc" and "application/grpc+proto"; no BWS/parameter handling. Tests grpcserver/service_test.go exercise only exac |
| `91102-3-13` | SHOULD | PARTIAL | A recipient should parse received protocol elements defensively, expecting grammar violations and unreasonable sizes. | size defenses present and tested: conn/server_handler.go:38 defaultMaxHeaderBytes + :159/:209 caps (conn/server_continuation_test.go:99), server/server.go:396-399 body cap (server/body_limit_test.go), |
| `91105-19` | SHOULD | PARTIAL | Specifications defining new fields should restrict values to VCHAR, SP, and HTAB. | grpcserver/service.go:359-364 statusToHPack emits []byte(st.Message) unencoded; grpcserver/status.go:119-124 StatusToTrailers does the same; grpcserver/status_test.go:46-67 round-trips only ASCII mess |
| `91106-49` | SHOULD | FAIL | A sender intending to generate trailer fields should send a Trailer header field in the header section naming the fields that might appear in the trailers. | grpcserver/service.go:339-345 grpcResponseHeaders() returns only {content-type: application/grpc}; every handler path (service.go:223, 251, 270, 299, 352) then sends grpc-status/grpc-message trailers. |
| `91107-61` | MUST | UNTESTED | A server sending 101 (Switching Protocols) must send an Upgrade header field naming the protocol(s) the connection is switching to. | implemented at server/h2c.go:77-80 ("Upgrade: h2c"); TestH2C_Upgrade (server/h2c_test.go:97-103) and server/integration/transport_test.go:243-252 both loop "skip/drain remaining headers until empty li |
| `91107-68` | MUST | UNTESTED | Any sender of Upgrade must also send an "Upgrade" connection option in the Connection header field. | implemented at server/h2c.go:78-79 ("Connection: Upgrade"); same unasserted header drain in server/h2c_test.go:97-103 and server/integration/transport_test.go:243-252 |
| `91107-24` | MUST | UNTESTED | When any field other than Connection supplies control information for the current connection, the sender must list that field's name in the Connection header field. | the only connection-control field the server emits is Upgrade, correctly listed at server/h2c.go:78-79; the 400 path (server/h2c.go:66-70) sends only "Connection: close". No test asserts either Connec |
| `91107-60` | SHOULD | UNTESTED | Recipients should compare each Upgrade protocol-name to supported protocols case-insensitively, despite registered preferred case. | implemented at server/h2c.go:63-64 via strings.EqualFold; every test sends lowercase "h2c" (server/h2c_test.go:87, server/integration/transport_test.go:230) |
| `91106-16` | SHOULD | UNTESTED | A recipient of a message with a supported major version but higher minor version should process it as the highest minor version it conforms to within that major version. | server/h2c.go:56-80 — the request version returned by http.ReadRequest is never examined, so every HTTP/1.x probe is handled identically; no test sends anything but "HTTP/1.1" (server/h2c_test.go:85,1 |

### RFC 9110 representation + methods

| ID | Level | Verdict | Requirement | Evidence |
|----|-------|---------|-------------|----------|
| `91108-43` | SHOULD | FAIL | Absent Transfer-Encoding, an origin server SHOULD send Content-Length when the content size is known before the header section completes. | server/health.go:100-105 writeHealthStatus (body length known, only content-type sent); middleware/gzip.go:245-256 flushNative and :292-303 withGzipEncoding (compressed length `len(out)` is known and  |
| `91108-26` | SHOULD | FAIL | A recipient SHOULD treat "x-gzip" as equivalent to "gzip". | middleware/gzip.go:95-103 acceptsGzip → middleware/gzip.go:106-130 containsToken(val, "gzip"); middleware/gzip.go:414-434 DecompressBody/DecompressBodyLimit key off gzip.NewReader only; no test feeds  |
| `91104-25` | SHOULD | FAIL | Before using an http(s) URI received from an untrusted source, a recipient should parse for userinfo and treat its presence as an error (phishing defense). | server/server.go:486-489 buildRequest copies :authority verbatim into Request.Authority; server/handler.go:447-450 concatenates it into `scheme + "://" + host + req.Path` for http.NewRequest; no valid |
| `91109-3` | MUST | PARTIAL | All general-purpose servers must support GET and HEAD. | server/server.go:471-493 buildRequest + :434 dispatchAndClose dispatch any :method to the handler (GET is exercised throughout, e.g. server/health_test.go:45); no HEAD-specific code or test exists any |

### RFC 9110 status codes

| ID | Level | Verdict | Requirement | Evidence |
|----|-------|---------|-------------|----------|
| `911015.5-15.6-2` | SHOULD | PARTIAL | For 4xx responses, the server should include a representation explaining the error, except for HEAD. | server/server.go:427-432 rejectTooLarge (413, nil headers + nil trailers, no DATA) covered by TestBodyLimit_BufferedRejected (server/body_limit_test.go:69-109, asserts status only); middleware/ratelim |
| `911015.5-15.6-58` | SHOULD | PARTIAL | For 5xx responses, the server should include a representation explaining the error, except for HEAD. | server/server.go:443-449 dispatchAndClose panic recovery (WriteHeaders(500, nil) + WriteTrailers(nil)) covered by TestE2E_HandlerPanic_IsolatedAndServerSurvives (server/integration/panic_test.go:16-51 |
| `911015.1-15.3-21` | MUST | UNTESTED | The server must generate an Upgrade header field in a 101 response indicating the protocol(s) in effect afterwards. | server/h2c.go:77-80 writes "Connection: Upgrade\r\nUpgrade: h2c\r\n"; TestH2C_Upgrade (server/h2c_test.go:63-129) and TestTransport_H2C_Upgrade_Fallback (server/integration/transport_test.go:187-252) |

### RFC 9110 conditional / range / conneg / auth

| ID | Level | Verdict | Requirement | Evidence |
|----|-------|---------|-------------|----------|
| `911012-52` | SHOULD (origin) | FAIL | An origin server should generate Vary on a cacheable response it wants selectively reused for subsequent requests. | middleware/gzip.go:66-92 (Gzip), :245-273 (flushNative/flushHTTP), :294-303 (withGzipEncoding); no test — middleware/gzip_e2e_test.go TestGzip_* assert content-encoding only. Repo-wide grep for `Vary` |
| `911012-19` | SHOULD (all) | FAIL | Recipients should treat any parameter named "q" as the weight regardless of its position among parameters. | middleware/gzip.go:95-103 acceptsGzip, :106-130 containsToken; middleware/gzip_test.go:80-107 TestContainsToken asserts {"gzip; q=0.8", "gzip", true} — the only q-bearing case, and it locks in q-ignor |
| `911012-37` | SHOULD (origin) | FAIL | If no available representation matches a non-empty Accept-Encoding, the origin server should respond without any content coding unless identity is marked unacceptable. | middleware/gzip.go:106-130 containsToken (word-boundary check accepts ';' at gzip.go:120) reached from acceptsGzip at gzip.go:95-103; no test in middleware/gzip_test.go or middleware/gzip_e2e_test.go  |

## 3. Split verdicts — need a human call

One verifier upheld the gap, the other overturned it. Never auto-resolved.

| ID | Level | Verdict | Requirement | Evidence |
|----|-------|---------|-------------|----------|
| `1-3-31` | informative | FAIL | The settings carried in HTTP2-Settings need no explicit SETTINGS ACK; the 101 response is their implicit acknowledgement. | server/h2c.go:77-80 (101 written unconditionally) with no corresponding apply-settings call; conn/server_conn.go:306 handshakeServerSettings only handles the post-preface SETTINGS frame; no test |
| `91126-18` | MUST | FAIL | After responding to a request that carried both Content-Length and Transfer-Encoding, the server must close the connection. | server/h2c.go:77-83 — after writing 101 the connection is handed to serveConnReader and kept open; no code in server/ inspects Transfer-Encoding (grep "Transfer-Encoding" over server/ returns zero hit |
| `91126-19` | MUST | FAIL | A server receiving an HTTP/1.0 message containing Transfer-Encoding must treat the framing as faulty and close the connection after processing the message. | server/h2c.go:50-84 — req.Proto / req.ProtoMajor are never inspected and Transfer-Encoding is never inspected. GOROOT net/http/transfer.go:637-640 explicitly ignores Transfer-Encoding on HTTP/1.0 requ |
| `91126-6` | MUST | PARTIAL | Every recipient must be able to parse the chunked transfer coding. | server/h2c.go:56 sets up a chunked body via stdlib readTransfer (GOROOT net/http/transfer.go:525-545), but req.Body is never read and h2c.go:83 passes the raw bufio.Reader to conn.NewServerConn. No te |
| `91128-9-53` | MUST | PARTIAL | A server receiving "close" must initiate connection closure after sending the final response to that request. | server/h2c.go:50-84 (handleHTTP1Upgrade) — the request's Connection header is never read (only req.Header.Get("Upgrade") at h2c.go:63-64); no test exercises Connection: close on the h2c probe |
| `91128-9-55` | MUST NOT | PARTIAL | A server that received "close" must not process any further requests on that connection. | server/h2c.go:63-83 (no Connection-token inspection) → server/h2c.go:107 s.acceptLoop; no test covers it |
| `91128-9-74` | MUST | UNTESTED | Servers must attempt to initiate an exchange of closure alerts before closing the connection. | conn/server_conn.go:449 (sc.transport.Close(), where transport is the *tls.Conn returned by tls.Listen in server/tls.go:46) and server/h2c.go:34,58,72,101 ; TestTLS_ListenAndServe (server/tls_test.go: |
| `91105-14` | MUST | FAIL | A server receiving request fields larger than it wishes to process must respond with an appropriate 4xx status. | conn/server_handler.go:159-161 and :209-211 return connError{ErrCodeProtocolError, "header block exceeds max size"}; TestServerConn_Continuation_OversizedBlock_EmitsProtocolError (conn/server_continua |
| `91106-36` | SHOULD NOT | PARTIAL | A server should not generate trailer fields it believes are necessary for the user agent to receive, because trailers may be discarded in transit. | grpcserver/service.go:236, 260, 289, 314, 355 all end the RPC with w.WriteTrailers(statusToHPack(...)); grpcserver/service_integration_test.go:329 asserts the trailers-only error response |
| `91105-26` | MUST | UNTESTED | A recipient must parse and ignore a reasonable number of empty list elements, bounded to avoid denial-of-service. | implemented at middleware/realip.go:129-139 (clientFromXFF skips elements normalizeIP rejects) and middleware/gzip.go:106-130 (containsToken skips runs of ',' and SP); no test case in middleware/reali |
| `91105-27` | MUST | UNTESTED | Grammar: recipients must accept lists matching [ element ] *( OWS "," OWS [ element ] ); empty elements do not count toward element cardinality. | same code as 91105-26 — middleware/realip.go:125-140, middleware/gzip.go:106-130; middleware/realip_test.go and middleware/gzip_test.go contain no leading-comma, trailing-comma, or empty-element case |
| `91104-5` | RECOMMENDED | UNTESTED | All senders and recipients should support URIs of at least 8000 octets in protocol elements. | conn/server_handler.go:38 `defaultMaxHeaderBytes = 1 << 20` and conn/server_handler.go:64-77 newServerConnHandler (cap overridable via AdvertisedSettings.MaxHeaderListSize, conn/server_conn.go:305); t |
| `91109-21` | SHOULD | UNTESTED | A server should send the same header fields for HEAD as it would for GET. | server/handler.go:244-262 WriteHeaders / :307-336 WriteHeader are method-agnostic; no HEAD test exists (grep over all *_test.go) |

## 4. Overturned

126 findings (107 of them N/A dismissals) were killed by the verifier pair — the judge was wrong or the rule does not bind this component. Not reproduced here; see the workflow journal.
