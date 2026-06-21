// k6_http2.js — k6 load test for poseidon-server.
//
// IMPORTANT — HTTP/2 vs h2c caveat:
//   k6's HTTP client only upgrades to HTTP/2 via ALPN over TLS. It does NOT
//   speak HTTP/2 cleartext (h2c) prior-knowledge. So:
//     * Against the plain h2c listener (POSEIDON_H2C / default :8080), k6 will
//       talk HTTP/1.1 — still a useful throughput/latency smoke, but NOT an
//       HTTP/2 test. For a real HTTP/2 path through k6, run the server with TLS
//       (POSEIDON_TLS_CERT / POSEIDON_TLS_KEY) and point BASE_URL at https://…;
//       k6 then negotiates h2 over ALPN automatically.
//     * For HTTP/2 cleartext load, prefer loadtest/h2load.sh (nghttp2), which
//       does h2c prior-knowledge correctly.
//
// This script asserts on the negotiated protocol so an accidental HTTP/1.1 run
// against a TLS endpoint is caught.
//
// Tool: k6 (https://k6.io). Install:
//   - macOS:        brew install k6
//   - Debian/Ubuntu: see https://k6.io/docs/get-started/installation/
//   - Docker:       docker run --rm -i grafana/k6 run - <loadtest/k6_http2.js
//
// Usage:
//   k6 run loadtest/k6_http2.js
//   BASE_URL=https://127.0.0.1:8443/ k6 run loadtest/k6_http2.js   # real HTTP/2
//   VUS=200 DURATION=30s k6 run loadtest/k6_http2.js
//
// Env knobs:
//   BASE_URL   target URL   (default http://127.0.0.1:8080/)
//   VUS        virtual users (default 50)
//   DURATION   test duration (default 30s)
//   EXPECT_H2  "true" to fail unless HTTP/2 is negotiated (default false)
//
// What to read in the summary:
//   - http_reqs ......... total + rate (RPS)
//   - http_req_duration . avg / p(50) / p(90) / p(95) / p(99) latency
//   - checks ............ status==200 and (optionally) proto==HTTP/2.0

import http from 'k6/http';
import { check } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:8080/';
const EXPECT_H2 = (__ENV.EXPECT_H2 || 'false') === 'true';

export const options = {
  vus: Number(__ENV.VUS || 50),
  duration: __ENV.DURATION || '30s',
  // TLS load tests often use self-signed certs; allow them.
  insecureSkipTLSVerify: true,
  thresholds: {
    http_req_failed: ['rate<0.01'],          // <1% errors
    http_req_duration: ['p(95)<50', 'p(99)<100'], // tune to your hardware
  },
};

export default function () {
  const res = http.get(BASE_URL);
  check(res, {
    'status is 200': (r) => r.status === 200,
    'http/2 negotiated': (r) => !EXPECT_H2 || r.proto === 'HTTP/2.0',
  });
}
