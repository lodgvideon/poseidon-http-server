# Security Policy

## Supported versions

Poseidon is pre-1.0; security fixes land on the latest `0.x` minor release. Please
track the newest tag — older tags do not receive backported fixes.

| Version | Supported |
| ------- | --------- |
| latest `0.4.x` | ✅ |
| older | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via GitHub's [Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability):
open the repository's **Security → Report a vulnerability** tab. This opens a
private advisory visible only to the maintainers.

Please include:

- affected version / commit,
- a description of the issue and its impact,
- reproduction steps or a proof-of-concept, and
- any suggested remediation.

You can expect an initial acknowledgement within a few days. Once a fix is
prepared, we coordinate a release and disclosure timeline with you and credit
you in the advisory unless you prefer to remain anonymous.

## Scope

This library implements HTTP/2 and gRPC transport surfaces that parse untrusted
input (frames, HPACK, length-prefixed messages). Reports of protocol-level DoS
(resource exhaustion, flow-control or HPACK abuse, frame-flood amplification),
memory-safety issues, and request-smuggling vectors are especially in scope.
Note that several DoS mitigations are configurable and secure-by-default (HTTP/2
Rapid Reset budget, request body-size limit, handshake/idle timeouts,
decompression-bomb bound, bounded rate-limiter memory) — see the
[usage guide](docs/usage.md) and CHANGELOG for the knobs and their defaults.
