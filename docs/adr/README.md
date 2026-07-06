# Architecture Decision Records

This directory records the significant architectural decisions made in
poseidon-http-server. Each ADR captures one decision: the context that forced
it, the choice that was made, and the consequences (good and bad) that follow.

ADRs are immutable once accepted. If a later decision overrides an earlier one,
add a new ADR and mark the old one `Superseded by ADR-XXXX` rather than editing
history.

## Index

| ADR | Title | Status |
| --- | --- | --- |
| [ADR-0001](0001-zero-allocation-hot-path-contract.md) | Zero-allocation contract on hot paths | Accepted |
| [ADR-0002](0002-reuse-client-codec-via-relative-replace.md) | Reuse the client frame/HPACK codec via a relative `replace` | Superseded by [ADR-0008](0008-consume-client-codec-as-tagged-module.md) |
| [ADR-0003](0003-serverconn-accept-stream-goroutine-model.md) | `ServerConn` accept-stream + per-stream-goroutine model | Accepted |
| [ADR-0004](0004-grpc-framing-and-status-trailers.md) | gRPC Length-Prefixed-Message framing + status-trailer design | Accepted |
| [ADR-0005](0005-h2c-prior-knowledge-and-upgrade.md) | h2c support: prior knowledge vs HTTP/1.1 Upgrade | Accepted |
| [ADR-0006](0006-responsewriter-interface-and-pusher.md) | `ResponseWriter` as an interface + Push via optional `Pusher` | Accepted |
| [ADR-0007](0007-rapid-reset-mitigation.md) | Rapid Reset (CVE-2023-44487) mitigation strategy | Accepted |

## Template

New ADRs use this lightweight template (copy `0000` numbering forward):

```markdown
# ADR-NNNN: <short title>

- **Status:** Proposed | Accepted | Superseded by ADR-XXXX | Deprecated
- **Date:** YYYY-MM-DD

## Context

What forces the decision? Constraints, requirements, prior art.

## Decision

The choice that was made, stated plainly.

## Consequences

What becomes easier, what becomes harder, and what trade-offs were accepted.
```

Sections are kept to **Title, Status, Context, Decision, Consequences** for
consistency across every record.
