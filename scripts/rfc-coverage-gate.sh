#!/usr/bin/env bash
#
# RFC conformance coverage gate.
#
# Ported from poseidon-http-client (scripts/rfc-coverage-gate.sh). The audit in
# docs/rfc-analysis/HTTP1_SERVER_RECONCILIATION.md found 24 MUST-level failures
# and traced every one of them back to the same root cause: this repository had
# no way to express "the RFC requires X" as something CI can fail on. This
# script is that way.
#
# Usage: scripts/rfc-coverage-gate.sh <go-test-verbose-output>
set -euo pipefail
RFC="${1:?usage: $0 <go test -v output file>}"

fail=0

# Tags this gate requires to have at least one passing conformance test.
#
# RFC7540 is obsolete (superseded by RFC 9113) but stays in the list because
# server/h2c.go implements the h2c Upgrade mechanism that only 7540 defines --
# 9113 marks it obsolete (rfc9113.txt:3613). If that path is ever removed, drop
# the tag in the same commit that deletes the tests.
#
# RFC9113 arrived with the RFC 9113 section 8.3 pseudo-header suites, which the
# HTTP/1.1 audit produced: the target URI was being reconstructed with no
# validation, and section 8.3 is the HTTP/2-native place to say so.
TAGS="RFC7540 RFC9110 RFC9112 RFC9113"

for tag in $TAGS; do
  if ! grep -E "^--- PASS: TestConformance_${tag}" "$RFC" >/dev/null; then
    echo "No ${tag} conformance tests passed"
    fail=1
  fi
done

if grep -E '^--- FAIL: TestConformance_' "$RFC" >/dev/null; then
  echo "Conformance test failures present"
  fail=1
fi

# Every conformance suite in the tree must be named in TAGS above.
#
# The list is hand-maintained, so it drifts: a new RFC's tests get written, the
# tag is not added, and that entire suite becomes deletable with the gate still
# green. In the client repo that was not hypothetical -- two suites sat ungated
# until someone happened to look, which is the thing a gate exists to replace.
#
# `|| true` on the grep because a tree with no conformance tests at all should
# fall through to the per-tag checks above (which fail loudly) rather than
# aborting here under `set -e` with a confusing message.
present=$(grep -rhoE "func TestConformance_(RFC[0-9]+)" --include='*_test.go' . 2>/dev/null \
  | sed -E 's/func TestConformance_//' | sort -u || true)
for tag in $present; do
  case " $TAGS " in
    *" $tag "*) ;;
    *)
      echo "TestConformance_${tag}_* tests exist but ${tag} is not in this gate's tag list;"
      echo "  the whole ${tag} suite could be deleted and this gate would still pass."
      echo "  Add ${tag} to TAGS in $0."
      fail=1
      ;;
  esac
done

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "RFC coverage gate OK"
