#!/usr/bin/env bash
# contention-gate-selftest.sh — assert that scripts/contention-gate.sh is still
# capable of reaching each of its verdicts.
#
# It runs no benchmarks. Checks 1-7 replay arms recorded under
# testdata/contention/, and check 8 compiles two arms without measuring them, so
# every verdict below is deterministic on any machine and this script is the one
# part of the nightly whose result does not depend on the runner's mood.
#
# Checks 1-7 alone were not enough, and the gap had teeth: they exercise the
# comparator and never the code that feeds it, so when the measurement path broke
# on a relative CONTENTION_OUT this script passed in the same job that then died
# in round 1. Check 8 exists because "the instrument responds" has to cover
# obtaining the measurement, not only judging it.
#
# Why it exists. This repository has already shipped a gate that could not fail:
# `make bench-gate` self-baselines when testdata/benchmarks/baseline.txt is
# absent, that file has never been committed, and so the script records a
# baseline and prints PASS without comparing anything (#101, #103, #177). It
# stayed that way for months because a permanently green check looks exactly like
# a passing one. "The instrument responds" is therefore checked on every run
# rather than assumed once.
#
# ---------------------------------------------------------------------------
# Fixture provenance
# ---------------------------------------------------------------------------
#
# All six arms are genuine `scripts/contention-gate.sh` output, each PAIR
# recorded in a single invocation on one host — an AMD Ryzen 7 7700 (8 cores /
# 16 threads), go1.26.6, 2026-08-17, at the script's defaults of
# -benchtime=300ms -count=5 with 5 interleaved rounds. None of them is
# hand-written or edited; that is the point of a fixture that stands in for a
# measurement.
#
#   clean_base.txt / clean_cur.txt
#       Both arms built from the same commit with an unmodified working tree
#       (CONTENTION_BASE_REF=HEAD), recorded at -cpu=16. Byte-identical source
#       on both sides — the null.
#
#   injected_base.txt / injected_cur.txt
#       Same, with one throwaway change in the current arm: a 75-iteration
#       arithmetic spin inside ServerConn.bumpFramesSent, which every write path
#       calls while HOLDING wmu — so the injection lengthens the connection's
#       serialised section, the archetypal regression for a connection-wide
#       write mutex. Recorded at -cpu=16. Measured +54.6% (HEADERS) and +61.3%
#       (DATA) on the shared arm.
#
#   flat_base.txt / flat_cur.txt
#       Identical source again, but recorded at -cpu=2, where one connection is
#       only ~2.4x an uncontended one instead of ~11x. It stands in for a runner
#       too small to show a connection-wide lock; the check below raises
#       CONTENTION_MIN_PENALTY above that recorded ratio rather than pretending
#       to own a one-core machine.
#
#   empty.txt
#       A real run whose -bench pattern matched nothing.
#
# CONTENTION_CPU is pinned per check because it names the core count the arms
# were RECORDED at, not the core count of whatever machine replays them.
set -uo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
gate="$root/scripts/contention-gate.sh"
fx="$root/testdata/contention"
fails=0

check() { # check <name> <want_rc> <baseline> <current> [extra env assignments...]
  local name="$1" want="$2" base="$3" cur="$4"; shift 4
  local out rc
  out="$(env CONTENTION_BASELINE="$fx/$base" CONTENTION_CURRENT="$fx/$cur" \
             "$@" bash "$gate" 2>&1)"
  rc=$?
  if [ "$rc" -ne "$want" ]; then
    printf 'selftest: FAIL %-22s want exit %s, got %s\n' "$name" "$want" "$rc" >&2
    printf '%s\n' "$out" | sed 's/^/    | /' >&2
    fails=$((fails + 1))
  else
    printf 'selftest: ok   %-22s exit %s\n' "$name" "$rc"
  fi
}

# 1. The instrument responds: a recorded arm carrying an injected regression
#    must be rejected.
check "red/injected-spin"    1 injected_base.txt injected_cur.txt CONTENTION_CPU=16

# 2. ...and does not fire on identical code.
check "green/identical-code" 0 clean_base.txt    clean_cur.txt    CONTENTION_CPU=16

# 3. Raising the limit above the injected regression turns the SAME input green.
#    This is here so a future edit that hard-codes a verdict is caught: a gate
#    whose answer does not move with its threshold is not reading its input.
check "threshold-is-read"    0 injected_base.txt injected_cur.txt CONTENTION_CPU=16 CONTENTION_THRESHOLD=500

# 4. NOT MEASURABLE is reachable, and is not a pass. Arms whose shared/control
#    ratio is below the configured minimum carry no contention signal.
check "not-measurable"       4 flat_base.txt     flat_cur.txt     CONTENTION_CPU=2 CONTENTION_MIN_PENALTY=3.0

# 5. ...and the same arms ARE judged once the minimum is below their recorded
#    ratio, so check 4 proved the guard rather than a broken fixture.
check "guard-is-read"        0 flat_base.txt     flat_cur.txt     CONTENTION_CPU=2 CONTENTION_MIN_PENALTY=2.0

# 6. Nothing-compared is reachable. Two arms that share no benchmark must not be
#    a pass — that is the shape `bench-gate` shipped as a green.
check "nothing-compared"     3 empty.txt         empty.txt        CONTENTION_CPU=16

# 7. Half a comparison is an error, not a pass: a recorded baseline measured
#    elsewhere against a fresh local run would compare two machines.
if out="$(env CONTENTION_BASELINE="$fx/clean_base.txt" CONTENTION_CPU=16 bash "$gate" 2>&1)"; then
  printf 'selftest: FAIL %-22s want exit 2, got 0\n' "one-arm-only" >&2
  fails=$((fails + 1))
else
  rc=$?
  if [ "$rc" -ne 2 ]; then
    printf 'selftest: FAIL %-22s want exit 2, got %s\n' "one-arm-only" "$rc" >&2
    printf '%s\n' "$out" | sed 's/^/    | /' >&2
    fails=$((fails + 1))
  else
    printf 'selftest: ok   %-22s exit %s\n' "one-arm-only" "$rc"
  fi
fi

# 8. The MEASUREMENT path can still produce two runnable arms.
#
#    Checks 1-7 replay recorded arms and compile nothing, so they exercise the
#    comparator and never the thing that feeds it. That gap is not theoretical:
#    every nightly run from #208 landing until this check was added failed in
#    round 1, while this selftest — the step that runs first, specifically to
#    assert the instrument works — passed in the same job. The comparator was
#    fine. The gate could not obtain anything to compare.
#
#    CONTENTION_OUT is deliberately RELATIVE here, because that is what
#    .github/workflows/perf-nightly.yml passes and a relative output directory
#    was the whole bug: the baseline arm compiles inside a subshell that cd's
#    into the exported tree, and `go test -c -o` resolves a relative -o against
#    its own working directory while still exiting 0.
#
#    Build-only, so this compiles but runs no benchmarks and stays deterministic.
buildout="selftest-buildpath-out"
rm -rf "${root:?}/$buildout"
if out="$(cd "$root" && env CONTENTION_OUT="$buildout" CONTENTION_BASE_REF=HEAD \
                            CONTENTION_BUILD_ONLY=1 bash "$gate" 2>&1)"; then
  printf 'selftest: ok   %-22s exit 0\n' "build-path/relative-out"
else
  rc=$?
  printf 'selftest: FAIL %-22s want exit 0, got %s\n' "build-path/relative-out" "$rc" >&2
  printf '%s\n' "$out" | sed 's/^/    | /' >&2
  fails=$((fails + 1))
fi
rm -rf "${root:?}/$buildout"

if [ "$fails" -ne 0 ]; then
  echo "selftest: $fails assertion(s) failed — contention-gate.sh no longer behaves as documented." >&2
  exit 1
fi
echo "selftest: PASS — the gate reaches red, green, not-measurable, nothing-compared and error,"
echo "selftest: and its measurement path still builds two runnable arms."
