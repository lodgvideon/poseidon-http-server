#!/usr/bin/env bash
# contention-gate.sh — fail on a lock-contention regression in conn's write path.
#
# Usage: scripts/contention-gate.sh
# Env:
#   CONTENTION_BASE_REF    git ref for the baseline arm (default: origin/main)
#   CONTENTION_BASELINE    pre-recorded baseline-arm output; skips building it
#   CONTENTION_CURRENT     pre-recorded current-arm output; skips building it
#   CONTENTION_CPU         goroutines per benchmark, i.e. -cpu (default: nproc)
#   CONTENTION_THRESHOLD   max allowed % regression in the shared-connection
#                          number before failing (default: 30)
#   CONTENTION_MIN_PENALTY minimum shared/control ratio for a pair to be judged
#                          at all (default: 2.0)
#   CONTENTION_ROUNDS      interleaved A/B rounds (default: 3)
#   CONTENTION_BENCHTIME   per-benchmark time (default: 300ms)
#   CONTENTION_COUNT       repetitions per round (default: 5)
#   CONTENTION_OUT         directory for raw output (default: a temp dir)
#   GO                     go binary (default: go)
#
# ---------------------------------------------------------------------------
# Why this is not `bench-gate` with another threshold (issue #121)
# ---------------------------------------------------------------------------
#
# Two reasons, and only the second is about thresholds.
#
# 1. `bench-gate` compares against a file. There is no committed baseline
#    (testdata/benchmarks/ is absent; #101, #103, #177), and an absolute latency
#    baseline recorded on one machine could not be compared against a run on
#    another anyway. This gate never compares across machines: it builds BOTH
#    arms here and runs them interleaved in this invocation.
#
# 2. `bench-gate`'s sec/op limit is +50%, deliberately set above the drift that
#    byte-identical code shows on a shared host (#126, #197). A connection-wide
#    lock does not have to cost 50% to matter — it costs a factor of the core
#    count in throughput while every added core makes the single-goroutine number
#    look fine. Same-runner A/B is what buys the tighter limit: both arms see the
#    same machine, minutes apart, so the drift a cross-run comparison has to
#    absorb is much of what a same-run comparison cancels.
#
# ---------------------------------------------------------------------------
# What it measures, and what was rejected
# ---------------------------------------------------------------------------
#
# Per `_SharedConn`/`_PerConn` pair (conn/bench_parallel_test.go), at one pinned
# core count N:
#
#   gated:   ns_Shared(N)                 — one connection, N goroutines
#   context: ns_Per(N)                    — N connections, N goroutines
#   guard:   penalty = Shared(N)/Per(N)   — how much the connection serialises
#
# The verdict is on ns_Shared(N). The control is NOT a divisor. That was the
# first design and the measurement rejected it, twice over:
#
#   * ns_Per(N) is a throughput number that falls as ~1/N, so it is tiny — ~9 ns
#     against the shared arm's ~110 ns on the reference host. Adding ONE
#     uncontended mutex acquisition to the write path moves it ~+140% and moves
#     the shared arm ~+4%, so Shared/Per would report a large IMPROVEMENT for a
#     change that added a lock. A gate that goes green on the regression it is
#     named after is worse than no gate.
#   * Measured rather than argued: over interleaved identical-code passes on the
#     reference host, the worst drift of the ratio Shared(N)/Per(N) was 23.4% on
#     the DATA pair against 8.4% for ns_Shared(N) alone, and the variants
#     normalising by the -cpu=1 arm were worse still (up to 92.7%), because the
#     single-goroutine measurement is the noisiest number in the set. Every ratio
#     considered was LOUDER than the raw number it was supposed to stabilise.
#
# So the control earns its place as a guard and as context, not as a divisor:
#
#   * guard — if Shared(N) is not at least CONTENTION_MIN_PENALTY times Per(N),
#     this machine is not serialising enough for a lock to show, and the pair is
#     reported NOT MEASURABLE rather than judged.
#   * context — the report prints the control's numbers beside the verdict, and
#     stops there. It does not classify the regression as "contention" or "work".
#     That classifier was written and then removed: two injected connection-wide
#     locks — an exclusive peer-settings read on the DATA path, and a second
#     mutex wrapped around the whole HEADERS write — moved the shared arm by
#     nothing measurable (+7.6% within noise, and −4.6% respectively). The write
#     path is already ~100% serialised on wmu, so a second lock takes away no
#     parallelism that wmu has not already taken. Read the pair of numbers: the
#     control at -cpu=N is a throughput figure and therefore a hypersensitive
#     detector of added WORK, so a control that moved with the shared arm points
#     at the work rather than the lock.
#
# What that means for what this gate can catch, stated rather than implied: on
# today's code the detectable regression is "the serialised section got longer".
# That is the operative regression for a connection-wide write mutex — the
# critical section IS the connection's throughput ceiling — but it is not a
# separate phenomenon from latency, and this gate does not pretend it is.
#
# The pairs are HEADERS and DATA. RegisterStream_{Shared,Per}Conn is deliberately
# excluded: its control allocates 816 B/op and is allocator-bound, and across
# identical-code passes on the reference host its control's median swung 175 ns
# to 672 ns — the penalty ratio crossed the guard threshold in both directions on
# the same code, so including it would add a pair whose verdict is a coin flip.
# The _TCP variants are excluded for the reason #197 measured: at ~10.5 us/op the
# write(2) dominates, and two rounds of the same injected slowdown disagreed in
# sign.
#
# ---------------------------------------------------------------------------
# Why it needs two arms and refuses to invent one
# ---------------------------------------------------------------------------
#
# There is no "no baseline found, recorded one, PASS" branch, on purpose.
# `bench-gate` has one, and with testdata/benchmarks/ absent from the repository
# it is the branch that always runs — which is why `make bench-gate` has never
# compared anything (#101, #103, #177). A gate that cannot fail reports success,
# which is worse than reporting nothing. When this script cannot obtain two arms
# it exits non-zero with a reason.
#
# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------
#
#   0  PASS            — every measurable pair within the limit
#   1  FAIL            — a pair's shared-connection number regressed past it
#   2  ERROR           — could not build an arm, run a benchmark, or read output
#   3  ERROR           — no pair was compared at all (nothing parsed)
#   4  NOT MEASURABLE  — no pair showed enough serialisation for a verdict
#
# 4 is deliberately not 0. On a machine where one connection is no slower than N
# connections, this gate observes nothing, and the honest report of "I measured
# nothing" is not a pass. The fix is a runner that can resolve it, or deleting
# the job — not a lower CONTENTION_MIN_PENALTY, which only buys back a green.
set -euo pipefail

GO="${GO:-go}"
BASE_REF="${CONTENTION_BASE_REF:-origin/main}"
THRESHOLD="${CONTENTION_THRESHOLD:-30}"
MIN_PENALTY="${CONTENTION_MIN_PENALTY:-2.0}"
ROUNDS="${CONTENTION_ROUNDS:-5}"
BENCHTIME="${CONTENTION_BENCHTIME:-300ms}"
COUNT="${CONTENTION_COUNT:-5}"

detect_cpu() {
  if [ -n "${CONTENTION_CPU:-}" ]; then echo "$CONTENTION_CPU"; return; fi
  if command -v nproc >/dev/null 2>&1; then nproc; return; fi
  "$GO" env GOMAXPROCS 2>/dev/null || echo 4
}
CPU="$(detect_cpu)"

if ! [ "$CPU" -ge 2 ] 2>/dev/null; then
  echo "contention-gate: NOT MEASURABLE — this machine reports '$CPU' CPU." >&2
  echo "contention-gate: a connection-wide lock costs nothing when nothing runs beside it." >&2
  exit 4
fi

OUT="${CONTENTION_OUT:-$(mktemp -d 2>/dev/null || echo ./contention-gate-out)}"
mkdir -p "$OUT"

BENCH_RE='^BenchmarkParallelWrite(Headers|Data)_(Shared|Per)Conn$'
PAIRS="WriteHeaders WriteData"

run_arm() { # run_arm <binary> <outfile>
  "$1" -test.run='^$' -test.bench="$BENCH_RE" \
       -test.benchtime="$BENCHTIME" -test.count="$COUNT" -test.cpu="$CPU" >>"$2" 2>&1
}

baseline="$OUT/baseline.txt"
current="$OUT/current.txt"

if [ -n "${CONTENTION_BASELINE:-}" ] || [ -n "${CONTENTION_CURRENT:-}" ]; then
  # Recorded-arm mode: the hook that makes this gate testable on known inputs,
  # and what scripts/contention-gate-selftest.sh drives. Both must be given —
  # comparing a recorded arm against a freshly measured one would compare two
  # machines, which is the error the whole script exists to avoid.
  if [ -z "${CONTENTION_BASELINE:-}" ] || [ -z "${CONTENTION_CURRENT:-}" ]; then
    echo "contention-gate: ERROR — set BOTH CONTENTION_BASELINE and CONTENTION_CURRENT, or neither." >&2
    exit 2
  fi
  echo "contention-gate: comparing recorded arms (no benchmarks run)."
  cp "$CONTENTION_BASELINE" "$baseline"
  cp "$CONTENTION_CURRENT" "$current"
else
  echo "contention-gate: baseline arm = $BASE_REF, current arm = working tree"
  echo "contention-gate: -cpu=$CPU  -benchtime=$BENCHTIME  -count=$COUNT  rounds=$ROUNDS"

  # The baseline tree comes from `git archive`, not `git worktree add`: archiving
  # is read-only on .git, so a repository that already has linked worktrees
  # checked out (this project keeps them under .claude/worktrees/) is untouched.
  basetree="$OUT/basetree"
  mkdir -p "$basetree"
  if ! git rev-parse --verify --quiet "$BASE_REF^{commit}" >/dev/null; then
    echo "contention-gate: ERROR — baseline ref '$BASE_REF' does not resolve." >&2
    echo "contention-gate: fetch it first (a shallow clone has no history), or set CONTENTION_BASE_REF." >&2
    exit 2
  fi
  if ! git archive --format=tar "$BASE_REF" | tar -x -C "$basetree"; then
    echo "contention-gate: ERROR — could not export '$BASE_REF' into $basetree." >&2
    exit 2
  fi

  # One binary per arm, compiled once and reused for every round, so a round is a
  # re-measurement and never a re-compilation (#197's method).
  ext=""; case "$(uname -s 2>/dev/null || echo unknown)" in MINGW*|MSYS*|CYGWIN*) ext=".exe";; esac
  binbase="$OUT/base.test$ext"
  bincur="$OUT/cur.test$ext"
  if ! ( cd "$basetree" && "$GO" test -c -o "$binbase" ./conn ) >"$OUT/build-base.log" 2>&1; then
    echo "contention-gate: ERROR — could not build the baseline arm from '$BASE_REF':" >&2
    cat "$OUT/build-base.log" >&2
    exit 2
  fi
  if ! "$GO" test -c -o "$bincur" ./conn >"$OUT/build-cur.log" 2>&1; then
    echo "contention-gate: ERROR — could not build the current arm from the working tree:" >&2
    cat "$OUT/build-cur.log" >&2
    exit 2
  fi

  # Interleaved, so a machine that drifts during the run drifts through both arms
  # rather than into one of them.
  #
  # CONTENTION_ROUNDS defaults to 5 because rounds, not the threshold, are what
  # buy this gate its sensitivity. Measured by resampling 20 interleaved
  # identical-code passes on the reference host (250 draws per configuration,
  # the machine deliberately busy):
  #
  #   rounds   worst identical-code delta   false reds at +30%
  #   3        +39.9%                       6/250  (2.4%)
  #   5        +27.1%                       0/250
  #   8        +24.0%                       0/250
  #
  # Three rounds would need +40% to reach 0/250, which is most of what
  # `bench-gate` already tolerates. Five costs about a minute more and lets the
  # limit sit at +30%.
  # The order ALTERNATES between rounds so that neither arm always gets the same
  # slot. This is a precaution, NOT a measured correction — said explicitly
  # because it was briefly claimed as one. Two runs that looked like a +22.69%
  # and +12.84% position effect on "identical" code turned out to be a real
  # change: origin/main had moved to #200 mid-session, and the DATA pair really
  # was ~20% faster there. With a baseline pinned to identical source the fixed
  # order showed +0.10% and -3.25%, i.e. no position effect this host can see.
  # Alternation costs nothing and is kept; no number is claimed for it.
  #
  # With an odd CONTENTION_ROUNDS the split is 3:2, not even. Left odd because 5
  # is the round count whose false-red rate was actually measured.
  : >"$baseline"; : >"$current"
  for r in $(seq 1 "$ROUNDS"); do
    if [ $((r % 2)) -eq 1 ]; then
      echo "contention-gate: round $r/$ROUNDS (baseline first)"
      first_bin="$binbase"; first_out="$baseline"; first_name="baseline"
      second_bin="$bincur"; second_out="$current"; second_name="current"
    else
      echo "contention-gate: round $r/$ROUNDS (current first)"
      first_bin="$bincur"; first_out="$current"; first_name="current"
      second_bin="$binbase"; second_out="$baseline"; second_name="baseline"
    fi
    if ! run_arm "$first_bin" "$first_out"; then
      echo "contention-gate: ERROR — $first_name arm failed in round $r; see $first_out" >&2
      exit 2
    fi
    if ! run_arm "$second_bin" "$second_out"; then
      echo "contention-gate: ERROR — $second_name arm failed in round $r; see $second_out" >&2
      exit 2
    fi
  done
fi

# A benchmark that panicked or hit b.Fatal still writes ns/op lines for whatever
# ran before it. Refuse those outputs rather than average them in. (This is the
# postcondition benchParAssertWrites reports through: a benchmark that stopped
# reaching the write path fails, and a failed arm must not be scored.)
for f in "$baseline" "$current"; do
  if grep -Eq '^(--- FAIL|FAIL|panic:|fatal error:)' "$f"; then
    echo "contention-gate: ERROR — a benchmark failed in $f:" >&2
    grep -E '^(--- FAIL|FAIL|panic:|fatal error:)' "$f" >&2
    exit 2
  fi
done

report="$OUT/contention-gate-report.txt"
findings="$OUT/contention-gate-findings.txt"
: >"$findings"
gate_rc=0

# The whole judgement, on medians of both arms, written as one awk program so the
# arithmetic sits next to the rule it feeds.
awk -v hi="$CPU" -v thr="$THRESHOLD" -v minp="$MIN_PENALTY" \
    -v pairs="$PAIRS" -v findings="$findings" '
  function med(arm, name,   key, c, i, j, x, a) {
    key = arm SUBSEP name
    c = n[key]
    if (c == 0) return ""
    for (i = 1; i <= c; i++) a[i] = v[key, i]
    for (i = 2; i <= c; i++) { x = a[i]; j = i - 1
      while (j >= 1 && a[j] > x) { a[j + 1] = a[j]; j-- }
      a[j + 1] = x }
    return (c % 2) ? a[(c + 1) / 2] : (a[c / 2] + a[c / 2 + 1]) / 2
  }
  FNR == 1 { arm = (armseen++ == 0) ? "base" : "cur" }
  /^Benchmark/ {
    name = $1; cpu = 1
    if (match(name, /-[0-9]+$/)) { cpu = substr(name, RSTART + 1) + 0; name = substr(name, 1, RSTART - 1) }
    if (cpu != hi + 0) next          # only the contended core count is scored
    val = ""
    for (i = 3; i <= NF; i++) if ($i == "ns/op") { val = $(i - 1) + 0; break }
    if (val == "") next
    key = arm SUBSEP name
    v[key, ++n[key]] = val
  }
  END {
    np = split(pairs, P, " ")
    printf "%-14s %10s %10s %8s %10s %10s %8s %9s %8s\n", \
           "PAIR", "base_ns", "cur_ns", "delta%", "ctrl_base", "ctrl_cur", "ctrl%", "penalty", "verdict"
    for (p = 1; p <= np; p++) {
      pr = P[p]
      S = "BenchmarkParallel" pr "_SharedConn"
      C = "BenchmarkParallel" pr "_PerConn"
      bS = med("base", S); bC = med("base", C)
      cS = med("cur",  S); cC = med("cur",  C)
      if (bS == "" || bC == "" || cS == "" || cC == "") {
        printf "  note: %s — missing samples in one arm at -cpu=%d, not compared\n", pr, hi > "/dev/stderr"
        continue
      }
      seen++
      d  = (cS / bS - 1) * 100
      dc = (cC / bC - 1) * 100
      bp = bS / bC; cp = cS / cC
      pen = (bp < cp) ? bp : cp
      if (pen < minp + 0) {
        printf "%-14s %10.4g %10.4g %+8.2f %10.4g %10.4g %+8.2f %9.2f %8s\n", pr, bS, cS, d, bC, cC, dc, pen, "SKIP"
        printf "  note: %s — one connection is only %.2fx an uncontended one; below %.2f there is no contention to regress\n", \
               pr, pen, minp + 0 > "/dev/stderr"
        continue
      }
      judged++
      bad = (d > thr + 0)
      printf "%-14s %10.4g %10.4g %+8.2f %10.4g %10.4g %+8.2f %9.2f %8s\n", pr, bS, cS, d, bC, cC, dc, pen, (bad ? "FAIL" : "ok")
      if (bad) {
        # Both deltas, no verdict on WHICH kind of regression it is. The obvious
        # rule — "the control did not share it, so it is the lock" — was not
        # shipped because it could not be exercised: two injected connection-wide
        # locks (an exclusive peer-settings read on the DATA path, and a second
        # mutex wrapping the whole HEADERS write) produced NO measurable
        # regression on the shared arm at all, one of them measuring faster than
        # the clean build. The write path is already ~100% serialised on wmu, so
        # there is no parallelism left for another lock to take away. A classifier
        # whose "contention" branch has never fired on a real regression is a
        # guess with a confident voice; the numbers are printed instead.
        printf "  %-14s shared %.4g -> %.4g ns (%+.2f%%, limit +%g%%); uncontended control %.4g -> %.4g ns (%+.2f%%)\n", \
               pr, bS, cS, d, thr + 0, bC, cC, dc > findings
      }
    }
    if (seen + 0 == 0) exit 3
    if (judged + 0 == 0) exit 4
  }
' "$baseline" "$current" >"$report" || gate_rc=$?

cat "$report"

if [ "$gate_rc" -eq 3 ]; then
  echo "contention-gate: ERROR — no pair had samples in both arms. Nothing was compared." >&2
  exit 3
elif [ "$gate_rc" -eq 4 ]; then
  echo "contention-gate: NOT MEASURABLE — no pair reached a ${MIN_PENALTY}x shared/uncontended ratio." >&2
  echo "contention-gate: this machine does not serialise enough for a connection-wide lock to show." >&2
  exit 4
elif [ "$gate_rc" -ne 0 ]; then
  echo "contention-gate: ERROR — could not evaluate the measurement (awk exit $gate_rc)." >&2
  exit 2
fi

if [ -s "$findings" ]; then
  echo "contention-gate: FAIL — the shared connection regressed beyond +${THRESHOLD}%:" >&2
  cat "$findings" >&2
  echo "contention-gate: raw output in $OUT" >&2
  exit 1
fi

echo "contention-gate: PASS — no pair's shared connection regressed beyond +${THRESHOLD}%."
echo "contention-gate: raw output in $OUT"
