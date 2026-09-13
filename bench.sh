#!/bin/sh
# bench.sh - Run the B[e]SH benchmark fixtures and report repeatable timings.
#
#   ./bench.sh                  build, then run every fixture in bench/
#   ./bench.sh kernel           run only fixtures whose name matches "kernel"
#   ./bench.sh --repeat 7       take the best of 7 runs instead of 3
#   ./bench.sh --mode off       time the interpreter only (off|auto|both)
#   ./bench.sh --no-build       skip the build step
#   ./bench.sh --list           list the fixtures without running them
#
# Each fixture is a BSH script in bench/ that prints "BENCH-OK <name> <value>".
# The value is a checksum of the work done: a fixture whose checksum changes
# between modes has found a behaviour difference, and a fixture that prints no
# result at all is reported as an error rather than as a fast run.
#
# Every fixture runs with an isolated HOME and an explicit BSH_MODULE_PATH, the
# same as test.sh, so a developer's own ~/.bshrc cannot move the numbers.
#
# Reported per fixture and mode:
#   best   the fastest of N runs - the least noisy estimate of the real cost
#   med    the median of N runs
#   net    best, minus the best time of bench/startup.bsh, so that process
#          start and framework registration are not counted in every row
# and, when both modes ran, the speedup of "auto" over "off" on the net figure.

set -u

REPO_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$REPO_DIR" || exit 1

# The benchmark binary is deliberately not the root ./bsh: compile.sh and
# test.sh build that one with -g and no optimisation, and overwriting it here
# would silently change what the next test run measured.
BSH_BIN="$REPO_DIR/.bench-bsh"
BENCH_HOME="$REPO_DIR/.bench-home"

DO_BUILD=1
LIST_ONLY=0
REPEAT=3
MODES="off auto"
FILTER=""

while [ $# -gt 0 ]; do
    case "$1" in
        --no-build) DO_BUILD=0 ;;
        --list) LIST_ONLY=1; DO_BUILD=0 ;;
        --repeat)
            shift
            [ $# -gt 0 ] || { printf 'bench.sh: --repeat needs a count\n'; exit 1; }
            REPEAT="$1"
            ;;
        --mode)
            shift
            [ $# -gt 0 ] || { printf 'bench.sh: --mode needs off|auto|both\n'; exit 1; }
            case "$1" in
                off) MODES="off" ;;
                auto) MODES="auto" ;;
                both) MODES="off auto" ;;
                *) printf 'bench.sh: unknown mode "%s"\n' "$1"; exit 1 ;;
            esac
            ;;
        -h|--help)
            sed -n '2,27p' "$0"
            exit 0
            ;;
        *) FILTER="$1" ;;
    esac
    shift
done

case "$REPEAT" in
    ''|*[!0-9]*) printf 'bench.sh: --repeat must be a positive integer\n'; exit 1 ;;
    0) printf 'bench.sh: --repeat must be at least 1\n'; exit 1 ;;
esac

# --- Build ---------------------------------------------------------------
#
# Benchmarks are built without -g: debug symbols are what compile.sh and
# test.sh want, but they are not what anyone should be timing.

SRC_DIR="$REPO_DIR/src"
FAYASM_SRC="$REPO_DIR/thirds/fayasm/src"

if [ "$DO_BUILD" -eq 1 ]; then
    printf '== build (optimised, -O2)\n'
    if [ ! -f "$FAYASM_SRC/fa_runtime.c" ]; then
        printf '   BUILD FAILED: %s is missing; run "git submodule update --init --recursive"\n' "$FAYASM_SRC"
        exit 1
    fi
    : > /tmp/bsh_bench_build.txt
    rm -rf "$REPO_DIR/.build-bench"
    mkdir -p "$REPO_DIR/.build-bench"
    fayasm_objects=""
    for source in "$FAYASM_SRC"/*.c; do
        object="$REPO_DIR/.build-bench/$(basename "$source" .c).o"
        if ! cc -O2 -fno-common -I"$FAYASM_SRC" -c "$source" -o "$object" 2>> /tmp/bsh_bench_build.txt; then
            printf '   BUILD FAILED (fayasm)\n'
            cat /tmp/bsh_bench_build.txt
            exit 1
        fi
        fayasm_objects="$fayasm_objects $object"
    done
    # shellcheck disable=SC2086
    if ! cc -O2 -fno-common -I"$SRC_DIR" -I"$FAYASM_SRC" \
            "$SRC_DIR"/bsh.c "$SRC_DIR"/besh_mem.c "$SRC_DIR"/besh_wasm.c "$SRC_DIR"/besh_jit.c $fayasm_objects \
            -o "$BSH_BIN" 2>> /tmp/bsh_bench_build.txt; then
        printf '   BUILD FAILED\n'
        cat /tmp/bsh_bench_build.txt
        exit 1
    fi
    printf '   built %s\n\n' "$BSH_BIN"
fi

if [ "$LIST_ONLY" -eq 0 ] && [ ! -x "$BSH_BIN" ]; then
    printf 'bench.sh: %s is missing; run without --no-build\n' "$BSH_BIN"
    exit 1
fi

# --- Environment ---------------------------------------------------------

rm -rf "$BENCH_HOME"
mkdir -p "$BENCH_HOME"
export HOME="$BENCH_HOME"
export BSH_MODULE_PATH="$REPO_DIR/framework:$REPO_DIR"

now() { perl -MTime::HiRes=time -e 'printf "%.6f", time'; }

# best_of <mode> <fixture> -> prints "<best> <median> <checksum>", or nothing on
# failure. Timing is wall clock around the whole process, which is the number a
# user actually waits for.
run_fixture() {
    _mode="$1"
    _fixture="$2"
    _times=""
    _checksum=""
    _n=0
    while [ "$_n" -lt "$REPEAT" ]; do
        _start=$(now)
        _out=$(BSH_COMPILE="$_mode" "$BSH_BIN" "$_fixture" 2>&1)
        _status=$?
        _end=$(now)
        if [ "$_status" -ne 0 ]; then
            printf 'ERROR exit %s\n' "$_status"
            return 1
        fi
        _line=$(printf '%s\n' "$_out" | grep '^BENCH-OK ' | head -1)
        if [ -z "$_line" ]; then
            printf 'ERROR no BENCH-OK line\n'
            return 1
        fi
        _this_checksum=$(printf '%s' "$_line" | awk '{print $3}')
        if [ -z "$_checksum" ]; then
            _checksum="$_this_checksum"
        elif [ "$_checksum" != "$_this_checksum" ]; then
            printf 'ERROR checksum changed between runs (%s vs %s)\n' "$_checksum" "$_this_checksum"
            return 1
        fi
        _times="$_times $(echo "$_end $_start" | awk '{printf "%.6f", $1 - $2}')"
        _n=$((_n + 1))
    done
    printf '%s' "$_times" | tr ' ' '\n' | grep -v '^$' | sort -n | awk -v cs="$_checksum" '
        { v[NR] = $1 }
        END {
            best = v[1]
            med = (NR % 2) ? v[int(NR/2) + 1] : (v[NR/2] + v[NR/2 + 1]) / 2
            printf "%.3f %.3f %s", best, med, cs
        }'
}

# --- Run -----------------------------------------------------------------

fixtures=$(find bench -maxdepth 1 -name '*.bsh' | sort)

if [ "$LIST_ONLY" -eq 1 ]; then
    for fixture in $fixtures; do
        name=$(basename "$fixture" .bsh)
        case "$FILTER" in
            "") printf '%s\n' "$name" ;;
            *) case "$name" in *"$FILTER"*) printf '%s\n' "$name" ;; esac ;;
        esac
    done
    exit 0
fi

# The startup fixture is the baseline every other row is corrected against, so
# it is measured first and always, whatever the filter says.
printf '== baseline\n'
startup_off=$(run_fixture off bench/startup.bsh)
case "$startup_off" in
    ERROR*) printf '   startup baseline failed: %s\n' "$startup_off"; exit 1 ;;
esac
STARTUP_BEST=$(printf '%s' "$startup_off" | awk '{print $1}')
printf '   startup + .bshrc: %ss (best of %s)\n\n' "$STARTUP_BEST" "$REPEAT"

printf '== fixtures (best of %s)\n\n' "$REPEAT"
printf '%-16s %-6s %8s %8s %8s  %s\n' fixture mode best med net checksum
printf '%-16s %-6s %8s %8s %8s  %s\n' ---------------- ------ -------- -------- -------- --------

errors=0
for fixture in $fixtures; do
    name=$(basename "$fixture" .bsh)
    if [ -n "$FILTER" ]; then
        case "$name" in
            *"$FILTER"*) ;;
            *) continue ;;
        esac
    fi

    net_off=""
    net_auto=""
    for mode in $MODES; do
        result=$(run_fixture "$mode" "$fixture")
        case "$result" in
            ERROR*)
                printf '%-16s %-6s %s\n' "$name" "$mode" "$result"
                errors=$((errors + 1))
                continue
                ;;
        esac
        best=$(printf '%s' "$result" | awk '{print $1}')
        med=$(printf '%s' "$result" | awk '{print $2}')
        checksum=$(printf '%s' "$result" | awk '{print $3}')
        net=$(echo "$best $STARTUP_BEST" | awk '{ d = $1 - $2; if (d < 0) d = 0; printf "%.3f", d }')
        printf '%-16s %-6s %8s %8s %8s  %s\n' "$name" "$mode" "$best" "$med" "$net" "$checksum"
        case "$mode" in
            off) net_off="$net"; checksum_off="$checksum" ;;
            auto) net_auto="$net"; checksum_auto="$checksum" ;;
        esac
    done

    if [ -n "$net_off" ] && [ -n "$net_auto" ]; then
        if [ "$checksum_off" != "$checksum_auto" ]; then
            printf '%-16s %-6s %s\n' "" "DIFF" \
                "interpreted and compiled results disagree: $checksum_off vs $checksum_auto"
            errors=$((errors + 1))
        fi
        echo "$net_off $net_auto" | awk -v n="$name" '
            {
                if ($2 <= 0.0005) { printf "%-16s %-6s %s\n", "", "ratio", "too fast to compare"; next }
                r = $1 / $2
                if (r >= 1.05)      verdict = "compiled faster"
                else if (r <= 0.95) verdict = "compiled SLOWER"
                else                verdict = "parity"
                printf "%-16s %-6s %.2fx  %s\n", "", "ratio", r, verdict
            }'
    fi
    printf '\n'
done

if [ "$errors" -ne 0 ]; then
    printf '== %s fixture error(s)\n' "$errors"
    exit 1
fi
exit 0
