#!/bin/sh
# test.sh - Build B[e]SH and run the test suite.
#
#   ./test.sh              build, then run every suite in tests/
#   ./test.sh core         run only suites whose name matches "core"
#   ./test.sh --no-build   skip the build step
#   ./test.sh --list       list the suites without running them
#
# Each suite is a BSH or Bash script in tests/ that prints "SUITE-RESULT: PASS"
# or "SUITE-RESULT: FAIL". A suite that crashes, hangs or exits early prints
# neither and is reported as a failure - silence is never treated as success.
#
# Every suite runs with an isolated HOME (so a developer's own ~/.bshrc cannot
# change the result) and an explicit BSH_MODULE_PATH.

set -u

REPO_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$REPO_DIR" || exit 1

BSH_BIN="$REPO_DIR/bsh"
TEST_HOME="$REPO_DIR/.test-home"
TIMEOUT_SECONDS=${BSH_TEST_TIMEOUT:-120}

DO_BUILD=1
LIST_ONLY=0
FILTER=""

for arg in "$@"; do
    case "$arg" in
        --no-build) DO_BUILD=0 ;;
        --list) LIST_ONLY=1 ;;
        -h|--help)
            sed -n '2,18p' "$0"
            exit 0
            ;;
        *) FILTER="$arg" ;;
    esac
done

# --- Build ---------------------------------------------------------------

if [ "$DO_BUILD" -eq 1 ]; then
    printf '== build\n'
    if ! cc -Wall -Wextra -fno-common -g bsh.c -o "$BSH_BIN" 2> /tmp/bsh_build_errors.txt; then
        printf '   BUILD FAILED\n'
        cat /tmp/bsh_build_errors.txt
        exit 1
    fi
    warning_count=$(grep -c 'warning:' /tmp/bsh_build_errors.txt || true)
    printf '   built %s (%s compiler warnings)\n' "$BSH_BIN" "$warning_count"
fi

if [ ! -x "$BSH_BIN" ]; then
    printf 'test.sh: %s is missing; run without --no-build\n' "$BSH_BIN"
    exit 1
fi

# --- Environment ---------------------------------------------------------

# An empty HOME directory: the shell falls back to the repository .bshrc, which
# is what the suites expect to be testing.
rm -rf "$TEST_HOME"
mkdir -p "$TEST_HOME"

export HOME="$TEST_HOME"
export BSH_MODULE_PATH="$REPO_DIR/framework:$REPO_DIR"

# `timeout` is not present everywhere (notably macOS), so a hung suite is
# bounded with perl's alarm instead.
run_with_timeout() {
    perl -e 'alarm shift; exec @ARGV' "$TIMEOUT_SECONDS" "$@"
}

# --- Run -----------------------------------------------------------------

suites=$(find tests -maxdepth 1 \( -name '*.bsh' -o -name '*.sh' \) | sort)

total=0
passed=0
failed=0
failed_names=""

for suite in $suites; do
    name=$(basename "$suite")
    name=${name%.bsh}
    name=${name%.sh}
    if [ -n "$FILTER" ]; then
        case "$name" in
            *"$FILTER"*) ;;
            *) continue ;;
        esac
    fi

    if [ "$LIST_ONLY" -eq 1 ]; then
        printf '%s\n' "$name"
        continue
    fi

    total=$((total + 1))
    output_file="/tmp/bsh_test_${name}.out"
    start=$(date +%s)
    run_with_timeout "$BSH_BIN" "$suite" > "$output_file" 2>&1
    status=$?
    end=$(date +%s)
    elapsed=$((end - start))

    # Suite output starts after the startup banner; show the suite's own lines.
    sed -n '/^== /,$p' "$output_file"

    if [ "$status" -eq 0 ] && \
       grep -qx 'SUITE-RESULT: PASS' "$output_file" && \
       ! grep -qx 'SUITE-RESULT: FAIL' "$output_file"; then
        passed=$((passed + 1))
        printf '   [PASS] %s (%ss)\n\n' "$name" "$elapsed"
    else
        failed=$((failed + 1))
        failed_names="$failed_names $name"
        if grep -q '^SUITE-RESULT: FAIL' "$output_file"; then
            printf '   [FAIL] %s (%ss) - assertions failed\n\n' "$name" "$elapsed"
        elif [ "$status" -ne 0 ]; then
            printf '   [FAIL] %s (%ss) - exited with status %s, full output in %s\n\n' \
                "$name" "$elapsed" "$status" "$output_file"
        else
            printf '   [FAIL] %s (%ss) - no result line (crash, hang or early exit); see %s\n\n' \
                "$name" "$elapsed" "$output_file"
        fi
    fi
done

if [ "$LIST_ONLY" -eq 1 ]; then
    exit 0
fi

printf '== summary\n'
printf '   %s suites, %s passed, %s failed\n' "$total" "$passed" "$failed"
if [ "$total" -eq 0 ]; then
    printf '   no suites matched filter: %s\n' "$FILTER"
    exit 1
fi
if [ "$failed" -ne 0 ]; then
    printf '   failing:%s\n' "$failed_names"
    exit 1
fi
exit 0
