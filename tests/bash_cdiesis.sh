#!/usr/bin/env bash
# End-to-end Bash syntax, CLI routing and persistent cDiesis object access.

set -u

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$repo_dir/framework/bash/cdiesis.sh"
trap cdiesis_close EXIT

pass=0
fail=0

assert_eq() {
    local actual=$1 expected=$2 label=$3
    if [[ $actual == "$expected" ]]; then
        pass=$((pass + 1))
        printf '  ok   %s\n' "$label"
    else
        fail=$((fail + 1))
        printf '  FAIL %s\n       expected [%s], got [%s]\n' "$label" "$expected" "$actual"
    fi
}

printf '== Bash: CLI and cDiesis object bridge\n'

cli_output=$(
    "$repo_dir/bsh" -c 'values=(bash syntax); printf "%s-%s" "${values[0]}" "${values[1]}"'
)
assert_eq "$cli_output" "bash-syntax" "-c executes genuine Bash array syntax"

cdiesis_import "$repo_dir/examples/bash/counter.cds"
cdiesis_new counter Counter 10
[[ $counter =~ ^obj#[0-9]+$ ]] && object_shape=handle || object_shape=invalid
assert_eq "$object_shape" "handle" "constructor returns a persistent object handle"

cdiesis_call after_add "$counter" Add 5
assert_eq "$after_add" "15" "instance method receives Bash argument"

cdiesis_get before_set "$counter" Value
assert_eq "$before_set" "15" "public field is readable from Bash"

cdiesis_set "$counter" Value 40
cdiesis_get after_set "$counter" Value
assert_eq "$after_set" "40" "public field is writable from Bash"

cdiesis_call method_read "$counter" Read
assert_eq "$method_read" "40" "method observes field mutation"

cdiesis_set "$counter" Label "Bash value with spaces"
cdiesis_get label_value "$counter" Label
assert_eq "$label_value" "Bash value with spaces" "bridge preserves spaced string values"

if cdiesis_get ignored "$counter" MissingField 2>/dev/null; then
    missing_field=accepted
else
    missing_field=rejected
fi
assert_eq "$missing_field" "rejected" "undeclared fields are rejected"

printf '%s\n' "-- Bash: CLI and cDiesis object bridge: $pass passed, $fail failed"
if [[ $fail -eq 0 ]]; then
    printf 'SUITE-RESULT: PASS\n'
else
    printf 'SUITE-RESULT: FAIL\n'
fi
