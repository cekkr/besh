#!/usr/bin/env bash
# Run with either:
#   ./bsh examples/bash/cdiesis_objects.sh
#   bash examples/bash/cdiesis_objects.sh

set -e

example_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd "$example_dir/../.." && pwd)
source "$repo_dir/framework/bash/cdiesis.sh"
trap cdiesis_close EXIT

# Import cDiesis source, construct an object, invoke a method, then read and
# write its public field through Bash functions and variables.
cdiesis_import "$example_dir/counter.cds"
cdiesis_new counter Counter 10
cdiesis_call after_add "$counter" Add 5
cdiesis_get property_value "$counter" Value
cdiesis_set "$counter" Value 40
cdiesis_call after_set "$counter" Read

printf 'object=%s\n' "$counter"
printf 'after Add(5)=%s\n' "$after_add"
printf 'Value property=%s\n' "$property_value"
printf 'after property set=%s\n' "$after_set"
