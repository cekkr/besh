#!/bin/sh
# compile.sh - canonical debug build of B[e]SH.
#
# The shell links the pinned Fayasm runtime directly from thirds/fayasm/src,
# so the submodule must be materialised first:
#
#     git submodule update --init --recursive
#
# -g keeps the result debuggable.

set -e

REPO_DIR=$(cd "$(dirname "$0")" && pwd)
SRC_DIR="$REPO_DIR/src"
FAYASM_SRC="$REPO_DIR/thirds/fayasm/src"

if [ ! -f "$FAYASM_SRC/fa_runtime.c" ]; then
    printf 'compile.sh: %s is missing; run "git submodule update --init --recursive"\n' "$FAYASM_SRC" >&2
    exit 1
fi

gcc -fno-common -g -I"$SRC_DIR" -I"$FAYASM_SRC" \
    "$SRC_DIR/bsh.c" "$SRC_DIR/besh_mem.c" "$SRC_DIR/besh_wasm.c" "$SRC_DIR/besh_jit.c" "$SRC_DIR/besh_hu.c" \
    "$FAYASM_SRC"/*.c \
    -o "$REPO_DIR/bsh"

# ./bsh
# ./bsh script.bsh
