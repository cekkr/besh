#!/usr/bin/env bash
# Bash-facing cDiesis object bridge.
#
# Source this library from a Bash script, then use ordinary Bash function calls:
#   cdiesis_import path/to/library.cds
#   cdiesis_new object_var ClassName constructor_arg...
#   cdiesis_call result_var "$object_var" MethodName arg...
#   cdiesis_get result_var "$object_var" FieldName
#   cdiesis_set "$object_var" FieldName value
#
# One prompt-free BSH process stays alive behind a pair of FIFOs. Consequently
# cDiesis classes, heap objects and field mutations survive every bridge call.

if [[ -n ${CDIESIS_BASH_LIBRARY_LOADED:-} ]]; then
    return 0
fi
CDIESIS_BASH_LIBRARY_LOADED=1

_cdiesis_library_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${BESH_BIN:=${_cdiesis_library_dir}/../../bsh}"

CDIESIS_BRIDGE_PID=
CDIESIS_BRIDGE_DIR=
CDIESIS_BRIDGE_SEQ=0
CDIESIS_LAST_ERROR=

_cdiesis_error() {
    CDIESIS_LAST_ERROR=$1
    printf 'cdiesis: %s\n' "$1" >&2
    return 1
}

_cdiesis_valid_identifier() {
    [[ $1 =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]
}

_cdiesis_valid_class() {
    [[ $1 =~ ^[A-Za-z_][A-Za-z0-9_.\$]*$ ]]
}

_cdiesis_valid_object() {
    [[ $1 =~ ^obj#[0-9]+$ ]]
}

_cdiesis_next_request() {
    CDIESIS_BRIDGE_SEQ=$((CDIESIS_BRIDGE_SEQ + 1))
    CDIESIS_REQUEST_FILE=${CDIESIS_BRIDGE_DIR}/request_${CDIESIS_BRIDGE_SEQ}.bsh
    CDIESIS_RESULT_FILE=${CDIESIS_BRIDGE_DIR}/result_${CDIESIS_BRIDGE_SEQ}
    CDIESIS_ERROR_FILE=${CDIESIS_BRIDGE_DIR}/error_${CDIESIS_BRIDGE_SEQ}
    CDIESIS_MARKER=__CDIESIS_BASH_DONE_${CDIESIS_BRIDGE_PID}_${CDIESIS_BRIDGE_SEQ}__
}

_cdiesis_submit() {
    printf 'import "%s"\n' "$CDIESIS_REQUEST_FILE" >&8 || {
        _cdiesis_error "cannot send request to the BSH bridge"
        return 1
    }

    local line
    while IFS= read -r line <&9; do
        if [[ $line == "$CDIESIS_MARKER" ]]; then
            return 0
        fi
    done
    _cdiesis_error "BSH bridge terminated before completing a request"
}

_cdiesis_read_result() {
    local destination=$1
    local value=
    local bridge_error=
    [[ -f $CDIESIS_RESULT_FILE ]] && value=$(<"$CDIESIS_RESULT_FILE")
    [[ -f $CDIESIS_ERROR_FILE ]] && bridge_error=$(<"$CDIESIS_ERROR_FILE")
    if [[ -n $bridge_error ]]; then
        _cdiesis_error "$bridge_error"
        return 1
    fi
    printf -v "$destination" '%s' "$value"
    CDIESIS_LAST_ERROR=
}

_cdiesis_start() {
    if [[ -n $CDIESIS_BRIDGE_PID ]] && kill -0 "$CDIESIS_BRIDGE_PID" 2>/dev/null; then
        return 0
    fi
    [[ -x $BESH_BIN ]] || {
        _cdiesis_error "B[e]SH executable not found at '$BESH_BIN'"
        return 1
    }

    CDIESIS_BRIDGE_DIR=$(mktemp -d "/tmp/besh-cdiesis.XXXXXX") || {
        _cdiesis_error "cannot create bridge directory"
        return 1
    }
    mkfifo "$CDIESIS_BRIDGE_DIR/input" "$CDIESIS_BRIDGE_DIR/output" || {
        _cdiesis_error "cannot create bridge FIFOs"
        return 1
    }

    "$BESH_BIN" --bsh-stdin \
        <"$CDIESIS_BRIDGE_DIR/input" >"$CDIESIS_BRIDGE_DIR/output" 2>&1 &
    CDIESIS_BRIDGE_PID=$!
    exec 8>"$CDIESIS_BRIDGE_DIR/input"
    exec 9<"$CDIESIS_BRIDGE_DIR/output"

    _cdiesis_next_request
    {
        printf 'import cdiesis\n'
        printf '$(CDS_STDLIB_ENABLED) = "0"\n'
        printf 'lang_load "cdiesis" __bash_cds_loaded\n'
        printf '$(CDS_TRAP) = ""\n'
        printf 'writefile "%s" __bash_cds_loaded\n' "$CDIESIS_RESULT_FILE"
        printf 'writefile "%s" CDS_TRAP\n' "$CDIESIS_ERROR_FILE"
        printf 'echo "%s"\n' "$CDIESIS_MARKER"
    } >"$CDIESIS_REQUEST_FILE"
    _cdiesis_submit || return 1

    local loaded=
    _cdiesis_read_result loaded || return 1
    [[ $loaded == 1 ]] || _cdiesis_error "cDiesis framework did not load"
}

_cdiesis_write_args() {
    local request_file=$1
    shift
    local index=0
    local value arg_file
    for value in "$@"; do
        arg_file=${CDIESIS_BRIDGE_DIR}/arg_${CDIESIS_BRIDGE_SEQ}_${index}
        printf '%s' "$value" >"$arg_file"
        printf 'readfile "%s" __cds_bash_arg_%d\n' "$arg_file" "$index" >>"$request_file"
        printf 'cds_arg_push "$__cds_bash_arg_%d"\n' "$index" >>"$request_file"
        index=$((index + 1))
    done
}

cdiesis_import() {
    [[ $# -eq 1 ]] || { _cdiesis_error "usage: cdiesis_import library.cds"; return 1; }
    [[ -f $1 ]] || { _cdiesis_error "library not found: $1"; return 1; }
    _cdiesis_start || return 1
    _cdiesis_next_request

    local source_copy=${CDIESIS_BRIDGE_DIR}/source_${CDIESIS_BRIDGE_SEQ}.cds
    cp "$1" "$source_copy" || { _cdiesis_error "cannot copy library: $1"; return 1; }
    {
        printf '$(CDS_TRAP) = ""\n'
        printf 'readfile "%s" __cds_bash_source\n' "$source_copy"
        printf 'cds_compile "bash_unit_%d" __cds_bash_source __cds_bash_result\n' "$CDIESIS_BRIDGE_SEQ"
        printf 'writefile "%s" __cds_bash_result\n' "$CDIESIS_RESULT_FILE"
        printf 'writefile "%s" CDS_TRAP\n' "$CDIESIS_ERROR_FILE"
        printf 'echo "%s"\n' "$CDIESIS_MARKER"
    } >"$CDIESIS_REQUEST_FILE"
    _cdiesis_submit || return 1

    local compiled=
    _cdiesis_read_result compiled || return 1
    [[ $compiled == 1 ]] || _cdiesis_error "cDiesis library failed to compile"
}

cdiesis_new() {
    [[ $# -ge 2 ]] || { _cdiesis_error "usage: cdiesis_new result_var ClassName [args...]"; return 1; }
    local destination=$1 class_name=$2
    shift 2
    _cdiesis_valid_identifier "$destination" || { _cdiesis_error "invalid Bash variable name: $destination"; return 1; }
    _cdiesis_valid_class "$class_name" || { _cdiesis_error "invalid cDiesis class name: $class_name"; return 1; }
    _cdiesis_start || return 1
    _cdiesis_next_request

    {
        printf '$(CDS_TRAP) = ""\n'
        printf 'cds_arg_reset\n'
    } >"$CDIESIS_REQUEST_FILE"
    _cdiesis_write_args "$CDIESIS_REQUEST_FILE" "$@"
    {
        printf 'cds_obj_new "%s" __cds_bash_result\n' "$class_name"
        printf 'writefile "%s" __cds_bash_result\n' "$CDIESIS_RESULT_FILE"
        printf 'writefile "%s" CDS_TRAP\n' "$CDIESIS_ERROR_FILE"
        printf 'echo "%s"\n' "$CDIESIS_MARKER"
    } >>"$CDIESIS_REQUEST_FILE"
    _cdiesis_submit || return 1
    _cdiesis_read_result "$destination"
}

cdiesis_call() {
    [[ $# -ge 3 ]] || { _cdiesis_error "usage: cdiesis_call result_var object MethodName [args...]"; return 1; }
    local destination=$1 object_ref=$2 method_name=$3
    shift 3
    _cdiesis_valid_identifier "$destination" || { _cdiesis_error "invalid Bash variable name: $destination"; return 1; }
    _cdiesis_valid_object "$object_ref" || { _cdiesis_error "invalid cDiesis object handle: $object_ref"; return 1; }
    _cdiesis_valid_identifier "$method_name" || { _cdiesis_error "invalid cDiesis method name: $method_name"; return 1; }
    _cdiesis_start || return 1
    _cdiesis_next_request

    {
        printf '$(CDS_TRAP) = ""\n'
        printf 'cds_arg_reset\n'
    } >"$CDIESIS_REQUEST_FILE"
    _cdiesis_write_args "$CDIESIS_REQUEST_FILE" "$@"
    {
        printf 'cds_invoke_virtual "%s" "%s" __cds_bash_result\n' "$object_ref" "$method_name"
        printf 'writefile "%s" __cds_bash_result\n' "$CDIESIS_RESULT_FILE"
        printf 'writefile "%s" CDS_TRAP\n' "$CDIESIS_ERROR_FILE"
        printf 'echo "%s"\n' "$CDIESIS_MARKER"
    } >>"$CDIESIS_REQUEST_FILE"
    _cdiesis_submit || return 1
    _cdiesis_read_result "$destination"
}

cdiesis_get() {
    [[ $# -eq 3 ]] || { _cdiesis_error "usage: cdiesis_get result_var object FieldName"; return 1; }
    local destination=$1 object_ref=$2 field_name=$3
    _cdiesis_valid_identifier "$destination" || { _cdiesis_error "invalid Bash variable name: $destination"; return 1; }
    _cdiesis_valid_object "$object_ref" || { _cdiesis_error "invalid cDiesis object handle: $object_ref"; return 1; }
    _cdiesis_valid_identifier "$field_name" || { _cdiesis_error "invalid cDiesis field name: $field_name"; return 1; }
    _cdiesis_start || return 1
    _cdiesis_next_request

    {
        printf '$(CDS_TRAP) = ""\n'
        printf 'cds_obj_class "%s" __cds_bash_class\n' "$object_ref"
        printf 'cds_class_field_type "$__cds_bash_class" "%s" __cds_bash_type\n' "$field_name"
        printf 'if $__cds_bash_type == "" {\n'
        printf '    $(CDS_TRAP) = "unknown field %s"\n' "$field_name"
        printf '} else {\n'
        printf '    cds_obj_get "%s" "%s" __cds_bash_result\n' "$object_ref" "$field_name"
        printf '}\n'
        printf 'writefile "%s" __cds_bash_result\n' "$CDIESIS_RESULT_FILE"
        printf 'writefile "%s" CDS_TRAP\n' "$CDIESIS_ERROR_FILE"
        printf 'echo "%s"\n' "$CDIESIS_MARKER"
    } >"$CDIESIS_REQUEST_FILE"
    _cdiesis_submit || return 1
    _cdiesis_read_result "$destination"
}

cdiesis_set() {
    [[ $# -eq 3 ]] || { _cdiesis_error "usage: cdiesis_set object FieldName value"; return 1; }
    local object_ref=$1 field_name=$2 value=$3
    _cdiesis_valid_object "$object_ref" || { _cdiesis_error "invalid cDiesis object handle: $object_ref"; return 1; }
    _cdiesis_valid_identifier "$field_name" || { _cdiesis_error "invalid cDiesis field name: $field_name"; return 1; }
    _cdiesis_start || return 1
    _cdiesis_next_request

    local value_file=${CDIESIS_BRIDGE_DIR}/set_${CDIESIS_BRIDGE_SEQ}
    printf '%s' "$value" >"$value_file"
    {
        printf '$(CDS_TRAP) = ""\n'
        printf 'readfile "%s" __cds_bash_value\n' "$value_file"
        printf 'cds_obj_class "%s" __cds_bash_class\n' "$object_ref"
        printf 'cds_class_field_type "$__cds_bash_class" "%s" __cds_bash_type\n' "$field_name"
        printf 'if $__cds_bash_type == "" {\n'
        printf '    $(CDS_TRAP) = "unknown field %s"\n' "$field_name"
        printf '} else {\n'
        printf '    cds_obj_set "%s" "%s" "$__cds_bash_value"\n' "$object_ref" "$field_name"
        printf '}\n'
        printf '$__cds_bash_result = "1"\n'
        printf 'writefile "%s" __cds_bash_result\n' "$CDIESIS_RESULT_FILE"
        printf 'writefile "%s" CDS_TRAP\n' "$CDIESIS_ERROR_FILE"
        printf 'echo "%s"\n' "$CDIESIS_MARKER"
    } >"$CDIESIS_REQUEST_FILE"
    _cdiesis_submit || return 1

    local ignored=
    _cdiesis_read_result ignored
}

cdiesis_close() {
    if [[ -n $CDIESIS_BRIDGE_PID ]]; then
        printf 'exit\n' >&8 2>/dev/null || true
        exec 8>&-
        exec 9<&-
        wait "$CDIESIS_BRIDGE_PID" 2>/dev/null || true
        CDIESIS_BRIDGE_PID=
    fi
    if [[ $CDIESIS_BRIDGE_DIR == /tmp/besh-cdiesis.* && -d $CDIESIS_BRIDGE_DIR ]]; then
        rm -rf "$CDIESIS_BRIDGE_DIR"
        CDIESIS_BRIDGE_DIR=
    fi
}
