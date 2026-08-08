# The B[e]SH bytecode path

B[e]SH executes BSH function bodies in one of two ways. The line-oriented
interpreter in [`bsh.c`](../bsh.c) is the reference implementation and always
available. The bytecode path parses a function body once, lowers it to a
WebAssembly module, and executes that module with the pinned
[Fayasm](../thirds/fayasm/) runtime linked into the same process.

Only function bodies are compiled. File-scope statements, the interactive
prompt, imports and startup scripts always run through `process_line`.

This document is the contract. It describes behaviour that is implemented and
covered by [`tests/bytecode_differential.bsh`](../tests/bytecode_differential.bsh),
[`tests/mem_heap.bsh`](../tests/mem_heap.bsh) and
[`tests/strlib_list.bsh`](../tests/strlib_list.bsh). Planned work is in
[`ROADMAP.md`](../ROADMAP.md) and is not described here.

## Modes

`bytecode mode <off|auto|force>` selects how much is compiled; `BSH_COMPILE`
sets the same thing from the environment before startup.

| mode | behaviour |
| --- | --- |
| `off` | interpreter only; nothing is compiled |
| `auto` | compile what can be compiled, interpret the rest (default) |
| `force` | same as `auto`, but report on stderr every function that would not compile |

`force` does not refuse to run anything — it makes the fallbacks visible.

Changing the mode discards every cached module, so a mode switch at file scope
is a clean boundary. Do not change the mode from inside a function: a module
that is currently executing cannot be freed, and the change will be ignored.

## Introspection

```
bytecode status                  # mode, call counts, fallbacks, heap size
bytecode info <function>         # print the tier, module size, promoted locals
bytecode info <function> <var>   # write the tier into <var> instead
bytecode dump <function>         # hex dump of the emitted module
bytecode invalidate [<function>] # drop cached modules
```

`bytecode info` compiles the function if it has not been compiled yet, so it is
the way to check a tier without calling anything.

## Tiers

Compilation produces one of two shapes from the same IR.

**Kernel.** Every statement lowered to native WebAssembly. The function's plain
`$name` variables become WebAssembly locals holding unboxed 32-bit integers,
and the body runs with no host call at all. A function reaches this tier when
every one of its statements is:

- an assignment of an integer literal or another promoted local;
- `prim` with one of the integer operations `iadd isub imul idiv imod iand ior
  ixor ishl ishr ieq ine ilt igt ile ige inot`, all operands native, result in a
  promoted local;
- `mem peek`/`peek16`/`peek32` or `mem poke`/`poke16`/`poke32` with native
  operands;
- `if <value>` or `while <value>` on a promoted local or integer literal;
- `return` of a native value, or with no value.

A comparison condition (`while $i < $n`) is deliberately *not* native: the
interpreter decides those in C with its own numeric-or-string rules, and
reproducing them on unboxed integers would change behaviour for values that are
not integers. Write `prim ilt "$i" "$n" go` and `while $go` when a loop should
stay on the kernel tier.

**General.** Everything else. Control flow is still real WebAssembly — `if`,
`block`/`loop`/`br_if` — and each statement is lowered once instead of being
re-tokenised on every execution, but values live in shell variables and are
reached through host imports.

A function is refused entirely, and interpreted, only when a statement would
open a block the compiler does not own.

## Values

Everything on the WebAssembly stack in the general tier is a 32-bit handle:

| low bits | meaning |
| --- | --- |
| `xxxx1` | small signed integer, value is `(int32_t)h >> 1` |
| `xxx10` | index into the permanent table (compile-time constants) |
| `xxx00` | index into the temporary table (per-invocation values) |

Handle `0` is the empty string. The temporary table is released back to a mark
when a compiled call returns, so recursion cannot leak it. An integer too wide
for the inline form is interned as text rather than truncated.

Kernel locals are *not* handles: they hold raw `i32` values, and are converted
at the two edges of the function.

## The `besh.v1` host ABI

Compiled code reaches the shell through one import module, `besh.v1`. Every
function takes and returns `i32`.

| import | signature | purpose |
| --- | --- | --- |
| `get` | `(name) -> handle` | scoped variable read |
| `set` | `(name, value) -> ()` | scoped variable write |
| `getidx` | `(base, index) -> handle` | `$arr[i]` read |
| `setidx` | `(base, index, value) -> ()` | `$arr[i]` write |
| `expand` | `(template) -> handle` | full variable expansion of a string |
| `binop` | `(op, lhs, rhs) -> handle` | resolved binary operator handler |
| `unop` | `(op, operand, prefix) -> handle` | resolved unary operator handler |
| `cond` | `(op, lhs, rhs) -> i32` | the C comparison `if`/`while` use |
| `truthy` | `(value, if_semantics) -> i32` | condition truthiness |
| `push` | `(value) -> ()` | append to the argument vector |
| `call` | `(name) -> handle` | user function or external command |
| `echo` | `() -> ()` | print the argument vector |
| `prim` | `(op) -> handle` | `prim` over the argument vector |
| `mem` | `(sub) -> handle` | `mem` over the argument vector |
| `raw` | `(line) -> i32` | hand a source line to `process_line` |
| `ret` | `(value) -> ()` | set the function's return value |
| `int` | `(handle) -> i32` | unbox for the kernel prologue |
| `box` | `(i32) -> handle` | box a raw integer |
| `guard` | `() -> i32` | did a kernel prologue see a non-integer? |
| `trap` | `(message) -> ()` | report and trap |

Plus one imported linear memory, `besh.v1`/`memory`, bound to the BSH heap.

Compiled code never receives a `Variable *`, a `UserFunction *`, or any other
process-local address. Fayasm resolves an imported memory while the module is
being attached, so the binding is established before `fa_Runtime_attachModule`.

### Which built-ins are lowered, and which are handed back

Natively modelled, with their arguments compiled as expressions: assignment,
indexed assignment, `if`, `else`, `while`, `return`, `echo`, `prim`, `mem`,
calls to user functions and external commands.

Handed back to `process_line` through the `raw` import, so that their
token-level semantics are unchanged: `defkeyword`, `defoperator`, `defunc`,
`loadlib`, `calllib`, `import`, `update_cwd`, `eval`, `exit`, `libloaded`,
`writefile`, `readfile`, `process`, `bytecode`. Anything the compiler does not
recognise at all takes the same route. This is why every B[e]SH command and
every syntax form keeps working inside a compiled function.

The list of interpreter built-ins lives in `is_interpreter_builtin` in
[`besh_jit.c`](../besh_jit.c) and must stay in step with the dispatch chain in
`process_line`.

### Unwinding

Offset 0 of the shared memory is reserved and holds a non-zero word when a
callee requested `return` or `exit`. Compiled code checks it after any statement
that can re-enter the interpreter, which is three instructions rather than a
host call. `return` inside compiled code calls `ret` and then returns; the
interpreter's own epilogue in `execute_user_function` publishes
`LAST_RETURN_VALUE` exactly as before.

### Deoptimisation

The kernel prologue loads each promoted variable and converts it to an integer.
If a value would not behave as a machine integer — it is neither empty, nor
`false`, nor a plain integer — the `guard` import reports it, the compiled
function returns before running any of the body, and the interpreter runs the
whole body instead. Nothing has been written at that point, so the bail-out is
free of side effects. `bytecode status` counts these as `deopts`.

## Cache invalidation

Cached modules are dropped when:

- `defoperator` runs — operator resolution is baked into the emitted module;
- `defkeyword` runs — aliases decide which statements compile natively;
- a function is redefined — only that function's module is dropped;
- the compile mode changes;
- `bytecode invalidate` is used.

Invalidation is refused while compiled code is on the C stack, since the module
being executed cannot be freed underneath itself.

## The heap

[`besh_mem.h`](../besh_mem.h) owns one contiguous byte array that is both the
BSH heap and the WebAssembly linear memory. A pointer is a byte offset into it;
`0` is null. `BSH_HEAP_BYTES` sets the initial size (default 4 MiB); the heap
grows on demand, but never while compiled code is running — that would move the
buffer Fayasm was handed. If the heap runs out during a compiled call the
allocation fails and says so.

A block header sits 8 bytes before every payload. A *vector* is a payload whose
first 16 bytes are `len`, `cap`, `esz`, `kind`; strings (`esz` 1, NUL
terminated) and lists (`esz` 4) are the same structure.

### The `mem` built-in

`mem <subcommand> [args...] [result_var]`, following `prim`: the result variable
is a bare name, and only value-producing subcommands take one.

```
mem alloc <bytes> <var>          mem free <ptr>
mem realloc <ptr> <bytes> <var>  mem size <ptr> <var>
mem valid <ptr> <len> <var>      mem heapsize <var>
mem peek|peek16|peek32 <ptr> <var>
mem poke|poke16|poke32 <ptr> <value>
mem peekf <ptr> <var>            mem pokef <ptr> <value>
mem copy <dst> <src> <n>         mem fill <ptr> <byte> <n>
mem vec <esz> <kind> <cap> <var> mem len|cap|esz|kind|data <ptr> <var>
mem setlen <ptr> <n>             mem reserve <ptr> <cap> <var>
mem at <ptr> <i> <var>           mem put <ptr> <i> <value>
mem push <ptr> <value> <var>     mem str <text> <var>
mem cstr <ptr> <var>             mem concat <a> <b> <var>
mem dump <ptr> <n> <var>
```

`LAST_MEM_STATUS` is `0` after a successful subcommand and `1` after a failure.

## Writing library code for the kernel tier

[`framework/strlib.bsh`](../framework/strlib.bsh) and
[`framework/list.bsh`](../framework/list.bsh) are written against these rules.
The pattern is:

- take and return integers, and use `return` rather than a result-variable
  parameter — an indirect write forces the general tier;
- keep loop conditions on a flag computed with `prim ilt` and friends;
- do allocation in a separate function, so the scanning loop stays a kernel;
- assert the tier in a test, because losing it is silent.

Measured on this checkout (macOS, `cc`, single run):

| workload | interpreter | bytecode |
| --- | --- | --- |
| 200k-iteration integer loop (`prim i*`, kernel tier) | 1.38 s | 0.69 s |
| 4k × (`str_find_from` + `str_hash`) over a 70-byte string | 10.33 s | 4.11 s |
| [`tests/cdiesis_stdlib.bsh`](../tests/cdiesis_stdlib.bsh) (general tier) | 24.19 s | 24.48 s |

The general tier is currently at parity, not faster: cDiesis framework code
spends its time inside BSH operator handlers reached through `binop`, which the
compiler calls exactly as often as the interpreter does. Compiling those
handlers themselves, and reducing host-call frequency, is Phase 4/5 work.

## Debugging

`BSH_COMPILE_DEBUG=1` prints, per function, the normalised statement list, how
each statement was modelled, the parse outcome, the tier, and the reason a
module failed to load or attach.
