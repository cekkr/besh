# Basic [extensible] Shell (B[e]SH)

![BeSH guy](https://github.com/cekkr/besh/blob/main/assets/eGuy.png?raw=true)

**Research exploration.** B[e]SH is a minimalist Unix-like shell whose language is
assembled at runtime rather than fixed in C. The C core owns tokenizing, scopes,
process execution and the foreign-function boundary; almost everything a user
would call "the language" — operators, arithmetic, string handling, even entire
other languages — is registered from `.bsh` scripts after startup.

It is not a replacement for a production shell. It is a place to find out how far
runtime syntax construction goes, and what it costs.

Two things grew out of that question and are now the most concrete parts of the
project: a **bytecode path** that compiles BSH function bodies to WebAssembly and
runs them on the in-process [Fayasm](thirds/fayasm/) runtime, and a **language
framework layer** in which a C#-shaped language (cDiesis), a stack language (RPN)
and real Bash are loadable, callable and unloadable at runtime.

**Status:** experimental throughout. The 12 suites in [`tests/`](tests/) pass on
the verified macOS toolchain; everything outside them should be read as scaffold.
Per-subsystem status is in [Current status](#current-status).

---

## Contents

- [Quick start](#quick-start)
- [Command line](#command-line)
- [The BSH language](#the-bsh-language)
- [Built-in commands](#built-in-commands)
- [Runtime extensibility](#runtime-extensibility)
- [The bytecode path](#the-bytecode-path)
- [The heap, pointers and the string library](#the-heap-pointers-and-the-string-library)
- [Framework modules](#framework-modules)
- [Language frameworks](#language-frameworks)
- [Bash](#bash)
- [Native extensions](#native-extensions)
- [Testing](#testing)
- [Repository layout](#repository-layout)
- [Current status](#current-status)
- [Research goals](#research-goals)

---

## Quick start

The pinned Fayasm runtime is compiled into the executable, so the submodule is a
build prerequisite.

```bash
git submodule update --init --recursive && ./compile.sh && ./test.sh
```

`compile.sh` is the canonical debug build (`gcc -g`, produces the ignored root
`bsh`). `test.sh` performs a stricter warnings-enabled build, creates an isolated
`HOME`, sets `BSH_MODULE_PATH`, bounds every suite with an alarm and requires an
explicit pass line from each.

Then:

```bash
./bsh examples/evalExample.bsh
```

```bash
./bsh
```

Startup executes `$HOME/.bshrc` when it exists and the repository [`.bshrc`](.bshrc)
otherwise. That script *is* the language definition: it aliases `function` to
`defunc`, imports the core frameworks, and registers every operator through
`defoperator`. Before it runs, `1 + 1` is not an expression.

Because `$HOME/.bshrc` wins, use an isolated `HOME` when you want to exercise the
repository startup path:

```bash
HOME=$PWD/.test-home BSH_MODULE_PATH=$PWD/framework ./bsh script.bsh
```

### Environment variables

| Variable | Effect |
| --- | --- |
| `BSH_MODULE_PATH` | Module search path. Default `./framework:~/.bsh_framework:/usr/local/share/bsh/framework`. `~` is **not** expanded — set it explicitly outside the repository. |
| `BSH_COMPILE` | `off` \| `auto` \| `force` — selects the execution path before startup (same as `bytecode mode`). |
| `BSH_COMPILE_DEBUG` | `1` prints, per function, the normalised statements, how each was modelled, the tier, and why a module failed to load. |
| `BSH_HEAP_BYTES` | Initial heap size. Default 4 MiB. |

---

## Command line

```bash
./bsh                              # interactive native BSH
./bsh program.bsh                  # native BSH script
./bsh program.sh arg1 arg2         # Bash script (delegated to installed bash)
./bsh -c 'printf "%s\n" "$1"' n v  # Bash command string
./bsh -s arg1                      # Bash source from stdin
./bsh --bash --noprofile           # explicit pass-through to bash
./bsh --bsh-stdin                  # prompt-free native BSH input (for adapters)
```

`.sh`, `-c`, `-s` and everything after `--bash` are forwarded as distinct argv
entries to the installed `bash`, which owns quoting, expansion, pipelines,
redirection, arrays, functions and exit status. `$HOME/.bshrc` is not loaded on
those paths. `--bsh-stdin` is a native BSH mode, not a Bash mode — it is what the
Bash→cDiesis bridge drives.

---

## The BSH language

Native `.bsh` is **not Bash syntax**. It has its own grammar, and its operator set
does not exist until a startup script registers it.

### Variables and expansion

Every value is a string.

```bsh
$name = "world"
$greeting = "hello $name"          # -> "hello world"
$braced = "${name}ly"              # -> "worldly"
$missing = "$never_set"            # unset expands to nothing
```

`$(expr)` is **indirection**: the inner text is expanded first, and the result is
used as a variable *name*.

```bsh
$target = "slot_a"
$($target) = "written indirectly"  # writes $slot_a
$read_back = "$($target)"          # reads $slot_a
```

This is how the result-variable convention works — see [Functions](#functions).

### Arrays

Arrays are name mangling, not a distinct storage kind. `$items[0]` is stored as
the ordinary variable `items_ARRAYIDX_0`.

```bsh
$items[0] = "first"
$items[1] = "second"
$idx = 1
echo "$items[$idx]"                # second
$items["key"] = "keyed"            # string indices work too
```

### Expressions and operators

Arithmetic, comparison and logical operators are registered by
[`framework/core_operators.bsh`](framework/core_operators.bsh) with explicit
precedence and associativity, and implemented by named BSH handler functions:

| Symbol | Form | Prec. | Handler |
| --- | --- | --- | --- |
| `.` | infix | 70 | `bsh_op_dot_handler` |
| `++` `--` | prefix / postfix | 60 | `bsh_op_prefix_increment`, … |
| `!` | prefix | 60 | `bsh_op_logical_not` |
| `*` `/` `%` | infix | 50 | `bsh_op_multiply`, … |
| `+` `-` | infix | 40 | `bsh_op_add_or_concat`, `bsh_op_subtract` |
| `==` `!=` `<` `>` `<=` `>=` | infix | 30 | `bsh_op_equals`, … |
| `&&` | infix | 20 | `bsh_op_logical_and` |
| `\|\|` | infix | 15 | `bsh_op_logical_or` |
| `?` | ternary | 5 | `bsh_op_ternary_handler` |

```bsh
$n = 3 * 4 + 2                     # 14
$t = "a" + "b"                     # "ab" — '+' picks concat for non-numbers
```

`+` is a *smart* handler: `bsh_op_add_or_concat` consults `type.bsh` and chooses
numeric addition or string concatenation. That decision is script policy, not C.

> Prefix and postfix registrations of the same symbol currently collide —
> `add_operator_definition` matches on the symbol alone, so the four `++`/`--`
> entries overwrite each other and startup prints a redefinition warning. Do not
> rely on both forms.

### Control flow

```bsh
if "1" == "1" {
    $branch = "then"
} else {
    $branch = "else"
}

if "a" == "a" { $one = "1"; $two = "2" }     # inline blocks, ';' separates

$i = 0
while $i < 5 {
    $sum = $sum + $i
    $i = $i + 1
}
```

`if` and `while` decide conditions **in C**, not through operator handlers — a
three-token comparison goes to `besh_compare_values`, anything else to the
expression evaluator. The two handlers use slightly different rules; the same C
functions back the compiled path's `cond`/`truthy` imports so both tiers agree.

### Functions

`defunc` (aliased to `function` by `.bshrc`) stores a body and a parameter list.
A call creates a lexical scope; parameters and plain assignments are local.

```bsh
function double (value result_var) {
    $doubled = $value + $value
    $($result_var) = "$doubled"
}

$out = ""
double "21" out                    # $out == "42"
```

That is the **result-variable convention**: the caller passes the *name* of the
destination and the callee writes through it. It is pervasive, and it is also a
known design concern ([`TooBad.md`](TooBad.md)) — the alternative is `return`:

```bsh
function add (a b) {
    prim iadd "$a" "$b" sum
    return $sum
}
add 20 22
echo "$LAST_RETURN_VALUE"          # 42
```

`return` is required for kernel-tier compilation; an indirect write forces the
general tier. See [Writing for the kernel tier](#writing-for-the-kernel-tier).

### Structured objects

An assignment whose value starts with `object:` or `json:` is flattened into
underscore-mangled variables plus a `<base>_BSH_STRUCT_TYPE` marker:

```bsh
$cfg = "object:[\"host\":\"localhost\",\"port\":\"8080\"]"
echo "$cfg_host"                   # localhost
```

The parser is handwritten and accepts bracketed quoted key/value pairs and nested
brackets — it is **not** general JSON, and untrusted JSON should not be fed to it.
Flattening works; `$cfg.host` dot expansion inside strings and `object:`
re-stringification on `echo` do not currently produce the documented result. Treat
this whole surface as scaffold.

---

## Built-in commands

Everything the C core dispatches directly, in `process_line`:

| Command | Form | Notes |
| --- | --- | --- |
| `echo` | `echo <args...>` | Expands and prints |
| `if` / `else` / `while` | see above | Blocks are `{ }`; loops replay by `ftell`/`fseek` |
| `defunc` | `defunc name (params) { … }` | `function` is a startup alias |
| `return` | `return [value]` | Publishes `LAST_RETURN_VALUE` |
| `defkeyword` | `defkeyword <target> <alias>` | Adds a name for an existing keyword |
| `defoperator` | `defoperator "<sym>" TYPE <t> PRECEDENCE <n> ASSOC <L\|R\|N> HANDLER "<fn>"` | Registers grammar; the handler owns semantics |
| `import` | `import <module>` or `import a.b.c` | Resolves against `BSH_MODULE_PATH`, executes in-process |
| `eval` | `eval <string>` | Re-enters `process_line` |
| `exit` | `exit [code]` | |
| `prim` | `prim <op> <args...> [result_var]` | The primitive operation set, below |
| `mem` | `mem <sub> <args...> [result_var]` | The heap; sets `LAST_MEM_STATUS` |
| `bytecode` | `bytecode <mode\|status\|info\|dump\|invalidate>` | Compiler control and introspection |
| `loadlib` | `loadlib <path.so> <alias>` | `dlopen` |
| `calllib` | `calllib <alias> <fn> [args…]` | Fixed ABI; sets `LAST_LIB_CALL_STATUS` / `LAST_LIB_CALL_OUTPUT` |
| `libloaded` | `libloaded <alias> <result_var>` | `"1"` / `"0"` |
| `writefile` | `writefile <path> <var_name>` | Sets `LAST_FILE_STATUS` |
| `readfile` | `readfile <path> <result_var>` | Sets `LAST_FILE_STATUS` |
| `process` | `process <result_var> <program> [args…]` | argv-preserving capture; sets `LAST_COMMAND_STATUS` |
| `update_cwd` | `update_cwd` | Refresh the shell's idea of cwd |

Anything else is looked up as a user function, then resolved against `PATH` and
run with `fork`/`execv`. External-command capture merges stdout and stderr into a
single fixed-size buffer, trims trailing newlines, and writes `LAST_COMMAND_STATUS`.

### `prim`

The primitive operations the core provides without any framework. The result
variable is a **bare name**, not `$name`.

| Group | Operations |
| --- | --- |
| Generic numeric | `add sub mul div mod neg abs trunc` |
| Generic compare | `eq ne lt gt le ge` |
| Integer (32-bit) | `iadd isub imul idiv imod iand ior ixor ishl ishr ieq ine ilt igt ile ige inot` |
| Logic / probes | `not truthy isint isfloat isnum` |
| String | `len charat substr indexof concat streq fieldcount field` |

```bsh
prim iadd 20 22 sum                # $sum == "42"
prim indexof "hello world" "world" at
```

The `i*` family is what the bytecode compiler lowers to native WebAssembly
instructions. The generic family goes through the interpreter's numeric-or-string
rules and does not.

---

## Runtime extensibility

This is the research subject, not a convenience layer.

### `defunc` — macros that become commands

A defined function is a new command name in the session. Because bodies are
replayed through the same dispatcher, functions can build control structures the
core does not have:

```bsh
function assert_equals (v1 v2 msg) {
    if $v1 != $v2 {
        echo "Assertion Failed: $msg ($v1 != $v2)"
    }
}
```

[`.bshrc`](.bshrc) itself defines `for_loop` this way — a numeric loop over a
command string, evaluated once per iteration with `eval`.

### `defoperator` — new grammar

```bsh
defoperator "**" TYPE BINARY_INFIX PRECEDENCE 55 ASSOC R HANDLER "bsh_op_power"

function bsh_op_power (op lhs rhs result_var) {
    # ... compute, then write through the result holder
    $($result_var) = "$value"
}
```

The C dispatcher calls a handler with exactly `operand_count + 2` parameters:
the operator symbol, the operands, and the name of the result holder. Registration
arity and handler arity are one contract across two files — changing one without
the other is the most common way to break the shell.

Running `defoperator` or `defkeyword` invalidates **every** cached bytecode
module, because operator resolution is baked into emitted code.

### `import`

`import <name>` resolves against `BSH_MODULE_PATH` and executes the module in the
same process, mutating the live registries. Dotted names are paths:
`import tests.lib.assert` loads `tests/lib/assert.bsh`. Imported `.bsh` is trusted
code, not data.

---

## The bytecode path

A shell that assembles its own language at runtime pays for it: every call to a
BSH function re-reads and re-parses the stored source lines. B[e]SH can instead
parse a function body once, lower it to a WebAssembly module, and run that module
with the Fayasm runtime linked into the same process.

**The interpreter stays the reference implementation.** Anything the compiler
cannot model is handed straight back to `process_line`, one statement at a time,
so every command and every syntax form keeps working inside a compiled function.
Any behavioural difference between the two paths is a bug in the compiler, never a
feature — [`tests/bytecode_differential.bsh`](tests/bytecode_differential.bsh) is
the guard.

Only *function bodies* are compiled. File scope, the interactive prompt, imports
and startup scripts always interpret.

### Modes and introspection

```
bytecode mode off|auto|force     # auto is the default; force reports every fallback
bytecode status                  # mode, call counts, kernels, fallbacks, deopts, heap
bytecode info <function>         # tier, module size, promoted locals
bytecode info <function> <var>   # write the tier into <var> instead
bytecode dump <function>         # hex dump of the emitted module
bytecode invalidate [<function>] # drop cached modules
```

```
$ bytecode info addup
addup: kernel (500 module bytes, 4 promoted locals)
$ bytecode status
bytecode: mode=auto calls=1 kernels=1 fallbacks=0 refused=0 deopts=0 heap=4194304 bytes
```

`bytecode info` compiles the function if it has not been compiled yet, so it is
the way to check a tier without calling anything. Do not change the mode from
inside a function — a module that is currently executing cannot be freed, and the
change is ignored.

### Two tiers

Both come out of the same IR.

**Kernel.** Every statement lowered to native WebAssembly, plain `$name` variables
promoted to WebAssembly locals holding unboxed 32-bit integers, **no host call at
all**. A function qualifies when every statement is an integer-literal or
promoted-local assignment, a `prim i*` operation on native operands, a `mem
peek*`/`poke*` with native operands, an `if`/`while` on a promoted local or
literal, or a `return`.

**General.** Everything else. Control flow is still real WebAssembly
(`if`, `block`/`loop`/`br_if`) and each statement is lowered once instead of being
re-tokenised per execution, but values live in shell variables and are reached
through host imports.

A function is refused outright, and interpreted, only when a statement would open
a block the compiler does not own.

### Writing for the kernel tier

```bsh
defunc addup (n) {
    $i = 0
    $sum = 0
    prim ilt "$i" "$n" go
    while $go {
        prim iadd "$sum" "$i" sum
        prim iadd "$i" 1 i
        prim ilt "$i" "$n" go
    }
    return $sum
}
```

Note `while $go` rather than `while $i < $n`. A comparison condition is
deliberately *not* native: the interpreter decides those in C with its own
numeric-or-string rules, and reproducing that on unboxed integers would change
behaviour for values that are not integers. Compute the flag with `prim ilt`
instead.

The rest of the recipe: take and return integers and use `return` rather than a
result-variable parameter (an indirect write forces the general tier); do
allocation in a separate function so the scanning loop stays a kernel; and
**assert the tier in a test**, because losing it is silent and produces correct
answers. [`tests/strlib_list.bsh`](tests/strlib_list.bsh) asserts the tier of
every kernel function in the string and list libraries.

### Measured

| Workload | Interpreter | Bytecode |
| --- | --- | --- |
| 200k-iteration integer loop (`prim i*`, kernel) | 1.38 s | 0.69 s |
| 4k × (`str_find_from` + `str_hash`) over 70 bytes | 10.33 s | 4.11 s |
| `tests/cdiesis_stdlib.bsh` (general tier) | 24.19 s | 24.48 s |

The general tier is currently **at parity, not faster**: cDiesis framework code
spends its time inside BSH operator handlers reached through the `binop` import,
which the compiler calls exactly as often as the interpreter does. Do not quote
the kernel numbers for framework code.

The full contract — handle encoding, the complete `besh.v1` import table, which
built-ins are lowered and which are handed back, unwinding through the reserved
abort word, the deoptimisation guard, cache invalidation — is in
[`guides/bytecode.md`](guides/bytecode.md).

---

## The heap, pointers and the string library

Shell values are strings, which is the right default and the wrong representation
for anything that scans text. Reaching for `sed` or `cut` was a reasonable answer
when the alternative was a fork per character; it is not a reasonable answer for a
shell that can compile its own functions.

So B[e]SH has a heap. `mem` hands out real addresses, and the same bytes are the
WebAssembly linear memory — a pointer means the same thing in a script, in the C
core, and inside emitted bytecode.

```bsh
mem alloc 64 buffer
mem poke32 "$buffer" 12345
mem peek32 "$buffer" value         # $value == "12345"
mem free "$buffer"
```

Address `0` is null; the first heap word is reserved for the compiled path's abort
flag. Every accessor is bounds checked, and `LAST_MEM_STATUS` is `0` on success.
The heap grows on demand but never while compiled code is running — that would
move the buffer Fayasm was handed.

`mem` subcommands (result variable is a bare name; only value-producing
subcommands take one):

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

### `strlib` and `list`

On top of the heap sit [`framework/strlib.bsh`](framework/strlib.bsh) and
[`framework/list.bsh`](framework/list.bsh): heap strings and dynamic lists written
as ordinary BSH functions, whose scanning loops compile to the kernel tier.
Searching, comparing, hashing, case folding, splitting and joining are library
code in this repository — no external process, no C extension to build.

```bsh
import list                        # pulls in mem.bsh and strlib.bsh

str_make "Hello, World"
$s = "$LAST_RETURN_VALUE"
str_upper "$s"
str_text "$s"
echo "$LAST_RETURN_VALUE"          # HELLO, WORLD

list_new_int 4
$xs = "$LAST_RETURN_VALUE"
list_push "$xs" 10
$xs = "$LAST_RETURN_VALUE"         # push may move the list — keep the result
list_push "$xs" 32
$xs = "$LAST_RETURN_VALUE"
list_sum "$xs"
echo "$LAST_RETURN_VALUE"          # 42
```

| Library | Kernel tier | Allocating |
| --- | --- | --- |
| `strlib` | `str_len` `str_byte` `str_set_byte` `str_cmp` `str_eq` `str_find_from` `str_hash` `str_upper` `str_lower` `str_reverse` | `str_make` `str_text` `str_alloc` `str_free` `str_find` `str_contains` `str_slice` `str_copy` `str_concat` `str_trim` |
| `list` | `list_len` `list_capacity` `list_get` `list_set` `list_index_of` `list_sum` | `list_new` `list_new_int` `list_free` `list_free_deep` `list_push` `list_pop` `str_split_byte` `str_join_byte` |

A string or list is an integer address; `0` is null. Kernel functions answer
through `return`, so callers read `$LAST_RETURN_VALUE`. Blocks are never reclaimed
automatically — `mem free`, `list_free` and `list_free_deep` are manual, and
`list_free_deep` assumes every element is an owned heap block.

---

## Framework modules

Imported with `import <name>`; resolved against `BSH_MODULE_PATH`.

| Module | Loaded by `.bshrc` | Purpose |
| --- | --- | --- |
| [`core_operators.bsh`](framework/core_operators.bsh) | yes | Registers the operator table and its BSH handlers |
| [`number.bsh`](framework/number.bsh) | yes | `math_add` … `math_le`, `math_not`, `math_is_int`/`math_is_float`. Uses the native `bshmath` alias when loaded, `prim` otherwise |
| [`string.bsh`](framework/string.bsh) | yes | Operations on BSH string *values*: `string_eq`, `string_concat`, `string_len`, `string_split`, indexing |
| [`type.bsh`](framework/type.bsh) | yes | `get_type` → `INTEGER` \| `FLOAT` \| `STRING` |
| [`c_compiler.bsh`](framework/c_compiler.bsh) | yes | `def_c_lib` — opt-in runtime C compilation (see [Native extensions](#native-extensions)) |
| [`mem.bsh`](framework/mem.bsh) | no | Names for the heap layout: vector header offsets, `MEM_KIND_*`, kernel accessors |
| [`strlib.bsh`](framework/strlib.bsh) | no | Heap strings |
| [`list.bsh`](framework/list.bsh) | no | Dynamic lists over the same vector representation |
| [`lang.bsh`](framework/lang.bsh) | no | Language-framework lifecycle and cross-language calls |
| [`cdiesis.bsh`](framework/cdiesis.bsh) + [`cdiesis/`](framework/cdiesis/) | no | The cDiesis language |
| [`rpn.bsh`](framework/rpn.bsh) | no | A stack language, used as the control experiment |
| [`bash.bsh`](framework/bash.bsh) | no | Bash as a loadable language |
| [`cwd.bsh`](framework/cwd.bsh) | no | Conceptual `pwd`/`cd`/`ls` over an `fs_utils` library that does not exist |
| [`extension/inline_if.bsh`](framework/extension/inline_if.bsh) | no | `iif` — both branches arrive evaluated, not lazy |
| [`extension/property_squares.bsh`](framework/extension/property_squares.bsh) | no | Bracket-style property access over mangled variables |

Startup deliberately does **not** compile native libraries: a plain shell session
must not depend on a C compiler being installed. `number.bsh` and `string.bsh`
pick up the native path automatically once the alias is loaded.

---

## Language frameworks

[`framework/lang.bsh`](framework/lang.bsh) registers named languages, loads and
unloads them at runtime, and routes calls between them.

```bsh
lang_register <name> <version> <module> <onload> <onunload> <eval_fn> <call_fn>
lang_load <name> <result_var>          lang_unload <name> <result_var>
lang_reload <name> <result_var>        lang_state <name> <result_var>
lang_arg_reset                          lang_arg_push <value>
lang_export <name> <symbol> <target>   lang_resolve <name> <symbol> <result_var>
lang_call <name> <symbol> <result_var> lang_eval <name> <source_var> <result_var>
```

Cross-language arguments travel in the shared vector (`LANG_ARG_N` / `LANG_ARG_<i>`),
never as positional BSH parameters; BSH bridge targets answer through `LANG_RETURN`.
A call into an unloaded framework sets `LANG_LAST_ERROR` and fails rather than
falling back.

Unload is **cooperative**: the C core has no `undefkeyword`, `undefoperator` or
function removal, so a framework can only be removed to the extent its own
`on_unload` hook drops its tables. This is not enforced isolation, and it is why
cDiesis registers no keyword and no operator with the C parser.

### cDiesis

cDiesis (Italian for the sharp sign: *do diesis* = C♯) is a statically typed,
class-based language with methods, single inheritance, virtual dispatch, generics
and a small standard library — written **entirely in BSH**. None of it lives in
`bsh.c`.

It exists as the adversarial test of the compiler's founding assumption: that
B[e]SH's runtime-enlarged language bottoms out in a small primitive set rather
than an open-ended pile of special cases. cDiesis deliberately brings the
constructs that usually justify a rich runtime and shows what each one costs at
the bottom: **17 opcodes, all operands strings, one host boundary.**

```csharp
namespace Demo;
using System;

class Hello {
    public static string Greet(string who) {
        string message = "Hello, " + who + "!";
        Console.WriteLine(message);
        return message;
    }

    public static int Main() {
        Greet("B[e]SH");
        int i = 0; int total = 0;
        while (i < 10) { total = total + i; i = i + 1; }
        Console.WriteValue("sum 0..9 = ", Convert.ToString(total));
        return total;
    }
}
```

Driven from BSH:

```bsh
import cdiesis
lang_load "cdiesis" ok

readfile "examples/cdiesis/hello.cds" SRC
cds_compile "demo" SRC compiled
cds_dump_ops Hello Main            # print the primitive lowering
lang_eval "cdiesis" SRC result
lang_unload "cdiesis" done
```

Public surface: `cds_compile`, `cds_run`, `cds_call`, `cds_dump_ops`. Object
references are the string handle `obj#<id>`; instance state is
`CDS_H_<id>_F_<field>`; compiled ops are `CDS_M_<Class>_<Method>_C<i>`; literals
are interned per unit. Arithmetic and comparison are delegated to the handlers in
`core_operators.bsh`, so the two languages cannot diverge numerically.

Standard library units ([`system.cds`](framework/cdiesis/lib/system.cds),
[`text.cds`](framework/cdiesis/lib/text.cds),
[`collections.cds`](framework/cdiesis/lib/collections.cds)) are cDiesis source
compiled by the same pipeline as user code.

Design, the full opcode table and its planned WebAssembly lowering:
[`guides/cdiesis.md`](guides/cdiesis.md).

### RPN

[`framework/rpn.bsh`](framework/rpn.bsh) is a second, deliberately unlike language
— stack-based, untyped, no compiler — used as the control experiment for the
framework mechanism and as the other end of cross-language calls. Its
`@lang:symbol/N` form pops arguments in reverse order.

[`examples/cdiesis/mixed_languages.bsh`](examples/cdiesis/mixed_languages.bsh)
runs BSH ↔ cDiesis ↔ RPN with a mid-run unload.

---

## Bash

Bash compatibility is implemented by **delegating to the installed `bash`**, not by
approximating Bash in the BSH tokenizer. Bash therefore keeps its actual quoting,
expansion, pipeline, redirection, array, function and built-in rules.

```bash
./bsh -c 'values=(real bash); printf "%s %s\n" "${values[0]}" "${values[1]}"'
```
```
real bash
```

As a loadable language:

```bsh
import bash
lang_load "bash" loaded

$SOURCE = "printf alpha | tr a-z A-Z"
lang_eval "bash" SOURCE output     # ALPHA
echo "$BASH_LAST_STATUS"           # 0

bash_run "tool.sh" output "first" "second"
lang_unload "bash" unloaded
```

Each `lang_eval`/`lang_call` starts a **fresh** Bash process — variables, functions
and cwd do not persist between them. Use a `.sh` file for a stateful program.

### cDiesis objects from Bash

[`framework/bash/cdiesis.sh`](framework/bash/cdiesis.sh) is a Bash 3.2+ library
that keeps one prompt-free BSH process alive through private FIFOs, so compiled
classes and `obj#<id>` heap objects persist across Bash calls:

```bash
source framework/bash/cdiesis.sh
trap cdiesis_close EXIT

cdiesis_import examples/bash/counter.cds
cdiesis_new counter Counter 10
cdiesis_call total "$counter" Add 5     # 15
cdiesis_get current "$counter" Value    # 15
cdiesis_set "$counter" Value 40
```

Values cross through private files, not generated command text, so spaces and
newlines stay data; class/method/field names are identifier-validated. Handles are
valid only until `cdiesis_close`. The bridge is a convenience API, **not a
sandbox** — everything runs with the user's permissions.

Run the complete example either way:

```bash
./bsh examples/bash/cdiesis_objects.sh
```

Full contract: [`guides/bash.md`](guides/bash.md).

---

## Native extensions

`loadlib` and `calllib` load a shared object and call symbols through a **fixed**
ABI — this is not a general FFI, and arbitrary C signatures are unsupported:

```c
int func_name(int argc, char *argv[], char *output_buffer, int buffer_size);
```

```bsh
loadlib "/path/to/lib.so" mylib
calllib mylib my_function "arg0" "arg1"
echo "$LAST_LIB_CALL_STATUS $LAST_LIB_CALL_OUTPUT"
```

Loaded functions must honour `buffer_size`, null-terminate their output, and not
retain the caller's pointers past the call. Native libraries are fully trusted;
there is no sandbox.

[`framework/c_compiler.bsh`](framework/c_compiler.bsh) provides `def_c_lib
<alias> <c_code_var> [cflags_var] [ldflags_var]`, which writes C source held in a
BSH variable to `/tmp/bsh_compile_cache/`, invokes `cc -shared -fPIC`, and calls
`loadlib`.

> **Known gap.** `def_c_lib` does not currently work end to end: its compiler
> invocation is written as `$BSH_C_COMPILER "-shared" …`, and a command name that
> comes from a variable is parsed as an expression rather than dispatched as an
> external command; its `$($lib_alias)_COMPILE_STATUS = …` status writes fail to
> parse for the same class of reason. The source file is written, nothing is
> compiled, and the status variables stay empty. No native library is created by
> startup, and none is required — `number.bsh` and `string.bsh` fall back to
> `prim`.

---

## Testing

```bash
./test.sh
```

```bash
./test.sh strlib
```

`test.sh` compiles the pinned Fayasm sources into ignored `.build-fayasm/`
objects, performs a warnings-enabled build of the B[e]SH sources against them,
creates an isolated `.test-home`, sets an explicit `BSH_MODULE_PATH`, bounds every
suite with an alarm, and accepts only a zero exit with an explicit pass line and
no failure. An empty filter match fails.

| Suite | Covers |
| --- | --- |
| `core_variables` | Assignment, interpolation, `${}`, indirection, arrays and their mangling |
| `core_functions` | Parameters, scopes, the result-variable convention, `return`, recursion, loops in stored bodies |
| `core_control` | `if`/`else`, nesting, inline blocks, `;`, `while` |
| `mem_heap` | The heap, blocks, vectors, every `mem` subcommand |
| `strlib_list` | Heap strings and lists — **and the compilation tier each function reaches** |
| `bytecode_differential` | Interpreted vs compiled agreement across values, operators, conditions, loops, calls, recursion, returns, scoping, indirection, arrays, primitives, raw built-ins, external commands, redefinition |
| `cdiesis_lifecycle` | `lang_*` register/load/unload/reload |
| `cdiesis_runtime` | Compilation, objects, virtual dispatch, control flow, boundary arguments |
| `cdiesis_stdlib` | The `.cds` standard library plus `hello`/`shapes`/`inventory` |
| `cdiesis_interop` | cDiesis ↔ RPN calls, callbacks, stack isolation, independent unload |
| `bash_framework` | Bash lifecycle, eval, call, script status |
| `bash_cdiesis` | Bash CLI syntax plus persistent cDiesis objects and fields |

Last verified run: **12 suites, 12 passed, 0 failed** (macOS, `gcc`/Apple clang).

Examples under [`examples/`](examples/) are demonstrations, not assertions —
comments saying "Expected" do not establish support. The exceptions are
`hello.cds`, `shapes.cds`, `inventory.cds` and `counter.cds`, which the suites
actually execute.

---

## Repository layout

```
bsh.c                    core: tokenizer, operator registry, evaluator, dispatcher,
                         scopes, blocks, modules, processes, dynamic libraries
besh_core.h              shared declarations across the translation units
besh_mem.{h,c}           the linear heap == the WebAssembly memory; the `mem` built-in
besh_wasm.{h,c}          a WebAssembly binary writer; knows nothing about BSH
besh_jit.{h,c}           IR, tier decision, emission, the `besh.v1` imports,
                         the Fayasm runtime pool, `bytecode`
.bshrc                   startup: this file defines the language
framework/               BSH modules — operators, number/string/type, mem/strlib/list,
                         lang, cdiesis, rpn, bash
guides/                  bytecode.md, cdiesis.md, bash.md, addToVSCode.md
tests/  test.sh          the acceptance suites and their harness
examples/                demonstrations (.bsh, .cds, .sh)
thirds/fayasm/           pinned WebAssembly runtime (git submodule)
gold/                    archived snapshots, including a Rust port experiment —
                         historical reference only, not built or validated
AGENTS.md                the full operational handbook
ROADMAP.md               planned work and the Fayasm phase gates
TooBad.md                the problem ledger
```

Generated or runtime artifacts — the root `bsh`, `allFramework.txt`,
`/tmp/bsh_compile_cache/`, `~/.bsh_history` — are not sources.
`python3 groupFramework.py` writes the ignored `allFramework.txt` bundle as a
debug inspection aid; it is not a build step.

---

## Current status

### Implemented and verified

- The line-oriented C core: dispatch, variables, expansion, indirection, arrays,
  functions, lexical scopes, `if`/`else`/`while`, module imports.
- The bytecode path on Fayasm, both tiers, with the differential suite as the
  guard. Roadmap Phases 0–3.
- The heap, `mem`, and the `strlib`/`list` libraries with tier assertions.
- The language-framework layer: lifecycle, cDiesis compiler and runtime, the
  `.cds` standard library, cDiesis ↔ RPN interop, Bash as a language, and the
  persistent Bash → cDiesis object bridge.
- Bash CLI delegation for `.sh`, `-c`, `-s`, `--bash`.

### Experimental / scaffold

- The entire shell is research-stage. Several peripheral built-ins are untested.
- Structured objects: flattening runs, but dot-property expansion and `object:`
  re-stringification do not behave as documented in the source comments.
- Runtime C compilation (`def_c_lib`) — see the gap noted above.
- [`framework/cwd.bsh`](framework/cwd.bsh) targets a library that does not exist.
- `is_string_lib_loaded` always reports true, so it is not a real readiness check.

### Known gaps

- Prefix and postfix registrations of the same operator symbol overwrite each
  other; `add_operator_definition` matches on the symbol alone.
- The bytecode path duplicates the interpreter's condition and dispatch decisions
  in C. Only the differential suite keeps them in step.
- The general tier is at parity with the interpreter, not faster. Only the integer
  kernel tier is faster.
- Cache invalidation is wholesale — no deterministic cache key, no disk cache, no
  mapping from a Fayasm trap back to a BSH source line.
- No direct `call` between compiled functions in one module.
- Heap blocks are never reclaimed automatically, and a pointer held across
  `besh_mem_shutdown` is not detected.
- `besh.v1` is implemented but not frozen: no independent ABI conformance tests,
  no compatibility promise.
- `lang_unload` is cooperative: the C core has no `undefkeyword`,
  `undefoperator`, or function removal (`CDS-REQ-0` … `CDS-REQ-8` in
  [`guides/cdiesis.md`](guides/cdiesis.md)).
- Native BSH is not Bash-compatible. Bash routing uses the `.sh` suffix rather
  than shebang inspection; framework calls are isolated subprocesses; capture
  merges stderr into stdout and is bounded by one shell value.
- No CI, no formatter/linter configuration, no packaging or release workflow.
  Portability beyond the verified macOS toolchain is untested.

### Planned

Group related framework functions into single modules with direct `call` between
them, derive a deterministic cache key from the IR, add disk caching, reduce
host-call frequency so the general tier beats the interpreter, and map traps back
to source lines. Phase gates are in [`ROADMAP.md`](ROADMAP.md); Phase 4 is partial
and Phase 5 has not started.

Nothing here is sandboxed. Imported `.bsh`, external commands, loaded libraries,
Bash subprocesses and the FIFO bridge all execute with the user's privileges, and
Fayasm runs in-process. Treat emitted modules as code, not as untrusted data.

---

## Research goals

B[e]SH is a platform for a handful of questions:

- How far can a shell's syntax and command set be extended at runtime through
  simple macro-like mechanisms before the mechanism itself becomes the problem?
- What does a string-centric data model actually cost once user-defined
  extensions carry the complex operations — and what changes when the shell can
  compile its own functions and hand them real pointers?
- Does an enlarged, runtime-assembled language really bottom out in a small
  primitive set? cDiesis is the adversarial answer: 17 opcodes, so far.
- What is the practical shape of an FFI boundary in a lightweight shell, and what
  does honesty about its limits look like?
- Are we alone in the universe?

Contributions, experiments and disagreement are welcome. So is scepticism about
any claim here that a test does not back.

### Final notes

Well, this is just for faya. An experimental shell about incremental syntax and
runtime construction.

Licensed under the [MIT License](LICENSE).
