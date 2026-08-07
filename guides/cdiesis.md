# cDiesis — a C#-shaped language framework for B[e]SH

**Status: experimental implementation, verified by the repository test suite.**
The lifecycle, compiler/runtime, 17-op executor, standard library, shipped
examples, cooperative unload/reload, and cDiesis/RPN boundary are exercised by
the `cdiesis_*` suites under [`tests/`](../tests/). The limits described below
remain intentional research boundaries, not production-support claims.

cDiesis (Italian for the sharp sign: *do diesis* = C♯) is a statically typed,
class-based language with methods, single inheritance, virtual dispatch,
generics and a small standard library. None of it lives in [`bsh.c`](../bsh.c).
It is a **language framework**: BSH code that can be imported, activated,
deactivated and replaced at runtime, that owns its own notation end to end, and
that reduces every construct it accepts to a fixed, tiny set of primitive
operations over shell strings.

## Why this exists

[`ROADMAP.md`](../ROADMAP.md) plans a pseudo-compiled execution path: lower
stable BSH semantics to WebAssembly, execute it with the pinned
[`fayasm`](../thirds/fayasm/) runtime, keep the C core as the owner of shell
state. That plan rests on an unproven assumption — that B[e]SH's enlarged
language really does bottom out in a small primitive set, rather than in an
open-ended pile of special cases.

cDiesis is the adversarial test of that assumption. It deliberately brings the
constructs that usually justify a rich runtime (typed locals, objects, fields,
inheritance, virtual dispatch, generic collections, `foreach`, a string builder)
and shows what each one costs at the bottom: **17 opcodes, all operands strings,
one host boundary**. If a C#-shaped language needs no eighteenth opcode, the
Fayasm lowering has a defensible target.

## Architecture

```
.cds source text
      │  framework/cdiesis/lexer.bsh
      ▼
token stream                       CDS_TK_<unit>_<i>_{K,V,L}
      │  framework/cdiesis/parser.bsh + statements.bsh + expressions.bsh
      ▼
declarations  ────────────────►    class table (framework/cdiesis/objects.bsh)
primitive ops ────────────────►    CDS_M_<Class>_<Method>_C<i>
      │  framework/cdiesis/ops.bsh
      ▼
executor over 17 opcodes           frames + slots, all strings
      │            │
      │            └── HOST op ──► framework/lang.bsh ──► bsh | rpn | any framework
      ▼
B[e]SH primitives: scoped string variables, name mangling, operator handlers
```

Ownership boundaries, mirroring the ones ROADMAP.md sets for the compiler:

| Layer | Owns |
| --- | --- |
| [`bsh.c`](../bsh.c) | tokenizing BSH, scopes, string variables, functions, process/library boundaries |
| [`framework/lang.bsh`](../framework/lang.bsh) | framework lifecycle, cross-language calls, argument vector, exports |
| [`framework/cdiesis.bsh`](../framework/cdiesis.bsh) + `framework/cdiesis/` | cDiesis notation, type system, object model, lowering, execution |
| [`framework/core_operators.bsh`](../framework/core_operators.bsh), [`number.bsh`](../framework/number.bsh), [`string.bsh`](../framework/string.bsh) | the arithmetic/string primitives both languages share |

cDiesis never calls `bsh.c` internals and never registers a keyword or operator
with the C parser. That restraint is what makes it unloadable.

## The primitive op set

Every cDiesis program is a list of these instructions and nothing else. Operands
are slot names; a slot is a shell variable `CDS_S_<frame>_<slot>` holding a
string.

| Opcode | Operands | Meaning | Planned WebAssembly lowering |
| --- | --- | --- | --- |
| `CONST` | `dst k<i>` | load an interned constant | `i32.const <handle>` |
| `MOVE` | `dst src` | slot to slot | `local.get` / `local.set` |
| `LOADV` | `dst name` | read a shell variable | `call besh.v1.var_get` |
| `STOREV` | `name src` | write a shell variable | `call besh.v1.var_set` |
| `FGET` | `dst obj field` | read an instance field | `call besh.v1.field_get` |
| `FSET` | `obj field src` | write an instance field | `call besh.v1.field_set` |
| `NEW` | `dst Class argc a0…` | allocate + run constructor | `call $ctor`, result is a handle |
| `CALL` | `dst Class Method argc a0…` | static / non-virtual call | `call $func` |
| `VCALL` | `dst obj Method argc a0…` | virtual dispatch | `call_indirect` over a vtable |
| `HOST` | `dst lang symbol argc a0…` | cross-language / shell call | `call besh.v1.host_call` |
| `BIN` | `dst op a b` | binary operator | `call besh.v1.op2`, or unboxed after a guard |
| `UN` | `dst op a` | unary operator | `call besh.v1.op1` |
| `CAST` | `dst type src` | checked conversion | `call besh.v1.cast` |
| `LABEL` | `L<i>` | branch target | `block` / `loop` boundary |
| `JMP` | `L<i>` | unconditional branch | `br` |
| `JMPF` | `L<i> cond` | branch if falsy | `i32.eqz` + `br_if` |
| `RET` | `src` | return | `return` |

`NOP` exists as the seventeenth for padding and for patched-out instructions.

Two properties matter for the Fayasm work:

- **No opcode carries a pointer.** Objects travel as the string handle
  `obj#<id>`; that is a table index in disguise, exactly what ROADMAP Phase 2
  requires of the host ABI ("never a cast pointer").
- **No opcode carries a literal.** String and character literals are interned
  into a per-unit constant pool (`CDS_K_<unit>_<i>`) at lex time, so the flat
  space-separated encoding of an op can never be ambiguous, and the pool maps
  directly onto a WebAssembly data section.

### Worked lowering

```csharp
public int Bump(int by) {
    this.Value = this.Value + by;
    return this.Value;
}
```

compiles to (slot names as the parser allocates them):

```
FGET  t0 this Value
BIN   t1 + t0 by
FSET  this Value t1
FGET  t2 this Value
RET   t2
```

and

```csharp
foreach (Shape shape in shapes) { total = total + shape.Area(); }
```

compiles to an index loop, because cDiesis has no iterator protocol and adding
one would mean adding an opcode:

```
CONST t3 k0
LABEL L0
VCALL t4 t2 Count 0
BIN   t5 < t3 t4
JMPF  L2 t5
VCALL t6 t2 Get 1 t3
MOVE  shape t6
VCALL t7 shape Area 0
BIN   total + total t7
LABEL L1
CONST t8 k1
BIN   t3 + t3 t8
JMP   L0
LABEL L2
```

Print the real thing for any compiled method with `cds_dump_ops <Class> <Method>`.

## The type system

Types are metadata, never storage. A declared type decides which checks run,
which default an uninitialised slot takes, and which conversions are legal; the
value itself is always a string, exactly as
[`AGENTS.md`](../AGENTS.md) requires ("String-first values with explicit
interpretation").

| Kind | Types | Default |
| --- | --- | --- |
| value | `int` `long` `float` `double` | `0` |
| value | `bool` | `false` |
| value | `char` | empty |
| reference | `string` `object` user classes generics | `null` |
| inferred | `var` | resolved at compile time to the initialiser's static type |

- Widening (`int` → `long`/`float`/`double`, anything → `string`) is implicit;
  narrowing needs an explicit cast, which traps on failure rather than
  silently producing zero.
- `int / int` truncates. The parser emits `CAST` after the division rather than
  leaving it to the runtime, so the static type decides the semantics.
- Runtime classification (`cds_type_of`) reuses [`framework/type.bsh`](../framework/type.bsh)
  and adds one discriminator: the `obj#` prefix.
- Generics are **erased**: `List<int>` becomes the flat type name `List$int`,
  one compiled body per generic class. Element typing is a runtime tag, not a
  specialised class.

## Objects

An instance is not a record; it is a set of shell variables sharing a numeric
prefix.

```
obj#7                       the reference, as passed around
CDS_H_7_CLASS   = "Square"  runtime class
CDS_H_7_F_Width = "5"       one variable per field
```

Method lookup walks the inheritance chain from the *runtime* class
(`cds_method_owner`), which is the whole of the vtable: an `override` wins
because the walk starts lower. `this` is parameter zero of every instance
method, so `CALL` and `VCALL` share one calling convention.

## Load, unload, reload

```bsh
import cdiesis                 # registers the framework with lang.bsh
lang_load "cdiesis" ok         # activates: types, heap, class table, stdlib
lang_eval "cdiesis" SRC out    # compile + run a unit
lang_unload "cdiesis" ok       # drop every table the framework owns
```

Unload is **cooperative, not enforced**, and the distinction is important
enough to state plainly:

- The C core has no `undefkeyword` / `undefoperator` / `undefunc`. A framework's
  BSH functions therefore still exist after unload.
- What unload actually does: clears `CDS_ACTIVE`, drops the class table, the
  heap, the type table, the compiled units, the constant pools and the extern
  bindings, and makes every public entry point refuse with an error.
- A call into an unloaded framework **fails loudly** (`LANG_LAST_ERROR`) instead
  of falling back, so a script cannot accidentally keep running against a
  language it believes it removed.
- A reload starts from an empty class table. Objects allocated before an unload
  do not survive it; their handles dangle and are rejected by
  `cds_obj_class`.

cDiesis is designed so this is honest: because it registers no C-level syntax,
"no cDiesis is active" is a real state of the process, not a pretence.

## Cross-language calls

[`framework/lang.bsh`](../framework/lang.bsh) owns one boundary used in both
directions.

**Out of cDiesis** — an `extern` declaration binds a name to another framework;
calls to it compile to a single `HOST` op:

```csharp
extern "rpn" int square(int value);
extern "bsh" string setvar(string name, string value);

int s = square(9);                 // HOST t0 rpn square 1 t_value
setvar("RESULT", Convert.ToString(s));
```

**Into cDiesis** — every compiled method is exported as `Class.Method`:

```bsh
lang_arg_reset
lang_arg_push "5"
lang_call "cdiesis" "Bridge.Triple" result
```

Values crossing the boundary are strings. Object handles may cross and come
back, but a foreign language cannot dereference one — it holds a token, not an
address. That is the same contract ROADMAP Phase 2 specifies for compiled code.

[`framework/rpn.bsh`](../framework/rpn.bsh) exists as the control experiment: a
stack language with no types, no classes and no compiler, plugged into the same
lifecycle and the same boundary. [`examples/cdiesis/mixed_languages.bsh`](../examples/cdiesis/mixed_languages.bsh)
runs BSH → cDiesis → RPN → cDiesis → BSH in one process, then unloads RPN while
cDiesis keeps working.

## Files

| File | Role |
| --- | --- |
| [`framework/lang.bsh`](../framework/lang.bsh) | framework registry, load/unload, cross-language call and argument vector, built-in `bsh` language |
| [`framework/cdiesis.bsh`](../framework/cdiesis.bsh) | entry module, lifecycle hooks, `cds_compile` / `cds_run` / `cds_call` / `cds_dump_ops` |
| [`framework/cdiesis/strutil.bsh`](../framework/cdiesis/strutil.bsh) | character cursor and field helpers over `string.bsh` |
| [`framework/cdiesis/types.bsh`](../framework/cdiesis/types.bsh) | type table, defaults, assignability, casts, generic name mangling |
| [`framework/cdiesis/ops.bsh`](../framework/cdiesis/ops.bsh) | the 17 opcodes, emitter, constant pool, frames, executor, host boundary |
| [`framework/cdiesis/objects.bsh`](../framework/cdiesis/objects.bsh) | class table, fields, methods, heap, virtual dispatch |
| [`framework/cdiesis/lexer.bsh`](../framework/cdiesis/lexer.bsh) | source text to token stream |
| [`framework/cdiesis/parser.bsh`](../framework/cdiesis/parser.bsh) | unit/class/member declarations |
| [`framework/cdiesis/statements.bsh`](../framework/cdiesis/statements.bsh) | statements, lowered to `LABEL`/`JMP`/`JMPF` |
| [`framework/cdiesis/expressions.bsh`](../framework/cdiesis/expressions.bsh) | precedence chain, assignment targets, member access |
| [`framework/cdiesis/interop.bsh`](../framework/cdiesis/interop.bsh) | `extern` registry, exports, BSH host functions |
| [`framework/cdiesis/lib/system.cds`](../framework/cdiesis/lib/system.cds) | `Console`, `Math`, `Convert`, `Str` |
| [`framework/cdiesis/lib/collections.cds`](../framework/cdiesis/lib/collections.cds) | `List`, `Stack`, `Dictionary` over mangled variables |
| [`framework/cdiesis/lib/text.cds`](../framework/cdiesis/lib/text.cds) | `StringBuilder`, `TextUtil` |
| [`framework/rpn.bsh`](../framework/rpn.bsh) | second language framework, for interop and unload contrast |
| [`examples/cdiesis/`](../examples/cdiesis/) | `.cds` demonstration units and their BSH drivers |

## Required core capabilities

These are the things `bsh.c` must provide before any of the above can run. Each
was checked against the current source; none is a hypothetical nicety.

| Id | Capability | Current state |
| --- | --- | --- |
| CDS-REQ-0 | The shell compiles at all | **Verified.** `./test.sh` builds the shell with `-Wall -Wextra` before running suites. |
| CDS-REQ-1 | Indirect variable access `$(name)` for read and write | **Verified.** Indirect reads, writes, and computed names are covered by `tests/core_variables.bsh`. |
| CDS-REQ-2 | A function writing a caller-named result variable must be visible to the caller | **Verified.** Indirect assignment writes the nearest enclosing owner, or the global scope for a new table name; nested and recursive results are covered by `tests/core_functions.bsh`. |
| CDS-REQ-3 | `while` loops inside function bodies | **Verified.** Stored function bodies replay by line index; nested loops and cDiesis compiler/executor loops are covered by the suite. |
| CDS-REQ-4 | Working numeric primitives (`math_*`) | **Verified fallback.** Framework handlers use the fixed C `prim` mechanism when `bshmath` is not loaded. |
| CDS-REQ-5 | Working string primitives (`string_len`, `string_char_at_index`) | **Verified fallback.** String helpers use `prim` when `bshstringlib` is not loaded. |
| CDS-REQ-6 | A file-read primitive, so `.cds` files can be loaded as data | **Verified.** `readfile` loads the shipped `.cds` examples in `tests/cdiesis_stdlib.bsh`. |
| CDS-REQ-7 | `undefkeyword` / `undefoperator` (or scoped registries) | **Not implemented by design.** Unload remains cooperative and is verified to drop framework-owned state and refuse subsequent calls. |
| CDS-REQ-8 | Headroom in core limits | `MAX_FUNC_LINES` 256, `MAX_FUNC_PARAMS` 10, `MAX_VAR_NAME_LEN` 256, `MAX_LINE_LENGTH` 2048, `MAX_SCOPE_DEPTH` 512. The current framework imports without truncation and all cDiesis suites pass. |

## Known limitations of the language itself

Separate from core gaps — these are cDiesis's own boundaries, chosen to keep the
primitive set small:

- Namespaces are recorded but not used for name resolution; class names are
  global and must be unique.
- `interface`, `struct`, properties (`{ get; set; }`), `switch`, `try`/`catch`,
  `lambda`, `async`, attributes, operator overloading and multiple type
  parameters are not implemented. `Dictionary<string, Item>` parses, but only
  the first type argument is recorded.
- Field initialisers are parsed and skipped; initialise fields in the
  constructor.
- Overloading is not supported: one method name per class, because the method
  table is keyed by name.
- `Console.Write` behaves like `WriteLine` until a partial-output host primitive
  exists.
- No garbage collection. `cds_obj_free` exists and the heap is dropped on
  unload, but nothing reclaims unreachable objects during a run.

## Relationship to the Fayasm roadmap

cDiesis is not on the critical path of [`ROADMAP.md`](../ROADMAP.md) and does
not implement any of its phases. It contributes three things to them:

1. **A lowering target proof.** A large surface language reduces to 17 opcodes
   with a mechanical WebAssembly mapping (table above), which is evidence for
   the Phase 1 IR being sized correctly.
2. **A ready-made differential fixture.** The same unit can be run through the
   interpreter in [`ops.bsh`](../framework/cdiesis/ops.bsh) and, later, through
   an emitted module, and compared instruction by instruction — the coverage
   Phase 3 demands.
3. **A worked host-ABI shape.** `HOST`, the `obj#<id>` handle, the constant pool
   and the argument vector are deliberately the same shapes Phase 2 proposes for
   `besh.v1`, so the boundary can be validated at BSH level before any C is
   written.

None of that is implementation. Do not treat this document as evidence that any
roadmap phase has started.
