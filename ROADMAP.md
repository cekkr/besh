# B[e]SH Roadmap

This roadmap records planned work for the current C/BSH implementation. It does not describe shipped behavior. Keep it synchronized with [`AGENTS.md`](AGENTS.md) as milestones move from planned to implemented.

## Direction

B[e]SH deliberately reduces the core language to primitive values and operations, then enlarges it at runtime through functions, operators, and framework modules. That structure makes functions and framework code a good candidate for a pseudo-compiled execution path: lower stable BSH semantics into WebAssembly bytecode, execute that bytecode with the pinned [`fayasm`](thirds/fayasm/) runtime, and retain the existing C core as the owner of shell state and operating-system effects.

“Pseudo-compiled” means that BSH source is translated into an in-memory WebAssembly module and interpreted or prepared by Fayasm. It does not mean native machine-code generation, ahead-of-time packaging, or replacement of B[e]SH's interactive parser.

Current status:

- Fayasm is pinned as a Git submodule at [`thirds/fayasm/`](thirds/fayasm/).
- B[e]SH does not yet link Fayasm, emit WebAssembly, or execute compiled BSH functions.
- The C interpreter builds and the isolated suite in [`test.sh`](test.sh) verifies the core baseline and experimental language frameworks; Fayasm integration has not begun.

## Architectural Boundary

The intended flow is:

`BSH function/framework source` → `tokens and stable BSH IR` → `WASM emitter` → `in-memory module` → `Fayasm runtime` → `typed host imports` → `existing B[e]SH primitives and scoped state`

Responsibilities remain separated:

- **B[e]SH owns:** source syntax, dynamic operator/keyword/function registries, lexical scopes, string values, module imports, external commands, dynamic libraries, errors visible to scripts, and compatibility behavior.
- **The BSH compiler owns:** validated intermediate representation (IR), control-flow lowering, WebAssembly module emission, source-to-bytecode diagnostics, cache keys, and interpreter/compiled-mode selection.
- **Fayasm owns:** WebAssembly module parsing, jobs, operand stacks, control execution, traps, host-call dispatch, and optional prepared microcode. Its public integration surfaces currently live in [`fa_wasm.h`](thirds/fayasm/src/fa_wasm.h), [`fa_runtime.h`](thirds/fayasm/src/fa_runtime.h), and [`fa_job.h`](thirds/fayasm/src/fa_job.h).
- **Host imports own the boundary:** compiled code MUST reach shell variables or side effects through explicit host callbacks. It MUST NOT receive raw `Variable *`, `UserFunction *`, scope-stack pointers, or other process-local internal addresses.

## Non-Goals

- Do not replace the line-oriented interactive shell or external-command execution with WebAssembly.
- Do not compile arbitrary native libraries loaded through `loadlib`.
- Do not claim WebAssembly sandboxing. Fayasm and its B[e]SH host callbacks run in-process with the user's privileges.
- Do not require every BSH construct to compile before shipping an opt-in compiled path; unsupported constructs must fall back safely.
- Do not change BSH-visible value, scoping, truthiness, error, or operator semantics merely because WebAssembly has different primitive types.
- Do not involve the archived Rust experiment under [`gold/bsh-rs/`](gold/bsh-rs/).

## Language Frameworks as a Lowering Study

**Status: experimental implementation, verified; not a Fayasm phase.**

The plan above assumes that B[e]SH's runtime-enlarged language bottoms out in a
small primitive set. [`framework/cdiesis.bsh`](framework/cdiesis.bsh) with
[`framework/cdiesis/`](framework/cdiesis/) is a study of that assumption from the
opposite direction: a C#-shaped language — static types, classes, single
inheritance, virtual dispatch, generics, `foreach`, a standard library — written
entirely as a loadable BSH framework, compiling to a fixed set of seventeen
primitive operations over shell strings, with one host boundary.
[`framework/lang.bsh`](framework/lang.bsh) owns the load/unload lifecycle and the
cross-language call boundary; [`framework/rpn.bsh`](framework/rpn.bsh) is a second,
structurally unlike language used as the control. The design, the opcode table
and its planned WebAssembly mapping are in [`guides/cdiesis.md`](guides/cdiesis.md).

What this contributes to the phases below:

- **Phase 1 sizing evidence.** The opcode set is a concrete proposal for how
  small a stable IR can be while still expressing a large surface language.
- **Phase 2 ABI rehearsal.** Opaque `obj#<id>` handles, a per-unit constant
  pool, an argument vector instead of positional parameters, and a single
  `HOST` operation are the same shapes `besh.v1` proposes — testable at BSH
  level before any C is written.
- **Phase 3 differential fixtures.** A cDiesis unit can be executed by the BSH
  executor and, later, by an emitted module, then compared instruction by
  instruction.

What it does not do: it implements no Fayasm phase, links no Fayasm, and emits
no WebAssembly. Its core prerequisites and the one intentionally cooperative
unload limitation are tracked as `CDS-REQ-0` … `CDS-REQ-8` in
[`guides/cdiesis.md`](guides/cdiesis.md). Do not treat the language framework as
progress against a Fayasm exit gate.

## Phase 0 — Restore and Measure the Interpreter Baseline

**Status: In progress — build and semantic suite established; benchmarks and independent Fayasm validation remain.**

1. Fix the blocking C compilation errors and the argument-buffer warnings documented in [`AGENTS.md`](AGENTS.md).
2. Add a non-interactive test harness that can run BSH fixtures with an isolated `HOME` and explicit `BSH_MODULE_PATH`.
3. Turn representative examples into assertions for:
   - function definition, calls, arguments, local/global scope, and return;
   - `if`, `else`, `while`, and nested blocks;
   - framework operator dispatch and result-holder variables;
   - imports, redefinitions, errors, and external-command boundaries.
4. Record baseline timings for startup, repeated function calls, loop-heavy functions, and operator-heavy framework code. Measure end-to-end time and dispatcher/parse time separately when possible.
5. Initialize and validate the pinned Fayasm checkout independently with its own documented build/test workflow. Do not make its build artifacts part of B[e]SH source control.

**Exit gate:** the interpreter builds, the selected semantic fixtures pass reliably, and benchmark commands are repeatable.

## Phase 1 — Define a Stable BSH Intermediate Representation

**Status: Planned**

The current `UserFunction` stores raw body lines and re-enters `process_line` for every invocation. Compilation must start from a stable semantic representation, not from ad hoc string rewriting.

1. Introduce a BSH IR for the initially supported subset:
   - string/number literals and variable references;
   - assignments and indirect result-variable assignment;
   - function calls;
   - unary, binary, and comparison operations after operator resolution;
   - `if`/`else`, `while`, and return;
   - structured blocks and source locations.
2. Parse function bodies once at definition/import time. Keep the original source for diagnostics and optional reinterpretation after registry changes.
3. Make the existing interpreter execute or validate the same IR before adding code generation. This prevents the compiler from becoming a second, subtly different language implementation.
4. Give every IR node explicit failure and side-effect semantics. Mark nodes that cannot initially compile, such as dynamic `eval`, runtime syntax mutation, or unsupported indirect calls.
5. Version the IR and operator-resolution contract so compiled artifacts can be invalidated deterministically.

**Exit gate:** interpreter behavior remains unchanged while supported functions execute from the parsed IR, with source-positioned errors and regression coverage.

## Phase 2 — Freeze the B[e]SH ↔ Fayasm Host ABI

**Status: Planned**

B[e]SH values remain strings even when a value can be interpreted as an integer or float. The first ABI should therefore favor semantic correctness over aggressive unboxing.

1. Use invocation-scoped opaque `i32` handles for BSH strings and other host-owned values. A handle indexes a B[e]SH-owned table; it is never a cast pointer and is invalid after its invocation/runtime generation ends.
2. Define a small versioned import module, provisionally `besh.v1`, with callbacks for:
   - constant/value interning;
   - scoped variable lookup and assignment;
   - truthiness evaluation;
   - resolved primitive/operator invocation;
   - user-function fallback dispatch;
   - error/trap reporting.
3. Use Fayasm's `fa_Runtime_bindHostFunction` and signature-aware `fa_RuntimeHostCall_*` helpers. Validate argument and result counts/types at every callback.
4. Map compiled function parameters and results to opaque value handles. Preserve the current result-holder convention at the boundary until a separately approved BSH API redesign replaces it.
5. Define ownership and cleanup for modules, runtimes, jobs, value tables, errors, and trap paths. No host handle may survive cache serialization or be embedded as a persistent WebAssembly constant.
6. Add ABI conformance tests independent of the BSH compiler, using a tiny hand-built or fixture WebAssembly module calling each host import.

**Exit gate:** a minimal Fayasm module can read/write scoped BSH values, invoke one primitive, return a value, propagate a controlled error, and clean up without leaks.

## Phase 3 — Emit and Execute the First Compiled Functions

**Status: Planned**

1. Add a BSH-to-WebAssembly emitter for the stable IR subset. Generate only the required type, import, function, export, code, and optional data sections.
2. Load emitted bytes from memory using Fayasm's module API, run the required parser/load phases, attach the module to `fa_Runtime`, bind `besh.v1` host functions, create a job, and execute the exported function.
3. Lower constructs conservatively:
   - local temporary values → WebAssembly locals containing opaque handles;
   - scoped BSH reads/writes → host imports;
   - `if`/`else` → structured WebAssembly conditionals;
   - `while` → `block`/`loop`/`br_if` control flow;
   - calls to compiled functions in the same unit → direct `call`;
   - unresolved/dynamic calls → host fallback dispatcher;
   - return → exported function result or an explicit host-managed return state, matching interpreter behavior.
4. Keep interpreter fallback per function. A compile failure in `auto` mode must preserve valid interpreted execution; it must not leave a partially registered module.
5. Add a planned mode switch with explicit semantics:
   - `off` — interpreter only;
   - `auto` — compile supported functions and fall back otherwise;
   - `force` — report unsupported/failed compilation instead of silently interpreting.
6. Produce diagnostics that identify the original BSH function and source line, even when the runtime reports only a WebAssembly function index or trap status.

**Exit gate:** literal assignment, variable access, function parameters/results, branching, loops, and a primitive call pass differential tests in interpreted and compiled modes.

## Phase 4 — Compile Framework Modules as Units

**Status: Planned**

Frameworks provide most of B[e]SH's enlarged language, so compiling them is the main performance objective.

1. Build a dependency graph when `import` loads framework files. Compile strongly related functions into one WebAssembly module when direct calls and shared constants justify it.
2. Export a stable dispatch entry for every compiled BSH function and keep the B[e]SH `UserFunction` registry authoritative for name lookup/redefinition.
3. Compile [`framework/core_operators.bsh`](framework/core_operators.bsh), [`framework/number.bsh`](framework/number.bsh), [`framework/string.bsh`](framework/string.bsh), and [`framework/type.bsh`](framework/type.bsh) incrementally, after their currently conceptual native dependencies are made real or replaced.
4. Preserve dynamic enlargement:
   - `defunc` adds or replaces one compilation unit;
   - `defoperator` changes operator resolution and invalidates affected IR/modules;
   - `defkeyword` changes future parsing and invalidates source parsed through the old alias map;
   - `import` records source/module dependencies and invalidates dependents on reload.
5. Keep `eval` and code that mutates syntax at runtime on the interpreter path until explicit deoptimization/recompilation semantics exist.

**Exit gate:** default framework startup can use compiled functions in `auto` mode, unsupported functions fall back, and framework redefinition tests produce the same results as a fresh interpreter process.

## Phase 5 — Cache, Specialize, and Optimize

**Status: Planned after semantic parity**

1. Cache emitted modules by a deterministic key containing:
   - canonical IR/source hash;
   - BSH compiler and host-ABI versions;
   - relevant operator/keyword/function registry generations;
   - Fayasm submodule revision and required feature set.
2. Start with in-memory caching. Add disk caching only after the byte format, invalidation, permissions, and corruption handling are specified and tested.
3. Measure eager compilation of default frameworks against lazy compilation and a call-count hotness threshold. Choose defaults from startup and steady-state evidence.
4. Add typed specialization only where proven safe:
   - keep generic strings as opaque handles;
   - unbox values to `i32`, `i64`, `f32`, or `f64` only after a guard or static proof;
   - deopt or call the generic host primitive when a guard fails;
   - preserve formatting, overflow, comparison, and error behavior visible to BSH.
5. Evaluate Fayasm prepared microcode/JIT options only after interpreter-dispatch savings are measured. Fayasm's current JIT prepares portable microcode rather than native code, and its own benchmarks require measured justification for added microcode coverage.
6. Profile host-import frequency. If calls dominate, batch only operations whose ordering, scope, and failure semantics remain observable-equivalent.

**Exit gate:** representative function/framework workloads improve over the interpreter baseline without semantic divergence, unacceptable startup regression, unsafe cache reuse, or hidden fallback.

## Required Differential and Safety Coverage

Every compiled milestone must run the same fixture in interpreter and compiled modes and compare:

- returned value and output;
- scoped/global variable state;
- `LAST_COMMAND_STATUS`, `LAST_LIB_CALL_STATUS`, `LAST_LIB_CALL_OUTPUT`, and other observable status variables touched by the path;
- function redefinition and import behavior;
- truthiness and string/numeric comparison edge cases;
- nested calls, recursion limit, loop behavior, and return unwinding;
- external-command ordering and captured output;
- errors, traps, and cleanup after partial execution;
- unsupported construct fallback in `auto` mode and rejection in `force` mode.

Use sanitizers or equivalent memory diagnostics for the host-handle table, runtime/module/job lifetimes, trap unwinding, and repeated compile/execute/free cycles.

## Success Criteria

The Fayasm path is ready to become a normal opt-in feature when:

1. The default remains behaviorally compatible and the interpreter remains available as a reference/fallback.
2. Supported functions and framework modules pass differential tests with no unexplained state or output divergence.
3. Dynamic redefinition invalidates or recompiles every affected artifact deterministically.
4. Host imports expose only the minimal required B[e]SH capabilities and reject invalid handles/types.
5. Benchmarks show a repeatable improvement on repeated function and framework execution, with startup and memory costs reported separately.
6. Build, submodule initialization, feature selection, debugging, and cache cleanup are documented and reproducible.

Do not set a numeric performance target until the Phase 0 benchmark harness provides a trustworthy baseline.
