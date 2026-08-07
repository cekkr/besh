# B[e]SH — AI Agent Reference

This is the fast-access operational reference for the Basic [extensible] Shell (B[e]SH), an early research shell for experimenting with a small C execution core and language behavior assembled at runtime from BSH scripts. The project is [`bsh.c`](bsh.c) together with [`.bshrc`](.bshrc) and [`framework/`](framework/). It is not intended to replace a production Unix shell. **[`gold/bsh-rs/`](gold/bsh-rs/) is an archived experimental Rust port, not part of the project implementation; ignore it during normal discovery, changes, builds, and validation.**

## Read This First

Use this source-of-truth order when facts conflict:

1. [`LICENSE`](LICENSE) — legal terms for all repository content.
2. Executable behavior and interfaces in [`bsh.c`](bsh.c), [`.bshrc`](.bshrc), and [`framework/`](framework/), plus a successful [`test.sh`](test.sh) run or focused execution check.
3. [`compile.sh`](compile.sh) and other root build/tool configuration — exact declared workflows for the project implementation.
4. [`README.md`](README.md) — project intent, vocabulary, and research goals; implementation claims in it must be checked against current source.
5. [`ROADMAP.md`](ROADMAP.md) — planned B[e]SH work and the Fayasm integration sequence; roadmap entries do not prove implementation.
6. [`TooBad.md`](TooBad.md), examples, studies, and comments marked conceptual — known concerns, demonstrations, and design exploration, not proof of working behavior.
7. [`gold/`](gold/) and Git history — historical reference only; neither overrides the current implementation.

When these disagree, inspect the affected control path and run the narrowest safe check. Do not upgrade a conceptual comment, README aspiration, example expectation, or archived-port behavior into a claim about the project implementation. Record unresolved contradictions under **Known Gaps**.

## Collaboration and Maintenance Rules

- Read this file completely and check `git status --short --branch` before every task. Preserve unrelated and untracked user work.
- Keep the C implementation and its runtime BSH framework synchronized when a contract crosses the boundary. In particular, operator handler names, argument counts, result-variable conventions, module paths, and C-library ABI changes usually span multiple files.
- Treat everything under [`gold/`](gold/) as historical reference. Do not edit, build, validate, or synchronize [`gold/bsh-rs/`](gold/bsh-rs/) during ordinary project work; an explicit historical/port task is required.
- Update this handbook in the same change when files, public commands, meaningful symbols, feature status, build commands, data formats, ABI contracts, or reusable failure-prevention rules change.
- Run the closest available build or execution check. State exactly what passed, failed, or was not run; examples are demonstrations, not an automated regression suite.
- Do not edit generated/runtime artifacts as sources. The ignored root `bsh`, ignored `allFramework.txt`, `/tmp/bsh_compile_cache`, dynamic libraries, and `~/.bsh_history` are derived or runtime data. Generated files preserved inside historical snapshots are not project inputs.
- Put future work and implementation concerns in [`TooBad.md`](TooBad.md) or a new, explicit roadmap/design document. Do not describe planned behavior as current behavior.
- Keep [`ROADMAP.md`](ROADMAP.md) synchronized when Fayasm integration priorities, phase status, host-ABI plans, or success criteria change. Move behavior into current-status sections only after implementation and verification.
- Do not modify [`gold/`](gold/) while implementing current behavior. Add or replace a snapshot only when the user explicitly asks to curate historical references.
- Before a commit, review `git diff --check`, validate every touched local Markdown link, and ensure `AGENTS.md` describes the post-commit tree rather than the desired future state.

## Essential Project Principles

### Minimal C mechanism, script-defined policy

- Keep tokenization, parsing, control flow, scoping, process execution, module lookup, and the foreign-function boundary in the C core.
- Keep extensible operator semantics and reusable higher-level behavior in BSH modules. Do not hard-code a framework operator's arithmetic/string policy in C merely to bypass a broken script handler.

### Runtime extensibility is the research subject

- `defunc`, `defkeyword`, `defoperator`, `import`, `loadlib`, and `calllib` are architectural surfaces, not incidental helpers.
- Preserve the ability for startup/framework scripts to register language behavior at runtime. Static syntax may remain only where the parser requires structural punctuation or assignment/control-flow machinery.

### String-first values with explicit interpretation

- Variables and command/library outputs are stored as strings. Numeric, boolean, object, and array meanings are imposed by handlers and naming conventions.
- Do not introduce implicit typed storage in one subsystem without defining expansion, assignment, truthiness, external-command, library-ABI, and compatibility behavior across the whole path.

### Research code must be described honestly

- This checkout is experimental. The isolated suite establishes a working core and cDiesis baseline, but untested features and example expectations MUST remain labeled honestly.
- Behavior in archived material under `gold/` does not establish current project behavior.

## Critical Implementation Contracts

- **Current/historical boundary:** Root C/BSH files own the implementation. Everything under [`gold/`](gold/) is historical and excluded from normal builds and parity expectations. Never copy a status claim, dependency, design decision, or behavior from an archived snapshot without verifying it against current C/BSH code.
- **Startup order creates the language:** [`main`](bsh.c) calls `initialize_shell`, then executes `$HOME/.bshrc` when present or the repository [`.bshrc`](.bshrc) as a fallback. Most operators do not exist before startup scripts call `defoperator`; parser/tokenizer changes must be checked both before and after startup registration.
- **Operator definition and handler signatures are coupled:** `handle_defoperator_statement`/`add_operator_definition` record symbol, grammatical type, precedence, associativity, and BSH handler. `invoke_bsh_operator_handler` requires exactly `operand_count + 2` parameters: operator symbol, operands, and result-holder variable name. Keep registrations in [`framework/core_operators.bsh`](framework/core_operators.bsh) aligned with handler definitions and downstream number/string functions.
- **Duplicate operator symbols currently overwrite by symbol:** `add_operator_definition` matches only `op_str`, not operator type. Registering both prefix and postfix `++` or `--` redefines one entry rather than storing two forms. Do not assume the four registrations in `core_operators.bsh` coexist; fix or test the registry before relying on both forms.
- **Scopes are stack-owned:** `enter_scope`, `leave_scope`, `get_variable_scoped`, and `set_variable_scoped` define lexical lookup. Function calls create a scope and must clean it on return. New paths must not write around these functions or leak local variables into global scope.
- **Array and object storage is name-mangled:** arrays use `<base>_ARRAYIDX_<expanded-index>`; object properties use underscore-separated names and `<base>_BSH_STRUCT_TYPE` metadata. Change the mangling only with assignment, expansion, property helpers, stringification, and round-trip checks updated together.
- **The BSH object format is not general JSON:** `object:`/`json:` assignment currently enters the same handwritten parser, which accepts bracketed quoted key/value pairs and nested brackets. Do not claim full JSON support or silently feed untrusted general JSON into it.
- **External commands execute directly:** `find_command_in_path_dynamic` resolves `PATH`; `execute_external_command` uses `fork`/`execv`, optionally captures both stdout and stderr into one fixed-size buffer, trims trailing newlines, and writes `LAST_COMMAND_STATUS`. Do not introduce shell-string execution as a shortcut; preserve argument boundaries.
- **Bash compatibility delegates instead of emulates:** CLI `.sh`, `-c`, `-s`, and `--bash` modes execute the installed `bash`; native `.bsh` input still uses the BSH parser. [`framework/bash.bsh`](framework/bash.bsh) reaches Bash through the argv-preserving `process` primitive. Do not claim that native BSH syntax is Bash-compatible or add partial Bash grammar to the BSH tokenizer.
- **The Bash/cDiesis bridge is stateful:** [`framework/bash/cdiesis.sh`](framework/bash/cdiesis.sh) keeps one `bsh --bsh-stdin` process alive through private FIFOs. Object handles and mutations survive bridge calls but become invalid at `cdiesis_close`; values cross through private files, while class/method/field names are identifier-validated.
- **Dynamic-library ABI is fixed:** `calllib` expects a symbol compatible with `int func(int argc, char *argv[], char *output_buffer, int buffer_size)`. `LAST_LIB_CALL_STATUS` and `LAST_LIB_CALL_OUTPUT` are the BSH-facing result channel. Arbitrary C signatures are unsupported and unsafe.
- **File-backed loops depend on seeking:** while-loop replay uses `ftell`/`fseek` through block frames. `execute_user_function` passes `NULL` as its input source, so do not assume identical loop behavior in interactive input, script files, imports, and stored function bodies without focused verification.
- **Module lookup is process-relative:** `BSH_MODULE_PATH` defaults to `./framework:~/.bsh_framework:/usr/local/share/bsh/framework`. The C code splits these strings but does not expand `~`; running outside the repository can prevent root `.bshrc` imports. Set `BSH_MODULE_PATH` explicitly in portable tests.

## Architecture and Data/Control Flow

Primary implementation:

`main` → `initialize_shell` → `$HOME/.bshrc` or [`.bshrc`](.bshrc) → `import` framework modules → `defoperator`/`defunc` registration

`script or stdin line` → `process_line` → `advanced_tokenize_line` → assignment / built-in / user function / external command / expression parser

`bsh -c` / `bsh -s` / `bsh *.sh` / `bsh --bash ...` → installed `bash` with the original argv boundaries

`expression` → `parse_expression_recursive` → `OperatorDefinition` lookup → `invoke_bsh_operator_handler` → BSH handler → optional `calllib` → result-holder variable

`assignment` → `evaluate_expression_from_tokens` → scoped string variable, array name mangling, or `object:` flattening → expansion / `echo` stringification

The process boundary is the external command launched by `fork`/`execv`. The native-code trust boundary is a loaded shared library invoked through the fixed BSH C ABI. Imported `.bsh` files execute in the same process and mutate global registries/state; they are trusted code, not data.

Planned Fayasm path (not implemented):

`parsed BSH function/framework IR` → `WASM emitter` → [`thirds/fayasm/`](thirds/fayasm/) in-memory module/runtime → narrow B[e]SH host imports → existing scoped variables and primitives. See [`ROADMAP.md`](ROADMAP.md); do not describe this path as current behavior.

## Linked Source Tree and File Reference

### [`bsh.c`](bsh.c)

Owns the primary shell executable: data structures, tokenizer, runtime operator registry, expression evaluator, dispatcher, scopes, blocks, module and executable resolution, dynamic libraries, structured values, and entry point. Framework semantics belong in `.bsh` files, not here.

- **Key functions and subparts:** `main` and `initialize_shell` bootstrap scopes, paths, variables, and startup scripts; `advanced_tokenize_line` emits tokens using registered operators; `process_line` dispatches all line forms; `parse_operand`, `parse_expression_recursive`, and `evaluate_expression_from_tokens` evaluate expressions; `handle_*` functions implement built-ins and control flow; `enter_scope`/`leave_scope` and scoped variable helpers own lifetime; `execute_script`, `execute_external_command`, and `execute_user_function` cross execution contexts; object parse/stringify helpers own the flattened representation.
- **Bash/process additions:** `delegate_to_bash` owns CLI routing for Bash entry points; `handle_process_statement` captures a child launched with distinct argv entries; `--bsh-stdin` runs prompt-free native BSH input for stateful adapters. `BSH_EXECUTABLE` exposes the resolved current binary to scripts.
- **Called by / depends on:** built by [`compile.sh`](compile.sh); loads [`.bshrc`](.bshrc) and modules in [`framework/`](framework/); uses POSIX process APIs and `dlfcn`.
- **Tests:** [`test.sh`](test.sh) builds with warnings enabled and runs the isolated suites under [`tests/`](tests/).
- **Common mistakes:** Do not add an operator only to C or only to a framework file; do not bypass scoped setters; do not assume capture keeps stderr separate; do not treat comments describing intended behavior as implemented.

### [`.bshrc`](.bshrc)

Repository fallback startup script. It sets `PS1`, aliases `function` to `defunc`, imports the core frameworks, selects built-in primitives unless native aliases are already loaded, and defines convenience functions.

- **Key functions and subparts:** imports `c_compiler`, `number`, `type`, `string`, then `core_operators`; selects the optional `bshmath` alias; defines `is_empty`, `scope_test`, and `for_loop`.
- **Called by / depends on:** selected by `main` only when `$HOME/.bshrc` does not exist; module resolution comes from `BSH_MODULE_PATH`.
- **Tests:** every suite uses an isolated `HOME` and the repository fallback startup script.
- **Common mistakes:** startup deliberately does not compile native libraries; numeric and string framework behavior falls back to `prim`.

### [`framework/core_operators.bsh`](framework/core_operators.bsh)

Registers arithmetic, comparison, increment/decrement, ternary, and dot operators and defines their BSH handlers.

- **Key functions and subparts:** `defoperator` registrations carry precedence/associativity; `bsh_op_add_or_concat` selects string or number behavior; arithmetic/comparison handlers delegate to `number.bsh`; increment handlers expect a variable name; ternary and dot handlers contain provisional semantics.
- **Depends on:** [`framework/type.bsh`](framework/type.bsh), [`framework/number.bsh`](framework/number.bsh), and [`framework/string.bsh`](framework/string.bsh).
- **Tests:** arithmetic and comparisons are exercised throughout the core and cDiesis suites; prefix/postfix collision still lacks a focused assertion.
- **Common mistakes:** Handler arity must match the C dispatcher. Prefix and postfix registration of the same symbol currently collide in C. The `[cite: 124]` text is stray prose, not syntax or evidence.

### [`framework/c_compiler.bsh`](framework/c_compiler.bsh)

Compiles C source held in a BSH variable into a shared library and loads it.

- **Key function:** `def_c_lib` derives `/tmp/bsh_compile_cache/<alias>.c` and `.so`, writes source with `writefile`, invokes `cc`, records status variables, then calls `loadlib`.
- **Depends on:** an external C compiler, writable `/tmp`, and the native ABI in [`bsh.c`](bsh.c).
- **Tests:** none.
- **Common mistakes:** native compilation is opt-in and executes a trusted external compiler; a status variable is not a substitute for a focused `calllib` check.

### [`framework/number.bsh`](framework/number.bsh)

Wraps the `bshmath` dynamic library for numeric operations, comparisons, logical negation, type probes, and prefix/postfix mutation.

- **Key functions:** `_math_binary_op_internal`, `_math_compare_op_internal`; public `math_add` through `math_le`; `math_not`; `bsh_unary_*`; `math_is_int` and `math_is_float`.
- **Depends on:** a loaded `bshmath` alias exposing the exact functions embedded in [`.bshrc`](.bshrc); `LAST_LIB_CALL_STATUS` and `LAST_LIB_CALL_OUTPUT` from `calllib`.
- **Tests:** [`examples/enhancedNumbers.bsh`](examples/enhancedNumbers.bsh) and [`examples/strNumExamples.bsh`](examples/strNumExamples.bsh) are demonstrations only.
- **Common mistakes:** Public functions include an operator-symbol parameter even when direct callers omit or repurpose it. Preserve and verify the result-variable convention rather than inferring conventional return values.

### [`framework/string.bsh`](framework/string.bsh)

Provides string comparison, concatenation, indexing, split, and length helpers, mostly through a proposed `bshstringlib`.

- **Key functions:** `_string_compare_op_internal`, `string_eq`, `string_ne`, pure-BSH `string_concat`, `string_char_at_index`, split helpers/`string_split`, and `string_len`.
- **Depends on:** a separately loaded `bshstringlib`, except concatenation; array helper calls in this file are written as if they were BSH commands even though their names currently identify C functions, not registered built-ins.
- **Tests:** string portions of [`examples/enhancedNumbers.bsh`](examples/enhancedNumbers.bsh) and [`examples/strNumExamples.bsh`](examples/strNumExamples.bsh).
- **Common mistakes:** `is_string_lib_loaded` always reports true, so it is not a real readiness check. No string library is created by `.bshrc`.

### [`framework/type.bsh`](framework/type.bsh)

Defines script-level classification of strings as `INTEGER`, `FLOAT`, or `STRING`.

- **Key function:** `get_type` calls `math_is_int` then `math_is_float` and writes through a caller-named result variable.
- **Depends on:** [`framework/number.bsh`](framework/number.bsh), although `.bshrc` imports this module before conditionally importing `number`.
- **Tests:** none.
- **Common mistakes:** The module can load before its dependencies because function bodies execute later; this does not mean numeric classification is available before `number` and `bshmath` work.

### [`framework/cwd.bsh`](framework/cwd.bsh)

Optional filesystem module offering BSH-level `pwd`, `cd`, and `ls` around a proposed `fs_utils` shared library.

- **Key functions:** `is_fs_utils_loaded`, `pwd`, `cd`, and `ls`; the trailing comments sketch C ABI implementations.
- **Depends on:** `BSH_FS_UTILS_LIB_ALIAS=fs_utils`, `calllib`, `update_cwd`, and an external library not present in the repository.
- **Tests:** none.
- **Common mistakes:** This module is not imported by default and its library-readiness probe is conceptual. Do not confuse it with OS-backed `update_cwd` in the core.

### [`framework/extension/inline_if.bsh`](framework/extension/inline_if.bsh)

Optional `iif` function for assigning one of two already-evaluated values to a result variable.

- **Key function:** `iif(condition_outcome, true_value, false_value, result_var_name)`.
- **Depends on:** normal BSH truth/result-variable conventions; it is not the parser's `? :` implementation.
- **Tests:** commented examples only.
- **Common mistakes:** Both branches arrive as values; this helper does not provide lazy evaluation.

### [`framework/extension/property_squares.bsh`](framework/extension/property_squares.bsh)

Optional simulation of bracket-style object property access over underscore-mangled variables.

- **Key functions:** `get_element` builds `<base>_<key>` and reads indirectly; `set_element` writes indirectly.
- **Depends on:** object flattening and indirect variable syntax from [`bsh.c`](bsh.c).
- **Tests:** commented examples only.
- **Common mistakes:** This is object-property sugar, not the core array `_ARRAYIDX_` representation.

### [`framework/lang.bsh`](framework/lang.bsh)

Language-framework manager: registration, load/unload/reload lifecycle, the shared cross-language argument vector, exported-symbol resolution, and the built-in `bsh` pseudo-language. Not imported by [`.bshrc`](.bshrc); loaded on demand by a language framework or a driver script.

- **Key functions:** `lang_register`, `lang_load`, `lang_unload`, `lang_reload`, `lang_is_loaded`/`lang_state`, `lang_arg_reset`/`lang_arg_push`/`lang_arg_get`, `lang_export`/`lang_resolve`, `lang_call`, `lang_eval`, the active-language stack helpers, and `bsh_lang_call`/`bsh_lang_eval`.
- **Contracts:** cross-language arguments travel in `LANG_ARG_N`/`LANG_ARG_<i>`, never as positional BSH parameters; BSH bridge targets answer through `LANG_RETURN`; a call into an unloaded framework sets `LANG_LAST_ERROR` and fails rather than falling back. `bsh_lang_call` bridges at most four arguments.
- **Tests:** lifecycle and symmetric cDiesis/RPN calls are covered by [`tests/cdiesis_lifecycle.bsh`](tests/cdiesis_lifecycle.bsh) and [`tests/cdiesis_interop.bsh`](tests/cdiesis_interop.bsh).
- **Common mistakes:** `lang_unload` cannot remove C-registered keywords or operators; unload is cooperative and depends on each framework's hook actually dropping its tables. Do not describe it as enforced isolation.

### [`framework/cdiesis.bsh`](framework/cdiesis.bsh) and [`framework/cdiesis/`](framework/cdiesis/)

The cDiesis language framework: a C#-shaped, statically typed, class-based language implemented entirely in BSH, whose every construct compiles to a fixed 17-opcode primitive set over shell strings. Design, opcode table, WebAssembly mapping and dependency list live in [`guides/cdiesis.md`](guides/cdiesis.md).

- **Entry module:** [`framework/cdiesis.bsh`](framework/cdiesis.bsh) registers with `lang.bsh` and owns `cdiesis_on_load`/`cdiesis_on_unload`, `cds_compile`, `cds_run`, `cds_call`, `cds_dump_ops`, and stdlib loading.
- **Submodules:** [`strutil.bsh`](framework/cdiesis/strutil.bsh) (character/field helpers over `string.bsh`), [`types.bsh`](framework/cdiesis/types.bsh) (type table, defaults, assignability, casts, generic name mangling), [`ops.bsh`](framework/cdiesis/ops.bsh) (opcodes, emitter, constant pool, frames, executor, `cds_host_call`), [`objects.bsh`](framework/cdiesis/objects.bsh) (class table, fields, methods, heap, `cds_method_owner` dispatch), [`lexer.bsh`](framework/cdiesis/lexer.bsh), [`parser.bsh`](framework/cdiesis/parser.bsh), [`statements.bsh`](framework/cdiesis/statements.bsh), [`expressions.bsh`](framework/cdiesis/expressions.bsh), [`interop.bsh`](framework/cdiesis/interop.bsh) (`extern` registry, exports, BSH host functions).
- **Standard library:** [`lib/system.cds`](framework/cdiesis/lib/system.cds), [`lib/text.cds`](framework/cdiesis/lib/text.cds), [`lib/collections.cds`](framework/cdiesis/lib/collections.cds) are cDiesis source compiled by the same pipeline as user code, not BSH.
- **Contracts:** object references are the string handle `obj#<id>`; instance state is `CDS_H_<id>_F_<field>`; compiled ops are `CDS_M_<Class>_<Method>_C<i>`; literals are interned per unit in `CDS_K_<unit>_<i>`; `CDS_ACTIVE` gates every public entry point after unload. Arithmetic and comparison are delegated to the handlers in [`framework/core_operators.bsh`](framework/core_operators.bsh) so the two languages cannot diverge numerically.
- **Tests:** [`tests/cdiesis_runtime.bsh`](tests/cdiesis_runtime.bsh) covers compilation, objects, virtual dispatch, control flow, and boundary arguments; [`tests/cdiesis_stdlib.bsh`](tests/cdiesis_stdlib.bsh) runs the stdlib plus `hello.cds`, `shapes.cds`, and `inventory.cds`.
- **Common mistakes:** Do not add an eighteenth opcode to make a construct work; the fixed set is the point. Do not register cDiesis syntax with `defkeyword`/`defoperator` — doing so would make the framework unremovable. Do not treat the `.cds` files as BSH scripts.

### [`framework/rpn.bsh`](framework/rpn.bsh)

A second, deliberately different loadable language (stack-based, untyped, no compiler) used as the control experiment for the framework mechanism and as the other end of cross-language calls.

- **Key functions:** `rpn_on_load`/`rpn_on_unload`, `rpn_eval`, `rpn_call`, `rpn_define`, `rpn_exec_token`, `rpn_foreign_call`, stack helpers.
- **Depends on:** [`framework/lang.bsh`](framework/lang.bsh) and [`framework/cdiesis/strutil.bsh`](framework/cdiesis/strutil.bsh) for field splitting and `cds_binary`.
- **Tests:** [`tests/cdiesis_interop.bsh`](tests/cdiesis_interop.bsh) covers direct calls, callbacks, stack isolation, and independent unload.
- **Common mistakes:** Its `@lang:symbol/N` form pops arguments in reverse order; do not assume left-to-right pushes.

### [`framework/bash.bsh`](framework/bash.bsh) and [`framework/bash/cdiesis.sh`](framework/bash/cdiesis.sh)

The Bash language adapter and Bash-facing cDiesis object bridge.

- **Key functions:** `bash_on_load`/`bash_on_unload`, `bash_eval`, `bash_run`, and `bash_call` register Bash with [`framework/lang.bsh`](framework/lang.bsh). The sourced Bash library exports `cdiesis_import`, `cdiesis_new`, `cdiesis_call`, `cdiesis_get`, `cdiesis_set`, and `cdiesis_close`.
- **Depends on:** an installed `bash`, the core `process` command, and `bsh --bsh-stdin`; cDiesis bridge calls additionally depend on [`framework/cdiesis.bsh`](framework/cdiesis.bsh). Bash 3.2 or newer is sufficient for the sourced library.
- **Tests:** [`tests/bash_framework.bsh`](tests/bash_framework.bsh) covers lifecycle/eval/call/script status and [`tests/bash_cdiesis.sh`](tests/bash_cdiesis.sh) covers CLI Bash syntax plus persistent cDiesis objects and fields.
- **Common mistakes:** Native `.bsh` is not Bash syntax. Framework eval/call starts a fresh Bash process each time, while only the cDiesis FIFO bridge is persistent. The captured channel intentionally merges stdout and stderr.

### [`examples/cdiesis/`](examples/cdiesis/)

Demonstration units and drivers for the language-framework work: [`hello.cds`](examples/cdiesis/hello.cds), [`shapes.cds`](examples/cdiesis/shapes.cds) (inheritance and virtual dispatch), [`inventory.cds`](examples/cdiesis/inventory.cds) (generics, dictionaries, `foreach`), [`interop.cds`](examples/cdiesis/interop.cds), plus the BSH drivers [`run_cdiesis.bsh`](examples/cdiesis/run_cdiesis.bsh) (compile, dump ops, run, unload, reload) and [`mixed_languages.bsh`](examples/cdiesis/mixed_languages.bsh) (BSH ↔ cDiesis ↔ RPN, with a mid-run unload).

- **Status:** demonstrations; `hello.cds`, `shapes.cds`, and `inventory.cds` are also executed by [`tests/cdiesis_stdlib.bsh`](tests/cdiesis_stdlib.bsh).
- **Common mistakes:** the older drivers assemble source inline, while current tests load `.cds` files through `readfile`.

### [`examples/bash/`](examples/bash/)

[`counter.cds`](examples/bash/counter.cds) is a cDiesis library with a mutable public field and instance methods. [`cdiesis_objects.sh`](examples/bash/cdiesis_objects.sh) is an ordinary Bash script that sources the bridge, compiles the library, constructs an object, calls methods, and reads/writes the field.

- **Execution:** both `bash examples/bash/cdiesis_objects.sh` and `./bsh examples/bash/cdiesis_objects.sh` use genuine Bash syntax.
- **Common mistakes:** call `cdiesis_close` (normally from an `EXIT` trap); handles belong to one bridge session and cannot be reused after it closes.

### [`examples/basicExample.bsh`](examples/basicExample.bsh)

Demonstrates script-defined loops, mutation helpers, a conceptual C-style loop, and direct `while`.

- **Key functions:** `for_to_step`, `pp`, `mm`, `is_less`, and `c_style_for`.
- **Depends on:** startup math/operator functions and `eval`-like indirect execution assumptions.
- **Status:** partly conceptual; expected-value comments are not assertions.

### [`examples/enhancedNumbers.bsh`](examples/enhancedNumbers.bsh)

Demonstrates unquoted integer/float tokens plus number and string helpers.

- **Key subparts:** arithmetic assignments, comparison-driven `if`, direct numeric arguments, string length/concatenation/indexing/splitting.
- **Depends on:** working startup math and string native libraries, which are not currently established.
- **Status:** demonstration/scaffold, not a passing test.

### [`examples/evalExample.bsh`](examples/evalExample.bsh)

Small demonstration of constructing command text and passing it to `eval`, including a dynamically named variable.

- **Depends on:** `handle_eval_statement` and two-stage variable expansion.
- **Status:** the narrowest candidate smoke script once the main build/startup path works; no assertions.

### [`examples/strNumExamples.bsh`](examples/strNumExamples.bsh)

Large expectation-oriented demonstration of numeric and string framework APIs.

- **Key subparts:** arithmetic/comparisons, logical negation, type probes, string operations, direct indexing, split loops, and while-loop behavior.
- **Depends on:** number/string primitives or optional native aliases and `!`, which is not registered in `core_operators.bsh`.
- **Status:** conceptual in several sections; comments saying “Expected” do not establish support.

### [`compile.sh`](compile.sh)

Canonical primary build wrapper: `gcc -fno-common bsh.c -o bsh -g`.

- **Produces:** ignored root executable `bsh` with debug symbols.
- **Tests:** compilation only.
- **Common mistakes:** The script has no strict shell flags and does not run the suite; use [`test.sh`](test.sh) for the acceptance gate.

### [`test.sh`](test.sh) and [`tests/`](tests/)

Build and acceptance harness. It performs a warnings-enabled build, creates an isolated `.test-home`, sets an explicit module path, bounds every `.bsh` suite with an alarm, and accepts only a zero exit with an explicit pass and no failure result; an empty filter match fails.

- **Suites:** core variables/expansion, functions/scopes/recursion, control flow, cDiesis lifecycle, compiler/runtime, standard library and shipped examples, cDiesis/RPN interop, the Bash language framework, Bash CLI routing, and Bash-to-cDiesis objects.
- **Discovery:** top-level `tests/*.bsh` and `tests/*.sh` are suites. Bash fixtures belong below `tests/fixtures/` so the runner does not execute them as standalone suites.
- **Common mistakes:** output before a timeout is buffered per suite; inspect the reported `/tmp/bsh_test_<name>.out` when a suite exits without a result line. Do not weaken silence or timeout into success.

### [`groupFramework.py`](groupFramework.py)

Debug-only bundler that writes ignored `allFramework.txt` by concatenating `.bshrc` and UTF-8 files found under `framework/`.

- **Key function:** `create_all_framework_file`; constants assume execution from the repository root.
- **Produces:** `allFramework.txt`, which MUST NOT be edited or committed as source.
- **Common mistakes:** `os.walk` order is not a runtime import order, and the generated header appends `.bsh` even when the relative filename already has that suffix.

### [`.gitmodules`](.gitmodules)

Pins the external Fayasm repository at `thirds/fayasm` through Git submodule metadata.

- **Depends on:** the superproject gitlink, which selects the exact Fayasm commit.
- **Common mistakes:** Do not edit code in the submodule as part of ordinary B[e]SH work or advance its commit implicitly. Review a submodule update as a dependency change.

### [`thirds/fayasm/`](thirds/fayasm/)

Pinned external experimental C99 WebAssembly runtime intended for the planned compiled-function/framework path. It is a dependency boundary, not current B[e]SH source.

- **Local instructions:** [`thirds/fayasm/AGENTS.md`](thirds/fayasm/AGENTS.md) applies to any explicit work inside the submodule; its [`thirds/fayasm/ROADMAP.md`](thirds/fayasm/ROADMAP.md) governs Fayasm's own priorities, not B[e]SH's integration sequence.
- **Relevant API:** module loading in [`thirds/fayasm/src/fa_wasm.h`](thirds/fayasm/src/fa_wasm.h); runtime, jobs, and host functions in [`thirds/fayasm/src/fa_runtime.h`](thirds/fayasm/src/fa_runtime.h) and [`thirds/fayasm/src/fa_job.h`](thirds/fayasm/src/fa_job.h).
- **Tests/build:** initialize with `git submodule update --init --recursive`; Fayasm's own `./build.sh` runs from inside the submodule and creates ignored dependency-local build output.
- **Common mistakes:** The submodule is experimental and in-process, not a security sandbox. No B[e]SH code links it yet; do not claim the roadmap is implemented.

### [`README.md`](README.md)

Defines public project identity, philosophy, terminology, intended syntax, and research questions.

- **Authority:** intent and user-facing explanation only; verify feature and command claims in code.
- **Common mistakes:** It discusses research intent and conceptual surfaces; verify implementation claims against source and tests.

### [`ROADMAP.md`](ROADMAP.md)

Owns planned work for stabilizing the interpreter and adding an opt-in Fayasm-backed pseudo-compiled execution path for BSH functions and framework modules.

- **Key subparts:** current architectural boundary; interpreter baseline; stable BSH IR; versioned host ABI; WebAssembly emission/execution; framework compilation; caching/specialization; differential tests and success gates.
- **Depends on:** current contracts in [`bsh.c`](bsh.c), framework semantics, and the pinned [`thirds/fayasm/`](thirds/fayasm/) API.
- **Common mistakes:** Planning is not shipped behavior. Do not skip IR/interpreter parity and compile raw function-body strings directly.

### [`TooBad.md`](TooBad.md)

Minimal problem ledger. It currently notes overuse of a third argument as a result parameter.

- **Authority:** active concern/backlog, not a specification.
- **Maintenance:** consolidate durable design decisions here or in a dedicated design document instead of scattering TODO claims through examples.

### [`gold/bsh-0.c`](gold/bsh-0.c)

Historical early C snapshot using simpler string-token arrays, global linked-list variables, fixed PATH arrays, and the earlier dispatcher.

- **Use:** archaeology and regression comparison only.
- **Common mistakes:** Never patch this file to fix the current executable and never copy its fixed-size value model into `bsh.c` without explicit design work.

### [`gold/bsh-1.c`](gold/bsh-1.c)

Historical version 0.8 snapshot introducing advanced tokens, dynamic operators, module lookup, structured data, and dot access.

- **Use:** compare prior design when current code is ambiguous.
- **Common mistakes:** Its unified operator-dispatch design differs from current per-handler registration; it is not generated and not built.

### [`gold/bsh-rs/`](gold/bsh-rs/)

Archived experimental Rust port, grouped here because the entire directory is outside the current project's implementation and validation scope.

- **Contents:** [`gold/bsh-rs/main.rs`](gold/bsh-rs/main.rs) is the single-file port experiment; [`gold/bsh-rs/Cargo.toml`](gold/bsh-rs/Cargo.toml) is its incomplete manifest; [`gold/bsh-rs/studies/logos_tokenizer.md`](gold/bsh-rs/studies/logos_tokenizer.md) records a tokenizer design note; `target/rust-analyzer/metadata/sysroot/Cargo.lock` is preserved tool metadata.
- **Use:** ignore during ordinary work. Inspect only for an explicitly requested historical or Rust-port task.
- **Common mistakes:** Do not run Cargo as project validation, import Rust dependencies/design choices into the C/BSH implementation, claim parity, or hand-edit preserved generated metadata.

### [`.gitignore`](.gitignore)

Ignores the primary `bsh` executable, framework bundle, and common compiled/debug artifacts.

- **Common mistakes:** Keep ignored build outputs out of commits and check `git status` after build/debug tooling.

### [`.vscode/launch.json`](.vscode/launch.json)

Defines a generic GDB launch configuration that asks for the program name.

- **Depends on:** a successful debug build and a VS Code GDB extension/environment.
- **Common mistakes:** This is editor convenience, not proof that GDB is installed or supported on every platform.

### [`guides/cdiesis.md`](guides/cdiesis.md)

Design document for the language-framework layer: cDiesis's architecture, the 17-opcode primitive set with its planned WebAssembly lowering, the type system, the object representation, load/unload semantics, the cross-language boundary, and the enumerated core capabilities (`CDS-REQ-0` … `CDS-REQ-8`) that `bsh.c` must provide before any of it can run.

- **Authority:** design and dependency analysis plus the verified cDiesis contract; production-readiness claims still require evidence beyond this research suite.
- **Maintenance:** keep the `CDS-REQ` table synchronized with **Known Gaps** here; when a requirement is implemented and verified, update both.

### [`guides/bash.md`](guides/bash.md)

Documents the boundary between native BSH and real Bash execution, direct CLI routing, the Bash language-framework API, captured-process limits, and the stateful Bash-to-cDiesis object bridge.

- **Authority:** current usage contract for `.sh`, `-c`, `-s`, `--bash`, `bash_eval`/`bash_run`/`bash_call`, and `cdiesis_*` Bash functions; verify behavior with the two `bash_*` suites.
- **Common mistakes:** Do not infer native Bash grammar in `.bsh` files or persistence across separate Bash framework subprocesses.

### [`guides/addToVSCode.md`](guides/addToVSCode.md)

Documents a `settings.json` association mapping `*.bsh` to shell script highlighting.

- **Scope:** editor syntax highlighting only; BSH is not guaranteed to be POSIX shell syntax.

### [`assets/eGuy.png`](assets/eGuy.png)

Project image displayed by the README.

- **Ownership:** documentation/branding asset only; it has no runtime role.

### [`LICENSE`](LICENSE)

MIT license for the repository. Preserve its notice in substantial copies.

## Features and Recurring Development Pitfalls

### Line-oriented C shell core — Experimental/scaffold

- **Behavior:** accepts a script path or interactive input and dispatches assignments, built-ins, user functions, expressions, and external commands.
- **Flow and owners:** `main` → `execute_script`/interactive loop → `process_line` in [`bsh.c`](bsh.c).
- **Constraints:** POSIX process and dynamic-loader APIs; fixed buffer/depth limits; file seeking for loops.
- **Tests and gaps:** core dispatch, variables, functions, scopes, and control flow are covered; several peripheral built-ins remain untested.

### Runtime-defined operators — Experimental/scaffold

- **Behavior:** framework scripts register symbols, precedence, associativity, grammatical form, and named BSH handlers.
- **Flow and owners:** [`.bshrc`](.bshrc) → [`framework/core_operators.bsh`](framework/core_operators.bsh) → `handle_defoperator_statement` → expression parser → `invoke_bsh_operator_handler`.
- **Constraints:** exact handler arity and result-holder mutation; dependencies on number/string modules.
- **Tests and gaps:** same-symbol prefix/postfix definitions still collide; startup and the operators used by the suite work end to end.

### Script functions and lexical scopes — Experimental/scaffold

- **Behavior:** `defunc` stores bodies and parameters; `function` is registered as an alias; invocation creates a local scope.
- **Flow and owners:** `handle_defunc_statement_advanced` → `UserFunction` list → `execute_user_function` → scope stack.
- **Constraints:** body lines are replayed with no backing input file; return/block state is global and must be restored.
- **Tests and gaps:** functions, scopes, returns, recursion, and stored-body loops are asserted in [`tests/core_functions.bsh`](tests/core_functions.bsh).

### Module imports — Experimental/scaffold

- **Behavior:** `import` resolves direct paths or dot/module names against `BSH_MODULE_PATH` and executes them in import mode.
- **Flow and owners:** `handle_import_statement` → `find_module_in_path` → `execute_script`.
- **Constraints:** relative default path, no `~` expansion, imported code mutates the live process.
- **Tests and gaps:** default startup depends on repository working directory.

### Dynamic native extensions — Known gap

- **Behavior:** C core can `dlopen` a library and call symbols through the fixed BSH ABI.
- **Flow and owners:** `loadlib`/`calllib` handlers in [`bsh.c`](bsh.c); scaffolding in [`framework/c_compiler.bsh`](framework/c_compiler.bsh).
- **Constraints:** native libraries are fully trusted; caller and callee must agree on buffers and ownership.
- **Tests and gaps:** repository runtime compilation does not write or compile source; startup assumes a library that is never created.

### Structured objects and name-mangled arrays — Experimental/scaffold

- **Behavior:** prefixed assignment flattens bracketed key/value data; property expansion reads mangled names; `echo` can reconstruct marked objects; arrays use a separate index-mangling convention.
- **Flow and owners:** `handle_assignment_advanced` → object/array helpers → scoped variables → `expand_variables_in_string_advanced`/`handle_echo_advanced`.
- **Constraints:** string-only leaves, fixed buffers, underscore collisions, current-scope metadata.
- **Tests and gaps:** parser is not full JSON; no round-trip tests; bracket object extensions and core arrays use different conventions.

### Loadable language frameworks — Experimental/scaffold

- **Behavior:** [`framework/lang.bsh`](framework/lang.bsh) registers named language frameworks, activates and deactivates them at runtime, and routes calls between them; [`framework/cdiesis.bsh`](framework/cdiesis.bsh), [`framework/rpn.bsh`](framework/rpn.bsh), and [`framework/bash.bsh`](framework/bash.bsh) use that lifecycle.
- **Flow and owners:** `import <framework>` → `lang_register` → `lang_load` → framework `on_load` hook → compile/execute → `lang_call`/`lang_eval` across frameworks → `lang_unload` → framework `on_unload` hook drops its tables.
- **Constraints:** unload is cooperative because the C core cannot undefine keywords, operators or functions; cross-language values are strings; object handles are opaque outside their owning framework.
- **Tests and gaps:** lifecycle, compiler/runtime, stdlib/examples, cross-language calls, and Bash subprocess behavior have focused suites; unload remains cooperative (`CDS-REQ-7`). Each Bash framework eval/call is process-isolated rather than a persistent shell session.

### Bash command-line and script support — Experimental

- **Behavior:** `.sh`, `-c`, `-s`, and explicit `--bash` command lines are forwarded to the installed Bash interpreter; `framework/bash.bsh` exposes captured Bash eval/call/run through the language manager; `framework/bash/cdiesis.sh` provides a persistent cDiesis object session to Bash.
- **Flow and owners:** `shell_main` → `delegate_to_bash` for direct CLI modes; `lang_eval` → `bash_eval` → `process` → `execute_external_command` for framework mode; Bash bridge → FIFO → `--bsh-stdin` → imported request scripts for cDiesis objects.
- **Constraints:** Bash must be on `PATH`; capture is capped at `INPUT_BUFFER_SIZE - 1` and merges stdout/stderr; bridge processes and temporary files are trusted local execution, not isolation.
- **Tests and gaps:** [`tests/bash_framework.bsh`](tests/bash_framework.bsh) and [`tests/bash_cdiesis.sh`](tests/bash_cdiesis.sh) cover the supported paths. Shebang detection for non-`.sh` filenames and persistent state across `lang_eval` calls are not provided.

### Pitfall: trusting startup success messages

- **Symptom / wrong assumption:** `.bshrc` reports that `bshmath` compiled or loaded and agents infer arithmetic works.
- **Cause and invariant:** `def_c_lib` simulates success without writing or compiling, then calls `loadlib` on a missing file. Only filesystem output, loader status, and a focused call prove success.
- **Risk area:** [`.bshrc`](.bshrc), [`framework/c_compiler.bsh`](framework/c_compiler.bsh), `handle_loadlib_statement`.
- **Safe pattern / regression check:** implement and verify source creation/compilation/loading as one path; then call a known ABI function and inspect `LAST_LIB_CALL_STATUS`/output.
- **Status:** active known bug/scaffold.

### Pitfall: unsequenced argument indexing

- **Symptom / wrong assumption:** external or library arguments point at the wrong buffer entry or behavior changes by compiler.
- **Cause and invariant:** expressions such as `args[arg_current++] = arg_buffer[arg_current-1]` both modify and read an index without sequencing.
- **Risk area:** `process_line` and external-call preparation in [`bsh.c`](bsh.c).
- **Safe pattern / regression check:** fill the current storage slot, assign its address, then increment in separate statements; compile with `-Wall -Wextra`.
- **Status:** active compiler warnings and regression risk.

### Pitfall: treating result-variable parameters as normal returns

- **Symptom / wrong assumption:** handlers appear to return empty values or mutate the wrong scope.
- **Cause and invariant:** BSH framework functions commonly receive the destination variable name and assign indirectly; [`TooBad.md`](TooBad.md) identifies overuse of this convention as a design concern.
- **Risk area:** operator invocation, number/string/type frameworks, and examples.
- **Safe pattern / regression check:** preserve current arity until a coordinated API redesign updates all callers/handlers and tests both local and caller-visible scope behavior.
- **Status:** deliberate current convention with an active design concern.

## Interface Ownership Map

- Executable entry points `./bsh` and `./bsh <script.bsh>` → `main` in [`bsh.c`](bsh.c); `./bsh <script.sh>`, `./bsh -c`, `./bsh -s`, and `./bsh --bash ...` → `delegate_to_bash`.
- Assignment `$name = expression` and `$array[index] = value` → `process_line` / `handle_assignment_advanced`.
- Built-ins `echo`, `defkeyword`, `defoperator`, `if`, `else`, `while`, `defunc`, `loadlib`, `calllib`, `import`, `update_cwd`, `eval`, `process`, and `exit` → dispatch table expressed by the conditional chain in `process_line`.
- Alias `function` → `defkeyword defunc function` in [`.bshrc`](.bshrc).
- User-defined command names → `UserFunction` registry / `execute_user_function`.
- Unknown command names → `PATH` resolution / `execute_external_command`.
- Standard operator surface → registrations in [`framework/core_operators.bsh`](framework/core_operators.bsh); C parser owns grammar and dispatch, named BSH functions own semantics.
- Module names → `handle_import_statement` / `find_module_in_path`; default modules live in [`framework/`](framework/).
- Native extension surface → `loadlib` and `calllib`; ABI defined under **Critical Implementation Contracts**.
- Language-framework lifecycle and cross-language calls → `lang_register`, `lang_load`, `lang_unload`, `lang_call`, `lang_eval`, `lang_export` in [`framework/lang.bsh`](framework/lang.bsh).
- Bash language and cDiesis bridge → [`framework/bash.bsh`](framework/bash.bsh) and [`framework/bash/cdiesis.sh`](framework/bash/cdiesis.sh); full usage contract in [`guides/bash.md`](guides/bash.md).
- cDiesis compile/run/introspect surface → `cds_compile`, `cds_run`, `cds_call`, `cds_dump_ops` in [`framework/cdiesis.bsh`](framework/cdiesis.bsh); the 17 opcodes and their executor are owned by [`framework/cdiesis/ops.bsh`](framework/cdiesis/ops.bsh).

## Build, Run, Test, Debug, and Release

Primary prerequisites: a POSIX-like environment with a C compiler, standard C/POSIX headers, and dynamic-loader support. Framework-native extensions additionally assume a compiler capable of shared libraries, but that workflow is incomplete.

```sh
git submodule update --init --recursive
./compile.sh
./test.sh
./bsh
./bsh examples/evalExample.bsh
./bsh -c 'printf "hello from Bash\n"'
./bsh examples/bash/cdiesis_objects.sh
python3 groupFramework.py
git diff --check
```

- `git submodule update --init --recursive` materializes the pinned Fayasm dependency. It contacts the configured Git remote when objects are absent and does not integrate or build Fayasm into B[e]SH.
- `./compile.sh` is the canonical debug build. `./test.sh` performs the stricter warnings-enabled build, creates an isolated `HOME`, sets `BSH_MODULE_PATH`, bounds every suite, and requires an explicit result line.
- `./bsh` starts native BSH interactively; `./bsh <path.bsh>` runs a BSH script. Startup executes a user `$HOME/.bshrc` preferentially, so use an isolated environment when testing repository startup behavior. `.sh`, `-c`, `-s`, and `--bash` route to Bash without BSH startup. `--bsh-stdin` is the prompt-free native input mode used by adapters, not a Bash mode.
- `python3 groupFramework.py` mutates ignored `allFramework.txt`; it is a debug inspection aid, not a build step.
- Linting, formatting, static analysis, benchmarks, packaging, release, and deployment workflows are not defined. The current warnings-enabled suite build is clean on the verified macOS toolchain.

Debugging: [`.vscode/launch.json`](.vscode/launch.json) provides a generic GDB launcher. There is no verified release process or versioning policy; do not infer one from source header comments.

## Test Ownership Map

- C compilation and warnings → [`compile.sh`](compile.sh) and the stricter build in [`test.sh`](test.sh).
- Startup/module/operator registration → every suite starts through the isolated repository [`.bshrc`](.bshrc).
- Evaluation and two-stage expansion → [`examples/evalExample.bsh`](examples/evalExample.bsh), demonstration only.
- Functions, scopes, and loops → [`tests/core_functions.bsh`](tests/core_functions.bsh) and [`tests/core_control.bsh`](tests/core_control.bsh).
- Numeric operators → the core and cDiesis suites; native ABI compilation/calls still need a focused automated suite.
- Basic strings and array indexing → [`tests/core_variables.bsh`](tests/core_variables.bsh) plus the cDiesis stdlib suite; splitting-specific behavior remains demonstration-only.
- Object flatten/stringify round trips → no focused fixture or test.
- Module path resolution is exercised by suite imports; external command capture, dynamic loading failures, extreme nesting limits, and global cleanup still lack focused tests.
- Language-framework lifecycle, cDiesis compilation/execution, stdlib/examples, and cross-language calls → [`tests/cdiesis_lifecycle.bsh`](tests/cdiesis_lifecycle.bsh), [`tests/cdiesis_runtime.bsh`](tests/cdiesis_runtime.bsh), [`tests/cdiesis_stdlib.bsh`](tests/cdiesis_stdlib.bsh), and [`tests/cdiesis_interop.bsh`](tests/cdiesis_interop.bsh).
- Bash language lifecycle/evaluation/script execution → [`tests/bash_framework.bsh`](tests/bash_framework.bsh); Bash CLI syntax and persistent cDiesis object access → [`tests/bash_cdiesis.sh`](tests/bash_cdiesis.sh).

When fixing behavior, add an automated test harness if practical. Until one exists, make focused scripts fail observably rather than relying only on printed “Expected” comments.

## Data, Security, Privacy, and Compatibility Boundaries

- Canonical project source is tracked root C, BSH, configuration, and documentation content outside [`gold/`](gold/). The root `bsh`, `allFramework.txt`, shared objects, `/tmp/bsh_compile_cache`, and `.bsh_history` are derived/runtime data.
- Shell variables live in process memory and are freed by scope/cleanup routines; there is no persistence, migration, backup, or restore mechanism.
- Imported BSH files, startup scripts, external executables, and loaded libraries execute with the user's privileges. There is no sandbox, signature verification, capability restriction, or trust separation.
- Bash scripts and command strings, Bash framework subprocesses, and the Bash/cDiesis bridge execute with the user's privileges. The bridge uses a private temporary directory and FIFOs for transport, but this is an IPC mechanism, not a sandbox.
- `$HOME/.bshrc` takes precedence over the repository fallback. Tests MUST avoid accidentally executing a real user startup file when reproducibility or safety matters.
- Never commit credentials or place secret values in `.bshrc`, examples, generated bundles, command output, or debug logs. External-command capture merges stderr with stdout and may store it in variables.
- Validate lengths against fixed buffers and recursion/nesting/argument limits before copying. Maintain null termination on every truncated string path.
- The native ABI passes caller-owned argument pointers and an output buffer to untrusted code. Loaded functions MUST honor `buffer_size`, null-terminate output, and not retain pointers past the call.
- No compatibility or deprecation policy is defined. Treat existing script syntax and ABI as research interfaces; describe breaking changes explicitly and update all in-repository callers in the same change.
- Archived experiments and snapshots under [`gold/`](gold/) have no compatibility promise with the current implementation.
- Fayasm runs in-process and is experimental; planned compiled BSH code must receive shell capabilities only through explicit, validated host imports. Treat emitted modules as code, not untrusted sandboxed data.

## Current Status and Known Gaps

### Shipped

- Repository source, research documentation, historical snapshots, framework modules, and examples are present under the ownership described above.
- The C source contains implementations for the documented core dispatch and extensibility mechanisms; this is a source-presence claim, not a working-release claim.
- Fayasm is pinned as a submodule dependency; no B[e]SH integration is shipped.

### Experimental / Scaffold

- The entire primary shell is research-stage.
- Script-defined operators, framework math/string/type support, runtime C compilation, structured objects, arrays, loop/function behavior, and optional filesystem extensions require focused validation.
- The language-framework layer ([`framework/lang.bsh`](framework/lang.bsh), cDiesis, RPN, and Bash) is an experimental implementation with focused lifecycle, runtime, stdlib/example, interop, Bash subprocess, and Bash/cDiesis bridge coverage.
- [`gold/bsh-rs/`](gold/bsh-rs/) is archived and excluded from current project scope.

### Known Gaps

- Compiler portability beyond the verified warnings-clean macOS toolchain remains untested.
- Runtime native compilation is opt-in and not covered by the current suite; startup intentionally uses built-in primitives.
- Prefix/postfix registrations for identical operator strings overwrite each other.
- Native string and filesystem libraries are absent; number/string operations have a verified `prim` fallback, while the optional filesystem framework remains untested.
- No CI, formatter/linter configuration, packaging, or release workflow exists.
- The language layer cannot truly remove syntax: the C core has no `undefkeyword`, `undefoperator`, or function removal, so `lang_unload` is cooperative. Full requirement list: `CDS-REQ-0` … `CDS-REQ-8` in [`guides/cdiesis.md`](guides/cdiesis.md).
- Native BSH is not Bash-compatible. Bash support depends on an installed `bash`; framework calls are isolated subprocesses, capture merges stderr/stdout and is limited to one BSH value, and automatic CLI routing uses the `.sh` suffix rather than shebang inspection.

### Planned

- Complete the remaining Phase 0 measurement and dependency-validation work, introduce stable BSH IR, define a narrow host ABI, and compile supported functions/frameworks to in-memory WebAssembly executed by Fayasm. Follow the phased gates in [`ROADMAP.md`](ROADMAP.md); none of the Fayasm path is implemented yet.

## Task Start and Handoff Checklist

1. Read this file, inspect `git status`, and identify whether the task targets current C/BSH code, documentation, or explicitly requested historical material.
2. Read the owning file subsections, relevant source, framework handlers, examples, and critical contracts before editing.
3. Trace cross-file names and arities: built-in dispatch, operator registration, handler parameters, result variables, module aliases, native symbols, and mangled data names.
4. Ignore [`gold/`](gold/) unless the user explicitly requests historical or archived-port work.
5. Treat [`thirds/fayasm/`](thirds/fayasm/) as a pinned dependency boundary; read its local instructions before explicit submodule work and never advance it accidentally.
6. Run the narrowest exact build/check available; capture existing blockers separately from regressions introduced by the task.
7. Update source docs, roadmap phase/status, known gaps, interface/test maps, and this handbook whenever durable facts changed.
8. Validate local Markdown links, run `git diff --check`, review the full diff, and report tests run, tests not run, generated artifacts, and remaining gaps.
