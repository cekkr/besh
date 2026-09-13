# B[e]SH — AI Agent Reference

This is the fast-access operational reference for the Basic [extensible] Shell (B[e]SH), an early research shell for experimenting with a small C execution core and language behavior assembled at runtime from BSH scripts. All C sources live in [`src/`](src/): the monolithic core is [`src/bsh.c`](src/bsh.c), and the `besh_*` files beside it hold optional features only — the bytecode path in [`src/besh_mem.c`](src/besh_mem.c), [`src/besh_wasm.c`](src/besh_wasm.c) and [`src/besh_jit.c`](src/besh_jit.c), and the `.hu` language-description layer in [`src/besh_hu.c`](src/besh_hu.c). The project is those, together with [`.bshrc`](.bshrc) and [`framework/`](framework/). The pinned [`thirds/fayasm/`](thirds/fayasm/) WebAssembly runtime is compiled into the executable. It is not intended to replace a production Unix shell. **[`gold/bsh-rs/`](gold/bsh-rs/) is an archived experimental Rust port, not part of the project implementation; ignore it during normal discovery, changes, builds, and validation.**

## Read This First

Use this source-of-truth order when facts conflict:

1. [`LICENSE`](LICENSE) — legal terms for all repository content.
2. Executable behavior and interfaces in [`src/bsh.c`](src/bsh.c), [`src/bsh.h`](src/bsh.h), [`src/besh_mem.c`](src/besh_mem.c), [`src/besh_wasm.c`](src/besh_wasm.c), [`src/besh_jit.c`](src/besh_jit.c), [`src/besh_hu.c`](src/besh_hu.c), [`.bshrc`](.bshrc), and [`framework/`](framework/), plus a successful [`test.sh`](test.sh) run or focused execution check.
3. [`compile.sh`](compile.sh) and other root build/tool configuration — exact declared workflows for the project implementation.
4. [`README.md`](README.md) — project intent, vocabulary, and research goals; implementation claims in it must be checked against current source.
5. [`ROADMAP.md`](ROADMAP.md) — planned B[e]SH work and the Fayasm integration sequence; roadmap entries do not prove implementation.
6. [`guides/bytecode.md`](guides/bytecode.md), [`guides/cdiesis.md`](guides/cdiesis.md), and [`guides/bash.md`](guides/bash.md) — usage contracts for shipped subsystems; verify feature claims against source and tests.
7. [`TooBad.md`](TooBad.md), examples, studies, and comments marked conceptual — known concerns, demonstrations, and design exploration, not proof of working behavior.
8. [`gold/`](gold/) and Git history — historical reference only; neither overrides the current implementation.

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
- **Startup order creates the language:** [`main`](src/bsh.c) calls `initialize_shell`, then executes `$HOME/.bshrc` when present or the repository [`.bshrc`](.bshrc) as a fallback. Most operators do not exist before startup scripts call `defoperator`; parser/tokenizer changes must be checked both before and after startup registration.
- **Operator definition and handler signatures are coupled:** `handle_defoperator_statement`/`add_operator_definition` record symbol, grammatical type, precedence, associativity, and BSH handler. `invoke_bsh_operator_handler` requires exactly `operand_count + 2` parameters: operator symbol, operands, and result-holder variable name. Keep registrations in [`framework/core_operators.bsh`](framework/core_operators.bsh) aligned with handler definitions and downstream number/string functions.
- **Operator definitions are keyed by symbol *and* grammatical form:** `add_operator_definition` matches `op_str` together with `op_type_prop`, so prefix and postfix `++`/`--` coexist as separate entries. Position-sensitive callers must therefore use `get_operator_definition_typed` (one form) or `get_operator_definition_after_operand` (infix, then postfix, then ternary opener); plain `get_operator_definition` returns the first registration for a symbol and is only correct where the form does not matter. `besh_unary_op_takes_variable_name` is the single place that says which unary operators receive a variable *name* to mutate — the expression parser special-cases them and the compiler refuses them, so both paths read the same predicate. A `TERNARY_SECONDARY` (or `OP_TYPE_NONE`) registration is allowed to name no handler, because the parser consumes it as a delimiter; `:` is registered that way so the tokenizer emits a token for it at all.
- **Input is read as logical lines, not physical ones:** `besh_read_logical_line` joins physical lines for as long as a double-quoted string is open, so a literal can span lines and the newline is part of the value. Every reader must use it — `execute_script`, the `--bsh-stdin` adapter and the interactive loop all do — because a caller that uses raw `fgets` would cut a statement in half. Downstream code needs no change: `advanced_tokenize_line`, `besh_split_line_into_statements`, `besh_line_needs_statement_split` and `count_unquoted_brace_delta` already treat a quoted region as opaque. `while`-loop replay still works because `ftell` is taken before the logical line is read.
- **A bare expression echoes only at the prompt:** `bsh_at_interactive_prompt` is true solely while a line typed interactively is executing. `execute_script` and `run_user_function_body` save, clear and restore it, so an imported module and a function body called from the prompt stay silent. There are four echo sites in `process_line` (standalone prefix, standalone postfix, standalone binary, general expression) and all four must be gated together; `LAST_OP_RESULT` is set regardless of mode.
- **Quoted arguments must be unescaped before expansion:** a `TOKEN_STRING` argument keeps its quotes in `tok->text`. `expand_token_argument` is the one helper that handles both cases, and positional built-in arguments go through it — expanding `tokens[i].text` directly makes `libloaded "$alias" out` look up a library literally named `"demolib"`.
- **Scopes are stack-owned:** `enter_scope`, `leave_scope`, `get_variable_scoped`, and `set_variable_scoped` define lexical lookup. Function calls create a scope and must clean it on return. New paths must not write around these functions or leak local variables into global scope.
- **Array and object storage is name-mangled:** arrays use `<base>_ARRAYIDX_<expanded-index>`; object properties use underscore-separated names and `<base>_BSH_STRUCT_TYPE` metadata. Change the mangling only with assignment, expansion, property helpers, stringification, and round-trip checks updated together.
- **The BSH object format is not general JSON:** `object:`/`json:` assignment currently enters the same handwritten parser, which accepts bracketed quoted key/value pairs and nested brackets. Do not claim full JSON support or silently feed untrusted general JSON into it.
- **External commands execute directly:** `find_command_in_path_dynamic` resolves `PATH`; `execute_external_command` uses `fork`/`execv`, optionally captures both stdout and stderr into one fixed-size buffer, trims trailing newlines, and writes `LAST_COMMAND_STATUS`. Do not introduce shell-string execution as a shortcut; preserve argument boundaries.
- **Bash compatibility delegates instead of emulates:** CLI `.sh`, `-c`, `-s`, and `--bash` modes execute the installed `bash`; native `.bsh` input still uses the BSH parser. [`framework/bash.bsh`](framework/bash.bsh) reaches Bash through the argv-preserving `process` primitive. Do not claim that native BSH syntax is Bash-compatible or add partial Bash grammar to the BSH tokenizer.
- **The Bash/cDiesis bridge is stateful:** [`framework/bash/cdiesis.sh`](framework/bash/cdiesis.sh) keeps one `bsh --bsh-stdin` process alive through private FIFOs. Object handles and mutations survive bridge calls but become invalid at `cdiesis_close`; values cross through private files, while class/method/field names are identifier-validated.
- **Dynamic-library ABI is fixed:** `calllib` expects a symbol compatible with `int func(int argc, char *argv[], char *output_buffer, int buffer_size)`. `LAST_LIB_CALL_STATUS` and `LAST_LIB_CALL_OUTPUT` are the BSH-facing result channel. Arbitrary C signatures are unsupported and unsafe.
- **File-backed loops depend on seeking:** while-loop replay uses `ftell`/`fseek` through block frames. `execute_user_function` passes `NULL` as its input source, so do not assume identical loop behavior in interactive input, script files, imports, and stored function bodies without focused verification.
- **The interpreter is the reference, the bytecode path is opt-in-by-default:** `run_user_function_body` in [`src/bsh.c`](src/bsh.c) offers each call to `besh_jit_run_function` first and replays the stored source lines only when it answers `BESH_RUN_FALLBACK`. Any behavior difference between the two is a bug in the compiler, never a new feature. [`tests/bytecode_differential.bsh`](tests/bytecode_differential.bsh) is the guard.
- **Conditions are decided in C, not by operator handlers:** `handle_if_statement_advanced` uses `besh_compare_values` for a three-token comparison and the expression evaluator otherwise; `handle_while_statement_advanced` uses a different rule again, and the two disagree on the case of `false`. `besh_compare_values` and `besh_value_is_true` are shared with the `cond`/`truthy` host imports so both tiers make the same choices. Changing either handler means changing the matching branch in `compile_one`.
- **The `besh.v1` host ABI is the only channel into the shell:** compiled code receives opaque `i32` handles, never a `Variable *`, `UserFunction *`, or scope-stack pointer. Imports, handle encoding, the reserved abort word at memory offset 0, and the deoptimisation guard are specified in [`guides/bytecode.md`](guides/bytecode.md). Fayasm resolves an imported memory during `fa_Runtime_attachModule`, so the memory binding must be established *before* attaching.
- **Built-ins are either modelled or handed back:** `is_interpreter_builtin` in [`src/besh_jit.c`](src/besh_jit.c) lists the commands compiled code routes to `process_line` through the `raw` import. It must stay in step with the dispatch chain in `process_line`; a built-in added to one and not the other changes behavior inside compiled functions only.
- **The heap is the WebAssembly memory:** [`src/besh_mem.c`](src/besh_mem.c) owns one contiguous buffer bound to Fayasm as `besh.v1`/`memory`. It must not move while compiled code runs, so `besh_mem_lock` refuses growth during execution. `coalesce_forward` rewrites its argument's header and must only ever be called on a free block; `besh_mem_realloc` must split the neighbour it absorbs rather than taking all of it.
- **Cached modules are invalidated wholesale:** `defoperator` and `defkeyword` drop every unit, redefinition drops one, and invalidation is refused while a module is executing. There is no deterministic cache key yet, so anything that changes how source resolves must call `besh_jit_invalidate_all`.
- **Module lookup is process-relative:** `BSH_MODULE_PATH` defaults to `./framework:~/.bsh_framework:/usr/local/share/bsh/framework`. The C code splits these strings but does not expand `~`; running outside the repository can prevent root `.bshrc` imports. Set `BSH_MODULE_PATH` explicitly in portable tests.

## Architecture and Data/Control Flow

Primary implementation:

`main` → `initialize_shell` → `$HOME/.bshrc` or [`.bshrc`](.bshrc) → `import` framework modules → `defoperator`/`defunc` registration

`script or stdin line` → `process_line` → `advanced_tokenize_line` → assignment / built-in / user function / external command / expression parser

`bsh -c` / `bsh -s` / `bsh *.sh` / `bsh --bash ...` → installed `bash` with the original argv boundaries

`expression` → `parse_expression_recursive` → `OperatorDefinition` lookup → `invoke_bsh_operator_handler` → BSH handler → optional `calllib` → result-holder variable

`assignment` → `evaluate_expression_from_tokens` → scoped string variable, array name mangling, or `object:` flattening → expansion / `echo` stringification

The process boundary is the external command launched by `fork`/`execv`. The native-code trust boundary is a loaded shared library invoked through the fixed BSH C ABI. Imported `.bsh` files execute in the same process and mutate global registries/state; they are trusted code, not data.

Compiled path (implemented; see [`guides/bytecode.md`](guides/bytecode.md)):

`function body` → `besh_split_line_into_statements` → IR in [`src/besh_jit.c`](src/besh_jit.c) → `src/besh_wasm.c` module bytes → `wasm_module_init_from_memory` → `fa_Runtime_attachModule` → `fa_Runtime_executeJob` → `besh.v1` host imports → existing scoped variables, operators, primitives and the shared heap

`heap pointer` → `mem` builtin or a compiled `i32.load`/`i32.store` → the one buffer owned by [`src/besh_mem.c`](src/besh_mem.c) and bound to Fayasm as `besh.v1`/`memory`

Not implemented: direct `call` between compiled functions in one module, a deterministic cache key, disk caching, and typed specialization beyond the integer kernel tier. See [`ROADMAP.md`](ROADMAP.md).

## Linked Source Tree and File Reference

### [`src/bsh.c`](src/bsh.c)

Owns the primary shell executable: data structures, tokenizer, runtime operator registry, expression evaluator, dispatcher, scopes, blocks, module and executable resolution, dynamic libraries, structured values, and entry point. **The core is monolithic — it is this one file.** New core behavior goes here; a new `besh_*.c` is for an optional feature only. Framework semantics belong in `.bsh` files, not here.

- **Key functions and subparts:** `main` and `initialize_shell` bootstrap scopes, paths, variables, and startup scripts; `advanced_tokenize_line` emits tokens using registered operators; `process_line` dispatches all line forms; `parse_operand`, `parse_expression_recursive`, and `evaluate_expression_from_tokens` evaluate expressions; `handle_*` functions implement built-ins and control flow; `enter_scope`/`leave_scope` and scoped variable helpers own lifetime; `execute_script`, `execute_external_command`, and `execute_user_function` cross execution contexts; object parse/stringify helpers own the flattened representation.
- **Bash/process additions:** `delegate_to_bash` owns CLI routing for Bash entry points; `handle_process_statement` captures a child launched with distinct argv entries; `--bsh-stdin` runs prompt-free native BSH input for stateful adapters. `BSH_EXECUTABLE` exposes the resolved current binary to scripts.
- **Called by / depends on:** built by [`compile.sh`](compile.sh); loads [`.bshrc`](.bshrc) and modules in [`framework/`](framework/); uses POSIX process APIs and `dlfcn`.
- **Bytecode integration:** `run_user_function_body` offers every call to `besh_jit_run_function` before replaying source lines; `besh_prim_dispatch`, `besh_split_line_into_statements`, `besh_line_needs_statement_split`, `besh_compare_values`, `besh_value_is_true`, `execute_user_function_values` and `besh_dispatch_command_values` are the interfaces the compiler consumes. `prim` carries the 32-bit integer operations (`iadd` … `ige`, `inot`) the compiler lowers natively.
- **Tests:** [`test.sh`](test.sh) builds with warnings enabled and runs the isolated suites under [`tests/`](tests/).
- **Common mistakes:** Do not add an operator only to C or only to a framework file; do not bypass scoped setters; do not assume capture keeps stderr separate; do not treat comments describing intended behavior as implemented. Do not change a condition handler without changing the matching branch in `compile_one`.

### [`src/bsh.h`](src/bsh.h)

The core's interface to the optional modules, and nothing more: the constants, tokenizer/operator/function types and the handful of `extern` globals and functions that [`src/besh_mem.c`](src/besh_mem.c), [`src/besh_wasm.c`](src/besh_wasm.c), [`src/besh_jit.c`](src/besh_jit.c) and [`src/besh_hu.c`](src/besh_hu.c) actually reach. Everything the core uses only for itself — scopes, blocks, path lists, dynamic libraries, the expression-parser context, the `handle_*` prototypes — is declared inside [`src/bsh.c`](src/bsh.c), not here.

- **Ownership:** [`src/bsh.c`](src/bsh.c) defines every global declared `extern` here; the header defines none.
- **Direction:** dependencies point one way. An optional module includes `bsh.h`; the core includes no `besh_*.h` except [`src/besh_jit.h`](src/besh_jit.h) and [`src/besh_hu.h`](src/besh_hu.h), for the hooks it calls.
- **Common mistakes:** the header is a budget, not a dumping ground — before adding a declaration, check that an optional module needs it, otherwise it belongs in `src/bsh.c`. `INPUT_BUFFER_SIZE` is defined here and `BESH_ARG_SIZE` in [`src/besh_mem.h`](src/besh_mem.h) is derived from it, so the `mem` argument vector cannot drift from the shell's own buffers — change one and you have changed both.

### [`src/besh_mem.h`](src/besh_mem.h) and [`src/besh_mem.c`](src/besh_mem.c)

Optional feature. The linear heap: pointers, blocks, vectors, heap strings, and the `mem` built-in. The same bytes are handed to Fayasm as an imported WebAssembly memory, so a pointer means the same thing in interpreted BSH, in C, and inside emitted bytecode.

- **Key functions:** `besh_mem_init`/`besh_mem_shutdown`, `besh_mem_alloc`/`besh_mem_realloc`/`besh_mem_free`, `besh_mem_lock`, `besh_vec_*`, `besh_str_*`, `besh_mem_command`, `besh_mem_produces_value`.
- **Layout:** an 8-byte block header before every payload; a vector payload starts with `len`, `cap`, `esz`, `kind`. Address 0 is null and the first word of the heap is reserved for the compiled path's abort flag.
- **Tests:** [`tests/mem_heap.bsh`](tests/mem_heap.bsh).
- **Common mistakes:** `coalesce_forward` marks its argument free, so calling it on a live block loses that allocation; `besh_mem_realloc` must split the neighbour it absorbs or a small vector will swallow the rest of the heap. Growth is refused while compiled code runs — that is deliberate, not a bug.

### [`src/besh_wasm.h`](src/besh_wasm.h) and [`src/besh_wasm.c`](src/besh_wasm.c)

Optional feature. A WebAssembly binary writer: LEB128, a growable byte buffer, instruction shorthands, and a module builder that emits the type, import, function, export and code sections. It knows nothing about BSH.

- **Key functions:** `besh_buf_*`, `besh_emit_*`, `besh_wasm_new`, `besh_wasm_type`, `besh_wasm_import_func`, `besh_wasm_import_memory`, `besh_wasm_add_func`, `besh_wasm_add_local`, `besh_wasm_code`, `besh_wasm_export_func`, `besh_wasm_finish`.
- **Tests:** exercised through every compiled function; `bytecode dump <function>` prints the bytes.
- **Common mistakes:** imported functions occupy the low function indices, so every import must be declared before the first `besh_wasm_add_func`; the builder sets an overflow flag rather than aborting, and `besh_wasm_finish` returns false for it.

### [`src/besh_jit.h`](src/besh_jit.h) and [`src/besh_jit.c`](src/besh_jit.c)

Optional feature. The compiled path: IR, statement and expression compilation, the kernel/general tier decision, WebAssembly emission, the `besh.v1` host imports, the Fayasm runtime pool, and the `bytecode` and `mem` built-ins.

- **Key functions:** `besh_jit_run_function`, `unit_compile`, `unit_build_ir`, `compile_block`/`compile_one`/`compile_expr_range`, `block_is_native`, `unit_emit`, `emit_stmt`/`emit_value`/`emit_int`/`emit_condition`, `unit_acquire_runtime`, `host_*` for each import, `handle_bytecode_statement`, `handle_mem_statement`.
- **Contracts:** full specification in [`guides/bytecode.md`](guides/bytecode.md) — handle encoding, import table, the reserved abort word, the kernel guard, tier rules, invalidation.
- **Tests:** [`tests/bytecode_differential.bsh`](tests/bytecode_differential.bsh) and the tier assertions in [`tests/strlib_list.bsh`](tests/strlib_list.bsh).
- **Common mistakes:** every unit keeps its own Fayasm runtime pool so re-entrant and recursive calls never share a job; a module currently executing must not be freed, which is why invalidation is refused during execution. `BSH_COMPILE_DEBUG=1` explains why a function did not reach the tier you expected.

### [`src/besh_hu.h`](src/besh_hu.h) and [`src/besh_hu.c`](src/besh_hu.c)

Optional feature. The `.hu` language-description language: a lexer for its sentences, the sentence parser that turns them into rules, the region recogniser that matches text against a grammar, generation-checked tree handles, and the `hu` built-in. A `.hu` script describes *some other* language; it never changes BSH's own syntax, registers no keyword and no operator.

- **Key functions:** `besh_hu_init`/`besh_hu_shutdown`, `hu_lex`, `hu_match_term`, `hu_apply_clause`/`hu_apply_sentence`/`hu_parse_source`, `hu_plan`, `hu_match`/`hu_match_inner`/`hu_child_extent`, `hu_const_match`, `hu_literal_at`/`hu_find_top`/`hu_find_close`/`hu_split`, `hu_handle_parse`, `besh_hu_command`, `besh_hu_produces_value`, `handle_hu_statement`.
- **Contracts:** full specification in [`guides/hu.md`](guides/hu.md) — the term and alias tables, quote-style meaning, list semantics, the recogniser's rules, handles, and the design limits. Four of those contracts are load-bearing and easy to break: alternatives backtrack while extents commit; `IF HAS` prunes but never decides; nothing is dropped in silence (an ordered sequence must consume its region and a leaf must match all of its own); a failure keeps the *deepest* expectation, which is what makes `hu error` useful.
- **Argument handling:** `define` and `rule` take their description argument verbatim — a quoted literal there is unescaped but **not** variable-expanded, because `$field` in a grammar means a field. The `raw_arg` column of `g_subs` is the single place that says so, and the subcommand is therefore expanded before its own arguments.
- **Tests:** [`tests/hu_language.bsh`](tests/hu_language.bsh).
- **Common mistakes:** Do not describe `.hu` as a language framework — [`framework/lang.bsh`](framework/lang.bsh) clients execute source, `.hu` describes it. Fields are global to a grammar, so one field cannot carry two conflicting `IS` rules; `hu_plan` takes the first. A field that must be followed by a sibling needs an extent rule (`IS`, `INSIDE`, `ENDS WITH`); `STARTS WITH` alone gives none, and today that surfaces as a parse failure rather than a load error. Trees are freed by hand — `hu free` — and a handle held past it is refused by generation, not by luck.

### [`.bshrc`](.bshrc)

Repository fallback startup script. It sets `PS1`, aliases `function` to `defunc`, imports the core frameworks, selects built-in primitives unless native aliases are already loaded, and defines convenience functions.

- **Key functions and subparts:** imports `c_compiler`, `number`, `type`, `string`, then `core_operators`; selects the optional `bshmath` alias; defines `is_empty`, `scope_test`, and `for_loop`.
- **Called by / depends on:** selected by `main` only when `$HOME/.bshrc` does not exist; module resolution comes from `BSH_MODULE_PATH`.
- **Tests:** every suite uses an isolated `HOME` and the repository fallback startup script.
- **Common mistakes:** startup deliberately does not compile native libraries; numeric and string framework behavior falls back to `prim`.

### [`framework/core_operators.bsh`](framework/core_operators.bsh)

Registers arithmetic, comparison, increment/decrement, ternary, and dot operators and defines their BSH handlers.

- **Key functions and subparts:** `defoperator` registrations carry precedence/associativity; `bsh_op_add_or_concat` selects string or number behavior; arithmetic/comparison handlers delegate to `number.bsh`; increment handlers expect a variable name; `:` is registered as a handler-less `TERNARY_SECONDARY` delimiter so the tokenizer emits it; `bsh_op_ternary_handler` selects with `prim truthy`; `bsh_op_dot_handler` joins with a literal dot and only special-cases an empty left operand.
- **Depends on:** [`framework/type.bsh`](framework/type.bsh), [`framework/number.bsh`](framework/number.bsh), and [`framework/string.bsh`](framework/string.bsh).
- **Tests:** [`tests/core_operators.bsh`](tests/core_operators.bsh) asserts every registered form — precedence, associativity, both `++`/`--` forms, the ternary including nesting, and `defoperator` at runtime.
- **Common mistakes:** Handler arity must match the C dispatcher. Do not print from a handler: every use of the operator would emit that line. The `[cite: 124]` text is stray prose, not syntax or evidence.

### [`framework/mem.bsh`](framework/mem.bsh)

Names for the heap layout: the vector header offsets, the `MEM_KIND_*` tags, and kernel-tier accessors (`mem_data`, `mem_count`, `mem_capacity`, `mem_elemsize`, `mem_kind`, `mem_set_count`).

- **Depends on:** the `mem` built-in only. Not imported by [`.bshrc`](.bshrc).
- **Tests:** [`tests/mem_heap.bsh`](tests/mem_heap.bsh) covers the built-in; the helpers are used by `strlib`/`list`.
- **Common mistakes:** the offsets here must match `BESH_VEC_HDR` and the `BESH_VEC_*` constants in [`src/besh_mem.h`](src/besh_mem.h).

### [`framework/strlib.bsh`](framework/strlib.bsh)

Strings held in the heap rather than in shell variables, written so their scanning loops compile to the kernel tier. This is the answer to string work that previously reached for external commands; [`framework/string.bsh`](framework/string.bsh) still owns operations on BSH string *values* and is unchanged.

- **Key functions:** `str_make`/`str_text`/`str_alloc`/`str_free`; kernel-tier `str_len`, `str_byte`, `str_set_byte`, `str_cmp`, `str_eq`, `str_find_from`, `str_hash`, `str_upper`, `str_lower`, `str_reverse`; allocating `str_find`, `str_contains`, `str_slice`, `str_copy`, `str_concat`, `str_trim`.
- **Contracts:** a string is an integer address, 0 is null, results come back through `return` (so callers read `$LAST_RETURN_VALUE`) because an indirect write would force the general tier.
- **Tests:** [`tests/strlib_list.bsh`](tests/strlib_list.bsh), including an assertion on the compilation tier of every kernel function.
- **Common mistakes:** do not convert these to the result-variable convention; do not use a comparison operator in a loop condition that must stay a kernel — compute a flag with `prim ilt` instead.

### [`framework/list.bsh`](framework/list.bsh)

Dynamic lists over the same vector representation: one load per index, resizable, passable by address — unlike the core's `<base>_ARRAYIDX_<index>` variables.

- **Key functions:** `list_new`, `list_new_int`, `list_free`, `list_free_deep`; kernel-tier `list_len`, `list_capacity`, `list_get`, `list_set`, `list_index_of`, `list_sum`; `list_push`, `list_pop`, `str_split_byte`, `str_join_byte`.
- **Contracts:** `list_push` may move the list, so callers must keep the returned address.
- **Tests:** [`tests/strlib_list.bsh`](tests/strlib_list.bsh).
- **Common mistakes:** `list_free_deep` assumes every element is an owned heap block; use `list_free` for a list of plain integers.

### [`framework/c_compiler.bsh`](framework/c_compiler.bsh)

Compiles C source held in a BSH variable into a shared library and loads it.

- **Key functions:** `def_c_lib` derives `/tmp/bsh_compile_cache/<alias>.c` and `.so`, writes source with `writefile`, invokes the compiler through the argv-preserving `process` primitive, records status variables, then calls `loadlib`. `_c_lib_set_status` builds the target name before assigning through `$(...)`.
- **Sets, for alias X:** `X_COMPILE_STATUS`, `X_LOAD_STATUS`, `X_PATH`, `X_COMPILE_OUTPUT` (compiler diagnostics, captured on success and failure).
- **Depends on:** an external C compiler, writable `/tmp`, and the native ABI in [`src/bsh.c`](src/bsh.c).
- **Tests:** [`tests/native_lib.bsh`](tests/native_lib.bsh), with the fixture [`tests/fixtures/native_demo.c`](tests/fixtures/native_demo.c).
- **Common mistakes:** the compiler must be invoked through `process`, not as `$BSH_C_COMPILER ...` — a line beginning with a variable is parsed as an expression, never dispatched as a command. Status names must be built first and written through `$($built_name)`: `$($alias)_SUFFIX` reads as the value of the variable named by `$alias` followed by literal text. Native compilation is opt-in and runs a trusted external compiler; a status variable is not a substitute for a focused `calllib` check.

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
- **Depends on:** object flattening and indirect variable syntax from [`src/bsh.c`](src/bsh.c).
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

- **Key functions:** `rpn_on_load`/`rpn_on_unload`, `rpn_eval`, `rpn_call`, `rpn_define`, `rpn_exec_token`, `rpn_apply_binary`, `rpn_foreign_call`, stack helpers.
- **Depends on:** [`framework/lang.bsh`](framework/lang.bsh) and [`framework/cdiesis/strutil.bsh`](framework/cdiesis/strutil.bsh) for field splitting. Arithmetic goes through `rpn_apply_binary`, which calls the `bsh_op_*` handlers in [`framework/core_operators.bsh`](framework/core_operators.bsh) directly — RPN must not depend on cDiesis being loaded, or it stops being a control experiment.
- **Tests:** [`tests/rpn_standalone.bsh`](tests/rpn_standalone.bsh) runs it with no other language present; [`tests/cdiesis_interop.bsh`](tests/cdiesis_interop.bsh) covers direct calls, callbacks, stack isolation, and independent unload.
- **Common mistakes:** Its `@lang:symbol/N` form pops arguments in reverse order; do not assume left-to-right pushes. `lang_eval` answers with the top of the stack, so a source string that never emits (`.`) or leaves a value returns empty. Do not reach for a `cds_*` helper outside `strutil` — that dependency is what made RPN unusable on its own.

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

### [`examples/hu/`](examples/hu/)

Descriptions and a driver for the `.hu` feature: [`c_prototype.hu`](examples/hu/c_prototype.hu) (the worked example — a C function prototype, the form [`framework/c_compiler.bsh`](framework/c_compiler.bsh) emits), [`bsh_statement.hu`](examples/hu/bsh_statement.hu) (bulleted alternatives, `IF HAS` guards, a script-defined constant), [`cdiesis.hu`](examples/hu/cdiesis.hu) (cDiesis declarations described rather than coded), [`cdiesis_generics.hu`](examples/hu/cdiesis_generics.hu) (an extension script that adds a construct and overrides a constant), and [`run_hu.bsh`](examples/hu/run_hu.bsh) (the driver: load, recognise, render, navigate, call BSH per node, fail usefully, extend at runtime).

- **Common mistakes:** the grammars describe real syntax from this repository on purpose; do not replace them with toy examples. `cdiesis.hu` gives each keyword its own field and uses `IS 'literal'` rather than `STARTS WITH` — both are deliberate, and the file says why.

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

Canonical primary build wrapper. It compiles `src/bsh.c`, `src/besh_mem.c`, `src/besh_wasm.c`, `src/besh_jit.c` and every `thirds/fayasm/src/*.c` into the ignored root executable `bsh` with debug symbols, and refuses to run when the submodule has not been initialised.

- **Produces:** ignored root executable `bsh`.
- **Tests:** compilation only.
- **Common mistakes:** The build needs `git submodule update --init --recursive` first. Use [`test.sh`](test.sh) for the acceptance gate; it is the one that enables warnings.

### [`test.sh`](test.sh) and [`tests/`](tests/)

Build and acceptance harness. It compiles the pinned Fayasm sources into ignored `.build-fayasm/` objects without project warning flags, performs a warnings-enabled build of the B[e]SH sources against them, creates an isolated `.test-home`, sets an explicit module path, bounds every `.bsh` suite with an alarm, and accepts only a zero exit with an explicit pass and no failure result; an empty filter match fails.

- **Suites (15):** core variables/expansion, functions/scopes/recursion, control flow, the runtime operator table, the heap and `mem` primitives, the heap string and list libraries with their compilation tiers, the interpreted-versus-compiled differential, native extensions and runtime C compilation, cDiesis lifecycle, compiler/runtime, standard library and shipped examples, cDiesis/RPN interop, standalone RPN, the Bash language framework, and Bash CLI routing plus Bash-to-cDiesis objects.
- **Discovery:** top-level `tests/*.bsh` and `tests/*.sh` are suites. Fixtures — Bash scripts, C sources, any other input — belong below `tests/fixtures/` so the runner does not execute them as standalone suites.
- **Common mistakes:** output before a timeout is buffered per suite; inspect the reported `/tmp/bsh_test_<name>.out` when a suite exits without a result line. Do not weaken silence or timeout into success.

### [`bench.sh`](bench.sh) and [`bench/`](bench/)

Benchmark harness. It builds its own `-O2` binary at ignored `.bench-bsh` rather than reusing the debug root `bsh`, runs each fixture under `BSH_COMPILE=off` and `BSH_COMPILE=auto`, and reports the best and median of N runs together with a net figure that subtracts a measured startup baseline.

- **Fixtures:** [`startup`](bench/startup.bsh) (the baseline every other row is corrected against), [`calls`](bench/calls.bsh) (function-call overhead), [`kernel_loop`](bench/kernel_loop.bsh) (integer loop, kernel tier), [`strlib_scan`](bench/strlib_scan.bsh) (heap-string scanning), [`operators`](bench/operators.bsh) (BSH operator handlers), [`cdiesis`](bench/cdiesis.bsh) (a compiled cDiesis unit).
- **Contract:** every fixture prints `BENCH-OK <name> <checksum>`. A missing line, a non-zero exit, a checksum that moves between runs, or a checksum that differs between the two modes is an error, not a fast run — so a timing pass doubles as a differential check.
- **Results:** recorded in [`guides/bytecode.md`](guides/bytecode.md) and summarised in [`README.md`](README.md). The general tier measures ~0.63× the interpreter; the kernel tier wins only when the loop is inside the compiled function.
- **Common mistakes:** do not quote kernel-tier numbers for framework code, and do not report a single run — the ratios only hold up across repeats. `.bench-bsh`, `.build-bench/` and `.bench-home/` are ignored artifacts.

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
- **Depends on:** current contracts in [`src/bsh.c`](src/bsh.c), framework semantics, and the pinned [`thirds/fayasm/`](thirds/fayasm/) API.
- **Common mistakes:** Planning is not shipped behavior. Do not skip IR/interpreter parity and compile raw function-body strings directly.

### [`TooBad.md`](TooBad.md)

Minimal problem ledger. It currently notes overuse of a third argument as a result parameter.

- **Authority:** active concern/backlog, not a specification.
- **Maintenance:** consolidate durable design decisions here or in a dedicated design document instead of scattering TODO claims through examples.

### [`gold/bsh-0.c`](gold/bsh-0.c)

Historical early C snapshot using simpler string-token arrays, global linked-list variables, fixed PATH arrays, and the earlier dispatcher.

- **Use:** archaeology and regression comparison only.
- **Common mistakes:** Never patch this file to fix the current executable and never copy its fixed-size value model into `src/bsh.c` without explicit design work.

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

Design document for the language-framework layer: cDiesis's architecture, the 17-opcode primitive set with its planned WebAssembly lowering, the type system, the object representation, load/unload semantics, the cross-language boundary, and the enumerated core capabilities (`CDS-REQ-0` … `CDS-REQ-8`) that `src/bsh.c` must provide before any of it can run.

- **Authority:** design and dependency analysis plus the verified cDiesis contract; production-readiness claims still require evidence beyond this research suite.
- **Maintenance:** keep the `CDS-REQ` table synchronized with **Known Gaps** here; when a requirement is implemented and verified, update both.

### [`guides/bytecode.md`](guides/bytecode.md)

The contract for the compiled path: modes and introspection commands, the kernel and general tiers and exactly what qualifies for each, the handle encoding, the full `besh.v1` import table, which built-ins are lowered and which are handed back to `process_line`, unwinding through the reserved abort word, the deoptimisation guard, cache invalidation, the heap and the `mem` built-in, how to write library code that stays on the kernel tier, and the measured timings.

- **Authority:** current usage contract for `bytecode`, `mem`, `BSH_COMPILE`, `BSH_COMPILE_DEBUG` and `BSH_HEAP_BYTES`; verify with the three bytecode/heap suites.
- **Common mistakes:** the general tier is measurably *slower* than the interpreter (~0.63x), not at parity; do not quote the kernel-tier numbers for framework code, and reproduce with [`bench.sh`](bench.sh) rather than citing a single run.

### [`guides/hu.md`](guides/hu.md)

The `.hu` contract: what a description is, the lexical rules, the term and alias tables (with every invented term marked as invented), the constants, what the region recogniser does, the whole `hu` built-in surface, the handle format, and the design limits with their reasons.

- **Called by / depends on:** describes [`src/besh_hu.c`](src/besh_hu.c); backed by [`tests/hu_language.bsh`](tests/hu_language.bsh).
- **Common mistakes:** the **Limits** section is design, not a defect list; do not "fix" an entry there without changing the recogniser and the guide together.

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
- **Flow and owners:** `main` → `execute_script`/interactive loop → `process_line` in [`src/bsh.c`](src/bsh.c).
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

### Dynamic native extensions — Experimental/scaffold

- **Behavior:** the C core can `dlopen` a library and call symbols through the fixed BSH ABI, and `def_c_lib` compiles C source held in a variable into such a library at runtime.
- **Flow and owners:** `loadlib`/`calllib`/`libloaded` handlers in [`src/bsh.c`](src/bsh.c); [`framework/c_compiler.bsh`](framework/c_compiler.bsh) drives `writefile` → `process` → `loadlib`.
- **Constraints:** native libraries are fully trusted; caller and callee must agree on buffers and ownership; the ABI is fixed and arbitrary C signatures are unsupported.
- **Tests and gaps:** [`tests/native_lib.bsh`](tests/native_lib.bsh) covers inline and file-backed source, argument boundaries, status/output channels, and compile-failure reporting. Startup still does not build any native library and does not need to — `number.bsh` and `string.bsh` fall back to `prim`.

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

### Bytecode execution on Fayasm — Experimental, verified

- **Behavior:** a BSH function body is parsed once into IR, lowered to an in-memory WebAssembly module, and executed by the linked Fayasm runtime; the interpreter remains the reference and the fallback. Two tiers come out of one IR: a "kernel" tier with unboxed integer locals and no host calls, and a "general" tier where control flow is WebAssembly and values move through `besh.v1` host imports. Statements the compiler does not model are handed back to `process_line`, so every command and syntax form still works inside a compiled function.
- **Flow and owners:** `run_user_function_body` → `besh_jit_run_function` → `unit_compile` → `besh_wasm_finish` → `wasm_module_init_from_memory` → `fa_Runtime_attachModule` → `fa_Runtime_executeJob` → `besh.v1` imports in [`src/besh_jit.c`](src/besh_jit.c).
- **Constraints:** compiled code sees only opaque handles; the shared heap cannot move during execution; caches are invalidated wholesale by `defoperator`/`defkeyword` and per function by redefinition; a mode change from inside a running function is ignored.
- **Tests and gaps:** [`tests/bytecode_differential.bsh`](tests/bytecode_differential.bsh) compares both modes across values, operators, conditions, loops, calls, recursion, returns, scoping, indirection, arrays, primitives, raw built-ins, external commands and redefinition. Gaps: no direct call between compiled functions, no deterministic cache key, no disk cache, no source-line mapping for traps, and the general tier is slower than the interpreter rather than faster.

### Heap, pointers and vectors — Experimental, verified

- **Behavior:** `mem` gives BSH real addresses into a contiguous heap that is also the WebAssembly linear memory. Blocks carry an 8-byte header; vectors carry `len`/`cap`/`esz`/`kind` and back both heap strings and lists.
- **Flow and owners:** `handle_mem_statement` → `besh_mem_command` in [`src/besh_mem.c`](src/besh_mem.c); compiled `mem peek*`/`poke*` lower to single WebAssembly memory instructions instead.
- **Constraints:** address 0 is null and the first heap word is the compiled path's abort flag; the heap grows on demand but never while compiled code runs; every accessor is bounds checked.
- **Tests and gaps:** [`tests/mem_heap.bsh`](tests/mem_heap.bsh) and [`tests/strlib_list.bsh`](tests/strlib_list.bsh). Gaps: no defragmentation, no ownership tracking — a leaked block is leaked until exit — and `mem` has no guard against a pointer from a previous `besh_mem_shutdown`.

### Language description with `.hu` — Experimental, verified

- A `.hu` script describes the syntax of another language and the recogniser matches text against it, producing a tree. It never changes BSH's own syntax; a grammar is data the shell reads, not syntax the shell gains.
- Implemented and covered: the sentence parser (terms, aliases, prose discard, ordered vs bulleted lists, clause attachment), the region recogniser with backtracking alternatives, runtime extension by file or single sentence, constant override in an extension, the BSH callback bridge, and generation-checked handles.
- Not implemented: the source document's "Karnaugh map" optimizer, and any load-time validation of a grammar. See [`TooBad.md`](TooBad.md).
- Contract: [`guides/hu.md`](guides/hu.md). Tests: [`tests/hu_language.bsh`](tests/hu_language.bsh).

### Pitfall: assuming a compiled function is a faster interpreted function

- **Symptom / wrong assumption:** a change to `handle_if_statement_advanced`, `handle_while_statement_advanced`, `prim_dispatch` or the built-in dispatch chain is made in [`src/bsh.c`](src/bsh.c) alone, and the suite still passes because the affected function happened to fall back.
- **Cause and invariant:** the compiler reimplements those decisions in `compile_one`/`emit_stmt`. The two must be changed together, and `is_interpreter_builtin` must list every built-in `process_line` handles.
- **Risk area:** [`src/bsh.c`](src/bsh.c) condition handlers and dispatch chain, `compile_one` and `is_interpreter_builtin` in [`src/besh_jit.c`](src/besh_jit.c).
- **Safe pattern / regression check:** add the construct to [`tests/bytecode_differential.bsh`](tests/bytecode_differential.bsh) and assert the tier, so agreement is checked against something that actually compiled.
- **Status:** active structural duplication, guarded by the differential suite.

### Pitfall: trusting startup success messages

- **Symptom / wrong assumption:** a framework prints that it loaded, and agents infer the capability behind it works.
- **Cause and invariant:** an echo at the bottom of a module proves the file parsed, nothing more. `def_c_lib` now reports real status in `<alias>_COMPILE_STATUS` / `<alias>_LOAD_STATUS`, but `.bshrc` deliberately builds no native library at all, and `is_string_lib_loaded` still always answers true.
- **Risk area:** [`.bshrc`](.bshrc), [`framework/c_compiler.bsh`](framework/c_compiler.bsh), [`framework/string.bsh`](framework/string.bsh), `handle_loadlib_statement`.
- **Safe pattern / regression check:** check `libloaded` and the recorded status variables, then call a known ABI function and inspect `LAST_LIB_CALL_STATUS`/output - which is what [`tests/native_lib.bsh`](tests/native_lib.bsh) does.
- **Status:** `def_c_lib` verified; readiness probes in `string.bsh` still unreliable.

### Pitfall: unsequenced argument indexing

- **Symptom / wrong assumption:** external or library arguments point at the wrong buffer entry or behavior changes by compiler.
- **Cause and invariant:** expressions such as `args[arg_current++] = arg_buffer[arg_current-1]` both modify and read an index without sequencing.
- **Risk area:** `process_line` and external-call preparation in [`src/bsh.c`](src/bsh.c).
- **Safe pattern / regression check:** fill the current storage slot, assign its address, then increment in separate statements; compile with `-Wall -Wextra`.
- **Status:** active compiler warnings and regression risk.

### Pitfall: treating result-variable parameters as normal returns

- **Symptom / wrong assumption:** handlers appear to return empty values or mutate the wrong scope.
- **Cause and invariant:** BSH framework functions commonly receive the destination variable name and assign indirectly; [`TooBad.md`](TooBad.md) identifies overuse of this convention as a design concern.
- **Risk area:** operator invocation, number/string/type frameworks, and examples.
- **Safe pattern / regression check:** preserve current arity until a coordinated API redesign updates all callers/handlers and tests both local and caller-visible scope behavior.
- **Status:** deliberate current convention with an active design concern.

## Interface Ownership Map

- Executable entry points `./bsh` and `./bsh <script.bsh>` → `main` in [`src/bsh.c`](src/bsh.c); `./bsh <script.sh>`, `./bsh -c`, `./bsh -s`, and `./bsh --bash ...` → `delegate_to_bash`.
- Assignment `$name = expression` and `$array[index] = value` → `process_line` / `handle_assignment_advanced`.
- Built-ins `echo`, `defkeyword`, `defoperator`, `if`, `else`, `while`, `defunc`, `loadlib`, `calllib`, `import`, `update_cwd`, `eval`, `prim`, `libloaded`, `writefile`, `readfile`, `process`, `exit`, `mem`, `bytecode`, and `hu` → dispatch table expressed by the conditional chain in `process_line`.
- Heap, pointers, vectors and heap strings → `mem` / `besh_mem_command` in [`src/besh_mem.c`](src/besh_mem.c).
- Compilation mode, introspection and cache control → `bytecode` / `handle_bytecode_statement` in [`src/besh_jit.c`](src/besh_jit.c); contract in [`guides/bytecode.md`](guides/bytecode.md).
- `.hu` grammars, recognition, tree navigation and the field→BSH-function bridge → `hu` / `handle_hu_statement` in [`src/besh_hu.c`](src/besh_hu.c); contract in [`guides/hu.md`](guides/hu.md).
- Compiled execution of a function body → `besh_jit_run_function`, called from `run_user_function_body` in [`src/bsh.c`](src/bsh.c).
- Heap string and list libraries → [`framework/strlib.bsh`](framework/strlib.bsh) and [`framework/list.bsh`](framework/list.bsh) over [`framework/mem.bsh`](framework/mem.bsh).
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

- `git submodule update --init --recursive` materializes the pinned Fayasm dependency and is now a build prerequisite: `compile.sh` and `test.sh` compile `thirds/fayasm/src/*.c` into the executable and stop with an explicit message when the submodule is missing.
- `./compile.sh` is the canonical debug build. `./test.sh` performs the stricter warnings-enabled build, creates an isolated `HOME`, sets `BSH_MODULE_PATH`, bounds every suite, and requires an explicit result line.
- `./bsh` starts native BSH interactively; `./bsh <path.bsh>` runs a BSH script. Startup executes a user `$HOME/.bshrc` preferentially, so use an isolated environment when testing repository startup behavior. `.sh`, `-c`, `-s`, and `--bash` route to Bash without BSH startup. `--bsh-stdin` is the prompt-free native input mode used by adapters, not a Bash mode.
- `python3 groupFramework.py` mutates ignored `allFramework.txt`; it is a debug inspection aid, not a build step.
- `BSH_COMPILE=off|auto|force` selects the execution path before startup, `BSH_COMPILE_DEBUG=1` explains each compilation decision, and `BSH_HEAP_BYTES` sets the initial heap size. `bytecode status` and `bytecode info <function>` report what actually happened.
- Linting, formatting, static analysis, benchmarks, packaging, release, and deployment workflows are not defined. The current warnings-enabled suite build is clean on the verified macOS toolchain.

Debugging: [`.vscode/launch.json`](.vscode/launch.json) provides a generic GDB launcher. There is no verified release process or versioning policy; do not infer one from source header comments.

## Test Ownership Map

- C compilation and warnings → [`compile.sh`](compile.sh) and the stricter build in [`test.sh`](test.sh).
- Startup/module/operator registration → every suite starts through the isolated repository [`.bshrc`](.bshrc).
- Evaluation and two-stage expansion → [`examples/evalExample.bsh`](examples/evalExample.bsh), demonstration only.
- Functions, scopes, and loops → [`tests/core_functions.bsh`](tests/core_functions.bsh) and [`tests/core_control.bsh`](tests/core_control.bsh).
- Numeric operators → the core and cDiesis suites; native ABI compilation/calls still need a focused automated suite.
- Basic strings and array indexing → [`tests/core_variables.bsh`](tests/core_variables.bsh) plus the cDiesis stdlib suite; splitting-specific behavior remains demonstration-only.
- Heap, pointers, vectors and heap strings → [`tests/mem_heap.bsh`](tests/mem_heap.bsh).
- Heap string and list libraries, and the compilation tier each reaches → [`tests/strlib_list.bsh`](tests/strlib_list.bsh).
- `.hu` descriptions, the region recogniser, runtime extension, the BSH bridge and handle safety → [`tests/hu_language.bsh`](tests/hu_language.bsh).
- Interpreted-versus-compiled agreement across every supported construct → [`tests/bytecode_differential.bsh`](tests/bytecode_differential.bsh). Fayasm's own harness is not run by [`test.sh`](test.sh).
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
- Fayasm is compiled into the executable and executes compiled BSH function bodies. The heap/pointer model, the `mem` and `bytecode` built-ins, and the heap string and list libraries are implemented and covered by focused suites.
- The `.hu` language-description language and its `hu` built-in are implemented and covered by [`tests/hu_language.bsh`](tests/hu_language.bsh).

### Experimental / Scaffold

- The entire primary shell is research-stage.
- Script-defined operators, framework math/string/type support, runtime C compilation, structured objects, arrays, loop/function behavior, and optional filesystem extensions require focused validation.
- The language-framework layer ([`framework/lang.bsh`](framework/lang.bsh), cDiesis, RPN, and Bash) is an experimental implementation with focused lifecycle, runtime, stdlib/example, interop, Bash subprocess, and Bash/cDiesis bridge coverage.
- `.hu` is an experimental implementation of a described-language recogniser. It is not a language framework and does not execute anything by itself.
- [`gold/bsh-rs/`](gold/bsh-rs/) is archived and excluded from current project scope.

### Known Gaps

- Compiler portability beyond the verified warnings-clean macOS toolchain remains untested, and the build now also compiles the pinned Fayasm sources.
- The bytecode path duplicates the interpreter's condition and dispatch decisions in C. Only the differential suite keeps them in step.
- The general tier is ~1.6x *slower* than the interpreter on framework workloads ([`bench.sh`](bench.sh)); the measured cost is host-call frequency into BSH operator handlers. Only the integer kernel tier is faster, and only when the loop sits inside the compiled function - a kernel function called in a hot loop loses to per-entry cost.
- Cache invalidation is wholesale. There is no deterministic cache key, no disk cache, and no mapping from a Fayasm trap back to a BSH source line.
- Heap blocks are never reclaimed automatically; `mem free` and `list_free_deep` are manual, and a pointer held across `besh_mem_shutdown` is not detected.
- `besh.v1` is implemented but not frozen: there are no ABI conformance tests independent of the BSH compiler, and no compatibility promise.
- Runtime native compilation is opt-in; startup intentionally uses built-in primitives and builds no native library.
- A logical line, multi-line string included, is still bounded by `INPUT_BUFFER_SIZE`; text larger than that must be read from a file. An unterminated literal at end of input is reported and the partial line is executed.
- `$($name)_SUFFIX` means "the value of the variable named by `$name`, then the literal text `_SUFFIX`" — reads and writes agree, but the notation reliably misleads. Build the name first and assign through `$($built_name)`.
- Native string and filesystem libraries are absent; number/string operations have a verified `prim` fallback, while the optional filesystem framework remains untested.
- No CI, formatter/linter configuration, packaging, or release workflow exists.
- The language layer cannot truly remove syntax: the C core has no `undefkeyword`, `undefoperator`, or function removal, so `lang_unload` is cooperative. Full requirement list: `CDS-REQ-0` … `CDS-REQ-8` in [`guides/cdiesis.md`](guides/cdiesis.md).
- `.hu` validates nothing at load time, hardcodes `'` and `"` as the described language's quotes, and has no "Karnaugh map" optimizer. Its expressiveness limits — global fields, no greedy-to-last, no right-associative or prefix-overlapping operators, no semantic ambiguity resolution — are listed with reasons in [`guides/hu.md`](guides/hu.md).
- Native BSH is not Bash-compatible. Bash support depends on an installed `bash`; framework calls are isolated subprocesses, capture merges stderr/stdout and is limited to one BSH value, and automatic CLI routing uses the `.sh` suffix rather than shebang inspection.

### Planned

- Reduce host-call frequency and per-entry cost so the general tier stops losing to the interpreter - the benchmark harness says this comes first - then group related framework functions into single modules with direct `call` between them, derive a deterministic cache key from the IR, add disk caching, and map traps back to source lines. Follow the phased gates in [`ROADMAP.md`](ROADMAP.md); Phases 0-3 are implemented, Phase 4 is partial and Phase 5 has not started.

## Task Start and Handoff Checklist

1. Read this file, inspect `git status`, and identify whether the task targets current C/BSH code, documentation, or explicitly requested historical material.
2. Read the owning file subsections, relevant source, framework handlers, examples, and critical contracts before editing.
3. Trace cross-file names and arities: built-in dispatch, operator registration, handler parameters, result variables, module aliases, native symbols, and mangled data names.
4. Ignore [`gold/`](gold/) unless the user explicitly requests historical or archived-port work.
5. Treat [`thirds/fayasm/`](thirds/fayasm/) as a pinned dependency boundary; read its local instructions before explicit submodule work and never advance it accidentally.
6. Run the narrowest exact build/check available; capture existing blockers separately from regressions introduced by the task.
7. Update source docs, roadmap phase/status, known gaps, interface/test maps, and this handbook whenever durable facts changed.
8. Validate local Markdown links, run `git diff --check`, review the full diff, and report tests run, tests not run, generated artifacts, and remaining gaps.
