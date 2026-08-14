## Problems

- Too often uses the third parameter as the result parameter. This is absurd. (why?)

  Partly answered, not fixed. `framework/strlib.bsh` and `framework/list.bsh`
  return through `return` and `$LAST_RETURN_VALUE` instead, and there is now a
  concrete reason to prefer that: an indirect write to a caller-named variable
  is a host call, so a function using the result-parameter convention cannot
  reach the bytecode path's kernel tier. The older frameworks (`number.bsh`,
  `string.bsh`, `type.bsh`, `core_operators.bsh`) still use the convention, and
  changing them means changing every caller and the operator dispatcher in
  `bsh.c` at the same time.

- The compiled path duplicates decisions the interpreter makes. `if` and
  `while` read their conditions differently from each other, and both differ
  from the expression parser; `compile_one` in `besh_jit.c` reimplements all
  three, and `is_interpreter_builtin` restates the dispatch chain in
  `process_line`. Only `tests/bytecode_differential.bsh` keeps them in step. The
  real fix is for the interpreter to execute the same IR, which is Phase 1 work
  that is not done.

- Heap blocks are freed by hand. `mem free` and `list_free_deep` are the only
  reclamation there is, so a script that drops a pointer leaks until exit.

- Compiling a function can make it slower. `bench.sh` measures the general tier
  at ~0.63× the interpreter, and a kernel-tier function called in a hot loop at
  the same 0.63×, because entering a compiled body costs more than a small body
  saves. `auto` is nonetheless the default. Until host-call frequency and
  per-entry cost come down (ROADMAP Phase 5, item 6), `auto` is the wrong default
  for anything that is not integer work against the heap, and the honest
  statement is that the compiled path is a win in two measured shapes and a loss
  in three.

- A logical line is still one buffer. Multi-line strings work, but the whole
  statement has to fit in `INPUT_BUFFER_SIZE`; past that the literal is
  truncated with a diagnostic and the text has to come from `readfile`. A real
  fix means growable line storage through the tokenizer, the function-body
  store, and the `ftell`/`fseek` loop replay.

- `$($name)_SUFFIX` does not mean what it looks like. It reads as "the value of
  the variable named by `$name`, then the literal text `_SUFFIX`" — not "the
  variable `<name>_SUFFIX`". Reads and writes agree with each other, so this is
  consistent rather than broken, but it reliably misleads: `framework/c_compiler.bsh`
  was written against the wrong reading and silently failed to record any status
  for as long as it existed. Building the name first and assigning through
  `$($built_name)` is the working idiom.
