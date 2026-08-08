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
