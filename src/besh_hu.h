/*
 * besh_hu.h - `.hu` human language scripting: a language-description language.
 *
 * A `.hu` script does not extend B[e]SH. It *describes the syntax of some other
 * language*, in sentences that read as English while executing exactly. The
 * runtime then recognises text against that description and produces a tree,
 * which a BSH script can walk, render as XML, bind into shell variables, or
 * drive with its own functions.
 *
 *     $root IS "CPrototype"
 *     $root CAN HAVE ONE OR MORE $prototype
 *     A $prototype ENDS WITH ';'
 *     A $prototype HAS:
 *     1. The $returnType, that IS a #word
 *     2. The $name of the function, that IS an #identifier
 *     3. The $parameters that ARE INSIDE '(', ')'
 *
 * Two sigils carry all the structure. `$field` names a nonterminal; `#constant`
 * names a character class or literal set. Bare UPPERCASE words are terms from a
 * fixed table; lowercase words are prose and are discarded. That asymmetry is
 * the whole trick: the prose is free, so a description can be made to read like
 * a sentence without changing what it means.
 *
 * Quoting distinguishes the two things a quoted string can be:
 *   "double"  a name  - the grammar's title
 *   'single'  a literal to match in the described language
 *
 * The recogniser is region-based. A field owns a contiguous span of the input
 * and its rules subdivide that span: INSIDE carves out a delimited interior,
 * SEPARATED BY splits on top-level separators, ENDS WITH splits on a
 * terminator, a numbered list matches in sequence, a bulleted list offers
 * alternatives. There is no backtracking, which is what makes a failure
 * explainable: `hu error` reports which field was entered and what the grammar
 * was still waiting for.
 *
 * This is an optional feature. Nothing in the core depends on it, it registers
 * no keyword and no operator, and a grammar is data the shell reads rather than
 * syntax the shell gains. The full contract is in guides/hu.md.
 */
#ifndef BESH_HU_H
#define BESH_HU_H

#include <stdbool.h>
#include <stddef.h>

#include "bsh.h"

/* Width of one `hu` argument. Derived from the core's value buffer so the
 * argument vector cannot drift from the buffers the shell hands over, exactly
 * as BESH_ARG_SIZE does for `mem`. */
#define BESH_HU_ARG_SIZE INPUT_BUFFER_SIZE

/* --- lifecycle ------------------------------------------------------- */

/* Idempotent. Called from initialize_shell so `hu` works inside .bshrc. */
void besh_hu_init(void);

/* Drops every grammar and every parse tree. Called from cleanup_shell before
 * the core tables are torn down. */
void besh_hu_shutdown(void);

/* --- the BSH-facing `hu` builtin ------------------------------------- */

/* Runs one `hu` subcommand. `argv` excludes the word "hu" itself. Returns
 * false when the subcommand is unknown or its arguments are wrong; the
 * diagnostic is written to `err`. On success `out` holds the textual result
 * (empty for subcommands that produce none). */
bool besh_hu_command(const char* sub, char argv[][BESH_HU_ARG_SIZE], int argc,
                     char* out, size_t out_size,
                     char* err, size_t err_size);

/* True when `sub` yields a value, and therefore takes a trailing result
 * variable in `hu <sub> [args...] <result_var>`. */
bool besh_hu_produces_value(const char* sub);

/* Built-in implemented by this module. */
void handle_hu_statement(Token* tokens, int num_tokens);

#endif /* BESH_HU_H */
