# `.hu` — human language scripting

**Status: experimental implementation, verified by [`tests/hu_language.bsh`](../tests/hu_language.bsh).**

A `.hu` script describes the syntax of *some other language*. It does not extend
B[e]SH. The runtime reads the description, recognises text against it, and
produces a tree that a BSH script can walk, render as XML, bind into shell
variables, or use to drive its own functions.

The design comes from a 2019 document describing a language called *Language*,
whose stated purpose was to recognise a structure in a text, store the data and
catalogue it. Its defining quality is that a script *appears* to be spoken
English while executing exactly. That property is preserved here, sigils, term
table and alias table included; everything added beyond the document is marked
**invented** below, which that document explicitly invites.

This document is the contract. It describes behaviour that is implemented and
covered by [`tests/hu_language.bsh`](../tests/hu_language.bsh). What `.hu`
deliberately cannot do is in **Limits**, and it is not a list of bugs.

A `.hu` grammar is **not** a language framework. [`framework/lang.bsh`](../framework/lang.bsh)
defines one as "a set of BSH functions that can read source text written in some
notation, lower it to B[e]SH primitives, and execute it" — cDiesis, RPN and Bash
are those. `.hu` is a *description*, implemented in C, and execution is optional
and delegated back to BSH. The two compose: a language framework could use a
`.hu` grammar as its front end instead of a hand-written lexer and parser, which
is what [`framework/cdiesis/lexer.bsh`](../framework/cdiesis/lexer.bsh) and
[`parser.bsh`](../framework/cdiesis/parser.bsh) do today in BSH.

## The shape of a description

```
/// The shape of a C function prototype.
$root IS "CPrototype"
$root CAN HAVE ONE OR MORE $prototype

A $prototype ENDS WITH ';'
A $prototype HAS:
1. The $returnType, that IS a #word
2. The $name of the function, that IS an #identifier
3. The $parameters that ARE INSIDE '(', ')'

$parameters CAN HAVE ONE OR MORE $parameter SEPARATED BY ','
A $parameter HAS:
1. The $type, that IS a #word
2. The $argument, that IS an #identifier
```

Given `int add(int a, int b);` that yields:

```xml
<root>
  <prototype>
    <returnType>int</returnType>
    <name>add</name>
    <parameters>
      <parameter>
        <type>int</type>
        <argument>a</argument>
      </parameter>
      <parameter>
        <type>int</type>
        <argument>b</argument>
      </parameter>
    </parameters>
  </prototype>
</root>
```

That script is [`examples/hu/c_prototype.hu`](../examples/hu/c_prototype.hu) and
that tree is the suite's anchor assertion.

## Lexical rules

| Written | Means |
| --- | --- |
| `$name` | a **field** — a nonterminal of the described language |
| `#name` | a **constant** — a character class or literal set |
| `'text'` | a **literal** of the described language |
| `"text"` | a **name**, used for the grammar's title |
| `WORD` | a **term**, if the table below has it |
| `word` | prose — discarded |
| `///` | a comment to end of line (document alias: `You know`) |
| `,` | a clause break within one sentence |
| `:` at end of line | the following list items complete this sentence |
| `1.` `2.` | an **ordered** list item — sequence is significant |
| `-` `*` | an **unordered** list item — an alternative |

Two rules carry most of the weight.

**Case decides everything.** A bare word is a term only if it is fully uppercase
*and* in the table. Lowercase prose is discarded silently, which is what lets a
sentence read as English. An uppercase word that is neither a term nor known
filler is reported — a misspelled `ENDSWITH` should not quietly become prose.
Because of this, `of` in `The $name of the function` is prose while `OF` is a
term, and the two never collide.

**Quote style decides meaning.** `"double"` is a name and `'single'` is a
literal. This is how `$root IS "CPrototype"` names the grammar while
`$prototype ENDS WITH ';'` matches a semicolon, with no positional rule to
remember.

## Terms

Exactly as the source document defines them, aliases included:

| Class | Canonical | Aliases |
| --- | --- | --- |
| comment | `///` | `You know` |
| verb | `HAVE` | `HAS`, `CONTAIN`, `CONTAINS`, `COMPOSED BY`, `COMPOSED OF` |
| verb | `IS` | `ARE`, `BE`, `REPRESENT`, `REPRESENTS` |
| conditional | `CAN`, `MUST` | `SHALL` |
| quantity | `ALL`, `ONE`, `ZERO` | `EVERY`, `NONE` |
| conjunction | `AND`, `OR`, `IF`, `THEN`, `ELSE`, `OF` | `WHICH` |
| comparison | `EQUALS`, `MORE`, `LESS`, `THAN` | `EQUAL`, `IS EQUAL TO` |

**Invented** — not in the source document, which invites new terms:

| Canonical | Aliases |
| --- | --- |
| `ENDS WITH` | `END WITH`, `TERMINATED BY` |
| `STARTS WITH` | `START WITH`, `BEGINS WITH` |
| `INSIDE` | `BETWEEN`, `WRAPPED IN`, `ENCLOSED IN` |
| `SEPARATED BY` | `DELIMITED BY`, `SPLIT BY` |
| `MATCHES` | `MATCH`, `LOOKS LIKE` |
| `EXTENDS` | `EXTENSION OF` |

Terms may be several words; the lexer matches the longest phrase first.
`hu terms` prints the live table.

Quantity phrases map to a range: `ONE` is exactly one, `ONE OR MORE` is one or
more, `ZERO OR MORE` and `ALL`/`EVERY` are zero or more. Without a quantity a
rule means exactly one.

## Constants

Built in: `#word` `#identifier` `#number` `#string` `#space` `#newLine` `#tab`
`#any` `#end` `#letter` `#digit` `#symbol` `#quote`.

A script defines its own the same way it writes anything else:

```
#sigil IS '$'
#keyword IS 'class' OR 'struct'
```

The source document says a script defines a constant once but **an extension may
override a constant from the description it extends**. That is implemented:
`#word IS #identifier` inside a file applied with `hu extend` narrows `#word`
for the whole grammar. [`examples/hu/cdiesis_generics.hu`](../examples/hu/cdiesis_generics.hu)
does exactly that.

## What the recogniser does

Region-based, and this is the whole of it. A field owns a contiguous span of the
input; its rules subdivide that span.

| Rule | Effect on the field's region |
| --- | --- |
| `STARTS WITH x` | requires `x` at the front and trims it off |
| `ENDS WITH x` | trims `x` off the back of this instance; the end of the region is also an implicit terminator |
| `IS INSIDE 'a', 'b'` | requires `a`, finds its matching `b`, and the field owns the interior |
| `CAN BE $x [IF HAS 'lit']` | alternatives, tried in order |
| `HAVE <qty> $x [SEPARATED BY 'sep']` | children; `sep` splits at top level, otherwise `$x`'s own terminator does |
| numbered children | matched in sequence, each consuming a prefix of what remains |
| `IS #const` / `IS 'lit'` | a leaf, which must match its whole region |

Four properties are worth stating outright, because they are what make a failure
explainable.

**Alternatives backtrack; extents commit.** When an alternative fails, every node
it built is dropped and the next is tried. Once a child has decided how far it
reaches, a later failure does not reopen that decision.

**`IF HAS` prunes, it does not decide.** A guard that does not fire skips an
attempt; a guard that fires still has to match. A literal whose edge is a word
character only matches on a word boundary, so a guard of `'if'` does not fire
inside `notify`.

**Nothing is dropped in silence.** An ordered sequence must account for its whole
region, and a leaf must match all of its own. Leaving input unexplained is a
failure, because a tree you cannot trust is worse than no tree.

**A failure reports what it was waiting for.** The deepest expectation reached is
kept and reported with a line and column:

```
line 1, col 8: field $prototype expected $parameters
```

This is the half of the source document's "Karnaugh map" idea that is worth
having — knowing which field was entered and what should have come next. The
compressed switch network itself is **not implemented**; the document says the
direct interpreter comes first, especially for debugging, and it does.

## The `hu` builtin

`hu <subcommand> [args...] [result_var]`. `LAST_HU_STATUS` is `0` on success and
`1` otherwise. A subcommand that yields a value writes it to a trailing result
variable when one is given, and prints it when one is not.

### Grammars

| Form | Effect |
| --- | --- |
| `hu load <path.hu> [var]` | loads a file; the value is the grammar's name |
| `hu define <name> <text> [var]` | loads an inline description |
| `hu rule <name> <sentence>` | applies one sentence to a live grammar |
| `hu extend <name> <path.hu>` | applies an extension script, constant overrides included |
| `hu unload <name>` | drops a grammar |
| `hu list [var]` | the loaded grammar names |
| `hu fields <name> [var]` | the field names |
| `hu rules <name> <field>` | prints what one field's sentences became |
| `hu terms` | prints the term table and the built-in constants |

`hu load` names the grammar from `$root IS "Name"`, and that name is what every
other subcommand takes. `hu extend` keeps the existing name even if the extension
restates a title, so a caller already holding it keeps working.

**`define` and `rule` take their description argument verbatim.** A quoted
literal in that position is not variable-expanded, because `$field` in a grammar
means a field and expanding it would leave nothing behind. A variable token there
*is* expanded, so building a description in a variable still works. Every other
argument, `hu parse`'s text included, expands normally.

### Recognition

| Form | Effect |
| --- | --- |
| `hu parse <name> <text> [var]` | recognises text; the value is a tree handle |
| `hu parsefile <name> <path> [var]` | the same, from a file |
| `hu error [var]` | the diagnostic from the last failed parse |
| `hu free <handle>` | releases a tree |
| `hu status` | grammars, trees and parse counts |

### Trees

| Form | Effect |
| --- | --- |
| `hu kind <handle> [var]` | the node's field name |
| `hu text <handle> [var]` | the text the node matched |
| `hu count <handle> [var]` | how many children it has |
| `hu child <handle> <index> [var]` | a child by position |
| `hu node <handle> <path> [var]` | a descendant by field path, `prototype/parameters/parameter` |
| `hu xml <handle> [var]` | the XML rendering |
| `hu tree <handle>` | prints an indented dump |
| `hu bind <handle> <prefix>` | publishes the node into shell variables |

`hu bind` sets `$<prefix>_KIND`, `$<prefix>_TEXT`, `$<prefix>_COUNT`,
`$<prefix>[i]` for each child, and `$<prefix>_<field>` for the first child with
that field name.

### Driving BSH from a description

| Form | Effect |
| --- | --- |
| `hu on <name> <field> <function>` | registers a BSH function for a field |
| `hu walk <handle>` | calls each registered function once per matching node |

The function receives two arguments: the node's handle and its matched text.

```bsh
function show_parameter (handle text) {
    hu node "$handle" "type" t
    hu text "$t" type_name
    echo "type is $type_name"
}
hu on "$g" parameter show_parameter
hu walk "$tree"
```

## Handles

A handle is `hu#<slot>.<generation>` for a tree, and `hu#<slot>.<generation>/<node>`
for a node inside it. The generation is bumped when a tree is freed, so a handle
held across `hu free` is **refused with a diagnostic** rather than resolving into
released memory. Trees are released by hand, like heap blocks; `hu status` is how
you notice one was forgotten.

## Limits

These are design limits, not defects, and each one is a place where the honest
answer is "describe it differently" or "this is not the tool".

- **Fields are global to a grammar.** One `$keyword` field cannot be `'namespace'`
  in one place and `'using'` in another; give each its own field.
  [`examples/hu/cdiesis.hu`](../examples/hu/cdiesis.hu) shows the shape.
- **A field followed by a sibling must say where it ends.** `IS`, `INSIDE` and
  `ENDS WITH` do; `STARTS WITH` alone does not, so a field with only that rule is
  only valid last. Today this shows up as a parse failure naming the field, not
  as a load-time error.
- **Quote characters are fixed.** The scanners treat `'` and `"` as quotes in the
  *described* language. A language that quotes differently will have its
  separators and terminators found inside what it considers a string.
- **Greedy-to-last is not expressible.** `unsigned long x` cannot be split into a
  two-word type and a name, because each ordered child takes the shortest thing
  that satisfies it.
- **Left-associative binary operators work; little else does.** Splitting on
  `'+'` and then on `'*'` gives correct precedence. Right associativity, unary
  prefixes, and operators that are prefixes of each other (`<` against `<=`) do
  not.
- **Ambiguity that needs meaning is out of scope.** `.hu` describes
  delimiter-structured languages — calls, blocks, lists, lines, records. It does
  not resolve a construct that needs to know what a name refers to.
- **Byte-oriented.** Bytes at or above `0x80` count as word characters so an
  accented identifier is not cut in half, but columns are byte offsets.
- **Recursion must make progress.** A field that reaches itself over the same
  region stops at a depth limit and reports it.

Bounded by construction: 16 grammars, 128 fields and 8 rules per field, 64 live
trees, 4096 nodes per tree, 64 levels of recursion. A tree's node storage starts
small and doubles, so a short parse costs little; exceeding any bound is reported
rather than truncated.

## Files

| Path | Purpose |
| --- | --- |
| [`src/besh_hu.h`](../src/besh_hu.h) | the module's interface and what `.hu` is |
| [`src/besh_hu.c`](../src/besh_hu.c) | lexer, sentence parser, recogniser, handles, the `hu` builtin |
| [`examples/hu/c_prototype.hu`](../examples/hu/c_prototype.hu) | the worked example: a C prototype |
| [`examples/hu/bsh_statement.hu`](../examples/hu/bsh_statement.hu) | alternatives, guards, a script-defined constant |
| [`examples/hu/cdiesis.hu`](../examples/hu/cdiesis.hu) | cDiesis declarations, described rather than coded |
| [`examples/hu/cdiesis_generics.hu`](../examples/hu/cdiesis_generics.hu) | an extension script, with a constant override |
| [`examples/hu/run_hu.bsh`](../examples/hu/run_hu.bsh) | demonstration driver |
| [`tests/hu_language.bsh`](../tests/hu_language.bsh) | the suite that backs this document |

## Debugging

`hu rules <grammar> <field>` prints what a sentence actually became, which is the
fastest way to find out that a line read as prose. `hu tree <handle>` prints the
recognised structure, and `hu error` says what a failed parse was waiting for.
