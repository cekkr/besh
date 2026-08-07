# Bash framework and command-line compatibility

**Status: experimental implementation, covered by `bash_*` test suites.**

B[e]SH's native `.bsh` language is not GNU Bash syntax. Assignments, function
parameters, expressions and extensible operators follow BSH's own grammar. Bash
compatibility is therefore implemented by routing Bash source to the installed
`bash` executable rather than approximating Bash in the BSH tokenizer.

## Command line

The `bsh` executable preserves native BSH script execution and adds Bash's
common command-line paths:

```sh
./bsh program.bsh                 # native BSH
./bsh program.sh arg1 arg2        # Bash script and positional arguments
./bsh -c 'printf "%s\n" "$1"' name value
./bsh -s arg1                     # Bash source from standard input
./bsh --bash --noprofile          # explicit pass-through to Bash
```

`.sh`, `-c`, `-s`, and everything after `--bash` are forwarded as distinct
arguments to `bash`. Bash owns expansion, quoting, pipelines, redirections,
arrays, functions, built-ins and exit status. `$HOME/.bshrc` is not loaded on
these paths. Other script names continue through the BSH interpreter.

## Language framework

[`framework/bash.bsh`](../framework/bash.bsh) plugs Bash into the same
`lang_register` lifecycle as cDiesis and RPN:

```bsh
import bash
lang_load "bash" loaded

$SOURCE = "printf alpha | tr a-z A-Z"
lang_eval "bash" SOURCE output
echo "$output"                 # ALPHA
echo "$BASH_LAST_STATUS"       # 0

bash_run "tool.sh" output "first" "second"
lang_unload "bash" unloaded
```

`bash_eval`, `bash_run`, and `bash_call` use the generic core command
`process <result-var> <program> [args...]`. `process` keeps argv boundaries,
captures combined stdout/stderr up to the shell value limit, sets
`LAST_COMMAND_STATUS`, and continues draining output after the capture buffer
fills so a verbose child cannot deadlock.

Each `lang_eval` or `lang_call` starts a fresh Bash process. Shell variables,
functions and working-directory changes do not persist between those calls.
Use a `.sh` file for a stateful Bash program.

## cDiesis objects from Bash

[`framework/bash/cdiesis.sh`](../framework/bash/cdiesis.sh) is a Bash 3.2+
library. It keeps one prompt-free BSH process alive through private FIFOs, so
compiled classes and `obj#<id>` heap objects persist across Bash calls:

```bash
source framework/bash/cdiesis.sh
trap cdiesis_close EXIT

cdiesis_import examples/bash/counter.cds
cdiesis_new counter Counter 10
cdiesis_call total "$counter" Add 5
cdiesis_get current "$counter" Value
cdiesis_set "$counter" Value 40
```

The public functions are:

| Function | Effect |
| --- | --- |
| `cdiesis_import file.cds` | Compile a cDiesis source library into the persistent session |
| `cdiesis_new result Class args...` | Construct an object and assign its handle to a Bash variable |
| `cdiesis_call result object Method args...` | Invoke an instance method |
| `cdiesis_get result object Field` | Read an instance field into a Bash variable |
| `cdiesis_set object Field value` | Write a declared instance field |
| `cdiesis_close` | Stop the bridge and remove its private temporary directory |

Values cross the bridge through private files, not generated command text, so
spaces and newlines remain data. Class, method, field and destination-variable
names are identifier-validated. The bridge is a convenience API, not a security
sandbox: sourced Bash, imported BSH and cDiesis code all execute with the user's
permissions. A bridge object is valid only until `cdiesis_close`.

See [`examples/bash/cdiesis_objects.sh`](../examples/bash/cdiesis_objects.sh)
for a complete executable example.
