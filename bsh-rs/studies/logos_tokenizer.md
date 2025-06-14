The `logos` tokenizer generator does not allow for the declaration of new token syntaxes at runtime. Its token definitions are declared in a Rust `enum` and are compiled into a highly efficient, finite-state automaton at **compile time**. This automaton cannot be modified once the program is running.

***

### `bsh.c` vs. `bsh-rs` Strategy

The original C implementation (`bsh.c`) achieves runtime syntax by having the tokenizer iterate through a dynamically populated list of operator strings. This is flexible but can be less performant.

The Rust implementation (`bsh-rs`) uses a different, more idiomatic strategy to achieve the same dynamic behavior:

* [cite_start]**Static Tokenizer, Dynamic Parser**: The `logos` tokenizer is defined at compile time with a *generic* `Operator` token that captures any potential sequence of operator characters (e.g., `+`, `==`, `*`, `++`). [cite: 1]
* [cite_start]**Runtime Configuration**: The `defoperator` builtin works at runtime, populating a `HashMap` with the specific properties of each operator (precedence, associativity, handler function). [cite: 1]
* **Dynamic Interpretation**: The **parser**, not the tokenizer, takes the generic `Operator(String)` token and looks up the captured string (like `"++"`) in the runtime `HashMap`. This lookup determines how the parser should handle the operator based on the script's definitions.

This approach combines the raw speed of a compile-time tokenizer with the runtime flexibility the `bsh` project requires.