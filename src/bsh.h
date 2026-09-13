/*
 * bsh.h - the C core's interface to the optional feature modules.
 *
 * The B[e]SH core is monolithic: every constant, type, global and function it
 * uses for itself is defined inside bsh.c. This header is deliberately *not* a
 * second copy of that core - it declares only the slice of it that the
 * optional modules shipped alongside the shell are allowed to reach:
 *
 *     besh_mem.c   the linear heap and the `mem` builtin
 *     besh_wasm.c  the WebAssembly binary writer
 *     besh_jit.c   the compiled (bytecode) execution path
 *     besh_hu.c    the `.hu` language-description language and the `hu` builtin
 *
 * Dependencies point one way only. bsh.c never includes a besh_*.h except to
 * call the small set of hooks in besh_jit.h and besh_hu.h; the besh_*.c files
 * include this header to see the core. Anything an optional module does not
 * need belongs in bsh.c, not here.
 *
 * bsh.c owns the *definitions* of every global declared `extern` below.
 */
#ifndef BSH_H
#define BSH_H

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>

// --- Constants shared with the optional modules ---
#define MAX_LINE_LENGTH 2048
#define MAX_ARGS 128
#define MAX_VAR_NAME_LEN 256
// Width of one BSH value buffer. besh_mem.h derives BESH_ARG_SIZE from this so
// that the heap's `mem` argument vector cannot drift from it.
#define INPUT_BUFFER_SIZE 16384
// Scratch arrays sized [MAX_CALL_ARGS][INPUT_BUFFER_SIZE] are static; keeping
// this well under MAX_ARGS is what keeps that memory reasonable.
#define MAX_CALL_ARGS 32
#define TOKEN_STORAGE_SIZE (MAX_LINE_LENGTH * 2) // Should be ample for token text
#define MAX_FUNC_LINES 256  // framework parsers contain deliberately large stored bodies
#define MAX_FUNC_PARAMS 10
#define MAX_OPERATOR_LEN 16 // Increased for potentially longer operators like "?:"

// --- Tokenizer Types (Simplified) ---
typedef enum {
    TOKEN_EMPTY,        // Should not appear in active processing
    TOKEN_WORD,         // Identifiers, command names, unquoted literals
    TOKEN_STRING,       // "quoted string"
    TOKEN_NUMBER,       // 123, 3.14 (parsed by C)
    TOKEN_VARIABLE,     // $var, ${var}
    TOKEN_OPERATOR,     // Generic for script-defined operators (+, ==, ++, ?:)
    TOKEN_LPAREN,       // (
    TOKEN_RPAREN,       // )
    TOKEN_LBRACE,       // {
    TOKEN_RBRACE,       // }
    TOKEN_LBRACKET,     // [
    TOKEN_RBRACKET,     // ]
    TOKEN_SEMICOLON,    // ;
    TOKEN_ASSIGN,       // = (could also be TOKEN_OPERATOR if fully dynamic)
    TOKEN_COMMENT,      // #...
    TOKEN_EOF,          // End of input
    TOKEN_ERROR         // Tokenization error
} TokenType;

typedef struct {
    TokenType type;
    const char *text; // Points into the token_storage buffer or original line
    int len;
    int line;         // Line number of the token
    int col;          // Column number of the token
} Token;

// --- Operator Definition (Dynamic List) ---
typedef enum {
    OP_TYPE_NONE,
    OP_TYPE_UNARY_PREFIX,
    OP_TYPE_UNARY_POSTFIX,
    OP_TYPE_BINARY_INFIX,
    OP_TYPE_TERNARY_PRIMARY,   // e.g., "?"
    OP_TYPE_TERNARY_SECONDARY, // e.g., ":"
} OperatorType;

typedef enum {
    ASSOC_NONE,
    ASSOC_LEFT,
    ASSOC_RIGHT
} OperatorAssociativity;

typedef struct OperatorDefinition {
    char op_str[MAX_OPERATOR_LEN + 1];
    TokenType token_type; // Will usually be TOKEN_OPERATOR, but can map to others if needed
    OperatorType op_type_prop; // The new type property (unary, binary, etc.)
    int precedence;
    OperatorAssociativity associativity;
    char bsh_handler_name[MAX_VAR_NAME_LEN]; // BSH function to call
    struct OperatorDefinition *next;
} OperatorDefinition;

// --- User-Defined Functions ---
typedef struct UserFunction {
    char name[MAX_VAR_NAME_LEN];
    char params[MAX_FUNC_PARAMS][MAX_VAR_NAME_LEN];
    int param_count;
    char* body[MAX_FUNC_LINES];
    int line_count;
    struct UserFunction *next;
} UserFunction;
extern UserFunction *function_list;

// --- Execution State ---
typedef enum {
    STATE_NORMAL, STATE_BLOCK_EXECUTE, STATE_BLOCK_SKIP,
    STATE_DEFINE_FUNC_BODY, STATE_IMPORT_PARSING,
    STATE_RETURN_REQUESTED // For 'return' and 'exit' functionality
} ExecutionState;
extern ExecutionState current_exec_state;
// For 'return' or 'exit' with value
extern char bsh_last_return_value[INPUT_BUFFER_SIZE];
extern bool bsh_return_value_is_set;

// --- Interpretation, so a module can fall back to the reference tier ---
void process_line(char *line, FILE *input_source, int current_line_no, ExecutionState exec_mode);

// --- Tokenizer, operators and keyword aliases ---
int advanced_tokenize_line(const char *line_text, int line_num, Token *tokens, int max_tokens, char *token_storage, size_t storage_size);
OperatorDefinition* get_operator_definition_typed(const char* op_str, OperatorType op_type_prop);
OperatorDefinition* get_operator_definition_after_operand(const char* op_str);
bool besh_unary_op_takes_variable_name(const char* op_str);
bool is_comparison_or_assignment_operator(const char* op_str);
const char* resolve_keyword_alias(const char* alias_name);

// --- Variables and scopes ---
char* get_variable_scoped(const char *name_raw);
void set_variable_scoped(const char *name_raw, const char *value_to_set, bool is_array_elem);
char* get_array_element_scoped(const char* array_base_name, const char* index_str_raw);
void set_array_element_scoped(const char* array_base_name, const char* index_str_raw, const char* value);
void expand_variables_in_string_advanced(const char *input_str, char *expanded_str, size_t expanded_str_size);

// --- BSH handler invocation ---
bool invoke_bsh_operator_handler(const char* bsh_handler_name,
                                 const char* op_symbol,
                                 int arg_count,
                                 const char* args[],
                                 const char* result_holder_bsh_var,
                                 char* c_result_buffer, size_t c_result_buffer_size);

// --- Text utilities ---
char* trim_whitespace(char *str);
char* unescape_string(const char* input, char* output_buffer, size_t buffer_size);

// --- Semantics the compiled tier must reproduce exactly ---
// `prim` primitives, shared so that compiled code computes the same values.
bool besh_prim_dispatch(const char* op, char args[][INPUT_BUFFER_SIZE], int argc,
                        char* out, size_t out_size);
// Statement normalisation, so the compiler sees exactly the statements the
// interpreter would have dispatched. Pieces returned by the splitter are
// malloc'd and owned by the caller.
int  besh_split_line_into_statements(const char* line, char** out, int max_out);
bool besh_line_needs_statement_split(const char* line);
// Condition evaluation, so `if`/`while` mean the same thing in both tiers.
bool besh_compare_values(const char* lhs, const char* op_str, const char* rhs);
bool besh_value_is_true(const char* text, bool if_semantics);
// Calling with already-expanded values instead of tokens.
void besh_dispatch_command_values(const char* name, const char** argv, int argc,
                                  char* out, size_t out_size);

#endif /* BSH_H */
