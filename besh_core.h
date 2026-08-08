/*
 * besh_core.h - Shared B[e]SH core declarations.
 *
 * The interpreter (bsh.c) and the bytecode path (besh_mem.c, besh_wasm.c,
 * besh_ir.c, besh_jit.c) need the same constants, token/operator/function
 * types and the same view of the shell's globals. Those definitions used to
 * live at the top of bsh.c; they live here so that exactly one description of
 * each type exists.
 *
 * bsh.c owns the *definitions* of every global declared `extern` below.
 */
#ifndef BESH_CORE_H
#define BESH_CORE_H

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>

#include "besh_mem.h"

// --- Constants and Definitions ---
#define MAX_LINE_LENGTH 2048
#define MAX_ARGS 128
#define MAX_VAR_NAME_LEN 256
#define INPUT_BUFFER_SIZE BESH_ARG_SIZE // also the cap on a single variable's value
// Scratch arrays sized [MAX_CALL_ARGS][INPUT_BUFFER_SIZE] are static; keeping
// this well under MAX_ARGS is what keeps that memory reasonable.
#define MAX_CALL_ARGS 32
#define MAX_FULL_PATH_LEN 1024
#ifndef PATH_MAX
    #ifdef _XOPEN_PATH_MAX
        #define PATH_MAX _XOPEN_PATH_MAX
    #else
        #define PATH_MAX 4096
    #endif
#endif
#define TOKEN_STORAGE_SIZE (MAX_LINE_LENGTH * 2) // Should be ample for token text
#define MAX_NESTING_DEPTH 128
#define MAX_FUNC_LINES 256  // framework parsers contain deliberately large stored bodies
#define MAX_FUNC_PARAMS 10
#define MAX_OPERATOR_LEN 16 // Increased for potentially longer operators like "?:"
#define DEFAULT_STARTUP_SCRIPT ".bshrc"
#define MAX_KEYWORD_LEN 32
#define MAX_SCOPE_DEPTH 512  // recursive framework code (parsers) needs real depth
#define DEFAULT_MODULE_PATH "./framework:~/.bsh_framework:/usr/local/share/bsh/framework"
#define MAX_EXPRESSION_TOKENS MAX_ARGS // Max tokens in a single expression to be parsed

#define JSON_STDOUT_PREFIX "json:" // json are not managed (?)
#define OBJECT_STDOUT_PREFIX "object:"

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
extern OperatorDefinition *operator_list_head;

// --- Keyword Aliasing (Dynamic List) ---
typedef struct KeywordAlias {
    char original[MAX_KEYWORD_LEN + 1];
    char alias[MAX_KEYWORD_LEN + 1];
    struct KeywordAlias *next;
} KeywordAlias;
extern KeywordAlias *keyword_alias_head;

// --- PATH Directories (Dynamic List) ---
typedef struct PathDirNode {
    char *path;
    struct PathDirNode *next;
} PathDirNode;
extern PathDirNode *path_list_head;
extern PathDirNode *module_path_list_head;

// Modules already imported in this process, so that 'import' is idempotent.
#define MAX_IMPORTED_MODULES 256
extern char imported_modules[MAX_IMPORTED_MODULES][MAX_FULL_PATH_LEN];
extern int imported_module_count;

// --- Variable Scoping and Management ---
typedef struct Variable {
    char name[MAX_VAR_NAME_LEN];
    char *value;
    bool is_array_element;
    int scope_id;
    struct Variable *next;       // next in hash bucket
    struct Variable *scope_next; // next variable created in the same scope
} Variable;

typedef struct ScopeFrame {
    int scope_id;
    struct Variable *vars_head; // variables created in this scope, newest first
} ScopeFrame;
extern ScopeFrame scope_stack[MAX_SCOPE_DEPTH];
extern int scope_stack_top;
extern int next_scope_id;
#define GLOBAL_SCOPE_ID 0

// Variables live in a hash table keyed by name. A single linked list made
// every read and write O(number of variables); framework code that builds
// tables out of mangled names (thousands of entries) turned that into
// quadratic behaviour. Chaining keeps lookup flat.
#define VARIABLE_BUCKET_COUNT 4096
extern Variable *variable_buckets[VARIABLE_BUCKET_COUNT];

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
extern bool is_defining_function;
extern UserFunction *current_function_definition;
// Depth of blocks opened *inside* the function body currently being captured.
// Only a '}' seen at depth 0 closes the definition itself.
extern int func_def_brace_depth;
// Guard against an operator handler that (directly or indirectly) uses the
// operator it implements.
#define MAX_OPERATOR_HANDLER_DEPTH 48
extern int bsh_operator_handler_depth;

// --- Execution State and Block Management ---
typedef enum {
    STATE_NORMAL, STATE_BLOCK_EXECUTE, STATE_BLOCK_SKIP,
    STATE_DEFINE_FUNC_BODY, STATE_IMPORT_PARSING,
    STATE_RETURN_REQUESTED // For 'return' and 'exit' functionality
} ExecutionState;
extern ExecutionState current_exec_state;
// For 'return' or 'exit' with value
extern char bsh_last_return_value[INPUT_BUFFER_SIZE];
extern bool bsh_return_value_is_set;
// 'exit' must terminate the shell/script; 'return' must only unwind the
// current function body. Both raise STATE_RETURN_REQUESTED, so this flag is
// what tells them apart.
extern bool bsh_exit_requested;
// Set by a '}' that closes a 'while' whose body came from a stored function
// body rather than a seekable file: the body executor jumps back to this
// 0-based body line instead of seeking.
extern int bsh_pending_body_jump;
// Offset of the line currently being executed from a script file. A 'while'
// must resume at its own header - ftell() after fgets() already points past it.
extern long bsh_current_line_start_fpos;

typedef enum {
    BLOCK_TYPE_IF, BLOCK_TYPE_ELSE, BLOCK_TYPE_WHILE, BLOCK_TYPE_FUNCTION_DEF
} BlockType;

typedef struct BlockFrame {
    BlockType type;
    long loop_start_fpos;
    int loop_start_line_no;
    bool condition_true;
    ExecutionState prev_exec_state;
} BlockFrame;
extern BlockFrame block_stack[MAX_NESTING_DEPTH];
extern int block_stack_top_bf;

// --- Dynamic Library Handles ---
typedef struct DynamicLib {
    char alias[MAX_VAR_NAME_LEN];
    void *handle;
    struct DynamicLib *next;
} DynamicLib;
extern DynamicLib *loaded_libs;

// --- Expression Parsing Context ---
// Used by the recursive descent parser
typedef struct ExprParseContext {
    Token* tokens;      // Array of tokens for the current expression
    int current_token_idx; // Index of the next token to process
    int num_tokens;     // Total number of tokens in the expression
    char* result_buffer; // Buffer to store the final result of the expression
    size_t result_buffer_size;
    int recursion_depth; // To prevent stack overflow in parser
} ExprParseContext;
#define MAX_EXPR_RECURSION_DEPTH 64

// --- Function Prototypes ---
// Core
void initialize_shell(void);
void process_line(char *line, FILE *input_source, int current_line_no, ExecutionState exec_mode);
void execute_script(const char *filename, bool is_import, bool is_startup_script);
void cleanup_shell(void);

// Tokenizer & Operator/Keyword Management
void initialize_operators_core_structural(void);
void add_operator_definition(const char* op_str, TokenType token_type, OperatorType op_type_prop, int precedence, OperatorAssociativity assoc, const char* bsh_handler);
OperatorDefinition* get_operator_definition(const char* op_str);
int match_operator_text(const char *input, const char **op_text);
void add_keyword_alias(const char* original, const char* alias_name);
const char* resolve_keyword_alias(const char* alias_name);
void free_keyword_alias_list(void);
int advanced_tokenize_line(const char *line_text, int line_num, Token *tokens, int max_tokens, char *token_storage, size_t storage_size);

// Path Management
void add_path_to_list(PathDirNode **list_head, const char* dir_path);
void free_path_dir_list(PathDirNode **list_head);
void initialize_module_path(void);

// Variable & Scope Management
int enter_scope(void);
void leave_scope(int scope_id_to_leave);
void cleanup_variables_for_scope(int scope_id);
char* get_variable_scoped(const char *name_raw);
void set_variable_scoped(const char *name_raw, const char *value_to_set, bool is_array_elem);
void expand_variables_in_string_advanced(const char *input_str, char *expanded_str, size_t expanded_str_size);
char* get_array_element_scoped(const char* array_base_name, const char* index_str_raw);
void set_array_element_scoped(const char* array_base_name, const char* index_str_raw, const char* value);

// Command Execution
bool find_command_in_path_dynamic(const char *command, char *full_path);
bool find_module_in_path(const char* module_name, char* full_path);
int execute_external_command(char *command_path, char **args, int arg_count, char *output_buffer, size_t output_buffer_size);
void execute_user_function(UserFunction* func, Token* call_arg_tokens, int call_arg_token_count, FILE* input_source_for_context);

// Expression Evaluation
bool evaluate_expression_from_tokens(Token* tokens, int num_tokens, char* result_buffer, size_t buffer_size);
bool parse_expression_recursive(ExprParseContext* ctx, int min_precedence);
bool parse_operand(ExprParseContext* ctx, char* operand_result_buffer, size_t operand_buffer_size);

// BSH Handler Invocation
bool invoke_bsh_operator_handler(const char* bsh_handler_name,
                                 const char* op_symbol,
                                 int arg_count,
                                 const char* args[],
                                 const char* result_holder_bsh_var,
                                 char* c_result_buffer, size_t c_result_buffer_size);

// Built-in Commands & Operation Handlers
void handle_defoperator_statement(Token *tokens, int num_tokens);
void handle_defkeyword_statement(Token *tokens, int num_tokens);
void handle_assignment_advanced(Token *tokens, int num_tokens);
void handle_echo_advanced(Token *tokens, int num_tokens);
bool evaluate_condition_advanced(Token* operand1_token, Token* operator_token, Token* operand2_token);
bool is_comparison_or_assignment_operator(const char* op_str);
void handle_if_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no);
void handle_else_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no);
void handle_while_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no);
void handle_defunc_statement_advanced(Token *tokens, int num_tokens);
void handle_loadlib_statement(Token *tokens, int num_tokens);
void handle_calllib_statement(Token *tokens, int num_tokens);
void handle_import_statement(Token *tokens, int num_tokens);
void handle_update_cwd_statement(Token *tokens, int num_tokens);
void handle_exit_statement(Token *tokens, int num_tokens);
void handle_eval_statement(Token *tokens, int num_tokens);
void handle_return_statement(Token *tokens, int num_tokens);
void handle_prim_statement(Token *tokens, int num_tokens);
void handle_libloaded_statement(Token *tokens, int num_tokens);
void handle_writefile_statement(Token *tokens, int num_tokens);
void handle_readfile_statement(Token *tokens, int num_tokens);
void handle_process_statement(Token *tokens, int num_tokens);
void set_variable_indirect(const char *name_raw, const char *value_to_set, bool is_array_elem);

// Block Management
void push_block_bf(BlockType type, bool condition_true, long loop_start_fpos, int loop_start_line_no);
BlockFrame* pop_block_bf(void);
BlockFrame* peek_block_bf(void);
void handle_opening_brace_token(Token token);
void handle_closing_brace_token(Token token, FILE* input_source);

// Utility & BSH Callers
char* trim_whitespace(char *str);
void free_all_variables(void);
void free_function_list(void);
void free_operator_list(void);
void free_loaded_libs(void);
long get_file_pos(FILE* f);
char* unescape_string(const char* input, char* output_buffer, size_t buffer_size);
bool input_source_is_file(FILE* f);

// object: management
void parse_and_flatten_bsh_object_string(const char* data_string, const char* base_var_name, int current_scope_id);
bool stringify_bsh_object_to_string(const char* base_var_name, char* output_buffer, size_t buffer_size);

// --- Interfaces the bytecode path needs from the interpreter ---------------
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
void execute_user_function_values(UserFunction* func, const char** argv, int argc);
void besh_dispatch_command_values(const char* name, const char** argv, int argc,
                                  char* out, size_t out_size);

// --- Bytecode path (besh_wasm.c / besh_ir.c / besh_jit.c) ---
#include "besh_jit.h"

#endif /* BESH_CORE_H */
