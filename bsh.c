/*
 * bsh - The Extensible Shell
 * Version: 0.9 (Dynamic Expression Parsing & Script-Defined Operators)
 * Copyright: Riccardo Cecchini <rcecchini.ds@gmail.com>
 *
 * === Overview ===
 * bsh is an extensible, lightweight command-line shell where a significant portion
 * of its syntax, operator behavior, and data handling logic is defined and
 * managed by BSH (bsh script) files at runtime, rather than being hardcoded
 * in this C core. The C core provides a foundational parsing engine,
 * execution environment, and a set of built-in commands that empower BSH
 * scripts to dynamically shape the shell's language.
 *
 * === Core Architectural Principles & Extensibility Mechanisms ===
 *
 * 1.  **Minimal C Core, Maximal BSH Script Control:**
 * The C core is intentionally kept minimal. Its primary responsibilities include:
 * - Tokenizing input based on a small set of fundamental token types and
 * a dynamically populated list of operator symbols.
 * - Parsing and evaluating expressions using an operator-precedence
 * (e.g., precedence climbing) algorithm. This parser is guided by operator
 * properties (type, precedence, associativity) defined by BSH scripts.
 * - Managing execution flow for control structures (if, while, functions).
 * - Variable scoping and management.
 * - Providing built-in commands for core operations, including those that
 * allow BSH scripts to modify the shell's behavior (e.g., `defoperator`).
 * - Interfacing with the operating system for command execution and
 * dynamic library loading.
 *
 * 2.  **Script-Defined Operators (`defoperator` built-in):**
 * - BSH scripts use the `defoperator` command to define most operator
 * symbols (e.g., "+", "*", "==", "++", "?", ":").
 * - For each operator, the script specifies:
 * - `TYPE`: Its grammatical role (e.g., `BINARY_INFIX`, `UNARY_PREFIX`,
 * `TERNARY_PRIMARY`). This informs the C expression parser.
 * - `PRECEDENCE`: An integer determining its binding strength.
 * - `ASSOC`: Associativity (Left, Right, or Non-associative).
 * - `HANDLER`: The name of a BSH function that implements the
 * operator's logic.
 * - The C core's tokenizer learns these operator symbols, and its expression
 * parser uses these properties to correctly interpret expressions.
 *
 * 3.  **BSH-Handled Operator Semantics:**
 * - When the C expression parser determines an operator should be applied,
 * it calls the specific BSH function designated as the `HANDLER` for that
 * operator.
 * - The C core passes the operator symbol and the (already evaluated)
 * operands as string arguments to this BSH handler function.
 * - The BSH handler function is then responsible for:
 * - Performing type checking on the operands (e.g., using a `type.bsh`
 * framework).
 * - Executing the appropriate logic (e.g., calling C functions from a
 * dynamically loaded math library, performing string manipulation).
 * - Setting a result variable that the C core reads back.
 * - This mechanism replaces a single, monolithic `__dynamic_op_handler` with
 * a system of specific, targeted BSH functions for each operator.
 *
 * 4.  **Generalized Expression Evaluation (C Core):**
 * - The C function `evaluate_expression_from_tokens` (and its recursive
 * helpers like `parse_expression_recursive`) implements a robust
 * operator-precedence parsing algorithm.
 * - It consumes a stream of tokens (produced by `advanced_tokenize_line`)
 * and, using the BSH-defined operator properties, constructs an implicit
 * evaluation tree, calling out to BSH handlers as needed.
 * - This allows for complex, nested expressions with user-defined operators
 * and precedences.
 *
 * 5.  **Structured Data Handling (`object:` prefix & `echo` stringification):**
 * - Command output prefixed with `object:` (e.g., `object:["key":"val"]`)
 * is automatically parsed by the C core when assigned to a variable.
 * - The C core "flattens" this structure into a set of BSH variables
 * (e.g., `$myobj_key = "val"`), marked with a metadata variable
 * (e.g., `$myobj_BSH_STRUCT_TYPE = "BSH_OBJECT_ROOT"`).
 * - The `echo` command, when given a variable representing such a BSH object,
 * will automatically "stringify" it back into the `object:[...]` format.
 * - This allows BSH scripts and external commands to exchange structured data.
 *
 * 6.  **Variable Property Access (Dot Notation - C Core):**
 * - The C core's variable expansion logic (`expand_variables_in_string_advanced`)
 * directly supports dot notation for accessing properties of these flattened
 * BSH objects (e.g., `$myobj.user.name` resolves to `myobj_user_name`).
 *
 * 7.  **Dynamic C Library Integration (`def_c_lib`, `loadlib`, `calllib`):**
 * - BSH scripts (e.g., `c_compiler.bsh`) can provide functions like
 * `def_c_lib` to compile C source code (defined in BSH strings) into
 * shared libraries at runtime using a system C compiler.
 * - The `loadlib` built-in loads these (or pre-compiled) shared libraries.
 * - The `calllib` built-in allows BSH scripts to invoke functions within
 * these loaded C libraries, passing arguments and receiving results. This
 * is crucial for performance-sensitive tasks or system calls.
 *
 * 8.  **User-Defined Functions & Lexical Scoping (BSH & C):**
 * - The `function` (or `defunc`) keyword allows BSH scripts to define
 * multi-line shell functions with parameters and local (lexical) scoping,
 * managed by the C core's scope stack.
 *
 * 9.  **Modular Framework (`import`, `BSH_MODULE_PATH`):**
 * - The `import` command allows loading of BSH script modules from paths
 * defined in the `BSH_MODULE_PATH` environment variable, facilitating
 * code organization and reuse.
 *
 * === Tokenization (`advanced_tokenize_line`) ===
 * - Produces a stream of `Token` structs, including line/column info.
 * - `TokenType` is minimal: `TOKEN_WORD`, `TOKEN_STRING`, `TOKEN_NUMBER`,
 * `TOKEN_VARIABLE`, `TOKEN_OPERATOR` (generic), structural punctuation
 * (`TOKEN_LPAREN`, etc.), `TOKEN_COMMENT`, `TOKEN_EOF`, `TOKEN_ERROR`.
 * - Recognizes operators based on the dynamic list populated by `defoperator`.
 *
 * === Goal ===
 * To provide a highly dynamic and introspective shell environment where the
 * language itself can be evolved and customized extensively through scripting,
 * moving beyond the limitations of traditional shells with fixed syntax.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>

// --- Constants and Definitions ---
#define MAX_LINE_LENGTH 2048
#define MAX_ARGS 128
#define MAX_VAR_NAME_LEN 256
#define INPUT_BUFFER_SIZE 4096
#define MAX_FULL_PATH_LEN 1024
#ifndef PATH_MAX
    #ifdef _XOPEN_PATH_MAX
        #define PATH_MAX _XOPEN_PATH_MAX
    #else
        #define PATH_MAX 4096
    #endif
#endif
#define TOKEN_STORAGE_SIZE (MAX_LINE_LENGTH * 2) // Should be ample for token text
#define MAX_NESTING_DEPTH 32
#define MAX_FUNC_LINES 100
#define MAX_FUNC_PARAMS 10
#define MAX_OPERATOR_LEN 16 // Increased for potentially longer operators like "?:"
#define DEFAULT_STARTUP_SCRIPT ".bshrc"
#define MAX_KEYWORD_LEN 32
#define MAX_SCOPE_DEPTH 64
#define DEFAULT_MODULE_PATH "./framework:~/.bsh_framework:/usr/local/share/bsh/framework"
#define MAX_EXPRESSION_TOKENS MAX_ARGS // Max tokens in a single expression to be parsed

#define JSON_STDOUT_PREFIX "json:"
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
    // TOKEN_QMARK, TOKEN_COLON removed, will be TOKEN_OPERATOR
} TokenType;

typedef struct {
    TokenType type;
    const char *text; // Points into the token_storage buffer or original line
    int len;
    int line;         // Line number of the token
    int col;          // Column number of the token
    // Precedence and associativity are properties of OPERATORS, not tokens themselves.
    // They will be looked up from OperatorDefinition when a TOKEN_OPERATOR is encountered.
} Token;

// --- Operator Definition (Dynamic List) ---
typedef enum {
    OP_TYPE_NONE,
    OP_TYPE_UNARY_PREFIX,
    OP_TYPE_UNARY_POSTFIX,
    OP_TYPE_BINARY_INFIX,
    // For ternary "A ? B : C", '?' could be TERNARY_COND_OP and ':' could be TERNARY_BRANCH_OP
    // Or a single operator token like "?:" defined with a special type.
    // For simplicity, let's imagine "?" and ":" are defined separately with specific roles if used in ternary.
    // A more robust way for ternary is for "?" to expect a ":" later at the same precedence level.
    OP_TYPE_TERNARY_PRIMARY, // e.g., "?"
    OP_TYPE_TERNARY_SECONDARY, // e.g., ":"
    // Add other N-ary types if needed
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
OperatorDefinition *operator_list_head = NULL;

// --- Keyword Aliasing (Dynamic List) ---
typedef struct KeywordAlias {
    char original[MAX_KEYWORD_LEN + 1];
    char alias[MAX_KEYWORD_LEN + 1];
    struct KeywordAlias *next;
} KeywordAlias;
KeywordAlias *keyword_alias_head = NULL;

// --- PATH Directories (Dynamic List) ---
typedef struct PathDirNode {
    char *path;
    struct PathDirNode *next;
} PathDirNode;
PathDirNode *path_list_head = NULL;
PathDirNode *module_path_list_head = NULL;

// --- Variable Scoping and Management ---
typedef struct Variable {
    char name[MAX_VAR_NAME_LEN];
    char *value;
    bool is_array_element;
    int scope_id;
    struct Variable *next;
} Variable;
Variable *variable_list_head = NULL;

typedef struct ScopeFrame {
    int scope_id;
} ScopeFrame;
ScopeFrame scope_stack[MAX_SCOPE_DEPTH];
int scope_stack_top = -1;
int next_scope_id = 1;
#define GLOBAL_SCOPE_ID 0

// --- User-Defined Functions ---
typedef struct UserFunction {
    char name[MAX_VAR_NAME_LEN];
    char params[MAX_FUNC_PARAMS][MAX_VAR_NAME_LEN];
    int param_count;
    char* body[MAX_FUNC_LINES];
    int line_count;
    struct UserFunction *next;
} UserFunction;
UserFunction *function_list = NULL;
bool is_defining_function = false;
UserFunction *current_function_definition = NULL;


// --- Execution State and Block Management ---
typedef enum {
    STATE_NORMAL, STATE_BLOCK_EXECUTE, STATE_BLOCK_SKIP,
    STATE_DEFINE_FUNC_BODY, STATE_IMPORT_PARSING,
    STATE_RETURN_REQUESTED // For 'return' and 'exit' functionality
} ExecutionState;
ExecutionState current_exec_state = STATE_NORMAL;
// For 'return' or 'exit' with value
char bsh_last_return_value[INPUT_BUFFER_SIZE]; 
bool bsh_return_value_is_set = false;


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
BlockFrame block_stack[MAX_NESTING_DEPTH];
int block_stack_top_bf = -1;

// --- Dynamic Library Handles ---
typedef struct DynamicLib {
    char alias[MAX_VAR_NAME_LEN];
    void *handle;
    struct DynamicLib *next;
} DynamicLib;
DynamicLib *loaded_libs = NULL;

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


// --- Function Prototypes (Updated/New) ---
// Core
void initialize_shell();
void process_line(char *line, FILE *input_source, int current_line_no, ExecutionState exec_mode);
void execute_script(const char *filename, bool is_import, bool is_startup_script);
void cleanup_shell();

// Tokenizer & Operator/Keyword Management
void initialize_operators_core_structural(); // Renamed
void add_operator_definition(const char* op_str, TokenType token_type, OperatorType op_type_prop, int precedence, OperatorAssociativity assoc, const char* bsh_handler); // Changed signature
OperatorDefinition* get_operator_definition(const char* op_str); // New helper
int match_operator_text(const char *input, const char **op_text); // Simplified from match_operator_dynamic
void add_keyword_alias(const char* original, const char* alias_name);
const char* resolve_keyword_alias(const char* alias_name);
void free_keyword_alias_list();
int advanced_tokenize_line(const char *line_text, int line_num, Token *tokens, int max_tokens, char *token_storage, size_t storage_size); // Added line_num, col

// Path Management
void add_path_to_list(PathDirNode **list_head, const char* dir_path);
void free_path_dir_list(PathDirNode **list_head);
void initialize_module_path();

// Variable & Scope Management
int enter_scope();
void leave_scope(int scope_id_to_leave);
void cleanup_variables_for_scope(int scope_id);
char* get_variable_scoped(const char *name_raw);
void set_variable_scoped(const char *name_raw, const char *value_to_set, bool is_array_elem);
void expand_variables_in_string_advanced(const char *input_str, char *expanded_str, size_t expanded_str_size); // Keep as is for now
char* get_array_element_scoped(const char* array_base_name, const char* index_str_raw);
void set_array_element_scoped(const char* array_base_name, const char* index_str_raw, const char* value);

// Command Execution
bool find_command_in_path_dynamic(const char *command, char *full_path);
bool find_module_in_path(const char* module_name, char* full_path);
int execute_external_command(char *command_path, char **args, int arg_count, char *output_buffer, size_t output_buffer_size);
void execute_user_function(UserFunction* func, Token* call_arg_tokens, int call_arg_token_count, FILE* input_source_for_context);

// Expression Evaluation (New/Rewritten)
bool evaluate_expression_from_tokens(Token* tokens, int num_tokens, char* result_buffer, size_t buffer_size);
bool parse_expression_recursive(ExprParseContext* ctx, int min_precedence); // Core of precedence climbing
bool parse_operand(ExprParseContext* ctx, char* operand_result_buffer, size_t operand_buffer_size); // Parses primary, unary prefix

// BSH Handler Invocation
bool invoke_bsh_operator_handler(const char* bsh_handler_name,
                                 const char* op_symbol, // The operator itself
                                 int arg_count, // Number of string arguments for BSH
                                 const char* args[], // Array of string arguments
                                 const char* result_holder_bsh_var,
                                 char* c_result_buffer, size_t c_result_buffer_size);
// Built-in Commands & Operation Handlers
void handle_defoperator_statement(Token *tokens, int num_tokens); // Updated
void handle_defkeyword_statement(Token *tokens, int num_tokens);
void handle_assignment_advanced(Token *tokens, int num_tokens); // Will use evaluate_expression_from_tokens
void handle_echo_advanced(Token *tokens, int num_tokens);
bool evaluate_condition_advanced(Token* operand1_token, Token* operator_token, Token* operand2_token); // May be replaced by generic expr eval
void handle_if_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no); // Will use evaluate_expression_from_tokens for condition
void handle_else_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no);
void handle_while_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no); // Will use evaluate_expression_from_tokens for condition
void handle_defunc_statement_advanced(Token *tokens, int num_tokens);
// void handle_inc_dec_statement_advanced(Token *tokens, int num_tokens, bool increment); // ++/-- are now generic TOKEN_OPERATOR
void handle_loadlib_statement(Token *tokens, int num_tokens);
void handle_calllib_statement(Token *tokens, int num_tokens);
void handle_import_statement(Token *tokens, int num_tokens);
void handle_update_cwd_statement(Token *tokens, int num_tokens);
// void handle_unary_op_statement(Token* var_token, Token* op_token, bool is_prefix); // Replaced by generic expression eval
void handle_exit_statement(Token *tokens, int num_tokens);
void handle_eval_statement(Token *tokens, int num_tokens);


// Block Management
void push_block_bf(BlockType type, bool condition_true, long loop_start_fpos, int loop_start_line_no);
BlockFrame* pop_block_bf();
BlockFrame* peek_block_bf();
void handle_opening_brace_token(Token token); // Needs to respect current_exec_state
void handle_closing_brace_token(Token token, FILE* input_source); // Needs to respect current_exec_state

// Utility & BSH Callers
char* trim_whitespace(char *str);
void free_all_variables();
void free_function_list();
void free_operator_list(); // Updated for new OperatorDefinition
void free_loaded_libs();
long get_file_pos(FILE* f);
char* unescape_string(const char* input, char* output_buffer, size_t buffer_size);
bool input_source_is_file(FILE* f);

// object: management
void parse_and_flatten_bsh_object_string(const char* data_string, const char* base_var_name, int current_scope_id);
bool stringify_bsh_object_to_string(const char* base_var_name, char* output_buffer, size_t buffer_size);


// --- Tokenizer & Operator/Keyword Management Implementations ---

// RENAMED from initialize_operators_dynamic
void initialize_operators_core_structural() {
    operator_list_head = NULL; // Ensure it's clear

    // Define only ABSOLUTELY structural tokens if they aren't handled by generic TOKEN_OPERATOR logic
    // and defoperator. For a truly dynamic system, even these could potentially be defined by
    // a very early, C-loaded "bootstrap.bsh" if defoperator was powerful enough from the start.
    // For now, let's assume these are fixed structure tokens and not "operators" in the sense
    // of performing calculations or logical operations that BSH scripts would define.
    // Their token types (TOKEN_LPAREN, etc.) are directly used by the C parser for syntax.

    // Example: If '(' is always TOKEN_LPAREN and not a user-definable operator symbol:
    // add_operator_definition("(", TOKEN_LPAREN, OP_TYPE_NONE, 0, ASSOC_NONE, ""); // No BSH handler for pure syntax
    // add_operator_definition(")", TOKEN_RPAREN, OP_TYPE_NONE, 0, ASSOC_NONE, "");
    // add_operator_definition("{", TOKEN_LBRACE, OP_TYPE_NONE, 0, ASSOC_NONE, "");
    // add_operator_definition("}", TOKEN_RBRACE, OP_TYPE_NONE, 0, ASSOC_NONE, "");
    // add_operator_definition("[", TOKEN_LBRACKET, OP_TYPE_NONE, 0, ASSOC_NONE, "");
    // add_operator_definition("]", TOKEN_RBRACKET, OP_TYPE_NONE, 0, ASSOC_NONE, "");
    // add_operator_definition(";", TOKEN_SEMICOLON, OP_TYPE_NONE, 0, ASSOC_NONE, "");

    // '=' could be special if C handles assignment uniquely, or a regular operator.
    // If it's special for $var = value:
    // add_operator_definition("=", TOKEN_ASSIGN, OP_TYPE_BINARY_INFIX, 2, ASSOC_RIGHT, "_bsh_assign"); // Or no handler if C manages it
    // Or it could be fully script defined. Let's assume for now TOKEN_ASSIGN is still a distinct type for process_line logic.
}


// New signature for adding richer operator definitions
void add_operator_definition(const char* op_str, TokenType token_type, OperatorType op_type_prop,
                             int precedence, OperatorAssociativity assoc, const char* bsh_handler_name_str) {
    if (strlen(op_str) > MAX_OPERATOR_LEN) {
        fprintf(stderr, "Warning: Operator '%s' too long (max %d chars).\n", op_str, MAX_OPERATOR_LEN);
        return;
    }

    // Check if operator already exists, update if so (optional, or disallow)
    OperatorDefinition *current = operator_list_head;
    while(current) {
        if (strcmp(current->op_str, op_str) == 0) {
            fprintf(stderr, "Warning: Operator '%s' already defined. Re-defining.\n", op_str);
            current->token_type = token_type;
            current->op_type_prop = op_type_prop;
            current->precedence = precedence;
            current->associativity = assoc;
            strncpy(current->bsh_handler_name, bsh_handler_name_str, MAX_VAR_NAME_LEN -1);
            current->bsh_handler_name[MAX_VAR_NAME_LEN -1] = '\0';
            return;
        }
        current = current->next;
    }

    OperatorDefinition *new_op = (OperatorDefinition*)malloc(sizeof(OperatorDefinition));
    if (!new_op) {
        perror("malloc for new operator definition failed");
        return;
    }
    strncpy(new_op->op_str, op_str, MAX_OPERATOR_LEN);
    new_op->op_str[MAX_OPERATOR_LEN] = '\0';
    new_op->token_type = token_type;
    new_op->op_type_prop = op_type_prop;
    new_op->precedence = precedence;
    new_op->associativity = assoc;
    strncpy(new_op->bsh_handler_name, bsh_handler_name_str, MAX_VAR_NAME_LEN -1);
    new_op->bsh_handler_name[MAX_VAR_NAME_LEN-1] = '\0';

    new_op->next = operator_list_head;
    operator_list_head = new_op;
}

// Helper to get an operator's full definition
OperatorDefinition* get_operator_definition(const char* op_str) {
    OperatorDefinition *current = operator_list_head;
    while (current) {
        if (strcmp(current->op_str, op_str) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// Simplified from match_operator_dynamic. Now only matches text, returns length.
// The caller (tokenizer) will then use get_operator_definition() if needed.
int match_operator_text(const char *input, const char **op_text) {
    OperatorDefinition *current = operator_list_head;
    const char* best_match_str = NULL;
    int longest_match_len = 0;

    // Check built-in single character structural tokens first if they are not in OperatorDefinition list
    // (e.g. '(', ')', '{', '}', '[', ']', ';', '=')
    // This depends on whether they are added to operator_list_head or handled separately by tokenizer.
    // For now, assume all symbols that can be TOKEN_OPERATOR are in operator_list_head.
    // Let's assume fixed punctuation like '(', ')', etc. are handled before this,
    // and this function is for TOKEN_OPERATOR candidates.

    while (current) {
        size_t op_len = strlen(current->op_str);
        if (strncmp(input, current->op_str, op_len) == 0) {
            if (op_len > longest_match_len) {
                longest_match_len = op_len;
                best_match_str = current->op_str; // Point to the string in the definition
            }
        }
        current = current->next;
    }

    if (longest_match_len > 0) {
        if (op_text) *op_text = best_match_str;
        return longest_match_len;
    }
    return 0;
}

void free_operator_list() {
    OperatorDefinition *current = operator_list_head;
    OperatorDefinition *next_op;
    while (current) {
        next_op = current->next;
        free(current);
        current = next_op;
    }
    operator_list_head = NULL;
}


// Updated tokenizer to be simpler and use new types/operator matching
int advanced_tokenize_line(const char *line_text, int line_num, Token *tokens, int max_tokens, char *token_storage, size_t storage_size) {
    int token_count = 0;
    const char *p = line_text;
    char *storage_ptr = token_storage;
    size_t remaining_storage = storage_size;
    int current_col = 1;

    auto void add_token(TokenType type, const char* text_start, int len) {
        if (token_count >= max_tokens -1 || remaining_storage <= len +1) { /* Ran out of space */ return; }
        tokens[token_count].type = type;
        tokens[token_count].line = line_num;
        tokens[token_count].col = current_col - len; // Approximate start column

        strncpy(storage_ptr, text_start, len);
        storage_ptr[len] = '\0';
        tokens[token_count].text = storage_ptr;
        tokens[token_count].len = len;

        storage_ptr += (len + 1);
        remaining_storage -= (len + 1);
        token_count++;
    };

    while (*p && token_count < max_tokens -1) { // -1 to leave space for EOF
        while (isspace((unsigned char)*p)) {
            if (*p == '\n') { line_num++; current_col = 1;} else { current_col++; }
            p++;
        }
        if (!*p) break;

        const char *p_token_start = p;
        int initial_col = current_col;

        // 1. Comments
        if (*p == '#') {
            const char *comment_start = p;
            while (*p && *p != '\n') p++; // Consume till end of line or string
            // add_token(TOKEN_COMMENT, comment_start, p - comment_start); // Optional: tokenize comments
            // For bsh, comments usually mean ignore rest of line for execution
            goto end_of_line_tokens; // Skip to add EOF
        }

        // 2. Variables
        if (*p == '$') {
            p++; current_col++;
            if (*p == '{') {
                p++; current_col++;
                while (*p && *p != '}') { p++; current_col++; }
                if (*p == '}') { p++; current_col++; }
            } else {
                while (isalnum((unsigned char)*p) || *p == '_') { p++; current_col++; }
            }
            // Array access like $var[index] or $var.prop needs more complex tokenization
            // For now, $var or ${var} is one token. Dot/bracket would be separate TOKEN_OPERATORs.
            add_token(TOKEN_VARIABLE, p_token_start, p - p_token_start);
            continue;
        }

        // 3. Strings
        if (*p == '"') {
            p++; current_col++; // Skip opening quote
            while (*p) {
                if (*p == '\\' && *(p+1)) { // Handle escaped char
                    p += 2; current_col += 2;
                } else if (*p == '"') {
                    p++; current_col++; // Skip closing quote
                    break;
                } else {
                    p++; current_col++;
                }
            }
            add_token(TOKEN_STRING, p_token_start, p - p_token_start);
            continue;
        }

        // 4. Numbers (simple integer or float looking)
        // This is basic; a more robust number parser might be needed.
        // It will just grab sequences of digits, optionally one decimal point, then more digits.
        // Negative numbers: '-' sign would be a separate TOKEN_OPERATOR if defined.
        if (isdigit((unsigned char)*p) || (*p == '.' && isdigit((unsigned char)*(p+1)))) {
            bool has_decimal = (*p == '.');
            if (has_decimal) { p++; current_col++;} // consume leading '.' if part of number like .5
            
            while (isdigit((unsigned char)*p)) { p++; current_col++; }
            if (!has_decimal && *p == '.') { // Check for decimal point
                p++; current_col++;
                has_decimal = true; // Only one decimal point allowed by this simple logic
                while (isdigit((unsigned char)*p)) { p++; current_col++; }
            }
            add_token(TOKEN_NUMBER, p_token_start, p - p_token_start);
            continue;
        }
        
        // 5. Punctuation/Structural tokens (if not defined as TOKEN_OPERATORs)
        // These are typically single characters that have fixed meaning.
        // If these are to be made dynamic, they should be defined via defoperator and become TOKEN_OPERATOR
        TokenType fixed_punct_type = TOKEN_EMPTY;
        switch (*p) {
            case '(': fixed_punct_type = TOKEN_LPAREN; break;
            case ')': fixed_punct_type = TOKEN_RPAREN; break;
            case '{': fixed_punct_type = TOKEN_LBRACE; break;
            case '}': fixed_punct_type = TOKEN_RBRACE; break;
            case '[': fixed_punct_type = TOKEN_LBRACKET; break;
            case ']': fixed_punct_type = TOKEN_RBRACKET; break;
            case ';': fixed_punct_type = TOKEN_SEMICOLON; break;
            // case '=': fixed_punct_type = TOKEN_ASSIGN; break; // Consider if '=' is always assign or can be '==' etc.
        }
        if (fixed_punct_type != TOKEN_EMPTY) {
            p++; current_col++;
            add_token(fixed_punct_type, p_token_start, 1);
            continue;
        }

        // 6. Script-Defined Operators (can be multi-character)
        const char *matched_op_text_ptr = NULL;
        int op_len = match_operator_text(p, &matched_op_text_ptr); // match_operator_text uses operator_list_head
        if (op_len > 0) {
            // The matched_op_text_ptr points to the op_str in an OperatorDefinition.
            // We still copy it to token_storage for consistency in Token.text.
            add_token(TOKEN_OPERATOR, p, op_len); // Type is generic TOKEN_OPERATOR
            p += op_len;
            current_col += op_len;
            continue;
        }


        // 7. Words (keywords, command names, identifiers)
        if (isalnum((unsigned char)*p) || *p == '_') { // Start of a word
            while (isalnum((unsigned char)*p) || *p == '_') {
                p++; current_col++;
            }
            add_token(TOKEN_WORD, p_token_start, p - p_token_start);
            continue;
        }

        // 8. Unrecognized character
        fprintf(stderr, "bsh: tokenize error: Unrecognized character '%c' at line %d, col %d.\n", *p, line_num, current_col);
        // For now, create an error token and try to continue. A real shell might stop or have better recovery.
        add_token(TOKEN_ERROR, p_token_start, 1);
        p++; current_col++; // Skip the bad character
    }

end_of_line_tokens:
    if (token_count < max_tokens) {
        tokens[token_count].type = TOKEN_EOF;
        tokens[token_count].text = "EOF"; // Static string, no need for storage_ptr
        tokens[token_count].len = 3;
        tokens[token_count].line = line_num;
        tokens[token_count].col = current_col;
        token_count++;
    }
    return token_count;
}


// --- Built-in Command Implementations (handle_defoperator_statement updated) ---

void handle_defoperator_statement(Token *tokens, int num_tokens) {
    if (current_exec_state == STATE_BLOCK_SKIP && current_exec_state != STATE_IMPORT_PARSING) return;

    // Syntax: defoperator <op_symbol_str> TYPE <type_enum_str> [PRECEDENCE <N>] [ASSOC <L|R|N>] HANDLER <bsh_func_name>
    // Example: defoperator "+" TYPE BINARY_INFIX PRECEDENCE 10 ASSOC L HANDLER "math_add"
    if (num_tokens < 6) { // Minimum: defoperator "sym" TYPE SOME_TYPE HANDLER "hdlr"
        fprintf(stderr, "Syntax: defoperator <op_symbol> TYPE <type> [PRECEDENCE <N>] [ASSOC <L|R|N>] HANDLER <handler_func>\n");
        fprintf(stderr, "  TYPE: UNARY_PREFIX, UNARY_POSTFIX, BINARY_INFIX, TERNARY_PRIMARY, TERNARY_SECONDARY\n");
        fprintf(stderr, "  ASSOC: L (left), R (right), N (none/non-assoc)\n");
        return;
    }

    char op_symbol[MAX_OPERATOR_LEN + 1];
    char bsh_handler_name[MAX_VAR_NAME_LEN];
    OperatorType op_type_prop = OP_TYPE_NONE;
    int precedence = 0; // Default precedence
    OperatorAssociativity assoc = ASSOC_LEFT; // Default associativity for binary

    // Token 1: Operator Symbol (string)
    if (tokens[1].type != TOKEN_STRING && tokens[1].type != TOKEN_WORD) { // Allow unquoted simple ops
        fprintf(stderr, "defoperator: Operator symbol must be a string or word.\n"); return;
    }
    // Unescape if it's a BSH string literal, or use text if it's a WORD
    char temp_op_sym_buf[MAX_OPERATOR_LEN*2]; // Buffer for potential unescaping
    const char* op_sym_src_ptr = tokens[1].text;
    if (tokens[1].type == TOKEN_STRING) {
        if (tokens[1].len - 2 > MAX_OPERATOR_LEN || tokens[1].len < 2) { /* Check quotes "" */
            fprintf(stderr, "defoperator: Invalid operator symbol string length.\n"); return;
        }
        strncpy(temp_op_sym_buf, tokens[1].text + 1, tokens[1].len - 2);
        temp_op_sym_buf[tokens[1].len - 2] = '\0';
        op_sym_src_ptr = temp_op_sym_buf;
    } else { // TOKEN_WORD
         if (tokens[1].len > MAX_OPERATOR_LEN) {
            fprintf(stderr, "defoperator: Operator symbol word too long.\n"); return;
        }
        // op_sym_src_ptr is already tokens[1].text which is fine
    }
    strncpy(op_symbol, op_sym_src_ptr, MAX_OPERATOR_LEN);
    op_symbol[MAX_OPERATOR_LEN] = '\0';
    if (strlen(op_symbol) == 0) {
        fprintf(stderr, "defoperator: Operator symbol cannot be empty.\n"); return;
    }


    int current_arg_idx = 2; // Start parsing from TYPE keyword

    // TYPE <type_enum_str>
    if (current_arg_idx + 1 >= num_tokens || strcmp(tokens[current_arg_idx].text, "TYPE") != 0) {
        fprintf(stderr, "defoperator: Missing 'TYPE' keyword or value.\n"); return;
    }
    current_arg_idx++; // Move to type_enum_str
    const char* type_str = tokens[current_arg_idx].text;
    if (strcmp(type_str, "UNARY_PREFIX") == 0) op_type_prop = OP_TYPE_UNARY_PREFIX;
    else if (strcmp(type_str, "UNARY_POSTFIX") == 0) op_type_prop = OP_TYPE_UNARY_POSTFIX;
    else if (strcmp(type_str, "BINARY_INFIX") == 0) op_type_prop = OP_TYPE_BINARY_INFIX;
    else if (strcmp(type_str, "TERNARY_PRIMARY") == 0) op_type_prop = OP_TYPE_TERNARY_PRIMARY;
    else if (strcmp(type_str, "TERNARY_SECONDARY") == 0) op_type_prop = OP_TYPE_TERNARY_SECONDARY;
    else { fprintf(stderr, "defoperator: Unknown operator TYPE '%s'.\n", type_str); return; }
    current_arg_idx++;

    // Optional: PRECEDENCE <N>
    if (current_arg_idx < num_tokens && strcmp(tokens[current_arg_idx].text, "PRECEDENCE") == 0) {
        current_arg_idx++;
        if (current_arg_idx >= num_tokens || tokens[current_arg_idx].type != TOKEN_NUMBER) {
            fprintf(stderr, "defoperator: PRECEDENCE requires a number.\n"); return;
        }
        precedence = atoi(tokens[current_arg_idx].text);
        current_arg_idx++;
    }

    // Optional: ASSOC <L|R|N>
    if (current_arg_idx < num_tokens && strcmp(tokens[current_arg_idx].text, "ASSOC") == 0) {
        current_arg_idx++;
        if (current_arg_idx >= num_tokens || tokens[current_arg_idx].type != TOKEN_WORD) {
            fprintf(stderr, "defoperator: ASSOC requires L, R, or N.\n"); return;
        }
        const char* assoc_str = tokens[current_arg_idx].text;
        if (strcmp(assoc_str, "L") == 0) assoc = ASSOC_LEFT;
        else if (strcmp(assoc_str, "R") == 0) assoc = ASSOC_RIGHT;
        else if (strcmp(assoc_str, "N") == 0) assoc = ASSOC_NONE;
        else { fprintf(stderr, "defoperator: Unknown ASSOC type '%s'.\n", assoc_str); return; }
        current_arg_idx++;
    }

    // HANDLER <bsh_func_name>
    if (current_arg_idx + 1 >= num_tokens || strcmp(tokens[current_arg_idx].text, "HANDLER") != 0) {
        fprintf(stderr, "defoperator: Missing 'HANDLER' keyword or value for operator '%s'.\n", op_symbol); return;
    }
    current_arg_idx++; // Move to bsh_func_name
    if (tokens[current_arg_idx].type != TOKEN_WORD && tokens[current_arg_idx].type != TOKEN_STRING) {
        fprintf(stderr, "defoperator: Handler name must be a word or string for operator '%s'.\n", op_symbol); return;
    }
    // Similar unescaping/copying for handler name if it can be a string
    const char* handler_name_src = tokens[current_arg_idx].text;
    if(tokens[current_arg_idx].type == TOKEN_STRING) {
        // unescape logic similar to op_symbol
        // For simplicity, assume handler name is TOKEN_WORD or simple TOKEN_STRING for now
        if (tokens[current_arg_idx].len - 2 < MAX_VAR_NAME_LEN && tokens[current_arg_idx].len >=2){
            strncpy(bsh_handler_name, tokens[current_arg_idx].text + 1, tokens[current_arg_idx].len - 2);
            bsh_handler_name[tokens[current_arg_idx].len - 2] = '\0';
        } else {
             fprintf(stderr, "defoperator: Invalid handler name string for operator '%s'.\n", op_symbol); return;
        }
    } else {
        strncpy(bsh_handler_name, handler_name_src, MAX_VAR_NAME_LEN - 1);
        bsh_handler_name[MAX_VAR_NAME_LEN - 1] = '\0';
    }
    
    if (strlen(bsh_handler_name) == 0) {
         fprintf(stderr, "defoperator: BSH handler name cannot be empty for operator '%s'.\n", op_symbol); return;
    }

    // Add the operator definition
    add_operator_definition(op_symbol, TOKEN_OPERATOR, op_type_prop, precedence, assoc, bsh_handler_name);
    // printf("DEBUG: Defined operator '%s' TYPE %d PREC %d ASSOC %d HANDLER '%s'\n",
    //        op_symbol, op_type_prop, precedence, assoc, bsh_handler_name);
}


// --- BSH Handler Invocation ---
bool invoke_bsh_operator_handler(const char* bsh_handler_name_param,
                                 const char* op_symbol_param, // The operator itself, for context if handler handles multiple
                                 int arg_count_for_bsh,      // Number of string arguments for BSH
                                 const char* bsh_args_str_array[], // Array of string arguments
                                 const char* result_holder_bsh_var_name,
                                 char* c_result_buffer, size_t c_result_buffer_size) {

    char bsh_handler_name[MAX_VAR_NAME_LEN];
    strncpy(bsh_handler_name, bsh_handler_name_param, MAX_VAR_NAME_LEN -1);
    bsh_handler_name[MAX_VAR_NAME_LEN -1] = '\0';
    
    char op_symbol[MAX_OPERATOR_LEN +1];
    strncpy(op_symbol, op_symbol_param ? op_symbol_param : "", MAX_OPERATOR_LEN);
    op_symbol[MAX_OPERATOR_LEN] = '\0';


    UserFunction* func = function_list;
    while (func) {
        if (strcmp(func->name, bsh_handler_name) == 0) break;
        func = func->next;
    }
    if (!func) {
        fprintf(stderr, "Error: BSH operator handler function '%s' not found.\n", bsh_handler_name);
        snprintf(c_result_buffer, c_result_buffer_size, "BSH_HANDLER_NOT_FOUND<%s>", bsh_handler_name);
        return false;
    }

    // The BSH handler function's parameters should match what C passes.
    // Typically: (op_symbol_str, operand1_str, operand2_str, ..., result_holder_name_str)
    // Total args passed to BSH = actual operands + op_symbol + result_holder_name
    int expected_bsh_params = arg_count_for_bsh + 2; // +2 for op_symbol and result_holder_var_name
    if (func->param_count != expected_bsh_params) {
        fprintf(stderr, "Error: BSH handler '%s' param count mismatch. Expected %d (op_sym, %d args, res_holder), got %d.\n",
                bsh_handler_name, expected_bsh_params, arg_count_for_bsh, func->param_count);
        snprintf(c_result_buffer, c_result_buffer_size, "BSH_HANDLER_PARAM_MISMATCH<%s>", bsh_handler_name);
        return false;
    }

    Token call_tokens_to_bsh[MAX_ARGS]; // Max args for a user function
    if (expected_bsh_params > MAX_ARGS) {
         fprintf(stderr, "Error: Too many arguments for BSH handler call internal limit.\n");
         snprintf(c_result_buffer, c_result_buffer_size, "BSH_HANDLER_ARG_LIMIT_EXCEEDED");
         return false;
    }

    // We need storage for the token text for these dynamic arguments.
    // Let's create a temporary buffer. This is a simplification.
    // A more robust solution would manage this memory more carefully or use a list of allocated strings.
    char arg_storage_for_bsh_call[MAX_ARGS][INPUT_BUFFER_SIZE]; // Max length for each arg string

    int current_bsh_token_idx = 0;

    // 1. Operator Symbol
    strncpy(arg_storage_for_bsh_call[current_bsh_token_idx], op_symbol, INPUT_BUFFER_SIZE -1);
    call_tokens_to_bsh[current_bsh_token_idx].type = TOKEN_STRING;
    call_tokens_to_bsh[current_bsh_token_idx].text = arg_storage_for_bsh_call[current_bsh_token_idx];
    call_tokens_to_bsh[current_bsh_token_idx].len = strlen(op_symbol);
    current_bsh_token_idx++;

    // 2. Actual arguments from C expression evaluation
    for (int i = 0; i < arg_count_for_bsh; ++i) {
        strncpy(arg_storage_for_bsh_call[current_bsh_token_idx], bsh_args_str_array[i], INPUT_BUFFER_SIZE -1);
        call_tokens_to_bsh[current_bsh_token_idx].type = TOKEN_STRING; // Pass evaluated C strings as BSH strings
        call_tokens_to_bsh[current_bsh_token_idx].text = arg_storage_for_bsh_call[current_bsh_token_idx];
        call_tokens_to_bsh[current_bsh_token_idx].len = strlen(bsh_args_str_array[i]);
        current_bsh_token_idx++;
    }
    
    // 3. Result Holder Variable Name
    strncpy(arg_storage_for_bsh_call[current_bsh_token_idx], result_holder_bsh_var_name, INPUT_BUFFER_SIZE -1);
    call_tokens_to_bsh[current_bsh_token_idx].type = TOKEN_WORD; // Pass as variable name
    call_tokens_to_bsh[current_bsh_token_idx].text = arg_storage_for_bsh_call[current_bsh_token_idx];
    call_tokens_to_bsh[current_bsh_token_idx].len = strlen(result_holder_bsh_var_name);
    current_bsh_token_idx++;


    execute_user_function(func, call_tokens_to_bsh, current_bsh_token_idx, NULL); // NULL for file context

    char* result_from_bsh = get_variable_scoped(result_holder_bsh_var_name);
    if (result_from_bsh) {
        strncpy(c_result_buffer, result_from_bsh, c_result_buffer_size - 1);
        c_result_buffer[c_result_buffer_size - 1] = '\0';
    } else {
        snprintf(c_result_buffer, c_result_buffer_size, "BSH_HANDLER_NO_RESULT<%s>", result_holder_bsh_var_name);
        // This might be an error or might be acceptable if the operation has side effects only
        // and doesn't produce a distinct "expression value".
    }
    return true;
}


// --- Expression Evaluation (New/Rewritten using Precedence Climbing) ---

// Forward declaration for recursive calls
bool parse_expression_recursive(ExprParseContext* ctx, int min_precedence);

// Parses a primary: number, variable, string, or parenthesized expression
// Also handles UNARY_PREFIX operators here as they have high precedence.
bool parse_operand(ExprParseContext* ctx, char* operand_result_buffer, size_t operand_buffer_size) {
    if (ctx->current_token_idx >= ctx->num_tokens) {
        fprintf(stderr, "Expression parser: Unexpected EOF while parsing operand.\n");
        strncpy(operand_result_buffer, "EXPR_PARSE_ERROR_EOF_OPERAND", operand_buffer_size-1);
        return false;
    }
    if (ctx->recursion_depth >= MAX_EXPR_RECURSION_DEPTH) {
        fprintf(stderr, "Expression parser: Max recursion depth reached.\n");
        strncpy(operand_result_buffer, "EXPR_PARSE_ERROR_RECURSION", operand_buffer_size-1);
        return false;
    }
    ctx->recursion_depth++;

    Token current_token = ctx->tokens[ctx->current_token_idx];
    operand_result_buffer[0] = '\0';

    if (current_token.type == TOKEN_NUMBER || current_token.type == TOKEN_VARIABLE || current_token.type == TOKEN_WORD) {
        expand_variables_in_string_advanced(current_token.text, operand_result_buffer, operand_buffer_size);
        ctx->current_token_idx++;
    } else if (current_token.type == TOKEN_STRING) {
        char unescaped[INPUT_BUFFER_SIZE];
        unescape_string(current_token.text, unescaped, sizeof(unescaped));
        expand_variables_in_string_advanced(unescaped, operand_result_buffer, operand_buffer_size);
        ctx->current_token_idx++;
    } else if (current_token.type == TOKEN_LPAREN) {
        ctx->current_token_idx++; // Consume '('
        if (!parse_expression_recursive(ctx, 0)) { // Parse sub-expression with lowest precedence
             // Error already printed by recursive call
             strncpy(operand_result_buffer, "EXPR_PARSE_ERROR_SUB_EXPR", operand_buffer_size-1);
             ctx->recursion_depth--; return false;
        }
        // Result of sub-expression is now in ctx->result_buffer (the main one)
        strncpy(operand_result_buffer, ctx->result_buffer, operand_buffer_size -1);
        
        if (ctx->current_token_idx >= ctx->num_tokens || ctx->tokens[ctx->current_token_idx].type != TOKEN_RPAREN) {
            fprintf(stderr, "Expression parser: Missing ')' at line %d col %d.\n", current_token.line, current_token.col);
            strncpy(operand_result_buffer, "EXPR_PARSE_ERROR_MISSING_RPAREN", operand_buffer_size-1);
            ctx->recursion_depth--; return false;
        }
        ctx->current_token_idx++; // Consume ')'
    } else if (current_token.type == TOKEN_OPERATOR) {
        OperatorDefinition* op_def = get_operator_definition(current_token.text);
        if (op_def && op_def->op_type_prop == OP_TYPE_UNARY_PREFIX) {
            ctx->current_token_idx++; // Consume prefix operator
            char rhs_operand_value[INPUT_BUFFER_SIZE];
            // The operand of a prefix operator is parsed with a precedence higher than the prefix operator itself,
            // or as a primary. Let's use op_def->precedence to be general.
            if (!parse_expression_recursive(ctx, op_def->precedence)) { // Parse operand for prefix op
                strncpy(operand_result_buffer, "EXPR_PARSE_ERROR_PREFIX_OPERAND", operand_buffer_size-1);
                ctx->recursion_depth--; return false;
            }
            // Result of RHS is in ctx->result_buffer
            strncpy(rhs_operand_value, ctx->result_buffer, sizeof(rhs_operand_value)-1);

            const char* bsh_args[] = {rhs_operand_value}; // Argument for unary prefix is the operand's value
            char temp_bsh_result_var[MAX_VAR_NAME_LEN]; // Temporary BSH var for the handler
            snprintf(temp_bsh_result_var, sizeof(temp_bsh_result_var), "__bsh_expr_temp_%d", rand());

            if (!invoke_bsh_operator_handler(op_def->bsh_handler_name, op_def->op_str, 1, bsh_args,
                                             temp_bsh_result_var, operand_result_buffer, operand_buffer_size)) {
                // Error already printed by invoke_bsh_operator_handler or result indicates error
                // operand_result_buffer might contain "BSH_HANDLER_NOT_FOUND", etc.
            }
        } else {
            fprintf(stderr, "Expression parser: Unexpected token '%s' (type %d) when expecting operand or prefix op at line %d col %d.\n",
                    current_token.text, current_token.type, current_token.line, current_token.col);
            strncpy(operand_result_buffer, "EXPR_PARSE_ERROR_UNEXPECTED_TOKEN_OPERAND", operand_buffer_size-1);
            ctx->recursion_depth--; return false;
        }
    } else {
        fprintf(stderr, "Expression parser: Unexpected token '%s' (type %d) when expecting operand at line %d col %d.\n",
                current_token.text, current_token.type, current_token.line, current_token.col);
        strncpy(operand_result_buffer, "EXPR_PARSE_ERROR_UNEXPECTED_TOKEN_PRIMARY", operand_buffer_size-1);
        ctx->recursion_depth--; return false;
    }
    ctx->recursion_depth--;
    return true;
}


// Precedence climbing main recursive function
// result is placed in ctx->result_buffer
bool parse_expression_recursive(ExprParseContext* ctx, int min_precedence) {
    if (ctx->recursion_depth >= MAX_EXPR_RECURSION_DEPTH) {
        fprintf(stderr, "Expression parser: Max recursion depth reached in main loop.\n");
        strncpy(ctx->result_buffer, "EXPR_PARSE_ERROR_RECURSION_MAIN", ctx->result_buffer_size-1);
        return false;
    }
    ctx->recursion_depth++;

    char lhs_value[INPUT_BUFFER_SIZE]; // Buffer for the left-hand side of an operation
    if (!parse_operand(ctx, lhs_value, sizeof(lhs_value))) {
        // Error, result_buffer likely already contains detailed error from parse_operand
        // strncpy(ctx->result_buffer, lhs_value, ctx->result_buffer_size-1); // Propagate error if needed
        ctx->recursion_depth--; return false;
    }
    // After parse_operand, lhs_value holds the result of the first operand/prefix op/sub-expression.
    // Copy it to the main result buffer as it might be the final result if no more ops.
    strncpy(ctx->result_buffer, lhs_value, ctx->result_buffer_size -1);
    ctx->result_buffer[ctx->result_buffer_size-1] = '\0';


    while (ctx->current_token_idx < ctx->num_tokens) {
        Token lookahead_op_token = ctx->tokens[ctx->current_token_idx];
        OperatorDefinition* op_def = NULL;

        if (lookahead_op_token.type == TOKEN_OPERATOR) {
            op_def = get_operator_definition(lookahead_op_token.text);
        } else if (lookahead_op_token.type == TOKEN_RPAREN || lookahead_op_token.type == TOKEN_EOF || 
                   lookahead_op_token.type == TOKEN_SEMICOLON /*or other expression terminators*/) {
            break; // End of current expression part
        } else { // Not an operator we can handle here, or unexpected token
            fprintf(stderr, "Expression parser: Unexpected token '%s' (type %d) after operand at line %d col %d.\n",
                lookahead_op_token.text, lookahead_op_token.type, lookahead_op_token.line, lookahead_op_token.col);
            strncpy(ctx->result_buffer, "EXPR_PARSE_ERROR_UNEXPECTED_TOKEN_AFTER_OPD", ctx->result_buffer_size-1);
            ctx->recursion_depth--; return false;
        }

        if (!op_def || op_def->precedence < min_precedence) {
            break; // Operator has lower precedence than current minimum, or not an infix/postfix operator we handle in this loop
        }
        
        // --- Handle Infix Binary and Postfix Unary Operators ---
        if (op_def->op_type_prop == OP_TYPE_BINARY_INFIX) {
            if (op_def->associativity == ASSOC_LEFT && op_def->precedence <= min_precedence) break; // precedence climbing part for left assoc.
            // For right associative, it's op_def->precedence < min_precedence, but let the general check handle it.

            ctx->current_token_idx++; // Consume binary operator
            
            char rhs_value[INPUT_BUFFER_SIZE];
            int next_min_precedence = (op_def->associativity == ASSOC_LEFT) ? (op_def->precedence + 1) : op_def->precedence;
            
            // Recursively parse the right-hand side
            if (!parse_expression_recursive(ctx, next_min_precedence)) {
                 // Error already printed by recursive call, result in ctx->result_buffer
                 ctx->recursion_depth--; return false;
            }
            // Result of RHS is in ctx->result_buffer
            strncpy(rhs_value, ctx->result_buffer, sizeof(rhs_value)-1);

            // Now have LHS (in lhs_value), operator (op_def), RHS (in rhs_value)
            // Invoke BSH handler
            const char* bsh_args[] = {lhs_value, rhs_value};
            char temp_bsh_result_var[MAX_VAR_NAME_LEN];
            snprintf(temp_bsh_result_var, sizeof(temp_bsh_result_var), "__bsh_expr_temp_%d", rand());

            if (!invoke_bsh_operator_handler(op_def->bsh_handler_name, op_def->op_str, 2, bsh_args,
                                             temp_bsh_result_var, lhs_value, sizeof(lhs_value))) { // Result stored back in lhs_value for next iteration
                // Error from BSH handler; lhs_value now contains the error string.
            }
            strncpy(ctx->result_buffer, lhs_value, ctx->result_buffer_size-1); // Update main result with new LHS

        } else if (op_def->op_type_prop == OP_TYPE_UNARY_POSTFIX) {
            // Postfix operators usually have high precedence and are applied immediately
            // The check "op_def->precedence < min_precedence" should correctly handle when to stop.
            ctx->current_token_idx++; // Consume postfix operator

            // LHS is in lhs_value. Apply postfix op to it.
            const char* bsh_args[] = {lhs_value}; // For postfix, operand is the LHS.
            char temp_bsh_result_var[MAX_VAR_NAME_LEN];
            snprintf(temp_bsh_result_var, sizeof(temp_bsh_result_var), "__bsh_expr_temp_%d", rand());

            if (!invoke_bsh_operator_handler(op_def->bsh_handler_name, op_def->op_str, 1, bsh_args,
                                             temp_bsh_result_var, lhs_value, sizeof(lhs_value))) { // Result stored back
                // Error from BSH handler
            }
            strncpy(ctx->result_buffer, lhs_value, ctx->result_buffer_size-1); // Update main result

        } else if (op_def->op_type_prop == OP_TYPE_TERNARY_PRIMARY && strcmp(op_def->op_str, "?") == 0) {
            // Special handling for ternary "A ? B : C"
            // LHS is the condition (A), already in lhs_value.
            ctx->current_token_idx++; // Consume '?'

            char true_branch_value[INPUT_BUFFER_SIZE];
            // Parse the "true" expression (B). Ternary often has low, specific precedence.
            // The precedence for parsing B and C should ensure they are fully parsed before ':' is handled.
            // Typically, the precedence passed for B would be 0 or a very low value to gather the whole expression.
            if (!parse_expression_recursive(ctx, 0 /* op_def->precedence - 1 or specific ternary prec */)) { // Parse B
                ctx->recursion_depth--; return false;
            }
            strncpy(true_branch_value, ctx->result_buffer, sizeof(true_branch_value)-1);

            if (ctx->current_token_idx >= ctx->num_tokens || 
                ctx->tokens[ctx->current_token_idx].type != TOKEN_OPERATOR ||
                strcmp(ctx->tokens[ctx->current_token_idx].text, ":") != 0) {
                fprintf(stderr, "Expression parser: Missing ':' in ternary operator at line %d col %d.\n",
                        lookahead_op_token.line, lookahead_op_token.col); // '?' token's location
                strncpy(ctx->result_buffer, "EXPR_PARSE_ERROR_MISSING_COLON", ctx->result_buffer_size-1);
                ctx->recursion_depth--; return false;
            }
            ctx->current_token_idx++; // Consume ':'

            char false_branch_value[INPUT_BUFFER_SIZE];
            if (!parse_expression_recursive(ctx, 0 /* op_def->precedence -1 or specific ternary prec */)) { // Parse C
                ctx->recursion_depth--; return false;
            }
            strncpy(false_branch_value, ctx->result_buffer, sizeof(false_branch_value)-1);

            // Now have Cond (lhs_value), TrueExpr (true_branch_value), FalseExpr (false_branch_value)
            // Invoke BSH handler for ternary. It expects 3 operands.
            const char* bsh_args[] = {lhs_value, true_branch_value, false_branch_value};
            char temp_bsh_result_var[MAX_VAR_NAME_LEN];
            snprintf(temp_bsh_result_var, sizeof(temp_bsh_result_var), "__bsh_expr_temp_%d", rand());

            // The BSH handler name for '?' (op_def->bsh_handler_name) should be designed for this.
            if (!invoke_bsh_operator_handler(op_def->bsh_handler_name, op_def->op_str, 3, bsh_args,
                                             temp_bsh_result_var, lhs_value, sizeof(lhs_value))) {
                // Error
            }
            strncpy(ctx->result_buffer, lhs_value, ctx->result_buffer_size-1);
        } else {
            // Not an infix binary or postfix unary we are expecting in this loop.
            // Could be an error or an operator type not handled by this simplified precedence climber.
            // Or it could just be an operator with precedence lower than min_precedence.
            // The loop condition (op_def->precedence < min_precedence) should handle breaking.
            // If we are here, it means it's an operator, but not one of the types this loop processes.
            fprintf(stderr, "Expression parser: Operator '%s' type %d not handled in main expression loop at line %d col %d.\n",
                op_def->op_str, op_def->op_type_prop, lookahead_op_token.line, lookahead_op_token.col);
             strncpy(ctx->result_buffer, "EXPR_PARSE_ERROR_UNHANDLED_OP_TYPE_IN_LOOP", ctx->result_buffer_size-1);
            ctx->recursion_depth--; return false;
        }
    } // end while
    ctx->recursion_depth--;
    return true;
}

// Top-level function to evaluate an expression from a token array
bool evaluate_expression_from_tokens(Token* expression_tokens, int num_expr_tokens,
                                     char* result_buffer, size_t buffer_size) {
    if (num_expr_tokens == 0) {
        result_buffer[0] = '\0';
        return true; // Empty expression is empty result
    }

    ExprParseContext ctx;
    ctx.tokens = expression_tokens;
    ctx.current_token_idx = 0;
    ctx.num_tokens = num_expr_tokens;
    ctx.result_buffer = result_buffer; // The final result will be placed here
    ctx.result_buffer_size = buffer_size;
    ctx.recursion_depth = 0;
    result_buffer[0] = '\0';

    if (!parse_expression_recursive(&ctx, 0)) { // Start with precedence 0
        // Error message already in result_buffer or printed to stderr
        // Ensure result_buffer contains an error marker if not already set by parser
        if (strlen(result_buffer) == 0 || 
            strncmp(result_buffer, "EXPR_PARSE_ERROR", strlen("EXPR_PARSE_ERROR")) != 0 ) {
            // strncpy(result_buffer, "EXPR_EVAL_FAILED_UNKNOWN", buffer_size-1);
        }
        return false;
    }

    // After successful parsing, ctx.result_buffer (which is the passed result_buffer) contains the final value.
    // Check if all tokens were consumed (optional, but good for validating full parse)
    if (ctx.current_token_idx < ctx.num_tokens && ctx.tokens[ctx.current_token_idx].type != TOKEN_EOF) {
         Token extra_token = ctx.tokens[ctx.current_token_idx];
         fprintf(stderr, "Expression parser: Unexpected tokens left after expression evaluation, starting with '%s' at line %d col %d.\n",
            extra_token.text, extra_token.line, extra_token.col);
         // This might indicate a flaw in the grammar or expression structure.
         // For now, we'll return true as we got *a* result, but with a warning.
         // Or, make it return false:
         // strncpy(result_buffer, "EXPR_PARSE_ERROR_TRAILING_TOKENS", buffer_size-1);
         // return false;
    }
    return true;
}


// --- process_line updated to use new expression evaluation ---
void process_line(char *line_raw, FILE *input_source, int current_line_no, ExecutionState exec_mode_param) {
    char line[MAX_LINE_LENGTH];
    strncpy(line, line_raw, MAX_LINE_LENGTH -1);
    line[MAX_LINE_LENGTH-1] = '\0';
    trim_whitespace(line);

    if (line[0] == '\0') return;

    // ... (function definition body capture remains similar) ...
    if (is_defining_function && current_function_definition &&
        (current_exec_state == STATE_DEFINE_FUNC_BODY || current_exec_state == STATE_IMPORT_PARSING || exec_mode_param == STATE_IMPORT_PARSING) &&
        block_stack_top_bf >=0 && peek_block_bf() && peek_block_bf()->type == BLOCK_TYPE_FUNCTION_DEF && 
        strncmp(line, "}", 1) != 0 && strncmp(line, "}", strlen(line)) != 0 ) { 

        if (current_function_definition->line_count < MAX_FUNC_LINES) {
            current_function_definition->body[current_function_definition->line_count] = strdup(line);
            if (!current_function_definition->body[current_function_definition->line_count]) {
                perror("strdup for function body line failed");
            } else {
                current_function_definition->line_count++;
            }
        } else { /* ... error handling for too many lines ... */ }
        return; 
    }


    Token tokens[MAX_EXPRESSION_TOKENS]; // Max tokens for one line/expression
    char token_storage[TOKEN_STORAGE_SIZE];
    int num_tokens = advanced_tokenize_line(line, current_line_no, tokens, MAX_EXPRESSION_TOKENS, token_storage, TOKEN_STORAGE_SIZE);

    if (num_tokens == 0 || tokens[0].type == TOKEN_EMPTY || tokens[0].type == TOKEN_EOF) return;
    if (tokens[0].type == TOKEN_COMMENT) return; // Already handled if tokenizer skips comments entirely

    // ... ( '{' and '}' handling for blocks remains similar, but ensure exec_state is checked ) ...
    if (tokens[0].type == TOKEN_LBRACE && num_tokens == 1) { handle_opening_brace_token(tokens[0]); return; }
    if (tokens[0].type == TOKEN_RBRACE && num_tokens == 1) { handle_closing_brace_token(tokens[0], input_source); return; }


    // ... (current_exec_state == STATE_BLOCK_SKIP logic remains similar) ...
    if (current_exec_state == STATE_BLOCK_SKIP && exec_mode_param != STATE_IMPORT_PARSING) {
        // ... (handle if, else, while, defunc for block nesting, and '}') ...
        return;
    }
    if (bsh_return_value_is_set && current_exec_state == STATE_RETURN_REQUESTED){
        // If a return/exit happened, subsequent lines in the current context (script/function) are skipped.
        return;
    }


    // --- Actual command/statement processing ---
    // 1. Assignment: $variable = <expression>
    // Need to identify if it's an assignment. A simple check:
    // $VAR = ...  -> tokens[0] is TOKEN_VARIABLE, tokens[1] is TOKEN_OPERATOR with text "=" (if '=' is TOKEN_OPERATOR)
    // OR tokens[1] is TOKEN_ASSIGN (if '=' is special).
    // Let's assume '=' is a TOKEN_OPERATOR defined with specific properties for assignment.
    bool is_assignment = false;
    if (num_tokens >= 3 && tokens[0].type == TOKEN_VARIABLE) {
        if (tokens[1].type == TOKEN_ASSIGN) { // If '=' is still special TOKEN_ASSIGN
            is_assignment = true;
        } else if (tokens[1].type == TOKEN_OPERATOR) {
            OperatorDefinition* op_eq = get_operator_definition(tokens[1].text);
            // We need a way to distinguish assignment '=' from comparison '==' if both are TOKEN_OPERATOR.
            // This could be done by a specific op_type_prop for assignment, or by convention in BSH handler.
            // For now, let's assume a BSH script defines "=" with a handler that performs assignment.
            // The expression evaluator will call this handler.
            // So, assignment is just a special case of expression evaluation where the top-level op is "=".
            // This means handle_assignment_advanced might become simpler or be folded into expression eval.
            // For this iteration, let's keep handle_assignment_advanced distinct for clarity of intent.
            if (strcmp(tokens[1].text, "=") == 0) { // Simple check for now
                 is_assignment = true;
            }
        }
    }

    if (is_assignment) {
        handle_assignment_advanced(tokens, num_tokens); // This will use evaluate_expression_from_tokens for RHS
    }
    // 2. Built-in keywords (if, while, defunc, echo, etc.)
    else if (tokens[0].type == TOKEN_WORD) {
        const char* command_name = resolve_keyword_alias(tokens[0].text);
        // ... (dispatch to handle_if, handle_while, handle_echo, handle_defunc, handle_defoperator, etc.) ...
        // These handlers for if/while will use evaluate_expression_from_tokens for their conditions.
        if (strcmp(command_name, "echo") == 0) { handle_echo_advanced(tokens, num_tokens); }
        else if (strcmp(command_name, "defkeyword") == 0) { handle_defkeyword_statement(tokens, num_tokens); }
        else if (strcmp(command_name, "defoperator") == 0) { handle_defoperator_statement(tokens, num_tokens); }
        else if (strcmp(command_name, "if") == 0) { handle_if_statement_advanced(tokens, num_tokens, input_source, current_line_no); }
        else if (strcmp(command_name, "else") == 0) { handle_else_statement_advanced(tokens, num_tokens, input_source, current_line_no); }
        else if (strcmp(command_name, "while") == 0) { handle_while_statement_advanced(tokens, num_tokens, input_source, current_line_no); }
        else if (strcmp(command_name, "defunc") == 0) { handle_defunc_statement_advanced(tokens, num_tokens); }
        else if (strcmp(command_name, "loadlib") == 0) { handle_loadlib_statement(tokens, num_tokens); }
        else if (strcmp(command_name, "calllib") == 0) { handle_calllib_statement(tokens, num_tokens); }
        else if (strcmp(command_name, "import") == 0) { handle_import_statement(tokens, num_tokens); }
        else if (strcmp(command_name, "update_cwd") == 0) { handle_update_cwd_statement(tokens, num_tokens); }
        else if (strcmp(command_name, "eval") == 0) { handle_eval_statement(tokens, num_tokens); }
        else if (strcmp(command_name, "exit") == 0) { handle_exit_statement(tokens, num_tokens); }
        // Add other built-ins here
        else {
            // Not a built-in keyword. Could be user function or external command OR standalone expression.
            UserFunction* func_to_run = function_list; /* ... find func ... */
            if (func_to_run) {
                execute_user_function(func_to_run, &tokens[1], num_tokens - 1, input_source);
            } else {
                // Try as external command OR evaluate the whole line as an expression
                char command_path_ext[MAX_FULL_PATH_LEN];
                if (find_command_in_path_dynamic(tokens[0].text, command_path_ext)) {
                    // ... (original external command execution logic) ...
                     char *args[MAX_ARGS + 1]; /* ... populate args ... */
                     execute_external_command(command_path_ext, args, num_tokens /*adjust*/, NULL, 0);
                } else {
                    // Not a known command, try to evaluate the whole line as an expression
                    char expression_result_buffer[INPUT_BUFFER_SIZE];
                    if (evaluate_expression_from_tokens(tokens, num_tokens, expression_result_buffer, sizeof(expression_result_buffer))) {
                        if (strlen(expression_result_buffer) > 0 &&
                            strncmp(expression_result_buffer, "EXPR_PARSE_ERROR", strlen("EXPR_PARSE_ERROR")) != 0 &&
                            strncmp(expression_result_buffer, "BSH_HANDLER_NOT_FOUND", strlen("BSH_HANDLER_NOT_FOUND")) !=0 &&
                            strncmp(expression_result_buffer, "BSH_HANDLER_NO_RESULT", strlen("BSH_HANDLER_NO_RESULT")) !=0 ) {
                            printf("%s\n", expression_result_buffer); // Print result of standalone expression
                        }
                        set_variable_scoped("LAST_OP_RESULT", expression_result_buffer, false);
                    } else {
                        // evaluate_expression_from_tokens returned false, error already printed or in buffer
                         fprintf(stderr, "bsh: Command not found and failed to evaluate as expression: %s (line %d)\n", tokens[0].text, current_line_no);
                         set_variable_scoped("LAST_OP_RESULT", expression_result_buffer, false); // Store error string
                    }
                }
            }
        }
    }
    // 3. Line is not assignment and not starting with a known command word.
    //    Assume it's a standalone expression to be evaluated.
    else {
        char expression_result_buffer[INPUT_BUFFER_SIZE];
        if (evaluate_expression_from_tokens(tokens, num_tokens, expression_result_buffer, sizeof(expression_result_buffer))) {
            if (strlen(expression_result_buffer) > 0 && /* ... more positive checks or fewer error checks ... */
                 strncmp(expression_result_buffer, "EXPR_PARSE_ERROR", strlen("EXPR_PARSE_ERROR")) != 0 &&
                 strncmp(expression_result_buffer, "BSH_HANDLER_NOT_FOUND", strlen("BSH_HANDLER_NOT_FOUND")) !=0 ) {
                printf("%s\n", expression_result_buffer);
            }
            set_variable_scoped("LAST_OP_RESULT", expression_result_buffer, false);
        } else {
            // Error already printed by evaluator, or in buffer
            fprintf(stderr, "bsh: Failed to evaluate expression starting with '%s' (line %d)\n", tokens[0].text, current_line_no);
            set_variable_scoped("LAST_OP_RESULT", expression_result_buffer, false); // Store error
        }
    }
}

// --- handle_assignment_advanced needs to use the new expression evaluator for RHS ---
void handle_assignment_advanced(Token *tokens, int num_tokens) {
    if (num_tokens < 3 || tokens[0].type != TOKEN_VARIABLE ) { /* Basic syntax check */ return; }
    // Operator at tokens[1] should be "=" (or its equivalent if defined differently)
    if (current_exec_state == STATE_BLOCK_SKIP) return;

    // LHS (variable name or array element)
    char var_token_text_copy[MAX_VAR_NAME_LEN * 2]; 
    strncpy(var_token_text_copy, tokens[0].text + 1, sizeof(var_token_text_copy) -1); 
    var_token_text_copy[sizeof(var_token_text_copy)-1] = '\0';

    char base_var_name[MAX_VAR_NAME_LEN]; char index_str_raw[MAX_VAR_NAME_LEN] = ""; bool is_array_assignment = false;
    // ... (logic to parse base_var_name and index_str_raw from var_token_text_copy for arrays - similar to original)
    char* bracket_ptr = strchr(var_token_text_copy, '[');
    if (bracket_ptr) {
        char* end_bracket_ptr = strrchr(bracket_ptr, ']');
        if (end_bracket_ptr && end_bracket_ptr > bracket_ptr) {
            is_array_assignment = true;
            size_t base_len = bracket_ptr - var_token_text_copy;
            strncpy(base_var_name, var_token_text_copy, base_len); base_var_name[base_len] = '\0';
            size_t index_len = end_bracket_ptr - (bracket_ptr + 1);
            strncpy(index_str_raw, bracket_ptr + 1, index_len); index_str_raw[index_len] = '\0';
        } else { fprintf(stderr, "Malformed array assignment: %s\n", tokens[0].text); return; }
    } else { strncpy(base_var_name, var_token_text_copy, MAX_VAR_NAME_LEN - 1); base_var_name[MAX_VAR_NAME_LEN - 1] = '\0'; }


    // RHS: Evaluate tokens from index 2 onwards
    char rhs_value_buffer[INPUT_BUFFER_SIZE];
    if (num_tokens > 2) { // If there is an RHS
        if (!evaluate_expression_from_tokens(&tokens[2], num_tokens - 2, rhs_value_buffer, sizeof(rhs_value_buffer))) {
            // Evaluation failed, error already printed or in rhs_value_buffer.
            // Optionally, set target variable to error string or do nothing.
            // For now, let's proceed to set whatever is in rhs_value_buffer (could be an error marker string).
             fprintf(stderr, "Error evaluating RHS for assignment to '%s'. Result: %s\n", base_var_name, rhs_value_buffer);
             // Decide if assignment should still happen with the error string, or if it should be skipped.
             // Let's assign the error string for now, so it's visible.
        }
    } else { // No RHS (e.g., $var =), set to empty string
        rhs_value_buffer[0] = '\0';
    }
    
    // Check for "object:" or "json:" prefix on the evaluated RHS result
    bool structured_data_parsed = false;
    const char* data_to_parse = NULL;
    const char* detected_prefix_str = NULL;

    if (strncmp(rhs_value_buffer, OBJECT_STDOUT_PREFIX, strlen(OBJECT_STDOUT_PREFIX)) == 0) {
        data_to_parse = rhs_value_buffer + strlen(OBJECT_STDOUT_PREFIX);
        detected_prefix_str = OBJECT_STDOUT_PREFIX; //
        structured_data_parsed = true;
    } else if (strncmp(rhs_value_buffer, JSON_STDOUT_PREFIX, strlen(JSON_STDOUT_PREFIX)) == 0) {
        data_to_parse = rhs_value_buffer + strlen(JSON_STDOUT_PREFIX);
        detected_prefix_str = JSON_STDOUT_PREFIX; //
        structured_data_parsed = true;
    }

    if (structured_data_parsed) {
        int current_scope_id_for_obj = (scope_stack_top >= 0) ? scope_stack[scope_stack_top].scope_id : GLOBAL_SCOPE_ID;
        parse_and_flatten_bsh_object_string(data_to_parse, base_var_name, current_scope_id_for_obj); //
        
        // The main variable ($base_var_name) can be set to the raw data (minus prefix) or a special marker.
        // Let's use the raw data (minus prefix).
        memmove(rhs_value_buffer, (char*)data_to_parse, strlen(data_to_parse) + 1);
    }

    // Perform the assignment
    if (is_array_assignment) {
        set_array_element_scoped(base_var_name, index_str_raw, rhs_value_buffer);
    } else {
        set_variable_scoped(base_var_name, rhs_value_buffer, false);
    }
}

// Conditions for if/while will use evaluate_expression_from_tokens
void handle_if_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no) {
    if (num_tokens < 2) { /* ... syntax error ... */ push_block_bf(BLOCK_TYPE_IF, false, 0, current_line_no); current_exec_state = STATE_BLOCK_SKIP; return; }

    bool condition_is_true = false;
    if (current_exec_state != STATE_BLOCK_SKIP) {
        char condition_result_str[INPUT_BUFFER_SIZE];
        // The condition is from tokens[1] to before '{' or end of line.
        int condition_end_idx = num_tokens -1;
        if (tokens[num_tokens-1].type == TOKEN_LBRACE) condition_end_idx--;
        if (tokens[condition_end_idx].type == TOKEN_COMMENT) condition_end_idx--;


        if (condition_end_idx >= 1) {
            if (evaluate_expression_from_tokens(&tokens[1], (condition_end_idx - 1) + 1,
                                                condition_result_str, sizeof(condition_result_str))) {
                // Evaluate truthiness of condition_result_str
                condition_is_true = (strcmp(condition_result_str, "1") == 0 ||
                                     strcasecmp(condition_result_str, "true") == 0 ||
                                     (strlen(condition_result_str) > 0 && strcmp(condition_result_str,"0") != 0 && strcasecmp(condition_result_str,"false") !=0 ) );
            } else {
                fprintf(stderr, "Error evaluating 'if' condition: %s (line %d)\n", condition_result_str, current_line_no);
                condition_is_true = false; // Treat evaluation error as false condition
            }
        } else { // No condition tokens after "if"
             fprintf(stderr, "Syntax error for 'if': Missing condition (line %d)\n", current_line_no);
             condition_is_true = false;
        }
    }

    push_block_bf(BLOCK_TYPE_IF, condition_is_true, 0, current_line_no);
    if (condition_is_true && current_exec_state != STATE_BLOCK_SKIP) { current_exec_state = STATE_BLOCK_EXECUTE; }
    else { current_exec_state = STATE_BLOCK_SKIP; }
    // ... rest of brace checking ...
}

// Similar changes for handle_while_statement_advanced and handle_else_statement_advanced (for 'else if' conditions).

void initialize_shell() {
    scope_stack_top = -1; 
    enter_scope();        

    // Initialize core structural operators if they are not dynamically defined
    initialize_operators_core_structural(); // Call the new initializer

    // ... rest of initialize_shell (PATH, BSH_MODULE_PATH, default vars) ...
    char *path_env = getenv("PATH"); //
    if (path_env) { //
        char *path_copy = strdup(path_env); //
        if (path_copy) { //
            char *token_path = strtok(path_copy, ":"); //
            while (token_path) { //
                add_path_to_list(&path_list_head, token_path); //
                token_path = strtok(NULL, ":"); //
            }
            free(path_copy); //
        } else { perror("strdup for PATH failed in initialize_shell"); } //
    }

    initialize_module_path();  //

    set_variable_scoped("SHELL_VERSION", "bsh-dynamic-expr-0.9", false); // Updated version
    set_variable_scoped("PS1", "bsh", false);  //

    char* initial_module_path_env = getenv("BSH_MODULE_PATH"); //
    if (!initial_module_path_env || strlen(initial_module_path_env) == 0) { //
        initial_module_path_env = DEFAULT_MODULE_PATH; //
    }
    set_variable_scoped("BSH_MODULE_PATH", initial_module_path_env, false); //
    
    char cwd_buffer[PATH_MAX]; //
    if (getcwd(cwd_buffer, sizeof(cwd_buffer)) != NULL) { //
        set_variable_scoped("CWD", cwd_buffer, false); //
    } else { //
        perror("bsh: getcwd() error on init"); //
        set_variable_scoped("CWD", "", false);  //
    }
}

int main(int argc, char *argv[]) {
    initialize_shell(); //

    // Execute default startup script
    char startup_script_path[MAX_FULL_PATH_LEN]; //
    char* home_dir = getenv("HOME"); //
    bool startup_executed = false; //
    if (home_dir) { //
        snprintf(startup_script_path, sizeof(startup_script_path), "%s/%s", home_dir, DEFAULT_STARTUP_SCRIPT); //
        if (access(startup_script_path, F_OK) == 0) { //
            execute_script(startup_script_path, false, true);  //
            startup_executed = true; //
        }
    }
    if (!startup_executed) {  //
         if (access(DEFAULT_STARTUP_SCRIPT, F_OK) == 0) { //
            execute_script(DEFAULT_STARTUP_SCRIPT, false, true); //
        }
    }

    if (argc > 1) {  //
        execute_script(argv[1], false, false);  //
    } else { // Interactive mode
        char line_buffer[INPUT_BUFFER_SIZE]; //
        char prompt_buffer[MAX_VAR_NAME_LEN + 30];  //
        int line_counter_interactive = 0; //

        while (1) { //
            // Reset return state for each interactive command
            bsh_return_value_is_set = false;
            current_exec_state = STATE_NORMAL; // Ensure normal state for new prompt

            char* current_prompt_val = get_variable_scoped("PS1"); //
            if (!current_prompt_val || strlen(current_prompt_val) == 0) { //
                current_prompt_val = "bsh";  //
            }

            char state_indicator[35] = "";  //
            // ... (prompt state indicator logic remains the same) ...

            snprintf(prompt_buffer, sizeof(prompt_buffer), "%s%s> ", current_prompt_val, state_indicator); //
            printf("%s", prompt_buffer); //

            if (!fgets(line_buffer, sizeof(line_buffer), stdin)) { //
                printf("\n");  //
                break; //
            }
            line_counter_interactive++; //
            process_line(line_buffer, stdin, line_counter_interactive, STATE_NORMAL); //

            if (bsh_return_value_is_set && current_exec_state == STATE_RETURN_REQUESTED) {
                // Handle 'exit' from interactive prompt
                long exit_code_val = 0;
                if (strlen(bsh_last_return_value) > 0) {
                    exit_code_val = strtol(bsh_last_return_value, NULL, 10);
                }
                cleanup_shell();
                // printf("Exiting shell with status %ld (from interactive 'exit').\n", exit_code_val);
                return exit_code_val;
            }

        }
    }

    cleanup_shell(); //
    return 0; //
}