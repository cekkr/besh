#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <ctype.h>
#include <dlfcn.h> // For dynamic library loading
#include <errno.h>
#include <limits.h> // For PATH_MAX (usually) or alternative for buffer sizes
#include <libgen.h> // For dirname, basename (often part of string.h or stdlib.h but good to be explicit)

// --- Constants and Definitions ---
#define MAX_LINE_LENGTH 2048
#define MAX_ARGS 128
#define MAX_VAR_NAME_LEN 256
// #define MAX_VAR_VALUE_LEN 2048 // No longer used for Variable->value storage
#define INPUT_BUFFER_SIZE 4096 // For reading lines, command output before strdup
#define MAX_FULL_PATH_LEN 1024 // For constructing full paths
#ifndef PATH_MAX // Define PATH_MAX if not defined (common on some systems)
    #ifdef _XOPEN_PATH_MAX
        #define PATH_MAX _XOPEN_PATH_MAX
    #else
        #define PATH_MAX 4096 // Fallback
    #endif
#endif
#define TOKEN_STORAGE_SIZE (MAX_LINE_LENGTH * 2)
#define MAX_NESTING_DEPTH 32 // For if/while/function call block nesting
#define MAX_FUNC_LINES 100   // Max lines in a user-defined function body
#define MAX_FUNC_PARAMS 10   // Max parameters for a user-defined function
#define MAX_OPERATOR_LEN 8   // Max length of an operator string (e.g., "==")
#define DEFAULT_STARTUP_SCRIPT ".bshrc" // Shell startup script
#define MAX_KEYWORD_LEN 32   // Max length for a keyword or its alias
#define MAX_SCOPE_DEPTH 64   // Max depth for lexical scopes (function calls)
#define DEFAULT_MODULE_PATH "./framework:~/.bsh_framework:/usr/local/share/bsh/framework" // Example default module path

// --- Tokenizer Types ---
typedef enum {
    TOKEN_EMPTY, TOKEN_WORD, TOKEN_STRING, TOKEN_VARIABLE, TOKEN_OPERATOR,
    TOKEN_LPAREN, TOKEN_RPAREN, TOKEN_LBRACE, TOKEN_RBRACE, TOKEN_LBRACKET, TOKEN_RBRACKET,
    TOKEN_ASSIGN, TOKEN_SEMICOLON, TOKEN_PIPE, TOKEN_AMPERSAND, TOKEN_COMMENT,
    TOKEN_EOF, TOKEN_ERROR
} TokenType;

typedef struct {
    TokenType type;
    const char *text; // Points into the token_storage buffer
    int len;
} Token;

// --- Operator Definition (Dynamic List) ---
typedef struct OperatorDefinition {
    char op_str[MAX_OPERATOR_LEN + 1];
    TokenType op_type;
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
    char *path; // Dynamically allocated string for the directory path
    struct PathDirNode *next;
} PathDirNode;
PathDirNode *path_list_head = NULL; // For executables
PathDirNode *module_path_list_head = NULL; // For BSH modules/framework scripts

// --- Variable Scoping and Management ---
typedef struct Variable {
    char name[MAX_VAR_NAME_LEN];
    char *value; // Dynamically allocated string for the variable's value
    bool is_array_element;
    int scope_id; // Identifier for the scope this variable belongs to
    struct Variable *next; // Next variable in the global list
} Variable;
Variable *variable_list_head = NULL; // Global list of all variables

typedef struct ScopeFrame {
    int scope_id;
    // Other scope-specific info could go here if needed
} ScopeFrame;
ScopeFrame scope_stack[MAX_SCOPE_DEPTH];
int scope_stack_top = -1; // -1 means global scope (scope_id 0) is not yet formally pushed
int next_scope_id = 1;    // Counter for unique scope IDs (0 is global)
#define GLOBAL_SCOPE_ID 0

// --- User-Defined Functions ---
typedef struct UserFunction {
    char name[MAX_VAR_NAME_LEN];
    char params[MAX_FUNC_PARAMS][MAX_VAR_NAME_LEN];
    int param_count;
    char* body[MAX_FUNC_LINES]; // Array of strings (lines of the function body)
    int line_count;
    struct UserFunction *next;
} UserFunction;
UserFunction *function_list = NULL;
bool is_defining_function = false;
UserFunction *current_function_definition = NULL;

// --- Execution State and Block Management (for if/while etc.) ---
typedef enum {
    STATE_NORMAL, STATE_BLOCK_EXECUTE, STATE_BLOCK_SKIP,
    STATE_DEFINE_FUNC_BODY, STATE_IMPORT_PARSING
} ExecutionState;
ExecutionState current_exec_state = STATE_NORMAL;

typedef enum {
    BLOCK_TYPE_IF, BLOCK_TYPE_ELSE, BLOCK_TYPE_WHILE, BLOCK_TYPE_FUNCTION_DEF
} BlockType;

typedef struct BlockFrame { // For if/while/else block control flow
    BlockType type;
    long loop_start_fpos;        // File position for `while` loop start (for fseek)
    int loop_start_line_no;      // Line number for `while` loop start
    bool condition_true;         // Was the entry condition for if/while true?
    ExecutionState prev_exec_state; // Execution state before entering this block
} BlockFrame;
BlockFrame block_stack[MAX_NESTING_DEPTH]; // Stack for if/while blocks
int block_stack_top_bf = -1; // Top of the block_stack (bf for Block Frame)

// --- Dynamic Library Handles ---
typedef struct DynamicLib {
    char alias[MAX_VAR_NAME_LEN];
    void *handle;
    struct DynamicLib *next;
} DynamicLib;
DynamicLib *loaded_libs = NULL;


// --- Function Prototypes ---

// Core
void initialize_shell();
void process_line(char *line, FILE *input_source, int current_line_no, ExecutionState exec_mode);
void execute_script(const char *filename, bool is_import, bool is_startup_script);
void cleanup_shell();

// Tokenizer & Keyword Aliasing
void initialize_operators_dynamic();
void add_operator_dynamic(const char* op_str, TokenType type);
int match_operator_dynamic(const char *input, const char **op_text, TokenType *matched_type);
void add_keyword_alias(const char* original, const char* alias_name);
const char* resolve_keyword_alias(const char* alias_name);
void free_keyword_alias_list();
int advanced_tokenize_line(const char *line, Token *tokens, int max_tokens, char *token_storage, size_t storage_size);

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
void expand_variables_in_string_advanced(const char *input_str, char *expanded_str, size_t expanded_str_size);
char* get_array_element_scoped(const char* array_base_name, const char* index_str_raw);
void set_array_element_scoped(const char* array_base_name, const char* index_str_raw, const char* value);

// Command Execution
bool find_command_in_path_dynamic(const char *command, char *full_path);
bool find_module_in_path(const char* module_name, char* full_path);
int execute_external_command(char *command_path, char **args, int arg_count, char *output_buffer, size_t output_buffer_size);
void execute_user_function(UserFunction* func, Token* call_arg_tokens, int call_arg_token_count, FILE* input_source_for_context);

// Built-in Commands
void handle_defkeyword_statement(Token *tokens, int num_tokens);
void handle_assignment_advanced(Token *tokens, int num_tokens);
void handle_echo_advanced(Token *tokens, int num_tokens);
bool evaluate_condition_advanced(Token* operand1_token, Token* operator_token, Token* operand2_token);
void handle_if_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no);
void handle_else_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no);
void handle_while_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no);
void handle_defunc_statement_advanced(Token *tokens, int num_tokens);
void handle_inc_dec_statement_advanced(Token *tokens, int num_tokens, bool increment);
void handle_loadlib_statement(Token *tokens, int num_tokens);
void handle_calllib_statement(Token *tokens, int num_tokens);
void handle_import_statement(Token *tokens, int num_tokens);

// Block Management (for if/while etc.)
void push_block_bf(BlockType type, bool condition_true, long loop_start_fpos, int loop_start_line_no);
BlockFrame* pop_block_bf();
BlockFrame* peek_block_bf();
void handle_opening_brace_token(Token token);
void handle_closing_brace_token(Token token, FILE* input_source);

// Utility
char* trim_whitespace(char *str);
void free_all_variables();
void free_function_list();
void free_operator_list();
void free_loaded_libs();
long get_file_pos(FILE* f);
char* unescape_string(const char* input, char* output_buffer, size_t buffer_size); // For string literals


// --- Main ---
int main(int argc, char *argv[]) {
    initialize_shell();

    // Execute default startup script
    char startup_script_path[MAX_FULL_PATH_LEN];
    char* home_dir = getenv("HOME");
    bool startup_executed = false;
    if (home_dir) {
        snprintf(startup_script_path, sizeof(startup_script_path), "%s/%s", home_dir, DEFAULT_STARTUP_SCRIPT);
        if (access(startup_script_path, F_OK) == 0) {
            execute_script(startup_script_path, false, true); // is_import=false, is_startup=true
            startup_executed = true;
        }
    }
    if (!startup_executed) { // Try current directory as fallback for default script
         if (access(DEFAULT_STARTUP_SCRIPT, F_OK) == 0) {
            execute_script(DEFAULT_STARTUP_SCRIPT, false, true);
        }
    }

    if (argc > 1) { // Script provided as argument
        execute_script(argv[1], false, false); // is_import=false, is_startup=false
    } else { // Interactive mode
        char line_buffer[INPUT_BUFFER_SIZE];
        char prompt_buffer[MAX_VAR_NAME_LEN + 30]; // For prompt string + state indicator
        int line_counter_interactive = 0;

        while (1) {
            char* current_prompt_val = get_variable_scoped("PS1");
            if (!current_prompt_val || strlen(current_prompt_val) == 0) {
                current_prompt_val = "bsh"; // Default prompt if PS1 is unset or empty
            }

            char state_indicator[35] = ""; // Buffer for block state indicator
            if (block_stack_top_bf >= 0) {
                BlockFrame* top_block = peek_block_bf();
                const char* block_type_str = "unknown";
                if (top_block) {
                    if (top_block->type == BLOCK_TYPE_IF) block_type_str = "if";
                    else if (top_block->type == BLOCK_TYPE_ELSE) block_type_str = "else";
                    else if (top_block->type == BLOCK_TYPE_WHILE) block_type_str = "while";
                    else if (top_block->type == BLOCK_TYPE_FUNCTION_DEF) block_type_str = "defunc_body";
                }

                if (current_exec_state == STATE_BLOCK_SKIP) {
                    snprintf(state_indicator, sizeof(state_indicator), "(skip %s %d)", block_type_str, block_stack_top_bf + 1);
                } else if (current_exec_state == STATE_DEFINE_FUNC_BODY && current_function_definition) {
                     snprintf(state_indicator, sizeof(state_indicator), "(defunc %s)", current_function_definition->name);
                } else if (top_block) { // Normal block execution
                    snprintf(state_indicator, sizeof(state_indicator), "(%s %d)", block_type_str, block_stack_top_bf + 1);
                }
            } else if (current_exec_state == STATE_DEFINE_FUNC_BODY && current_function_definition) {
                // Function definition started but '{' not yet encountered
                snprintf(state_indicator, sizeof(state_indicator), "(defunc %s...)", current_function_definition->name);
            }

            snprintf(prompt_buffer, sizeof(prompt_buffer), "%s%s> ", current_prompt_val, state_indicator);
            printf("%s", prompt_buffer);

            if (!fgets(line_buffer, sizeof(line_buffer), stdin)) {
                printf("\n"); // EOF (Ctrl+D)
                break;
            }
            line_counter_interactive++;
            process_line(line_buffer, stdin, line_counter_interactive, STATE_NORMAL);
        }
    }

    cleanup_shell();
    return 0;
}

// --- Core Implementations ---

void initialize_shell() {
    scope_stack_top = -1; // Initialize scope stack
    enter_scope();        // Enter global scope (scope_id 0)

    // Initialize executable PATH
    char *path_env = getenv("PATH");
    if (path_env) {
        char *path_copy = strdup(path_env);
        if (path_copy) {
            char *token_path = strtok(path_copy, ":");
            while (token_path) {
                add_path_to_list(&path_list_head, token_path);
                token_path = strtok(NULL, ":");
            }
            free(path_copy);
        } else { perror("strdup for PATH failed in initialize_shell"); }
    }

    initialize_module_path(); // Initialize BSH_MODULE_PATH list
    initialize_operators_dynamic(); // Initialize built-in operators

    // Set some initial shell variables in the global scope
    set_variable_scoped("SHELL_VERSION", "bsh-dynamic-vals-0.5", false);
    set_variable_scoped("PS1", "bsh", false); // Default prompt

    // Set BSH_MODULE_PATH as a shell variable too, so scripts can inspect/modify it
    char* initial_module_path_env = getenv("BSH_MODULE_PATH");
    if (!initial_module_path_env || strlen(initial_module_path_env) == 0) {
        initial_module_path_env = DEFAULT_MODULE_PATH;
    }
    set_variable_scoped("BSH_MODULE_PATH", initial_module_path_env, false);
}

void cleanup_shell() {
    free_all_variables();
    free_function_list();
    free_operator_list();
    free_keyword_alias_list();
    free_path_dir_list(&path_list_head);
    free_path_dir_list(&module_path_list_head);
    free_loaded_libs();

    // Ensure all scopes are formally left (though variables are cleaned by free_all_variables)
    while(scope_stack_top >= 0) { // Should only be global scope left if balanced
        leave_scope(scope_stack[scope_stack_top].scope_id);
    }
}

// --- Path Management ---
void add_path_to_list(PathDirNode **list_head, const char* dir_path) {
    PathDirNode *new_node = (PathDirNode*)malloc(sizeof(PathDirNode));
    if (!new_node) { perror("malloc for path node failed"); return; }
    new_node->path = strdup(dir_path);
    if (!new_node->path) { perror("strdup for path string failed"); free(new_node); return; }
    new_node->next = NULL;

    if (!*list_head) { *list_head = new_node; }
    else { PathDirNode *current = *list_head; while (current->next) current = current->next; current->next = new_node; }
}

void free_path_dir_list(PathDirNode **list_head) {
    PathDirNode *current = *list_head;
    PathDirNode *next_node;
    while (current) {
        next_node = current->next;
        free(current->path);
        free(current);
        current = next_node;
    }
    *list_head = NULL;
}

void initialize_module_path() {
    char *module_path_env = getenv("BSH_MODULE_PATH");
    char *effective_module_path = module_path_env;

    if (!module_path_env || strlen(module_path_env) == 0) {
        effective_module_path = DEFAULT_MODULE_PATH;
    }

    if (effective_module_path && strlen(effective_module_path) > 0) {
        char *path_copy = strdup(effective_module_path);
        if (path_copy) {
            char *token_path = strtok(path_copy, ":");
            while (token_path) {
                if(strlen(token_path) > 0) add_path_to_list(&module_path_list_head, token_path);
                token_path = strtok(NULL, ":");
            }
            free(path_copy);
        } else { perror("strdup for BSH_MODULE_PATH processing failed"); }
    }
}

// --- Tokenizer & Keyword Aliasing ---
void initialize_operators_dynamic() {
    // Order for matching: longest first if not using a more complex matching like Trie
    add_operator_dynamic("==", TOKEN_OPERATOR); add_operator_dynamic("!=", TOKEN_OPERATOR);
    add_operator_dynamic(">=", TOKEN_OPERATOR); add_operator_dynamic("<=", TOKEN_OPERATOR);
    add_operator_dynamic("&&", TOKEN_OPERATOR); add_operator_dynamic("||", TOKEN_OPERATOR);
    add_operator_dynamic("=", TOKEN_ASSIGN);   add_operator_dynamic(">", TOKEN_OPERATOR);
    add_operator_dynamic("<", TOKEN_OPERATOR);  add_operator_dynamic("+", TOKEN_OPERATOR);
    add_operator_dynamic("-", TOKEN_OPERATOR);  add_operator_dynamic("*", TOKEN_OPERATOR);
    add_operator_dynamic("/", TOKEN_OPERATOR);  add_operator_dynamic("%", TOKEN_OPERATOR);
    add_operator_dynamic("!", TOKEN_OPERATOR);  add_operator_dynamic("(", TOKEN_LPAREN);
    add_operator_dynamic(")", TOKEN_RPAREN);  add_operator_dynamic("{", TOKEN_LBRACE);
    add_operator_dynamic("}", TOKEN_RBRACE);  add_operator_dynamic("[", TOKEN_LBRACKET);
    add_operator_dynamic("]", TOKEN_RBRACKET);add_operator_dynamic(";", TOKEN_SEMICOLON);
    add_operator_dynamic("|", TOKEN_PIPE);    add_operator_dynamic("&", TOKEN_AMPERSAND);
}

void add_operator_dynamic(const char* op_str, TokenType type) {
    if (strlen(op_str) > MAX_OPERATOR_LEN) {
        fprintf(stderr, "Warning: Operator '%s' too long (max %d chars).\n", op_str, MAX_OPERATOR_LEN);
        return;
    }
    OperatorDefinition *new_op = (OperatorDefinition*)malloc(sizeof(OperatorDefinition));
    if (!new_op) { perror("malloc for new operator failed"); return; }
    strcpy(new_op->op_str, op_str); new_op->op_type = type;
    new_op->next = operator_list_head; operator_list_head = new_op; // Prepend
}

int match_operator_dynamic(const char *input, const char **op_text, TokenType *matched_type) {
    OperatorDefinition *current = operator_list_head;
    const char* best_match_text = NULL;
    TokenType best_match_type = TOKEN_EMPTY; // Default if no specific type found for a generic op
    int longest_match_len = 0;

    while (current) {
        size_t op_len = strlen(current->op_str);
        if (strncmp(input, current->op_str, op_len) == 0) {
            if (op_len > longest_match_len) {
                longest_match_len = op_len;
                best_match_text = current->op_str;
                best_match_type = current->op_type;
            }
        }
        current = current->next;
    }

    if (longest_match_len > 0) {
        *op_text = best_match_text; // This points to the string within OperatorDefinition
        if(matched_type) *matched_type = best_match_type;
        return longest_match_len;
    }
    return 0; // No operator matched
}

void add_keyword_alias(const char* original, const char* alias_name) {
    if (strlen(original) > MAX_KEYWORD_LEN || strlen(alias_name) > MAX_KEYWORD_LEN) {
        fprintf(stderr, "Keyword or alias too long (max %d chars).\n", MAX_KEYWORD_LEN); return;
    }
    KeywordAlias* current = keyword_alias_head;
    while(current){ // Check if alias already exists
        if(strcmp(current->alias, alias_name) == 0){
            fprintf(stderr, "Warning: Alias '%s' already defined for '%s'. Overwriting with new original '%s'.\n", alias_name, current->original, original);
            strncpy(current->original, original, MAX_KEYWORD_LEN); // Overwrite original
            current->original[MAX_KEYWORD_LEN] = '\0';
            return;
        }
        current = current->next;
    }
    KeywordAlias *new_alias = (KeywordAlias*)malloc(sizeof(KeywordAlias));
    if (!new_alias) { perror("malloc for keyword alias failed"); return; }
    strncpy(new_alias->original, original, MAX_KEYWORD_LEN); new_alias->original[MAX_KEYWORD_LEN] = '\0';
    strncpy(new_alias->alias, alias_name, MAX_KEYWORD_LEN); new_alias->alias[MAX_KEYWORD_LEN] = '\0';
    new_alias->next = keyword_alias_head; keyword_alias_head = new_alias; // Prepend
}

const char* resolve_keyword_alias(const char* alias_name) {
    KeywordAlias *current = keyword_alias_head;
    while (current) {
        if (strcmp(current->alias, alias_name) == 0) {
            return current->original; // Return pointer to original keyword string
        }
        current = current->next;
    }
    return alias_name; // No alias found, return the input name itself
}

void free_keyword_alias_list() {
    KeywordAlias *current = keyword_alias_head; KeywordAlias *next_ka;
    while (current) { next_ka = current->next; free(current); current = next_ka; }
    keyword_alias_head = NULL;
}

int advanced_tokenize_line(const char *line, Token *tokens, int max_tokens, char *token_storage, size_t storage_size) {
    int token_count = 0; const char *p = line; char *storage_ptr = token_storage;
    size_t remaining_storage = storage_size;
    while (*p && token_count < max_tokens) {
        while (isspace((unsigned char)*p)) p++; // Skip leading whitespace
        if (!*p) break; // End of line
        if (*p == '#') {tokens[token_count].type = TOKEN_COMMENT; tokens[token_count].text = p; tokens[token_count].len = strlen(p); token_count++; break;} // Comment consumes rest of line

        tokens[token_count].text = storage_ptr; // Tentatively set text pointer

        const char *matched_op_text = NULL; TokenType matched_op_type = TOKEN_OPERATOR; // Default to generic operator if type not specific
        int op_len = match_operator_dynamic(p, &matched_op_text, &matched_op_type);

        if (op_len > 0) { // Operator matched
            tokens[token_count].type = matched_op_type;
            tokens[token_count].len = op_len;
            if (remaining_storage > op_len) {
                strncpy(storage_ptr, p, op_len); // Copy the matched part of input string
                storage_ptr[op_len] = '\0';
                storage_ptr += (op_len + 1); // Advance storage pointer
                remaining_storage -= (op_len + 1);
            } else { tokens[token_count].type = TOKEN_ERROR; /* Ran out of storage */ break; }
            p += op_len; // Advance input pointer
        } else if (*p == '"') { // Quoted string
            tokens[token_count].type = TOKEN_STRING;
            const char *start = p; // Keep quotes as part of token text for now
            p++; // Skip opening quote
            while (*p && (*p != '"' || (*(p-1) == '\\' && (p-2 < start || *(p-2) != '\\' )))) { // Handle escaped quotes like \"
                p++;
            }
            if (*p == '"') p++; // Skip closing quote
            tokens[token_count].len = p - start;
            if (remaining_storage > (size_t)tokens[token_count].len) {
                strncpy(storage_ptr, start, tokens[token_count].len);
                storage_ptr[tokens[token_count].len] = '\0';
                storage_ptr += (tokens[token_count].len + 1);
                remaining_storage -= (tokens[token_count].len + 1);
            } else { tokens[token_count].type = TOKEN_ERROR; break; }
        } else if (*p == '$') { // Variable
            tokens[token_count].type = TOKEN_VARIABLE;
            const char *start = p; p++; // Skip '$'
            if (*p == '{') { // ${variable_name[index]}
                p++; // Skip '{'
                // Allow more complex expressions inside ${...}, expansion logic will parse it
                while (*p && *p != '}') { p++; } // Simplified: just find matching '}'
                if (*p == '}') p++; // Skip '}'
            } else { // $variable_name or $arr[index]
                while (isalnum((unsigned char)*p) || *p == '_') p++;
                if (*p == '[') { // Array access $arr[index]
                    p++; // Skip '['
                    int bracket_depth = 1;
                    while(*p && bracket_depth > 0) {
                        if (*p == '[') bracket_depth++; else if (*p == ']') bracket_depth--;
                        if (bracket_depth == 0 && *(p) == ']') { p++; break; } // Consume final ']' for token
                        p++;
                    }
                }
            }
            tokens[token_count].len = p - start;
            if (remaining_storage > (size_t)tokens[token_count].len) {
                strncpy(storage_ptr, start, tokens[token_count].len);
                storage_ptr[tokens[token_count].len] = '\0';
                storage_ptr += (tokens[token_count].len + 1);
                remaining_storage -= (tokens[token_count].len + 1);
            } else { tokens[token_count].type = TOKEN_ERROR; break; }
        } else { // Word (command, argument, unquoted identifier)
            tokens[token_count].type = TOKEN_WORD;
            const char *start = p;
            while (*p && !isspace((unsigned char)*p)) {
                const char* temp_op_text_check = NULL; TokenType temp_op_type_check;
                if (match_operator_dynamic(p, &temp_op_text_check, &temp_op_type_check) > 0) break; // Stop if an operator starts
                if (*p == '"' || *p == '$' || *p == '#') break; // Stop if other special token starts
                // As per spec: "A word can be composed only from alphanumeric values and _"
                if (!isalnum((unsigned char)*p) && *p != '_') break; // Break on non-alnum/_
                p++;
            }
            tokens[token_count].len = p - start;
            if (tokens[token_count].len == 0 && *p) { /* Should not happen if *p was not whitespace or special */ p++; continue; }
            if (tokens[token_count].len == 0 && !*p) break; // EOS

            if (remaining_storage > (size_t)tokens[token_count].len) {
                strncpy(storage_ptr, start, tokens[token_count].len);
                storage_ptr[tokens[token_count].len] = '\0';
                storage_ptr += (tokens[token_count].len + 1);
                remaining_storage -= (tokens[token_count].len + 1);
            } else { tokens[token_count].type = TOKEN_ERROR; break; }
        }
        token_count++;
    }
    if (token_count < max_tokens) { // Add EOF token if space
        tokens[token_count].type = TOKEN_EOF;
        tokens[token_count].text = "EOF"; // Not from token_storage
        tokens[token_count].len = 3;
        // token_count++; // Optionally count EOF if it's processed by loops
    }
    return token_count;
}

// --- Variable & Scope Management ---
int enter_scope() {
    if (scope_stack_top + 1 >= MAX_SCOPE_DEPTH) {
        fprintf(stderr, "Error: Maximum scope depth exceeded (%d).\n", MAX_SCOPE_DEPTH);
        return -1; // Indicate error
    }
    scope_stack_top++;
    scope_stack[scope_stack_top].scope_id = (scope_stack_top == 0 && next_scope_id == 1) ? GLOBAL_SCOPE_ID : next_scope_id++;
    // Ensure global scope is always ID 0, even if enter_scope is called multiple times at init.
    if (scope_stack_top == 0) scope_stack[scope_stack_top].scope_id = GLOBAL_SCOPE_ID;

    return scope_stack[scope_stack_top].scope_id;
}

void leave_scope(int scope_id_to_leave) {
    if (scope_stack_top < 0 ) { // No scopes to leave
        // fprintf(stderr, "Warning: leave_scope called when scope stack is empty.\n");
        return;
    }
    if (scope_stack[scope_stack_top].scope_id != scope_id_to_leave) {
        if (scope_id_to_leave != GLOBAL_SCOPE_ID || scope_stack[scope_stack_top].scope_id != GLOBAL_SCOPE_ID) {
             fprintf(stderr, "Error: Scope mismatch on leave_scope. Trying to leave %d, current top is %d.\n",
                scope_id_to_leave, scope_stack[scope_stack_top].scope_id );
        }
        // Attempt to recover by just popping, but this indicates a logic flaw elsewhere.
        scope_stack_top--;
        return;
    }
    if (scope_id_to_leave != GLOBAL_SCOPE_ID) { // Don't clean global vars on 'leave_scope(0)'
        cleanup_variables_for_scope(scope_id_to_leave);
    }
    scope_stack_top--;
}

void cleanup_variables_for_scope(int scope_id) {
    if (scope_id == GLOBAL_SCOPE_ID) return; // Global scope variables are not cleaned up this way

    Variable *current = variable_list_head;
    Variable *prev = NULL;
    while (current != NULL) {
        if (current->scope_id == scope_id) {
            Variable *to_delete = current;
            if (prev == NULL) { // Deleting head of the list
                variable_list_head = current->next;
            } else { // Deleting middle or tail element
                prev->next = current->next;
            }
            current = current->next; // Move current before freeing to_delete
            // printf("Cleaning var '%s' (value '%s') from scope %d\n", to_delete->name, to_delete->value, to_delete->scope_id);
            if (to_delete->value) free(to_delete->value);
            free(to_delete);
            // If prev was not NULL, it remains the same. If prev was NULL, it's still NULL for the new head.
        } else {
            prev = current;
            current = current->next;
        }
    }
}

void free_all_variables() {
    Variable *current = variable_list_head;
    Variable *next_var;
    while (current != NULL) {
        next_var = current->next;
        if (current->value) free(current->value);
        free(current);
        current = next_var;
    }
    variable_list_head = NULL;
}

char* get_variable_scoped(const char *name_raw) {
    char clean_name[MAX_VAR_NAME_LEN];
    strncpy(clean_name, name_raw, MAX_VAR_NAME_LEN -1); clean_name[MAX_VAR_NAME_LEN-1] = '\0';
    trim_whitespace(clean_name);
    if (strlen(clean_name) == 0) return NULL;

    // Search from current (innermost) scope outwards to global
    for (int i = scope_stack_top; i >= 0; i--) {
        int current_search_scope_id = scope_stack[i].scope_id;
        Variable *current_node = variable_list_head;
        while (current_node != NULL) {
            if (current_node->scope_id == current_search_scope_id && strcmp(current_node->name, clean_name) == 0) {
                return current_node->value; // Found
            }
            current_node = current_node->next;
        }
    }
    return NULL; // Not found in any active scope
}

void set_variable_scoped(const char *name_raw, const char *value_to_set, bool is_array_elem) {
    if (scope_stack_top < 0) {
        fprintf(stderr, "Critical Error: No active scope to set variable '%s'. Shell not initialized?\n", name_raw);
        return;
    }
    int current_scope_id = scope_stack[scope_stack_top].scope_id;

    char clean_name[MAX_VAR_NAME_LEN];
    strncpy(clean_name, name_raw, MAX_VAR_NAME_LEN -1); clean_name[MAX_VAR_NAME_LEN-1] = '\0';
    trim_whitespace(clean_name);
    if (strlen(clean_name) == 0) { fprintf(stderr, "Error: Cannot set variable with empty name.\n"); return; }

    // Try to update if variable already exists in the CURRENT scope
    Variable *current_node = variable_list_head;
    while (current_node != NULL) {
        if (current_node->scope_id == current_scope_id && strcmp(current_node->name, clean_name) == 0) {
            if (current_node->value) free(current_node->value); // Free old value
            current_node->value = strdup(value_to_set);
            if (!current_node->value) { perror("strdup failed for variable value update"); current_node->value = strdup(""); /* Fallback to empty */ }
            current_node->is_array_element = is_array_elem;
            return;
        }
        current_node = current_node->next;
    }

    // Not found in current scope, create new variable in current scope
    Variable *new_var = (Variable*)malloc(sizeof(Variable));
    if (!new_var) { perror("malloc for new variable failed"); return; }
    strncpy(new_var->name, clean_name, MAX_VAR_NAME_LEN - 1); new_var->name[MAX_VAR_NAME_LEN - 1] = '\0';
    new_var->value = strdup(value_to_set);
    if (!new_var->value) { perror("strdup failed for new variable value"); free(new_var); new_var = NULL; /* Critical error */ return; }
    new_var->is_array_element = is_array_elem;
    new_var->scope_id = current_scope_id;
    new_var->next = variable_list_head; // Prepend to global list
    variable_list_head = new_var;
}

void expand_variables_in_string_advanced(const char *input_str, char *expanded_str, size_t expanded_str_size) {
    const char *p_in = input_str; char *p_out = expanded_str;
    size_t remaining_size = expanded_str_size - 1; expanded_str[0] = '\0';

    while (*p_in && remaining_size > 0) {
        if (*p_in == '$') {
            p_in++; // Skip '$'
            char var_name_buffer[MAX_VAR_NAME_LEN * 2]; // Buffer for var name or arr[idx] form
            char *pv = var_name_buffer;

            if (*p_in == '{') { // ${...}
                p_in++; // Skip '{'
                int brace_level = 1;
                while (*p_in && brace_level > 0 && (pv - var_name_buffer < (long)sizeof(var_name_buffer) - 1)) {
                    if (*p_in == '{') brace_level++;
                    else if (*p_in == '}') brace_level--;
                    if (brace_level > 0) *pv++ = *p_in; // Copy content within braces
                    p_in++;
                }
                *pv = '\0'; // Null-terminate the extracted content
                // p_in is now at char after '}' or at EOS
            } else { // $var or $arr[idx] (no curly braces)
                while (isalnum((unsigned char)*p_in) || *p_in == '_') { // Read base variable name
                    if (pv - var_name_buffer < MAX_VAR_NAME_LEN -1) *pv++ = *p_in++; else break;
                }
                // *pv = '\0'; // Tentatively terminate base name
                if (*p_in == '[') { // Array access part
                    // pv should be at the end of base name to append '['
                    if (pv - var_name_buffer < (long)sizeof(var_name_buffer) -1) *pv++ = *p_in++; else break; // Add '['
                    int bracket_level = 1;
                    while (*p_in && bracket_level > 0 && (pv - var_name_buffer < (long)sizeof(var_name_buffer) - 1)) {
                        if (*p_in == '[') bracket_level++;
                        else if (*p_in == ']') bracket_level--;
                        *pv++ = *p_in++; // Copy index part including the final ']'
                    }
                }
                *pv = '\0'; // Terminate full var_name_buffer (e.g. "var" or "arr[idx]")
            }

            // Parse var_name_buffer for base name and index if it's an array.
            char base_var_name[MAX_VAR_NAME_LEN];
            char index_str_raw[MAX_VAR_NAME_LEN] = ""; // Index part, possibly quoted or another var
            bool is_array_access = false;

            char* bracket_ptr = strchr(var_name_buffer, '[');
            if (bracket_ptr) {
                char* end_bracket_ptr = strrchr(bracket_ptr, ']'); // Find last ']'
                if (end_bracket_ptr && end_bracket_ptr > bracket_ptr) {
                    is_array_access = true;
                    size_t base_len = bracket_ptr - var_name_buffer;
                    strncpy(base_var_name, var_name_buffer, base_len); base_var_name[base_len] = '\0';
                    size_t index_len = end_bracket_ptr - (bracket_ptr + 1);
                    strncpy(index_str_raw, bracket_ptr + 1, index_len); index_str_raw[index_len] = '\0';
                } else { // Malformed array syntax
                    strncpy(base_var_name, var_name_buffer, MAX_VAR_NAME_LEN -1); base_var_name[MAX_VAR_NAME_LEN -1] = '\0';
                }
            } else { // Simple variable
                strncpy(base_var_name, var_name_buffer, MAX_VAR_NAME_LEN -1); base_var_name[MAX_VAR_NAME_LEN -1] = '\0';
            }

            char *value_to_insert = NULL;
            if (is_array_access) {
                value_to_insert = get_array_element_scoped(base_var_name, index_str_raw);
            } else {
                value_to_insert = get_variable_scoped(base_var_name);
            }

            if (value_to_insert) {
                size_t val_len = strlen(value_to_insert);
                if (val_len < remaining_size) {
                    strcpy(p_out, value_to_insert); p_out += val_len; remaining_size -= val_len;
                } else { // Not enough space in output buffer
                    strncpy(p_out, value_to_insert, remaining_size); p_out += remaining_size; remaining_size = 0;
                }
            } // If variable not found, it expands to nothing (empty string)
        } else if (*p_in == '\\' && *(p_in+1) == '$') { // Escaped dollar sign \$
            p_in++; // Skip '\'
            if (remaining_size > 0) { *p_out++ = *p_in++; remaining_size--; } // Copy '$'
        } else { // Regular character
            *p_out++ = *p_in++; remaining_size--;
        }
    }
    *p_out = '\0'; // Null-terminate the expanded string
}

char* get_array_element_scoped(const char* array_base_name, const char* index_str_raw_param) {
    char index_str_raw[INPUT_BUFFER_SIZE]; // Local copy for modification if needed
    strncpy(index_str_raw, index_str_raw_param, sizeof(index_str_raw) -1);
    index_str_raw[sizeof(index_str_raw)-1] = '\0';

    char expanded_index_val[INPUT_BUFFER_SIZE];
    if (index_str_raw[0] == '"' && index_str_raw[strlen(index_str_raw)-1] == '"') {
        unescape_string(index_str_raw, expanded_index_val, sizeof(expanded_index_val));
    } else if (index_str_raw[0] == '$') {
        expand_variables_in_string_advanced(index_str_raw, expanded_index_val, sizeof(expanded_index_val));
    } else { // Unquoted literal key
        strncpy(expanded_index_val, index_str_raw, sizeof(expanded_index_val)-1);
        expanded_index_val[sizeof(expanded_index_val)-1] = '\0';
    }
    char mangled_name[MAX_VAR_NAME_LEN * 2]; // Base + _ARRAYIDX_ + index
    snprintf(mangled_name, sizeof(mangled_name), "%s_ARRAYIDX_%s", array_base_name, expanded_index_val);
    return get_variable_scoped(mangled_name);
}

void set_array_element_scoped(const char* array_base_name, const char* index_str_raw_param, const char* value) {
    char index_str_raw[INPUT_BUFFER_SIZE];
    strncpy(index_str_raw, index_str_raw_param, sizeof(index_str_raw) -1);
    index_str_raw[sizeof(index_str_raw)-1] = '\0';

    char expanded_index_val[INPUT_BUFFER_SIZE];
    if (index_str_raw[0] == '"' && index_str_raw[strlen(index_str_raw)-1] == '"') {
        unescape_string(index_str_raw, expanded_index_val, sizeof(expanded_index_val));
    } else if (index_str_raw[0] == '$') {
        expand_variables_in_string_advanced(index_str_raw, expanded_index_val, sizeof(expanded_index_val));
    } else {
        strncpy(expanded_index_val, index_str_raw, sizeof(expanded_index_val)-1);
        expanded_index_val[sizeof(expanded_index_val)-1] = '\0';
    }
    char mangled_name[MAX_VAR_NAME_LEN * 2];
    snprintf(mangled_name, sizeof(mangled_name), "%s_ARRAYIDX_%s", array_base_name, expanded_index_val);
    set_variable_scoped(mangled_name, value, true); // true: is_array_element
}


// --- Command Execution ---
bool find_command_in_path_dynamic(const char *command, char *full_path) {
    if (strchr(command, '/') != NULL) { // Command contains a path
        if (access(command, X_OK) == 0) {
            strncpy(full_path, command, MAX_FULL_PATH_LEN -1); full_path[MAX_FULL_PATH_LEN-1] = '\0';
            return true;
        }
        return false;
    }
    PathDirNode *current_path_node = path_list_head;
    while (current_path_node) {
        snprintf(full_path, MAX_FULL_PATH_LEN, "%s/%s", current_path_node->path, command);
        if (access(full_path, X_OK) == 0) return true;
        current_path_node = current_path_node->next;
    }
    return false;
}

bool find_module_in_path(const char* module_spec, char* result_full_path) {
    char module_path_part[MAX_FULL_PATH_LEN];
    strncpy(module_path_part, module_spec, sizeof(module_path_part) - 1);
    module_path_part[sizeof(module_path_part) - 1] = '\0';

    char *dot = strrchr(module_path_part, '.');
    if (dot && strchr(module_path_part, '/') == NULL) { // Contains '.' but no '/', assume library.part
        *dot = '/'; // Replace last dot with slash
        strncat(module_path_part, ".bsh", sizeof(module_path_part) - strlen(module_path_part) - 1);
    } else if (strchr(module_path_part, '/') == NULL && (strstr(module_path_part, ".bsh") == NULL) ) {
        strncat(module_path_part, ".bsh", sizeof(module_path_part) - strlen(module_path_part) - 1);
    }

    // 1. Try as direct path (absolute or relative to CWD)
    char temp_path[PATH_MAX];
    if (realpath(module_path_part, temp_path) && access(temp_path, F_OK) == 0) {
        strncpy(result_full_path, temp_path, MAX_FULL_PATH_LEN -1);
        result_full_path[MAX_FULL_PATH_LEN-1] = '\0';
        return true;
    }
     // If realpath fails (e.g. file doesn't exist yet for relative path), try access on original
    if (access(module_path_part, F_OK) == 0) {
         strncpy(result_full_path, module_path_part, MAX_FULL_PATH_LEN -1); // Use as is if accessible
         result_full_path[MAX_FULL_PATH_LEN-1] = '\0';
         return true;
    }


    if (strchr(module_spec, '/') != NULL) { // If original spec contained a path, don't search module_path
        return false;
    }

    // 2. Search in BSH_MODULE_PATH
    PathDirNode *current_module_dir = module_path_list_head;
    while (current_module_dir) {
        snprintf(result_full_path, MAX_FULL_PATH_LEN, "%s/%s", current_module_dir->path, module_path_part);
        if (realpath(result_full_path, temp_path) && access(temp_path, F_OK) == 0) {
             strncpy(result_full_path, temp_path, MAX_FULL_PATH_LEN -1);
             result_full_path[MAX_FULL_PATH_LEN-1] = '\0';
            return true;
        } else if (access(result_full_path, F_OK) == 0) { // Fallback if realpath fails but access works
            return true;
        }
        current_module_dir = current_module_dir->next;
    }
    result_full_path[0] = '\0'; // Clear path if not found
    return false;
}

int execute_external_command(char *command_path, char **args, int arg_count, char *output_buffer, size_t output_buffer_size) {
    pid_t pid; int status; int pipefd[2] = {-1, -1};
    if (output_buffer) { if (pipe(pipefd) == -1) { perror("pipe failed for cmd output"); return -1; } }
    pid = fork();
    if (pid == 0) { // Child
        if (output_buffer) { close(pipefd[0]); dup2(pipefd[1], STDOUT_FILENO); dup2(pipefd[1], STDERR_FILENO); close(pipefd[1]); }
        execv(command_path, args);
        perror("execv failed"); exit(EXIT_FAILURE);
    } else if (pid < 0) { // Fork error
        perror("fork failed"); if (output_buffer) { close(pipefd[0]); close(pipefd[1]); } return -1;
    } else { // Parent
        if (output_buffer) {
            close(pipefd[1]); ssize_t bytes_read; size_t total_bytes_read = 0;
            char read_buf[INPUT_BUFFER_SIZE]; output_buffer[0] = '\0';
            while((bytes_read = read(pipefd[0], read_buf, sizeof(read_buf)-1)) > 0) {
                if (total_bytes_read + bytes_read < output_buffer_size) {
                    read_buf[bytes_read] = '\0'; strcat(output_buffer, read_buf); total_bytes_read += bytes_read;
                } else { strncat(output_buffer, read_buf, output_buffer_size - total_bytes_read -1); break; }
            } close(pipefd[0]);
            // Trim trailing newlines
            char* nl = strrchr(output_buffer, '\n');
            while(nl && (nl == output_buffer + strlen(output_buffer) -1)) { *nl = '\0'; nl = strrchr(output_buffer, '\n');}
        }
        do { waitpid(pid, &status, WUNTRACED); } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        // Set $? (LAST_COMMAND_STATUS)
        char status_str[12]; snprintf(status_str, sizeof(status_str), "%d", WEXITSTATUS(status));
        set_variable_scoped("LAST_COMMAND_STATUS", status_str, false);
        return WEXITSTATUS(status);
    }
    return -1; // Should not be reached
}

void execute_user_function(UserFunction* func, Token* call_arg_tokens, int call_arg_token_count, FILE* input_source_for_context) {
    if (!func) return;
    int function_scope_id = enter_scope();
    if (function_scope_id == -1) { /* Max scope depth reached */ return; }

    // Set parameters in the new function scope
    for (int i = 0; i < func->param_count; ++i) {
        if (i < call_arg_token_count) {
            char expanded_arg_val[INPUT_BUFFER_SIZE]; // Use larger buffer for expansion
            if (call_arg_tokens[i].type == TOKEN_STRING) {
                 char unescaped_temp[INPUT_BUFFER_SIZE];
                 unescape_string(call_arg_tokens[i].text, unescaped_temp, sizeof(unescaped_temp));
                 expand_variables_in_string_advanced(unescaped_temp, expanded_arg_val, sizeof(expanded_arg_val));
            } else {
                 expand_variables_in_string_advanced(call_arg_tokens[i].text, expanded_arg_val, sizeof(expanded_arg_val));
            }
            set_variable_scoped(func->params[i], expanded_arg_val, false);
        } else {
            set_variable_scoped(func->params[i], "", false); // Unprovided params are empty strings
        }
    }

    int func_outer_block_stack_top_bf = block_stack_top_bf;
    ExecutionState func_outer_exec_state = current_exec_state;
    current_exec_state = STATE_NORMAL; // Functions start in normal state internally

    for (int i = 0; i < func->line_count; ++i) {
        char line_copy[MAX_LINE_LENGTH]; // Function body lines are original lines
        strncpy(line_copy, func->body[i], MAX_LINE_LENGTH-1); line_copy[MAX_LINE_LENGTH-1] = '\0';
        process_line(line_copy, NULL, i + 1, STATE_NORMAL); // Pass NULL input_source for in-memory lines
    }

    // Restore block execution context from within the function
    while(block_stack_top_bf > func_outer_block_stack_top_bf) {
        pop_block_bf();
    }
    current_exec_state = func_outer_exec_state;

    leave_scope(function_scope_id); // Clean up function's local variables
}

// --- Built-in Commands ---
void handle_defkeyword_statement(Token *tokens, int num_tokens) {
    if (num_tokens != 3 || tokens[1].type != TOKEN_WORD || tokens[2].type != TOKEN_WORD) {
        fprintf(stderr, "Syntax: defkeyword <original_keyword> <new_alias>\n"); return;
    }
    if (current_exec_state == STATE_BLOCK_SKIP) return;
    add_keyword_alias(tokens[1].text, tokens[2].text);
    // printf("Keyword alias defined: '%s' -> '%s'\n", tokens[2].text, tokens[1].text);
}

void handle_assignment_advanced(Token *tokens, int num_tokens) {
    if (num_tokens < 3 || tokens[0].type != TOKEN_VARIABLE || tokens[1].type != TOKEN_ASSIGN) {
        fprintf(stderr, "Assignment syntax: $variable = value | $array[index] = value\n"); return;
    }
    if (current_exec_state == STATE_BLOCK_SKIP) return;

    char var_token_text_copy[MAX_VAR_NAME_LEN * 2]; // For parsing $arr[idx] from token text
    strncpy(var_token_text_copy, tokens[0].text + 1, sizeof(var_token_text_copy) -1); // Skip '$'
    var_token_text_copy[sizeof(var_token_text_copy)-1] = '\0';

    char base_var_name[MAX_VAR_NAME_LEN]; char index_str_raw[MAX_VAR_NAME_LEN] = ""; bool is_array_assignment = false;
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

    char value_to_set[INPUT_BUFFER_SIZE]; value_to_set[0] = '\0'; // Use larger buffer
    bool is_rhs_command = false;
    if (num_tokens > 2 && tokens[2].type == TOKEN_WORD) {
        char expanded_first_rhs_token[INPUT_BUFFER_SIZE];
        expand_variables_in_string_advanced(tokens[2].text, expanded_first_rhs_token, sizeof(expanded_first_rhs_token));
        UserFunction* func = function_list; while(func) { if (strcmp(expanded_first_rhs_token, func->name) == 0) { is_rhs_command = true; break; } func = func->next; }
        if (!is_rhs_command) { char full_cmd_path_check[MAX_FULL_PATH_LEN]; if (find_command_in_path_dynamic(expanded_first_rhs_token, full_cmd_path_check)) is_rhs_command = true; }
    }

    if (is_rhs_command) {
        char *cmd_args[MAX_ARGS + 1]; char expanded_cmd_args_storage[MAX_ARGS][INPUT_BUFFER_SIZE]; int cmd_arg_count = 0;
        for (int i = 2; i < num_tokens; i++) {
            if (tokens[i].type == TOKEN_WORD || tokens[i].type == TOKEN_STRING || tokens[i].type == TOKEN_VARIABLE) {
                if (tokens[i].type == TOKEN_STRING) { char unescaped_val[INPUT_BUFFER_SIZE]; unescape_string(tokens[i].text, unescaped_val, sizeof(unescaped_val)); expand_variables_in_string_advanced(unescaped_val, expanded_cmd_args_storage[cmd_arg_count], INPUT_BUFFER_SIZE);
                } else { expand_variables_in_string_advanced(tokens[i].text, expanded_cmd_args_storage[cmd_arg_count], INPUT_BUFFER_SIZE); }
                cmd_args[cmd_arg_count] = expanded_cmd_args_storage[cmd_arg_count]; cmd_arg_count++;
            }
        } cmd_args[cmd_arg_count] = NULL;
        if (cmd_arg_count > 0) {
            bool is_user_func_rhs = false; UserFunction* user_func_check = function_list; while(user_func_check){ if(strcmp(cmd_args[0], user_func_check->name) == 0) {is_user_func_rhs = true; break;} user_func_check = user_func_check->next; }
            if(is_user_func_rhs){ fprintf(stderr, "Assigning output of user-defined functions not directly supported for capture. Execute separately.\n"); }
            else { char full_cmd_path_check[MAX_FULL_PATH_LEN]; if (find_command_in_path_dynamic(cmd_args[0], full_cmd_path_check)) { execute_external_command(full_cmd_path_check, cmd_args, cmd_arg_count, value_to_set, sizeof(value_to_set)); }
                   else { fprintf(stderr, "Command for assignment not found: %s\n", cmd_args[0]); }
            }
        }
    } else { // RHS is a literal value
        char combined_value[INPUT_BUFFER_SIZE] = ""; size_t current_len = 0;
        for (int i = 2; i < num_tokens; i++) {
            char expanded_token_val[INPUT_BUFFER_SIZE];
            if (tokens[i].type == TOKEN_STRING) { char unescaped_temp[INPUT_BUFFER_SIZE]; unescape_string(tokens[i].text, unescaped_temp, sizeof(unescaped_temp)); expand_variables_in_string_advanced(unescaped_temp, expanded_token_val, sizeof(expanded_token_val));
            } else { expand_variables_in_string_advanced(tokens[i].text, expanded_token_val, sizeof(expanded_token_val)); }
            size_t token_len = strlen(expanded_token_val);
            if (current_len + token_len + (current_len > 0 ? 1 : 0) < INPUT_BUFFER_SIZE) {
                if (current_len > 0) { strcat(combined_value, " "); current_len++; }
                strcat(combined_value, expanded_token_val); current_len += token_len;
            } else { fprintf(stderr, "Value too long for assignment.\n"); break; }
        }
        strncpy(value_to_set, combined_value, sizeof(value_to_set) -1); value_to_set[sizeof(value_to_set)-1] = '\0';
    }

    if (is_array_assignment) set_array_element_scoped(base_var_name, index_str_raw, value_to_set);
    else set_variable_scoped(base_var_name, value_to_set, false);
}

void handle_echo_advanced(Token *tokens, int num_tokens) {
    if (current_exec_state == STATE_BLOCK_SKIP) return;
    char expanded_arg[INPUT_BUFFER_SIZE];
    for (int i = 1; i < num_tokens; i++) {
        if (tokens[i].type == TOKEN_STRING) {
            char unescaped_val[INPUT_BUFFER_SIZE];
            unescape_string(tokens[i].text, unescaped_val, sizeof(unescaped_val));
            expand_variables_in_string_advanced(unescaped_val, expanded_arg, sizeof(expanded_arg));
        } else {
            expand_variables_in_string_advanced(tokens[i].text, expanded_arg, sizeof(expanded_arg));
        }
        printf("%s%s", expanded_arg, (i == num_tokens - 1) ? "" : " ");
    }
    printf("\n");
}

bool evaluate_condition_advanced(Token* operand1_token, Token* operator_token, Token* operand2_token) {
    if (!operand1_token || !operator_token || !operand2_token) return false;
    // No STATE_BLOCK_SKIP check here; this function is called only if not skipping.

    char val1_expanded[INPUT_BUFFER_SIZE], val2_expanded[INPUT_BUFFER_SIZE];
    if (operand1_token->type == TOKEN_STRING) { char unescaped[INPUT_BUFFER_SIZE]; unescape_string(operand1_token->text, unescaped, sizeof(unescaped)); expand_variables_in_string_advanced(unescaped, val1_expanded, sizeof(val1_expanded));
    } else { expand_variables_in_string_advanced(operand1_token->text, val1_expanded, sizeof(val1_expanded)); }
    if (operand2_token->type == TOKEN_STRING) { char unescaped[INPUT_BUFFER_SIZE]; unescape_string(operand2_token->text, unescaped, sizeof(unescaped)); expand_variables_in_string_advanced(unescaped, val2_expanded, sizeof(val2_expanded));
    } else { expand_variables_in_string_advanced(operand2_token->text, val2_expanded, sizeof(val2_expanded)); }

    const char* op_str = operator_token->text;
    if (strcmp(op_str, "==") == 0) return strcmp(val1_expanded, val2_expanded) == 0;
    if (strcmp(op_str, "!=") == 0) return strcmp(val1_expanded, val2_expanded) != 0;

    long num1, num2; char *endptr1, *endptr2;
    errno = 0; num1 = strtol(val1_expanded, &endptr1, 10); bool num1_valid = (errno == 0 && val1_expanded[0] != '\0' && *endptr1 == '\0');
    errno = 0; num2 = strtol(val2_expanded, &endptr2, 10); bool num2_valid = (errno == 0 && val2_expanded[0] != '\0' && *endptr2 == '\0');
    bool numeric_possible = num1_valid && num2_valid;

    if (numeric_possible) {
        if (strcmp(op_str, ">") == 0) return num1 > num2; if (strcmp(op_str, "<") == 0) return num1 < num2;
        if (strcmp(op_str, ">=") == 0) return num1 >= num2; if (strcmp(op_str, "<=") == 0) return num1 <= num2;
    } else { // Fallback to string comparison for >, <, >=, <=
        if (strcmp(op_str, ">") == 0) return strcmp(val1_expanded, val2_expanded) > 0;
        if (strcmp(op_str, "<") == 0) return strcmp(val1_expanded, val2_expanded) < 0;
        if (strcmp(op_str, ">=") == 0) return strcmp(val1_expanded, val2_expanded) >= 0;
        if (strcmp(op_str, "<=") == 0) return strcmp(val1_expanded, val2_expanded) <= 0;
    }
    fprintf(stderr, "Unsupported operator or type mismatch in condition: '%s' %s '%s'\n", val1_expanded, op_str, val2_expanded);
    return false;
}

void handle_if_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no) {
    if (num_tokens < 4) {
        fprintf(stderr, "Syntax error for 'if'. Expected: if <op1> <op> <op2> [{]\n");
        if (block_stack_top_bf < MAX_NESTING_DEPTH -1 && current_exec_state != STATE_BLOCK_SKIP) {
           push_block_bf(BLOCK_TYPE_IF, false, 0, current_line_no); current_exec_state = STATE_BLOCK_SKIP;
        } return;
    }
    bool condition_result = false;
    if (current_exec_state != STATE_BLOCK_SKIP) {
         condition_result = evaluate_condition_advanced(&tokens[1], &tokens[2], &tokens[3]);
    }
    push_block_bf(BLOCK_TYPE_IF, condition_result, 0, current_line_no);
    if (condition_result && current_exec_state != STATE_BLOCK_SKIP) current_exec_state = STATE_BLOCK_EXECUTE;
    else current_exec_state = STATE_BLOCK_SKIP;
    // Check for '{' on same line or expect on next
    if (! (num_tokens > 4 && tokens[num_tokens-1].type == TOKEN_LBRACE) && !(num_tokens == 4) ) {
        fprintf(stderr, "Syntax error for 'if': '{' expected after condition or on next line, or unexpected tokens.\n");
    }
}

void handle_else_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no) {
    BlockFrame* prev_block_frame = peek_block_bf();
    if (!prev_block_frame || (prev_block_frame->type != BLOCK_TYPE_IF && prev_block_frame->type != BLOCK_TYPE_ELSE)) {
        fprintf(stderr, "Error: 'else' without a preceding 'if' or 'else if' block.\n");
        if (current_exec_state != STATE_BLOCK_SKIP) {
            current_exec_state = STATE_BLOCK_SKIP; push_block_bf(BLOCK_TYPE_ELSE, false, 0, current_line_no);
        } return;
    }
    BlockFrame closed_if_or_else_if = *pop_block_bf(); bool execute_this_else_branch = false;
    if (closed_if_or_else_if.condition_true) execute_this_else_branch = false;
    else {
        if (num_tokens > 1 && tokens[1].type == TOKEN_WORD && strcmp(resolve_keyword_alias(tokens[1].text), "if") == 0) { // "else if"
            if (num_tokens < 5) { fprintf(stderr, "Syntax error for 'else if'.\n"); execute_this_else_branch = false; }
            else { if (current_exec_state != STATE_BLOCK_SKIP) execute_this_else_branch = evaluate_condition_advanced(&tokens[2], &tokens[3], &tokens[4]);
                   else execute_this_else_branch = false;
            }
        } else execute_this_else_branch = true; // Simple "else"
    }
    push_block_bf(BLOCK_TYPE_ELSE, execute_this_else_branch, 0, current_line_no);
    if (execute_this_else_branch && current_exec_state != STATE_BLOCK_SKIP) current_exec_state = STATE_BLOCK_EXECUTE;
    else current_exec_state = STATE_BLOCK_SKIP;
    // Check for '{' on same line or expect on next
    int expected_brace_token_idx = (num_tokens > 1 && tokens[1].type == TOKEN_WORD && strcmp(resolve_keyword_alias(tokens[1].text), "if") == 0) ? 5 : 1;
    if (! (num_tokens > expected_brace_token_idx && tokens[num_tokens-1].type == TOKEN_LBRACE) && !(num_tokens == expected_brace_token_idx) ) {
         if (num_tokens > expected_brace_token_idx || (num_tokens == expected_brace_token_idx && tokens[num_tokens-1].type != TOKEN_LBRACE && tokens[0].type != TOKEN_EOF) )
            fprintf(stderr, "Syntax error for 'else'/'else if': '{' expected or unexpected tokens.\n");
    }
}

void handle_while_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no) {
    if (num_tokens < 4) {
        fprintf(stderr, "Syntax error for 'while'. Expected: while <op1> <op> <op2> [{]\n");
        if (block_stack_top_bf < MAX_NESTING_DEPTH -1 && current_exec_state != STATE_BLOCK_SKIP) {
           push_block_bf(BLOCK_TYPE_WHILE, false, 0, current_line_no); current_exec_state = STATE_BLOCK_SKIP;
        } return;
    }
    bool condition_result = false; long loop_fpos_at_while_line = -1;
    // TODO: If input_source is a file, try to get ftell() *before* this line was read by execute_script
    // and pass it here as an argument to process_line, then to push_block_bf.
    // For now, loop_start_fpos in BlockFrame might not be accurately set for fseek-based looping.
    // current_line_no is more reliable for conceptual looping or in-memory script parts.

    if (current_exec_state != STATE_BLOCK_SKIP) {
        condition_result = evaluate_condition_advanced(&tokens[1], &tokens[2], &tokens[3]);
    }
    push_block_bf(BLOCK_TYPE_WHILE, condition_result, loop_fpos_at_while_line, current_line_no);
    if (condition_result && current_exec_state != STATE_BLOCK_SKIP) current_exec_state = STATE_BLOCK_EXECUTE;
    else current_exec_state = STATE_BLOCK_SKIP;

    if (! (num_tokens > 4 && tokens[num_tokens-1].type == TOKEN_LBRACE) && !(num_tokens == 4) ) {
         fprintf(stderr, "Syntax error for 'while': '{' expected after condition or on next line, or unexpected tokens.\n");
    }
}

void handle_defunc_statement_advanced(Token *tokens, int num_tokens) {
    if (num_tokens < 2 || tokens[1].type != TOKEN_WORD) {
        fprintf(stderr, "Syntax: defunc <funcname> [(param1 ...)] [{]\n"); return;
    }
    if (is_defining_function && current_exec_state != STATE_IMPORT_PARSING) {
        fprintf(stderr, "Error: Cannot nest function definitions during normal execution.\n"); return;
    }
    if (current_exec_state == STATE_BLOCK_SKIP && current_exec_state != STATE_IMPORT_PARSING) {
        push_block_bf(BLOCK_TYPE_FUNCTION_DEF, false, 0, 0); return; // Skip body
    }

    current_function_definition = (UserFunction*)malloc(sizeof(UserFunction));
    if (!current_function_definition) { perror("malloc for function definition failed"); return; }
    memset(current_function_definition, 0, sizeof(UserFunction));
    strncpy(current_function_definition->name, tokens[1].text, MAX_VAR_NAME_LEN - 1);

    int token_idx = 2;
    if (token_idx < num_tokens && tokens[token_idx].type == TOKEN_LPAREN) {
        token_idx++; // Skip '('
        while(token_idx < num_tokens && tokens[token_idx].type != TOKEN_RPAREN) {
            if (tokens[token_idx].type == TOKEN_WORD) {
                if (current_function_definition->param_count < MAX_FUNC_PARAMS) {
                    strncpy(current_function_definition->params[current_function_definition->param_count++], tokens[token_idx].text, MAX_VAR_NAME_LEN -1);
                } else { fprintf(stderr, "Too many parameters for function %s.\n", current_function_definition->name); free(current_function_definition); current_function_definition = NULL; return; }
            } else { fprintf(stderr, "Syntax error in function parameters: Expected word for %s.\n", current_function_definition->name); free(current_function_definition); current_function_definition = NULL; return; }
            token_idx++;
        }
        if (token_idx < num_tokens && tokens[token_idx].type == TOKEN_RPAREN) token_idx++; // Skip ')'
        else { fprintf(stderr, "Syntax error in function parameters: missing ')' for %s.\n", current_function_definition->name); free(current_function_definition); current_function_definition = NULL; return; }
    }

    if (token_idx < num_tokens && tokens[token_idx].type == TOKEN_LBRACE) { // '{' on same line
        is_defining_function = true;
        if (current_exec_state != STATE_IMPORT_PARSING) current_exec_state = STATE_DEFINE_FUNC_BODY;
        push_block_bf(BLOCK_TYPE_FUNCTION_DEF, true, 0, 0); // True = collect body
    } else if (token_idx == num_tokens) { // Expect '{' on next line
        is_defining_function = true;
        if (current_exec_state != STATE_IMPORT_PARSING) current_exec_state = STATE_DEFINE_FUNC_BODY;
        // The '{' on next line will call handle_opening_brace_token which should push the block.
    } else {
        fprintf(stderr, "Syntax error in function definition: '{' expected for %s, got '%s'.\n", current_function_definition->name, tokens[token_idx].text);
        free(current_function_definition); current_function_definition = NULL;
    }
}

void handle_inc_dec_statement_advanced(Token *tokens, int num_tokens, bool increment) {
    if (num_tokens != 2 || (tokens[1].type != TOKEN_VARIABLE && tokens[1].type != TOKEN_WORD)) {
        fprintf(stderr, "Syntax: %s <$varname_or_varname | $arr[idx]>\n", increment ? "inc" : "dec"); return;
    }
    if (current_exec_state == STATE_BLOCK_SKIP) return;

    const char* var_name_token_text = tokens[1].text;
    char var_name_or_base[MAX_VAR_NAME_LEN];
    bool is_array_op = false;
    char index_raw[MAX_VAR_NAME_LEN] = "";

    if (tokens[1].type == TOKEN_VARIABLE) { // $var or $arr[idx]
        char temp_text[MAX_VAR_NAME_LEN * 2]; // For $arr[idx] form
        strncpy(temp_text, var_name_token_text + 1, sizeof(temp_text)-1); temp_text[sizeof(temp_text)-1] = '\0';
        char* bracket = strchr(temp_text, '[');
        if (bracket) {
            char* end_bracket = strrchr(bracket, ']');
            if (end_bracket && end_bracket > bracket + 1) {
                is_array_op = true;
                size_t base_len = bracket - temp_text;
                strncpy(var_name_or_base, temp_text, base_len); var_name_or_base[base_len] = '\0';
                size_t index_len = end_bracket - (bracket + 1);
                strncpy(index_raw, bracket + 1, index_len); index_raw[index_len] = '\0';
            } else { fprintf(stderr, "Malformed array index in %s: %s\n", increment ? "inc" : "dec", var_name_token_text); return; }
        } else { strncpy(var_name_or_base, temp_text, MAX_VAR_NAME_LEN -1); var_name_or_base[MAX_VAR_NAME_LEN-1] = '\0'; }
    } else { // var (unquoted word, cannot be array for inc/dec directly this way)
        strncpy(var_name_or_base, var_name_token_text, MAX_VAR_NAME_LEN -1); var_name_or_base[MAX_VAR_NAME_LEN-1] = '\0';
    }

    char* current_val_str;
    if (is_array_op) current_val_str = get_array_element_scoped(var_name_or_base, index_raw);
    else current_val_str = get_variable_scoped(var_name_or_base);

    long current_val = 0;
    if (current_val_str) {
        char *endptr; errno = 0;
        current_val = strtol(current_val_str, &endptr, 10);
        if (errno != 0 || *current_val_str == '\0' || *endptr != '\0') {
            fprintf(stderr, "Warning: Variable/element '%s%s%s%s' ('%s') is not a valid integer for %s. Treating as 0.\n",
                tokens[1].type == TOKEN_VARIABLE ? "$" : "", var_name_or_base, is_array_op ? "[" : "", is_array_op ? index_raw : "",
                current_val_str ? current_val_str : "NULL", increment ? "inc" : "dec");
            current_val = 0;
        }
    }
    current_val += (increment ? 1 : -1);
    char new_val_str[MAX_VAR_NAME_LEN]; // Sufficient for long
    snprintf(new_val_str, sizeof(new_val_str), "%ld", current_val);

    if (is_array_op) set_array_element_scoped(var_name_or_base, index_raw, new_val_str);
    else set_variable_scoped(var_name_or_base, new_val_str, false);
}

void handle_loadlib_statement(Token *tokens, int num_tokens) {
    if (num_tokens != 3) { fprintf(stderr, "Syntax: loadlib <path_or_$var> <alias_or_$var>\n"); return; }
    if (current_exec_state == STATE_BLOCK_SKIP) return;
    char lib_path[MAX_FULL_PATH_LEN], alias[MAX_VAR_NAME_LEN];
    char temp_val_holder[INPUT_BUFFER_SIZE];

    expand_variables_in_string_advanced(tokens[1].text, temp_val_holder, sizeof(temp_val_holder));
    if(tokens[1].type == TOKEN_STRING) unescape_string(temp_val_holder, lib_path, sizeof(lib_path)); else strncpy(lib_path, temp_val_holder, sizeof(lib_path)-1); lib_path[sizeof(lib_path)-1] = '\0';

    expand_variables_in_string_advanced(tokens[2].text, temp_val_holder, sizeof(temp_val_holder));
    if(tokens[2].type == TOKEN_STRING) unescape_string(temp_val_holder, alias, sizeof(alias)); else strncpy(alias, temp_val_holder, sizeof(alias)-1); alias[sizeof(alias)-1] = '\0';

    if (strlen(lib_path) == 0 || strlen(alias) == 0) { fprintf(stderr, "loadlib error: Path or alias is empty.\n"); return; }
    DynamicLib* current_lib = loaded_libs; while(current_lib) { if (strcmp(current_lib->alias, alias) == 0) { fprintf(stderr, "Error: Lib alias '%s' in use.\n", alias); return; } current_lib = current_lib->next; }
    void *handle = dlopen(lib_path, RTLD_LAZY | RTLD_GLOBAL);
    if (!handle) { fprintf(stderr, "Error loading library '%s': %s\n", lib_path, dlerror()); return; }
    DynamicLib *new_lib_entry = (DynamicLib*)malloc(sizeof(DynamicLib));
    if (!new_lib_entry) { perror("malloc for new_lib_entry failed"); dlclose(handle); return; }
    strncpy(new_lib_entry->alias, alias, MAX_VAR_NAME_LEN -1); new_lib_entry->alias[MAX_VAR_NAME_LEN-1] = '\0';
    new_lib_entry->handle = handle; new_lib_entry->next = loaded_libs; loaded_libs = new_lib_entry;
    // printf("Library '%s' loaded as alias '%s'.\n", lib_path, alias);
}

void handle_calllib_statement(Token *tokens, int num_tokens) {
    if (num_tokens < 3) { fprintf(stderr, "Syntax: calllib <alias> <func_name> [args...]\n"); return; }
    if (current_exec_state == STATE_BLOCK_SKIP) return;
    char alias[MAX_VAR_NAME_LEN], func_name[MAX_VAR_NAME_LEN];
    char temp_val_holder[INPUT_BUFFER_SIZE];

    expand_variables_in_string_advanced(tokens[1].text, temp_val_holder, sizeof(temp_val_holder));
    if(tokens[1].type == TOKEN_STRING) unescape_string(temp_val_holder, alias, sizeof(alias)); else strncpy(alias, temp_val_holder, sizeof(alias)-1); alias[sizeof(alias)-1] = '\0';

    expand_variables_in_string_advanced(tokens[2].text, temp_val_holder, sizeof(temp_val_holder));
    if(tokens[2].type == TOKEN_STRING) unescape_string(temp_val_holder, func_name, sizeof(func_name)); else strncpy(func_name, temp_val_holder, sizeof(func_name)-1); func_name[sizeof(func_name)-1] = '\0';

    if (strlen(alias) == 0 || strlen(func_name) == 0) { fprintf(stderr, "calllib error: Alias or func name empty.\n"); return; }
    DynamicLib* lib_entry = loaded_libs; void* lib_handle = NULL;
    while(lib_entry) { if (strcmp(lib_entry->alias, alias) == 0) { lib_handle = lib_entry->handle; break; } lib_entry = lib_entry->next; }
    if (!lib_handle) { fprintf(stderr, "Error: Library alias '%s' not found.\n", alias); return; }
    dlerror(); void* func_ptr = dlsym(lib_handle, func_name); char* dlsym_error = dlerror();
    if (dlsym_error != NULL) { fprintf(stderr, "Error finding func '%s' in lib '%s': %s\n", func_name, alias, dlsym_error); return; }
    if (!func_ptr) { fprintf(stderr, "Error finding func '%s' (ptr NULL, no dlerror).\n", func_name); return; }

    typedef int (*lib_func_sig_t)(int, char**, char*, int); // Expected signature
    lib_func_sig_t target_func = (lib_func_sig_t)func_ptr;
    int lib_argc = num_tokens - 3;
    char* lib_argv_expanded_storage[MAX_ARGS][INPUT_BUFFER_SIZE]; char* lib_argv[MAX_ARGS + 1];
    for(int i=0; i < lib_argc; ++i) {
        if (tokens[i+3].type == TOKEN_STRING) { char unescaped[INPUT_BUFFER_SIZE]; unescape_string(tokens[i+3].text, unescaped, sizeof(unescaped)); expand_variables_in_string_advanced(unescaped, lib_argv_expanded_storage[i], INPUT_BUFFER_SIZE);
        } else { expand_variables_in_string_advanced(tokens[i+3].text, lib_argv_expanded_storage[i], INPUT_BUFFER_SIZE); }
        lib_argv[i] = lib_argv_expanded_storage[i];
    } lib_argv[lib_argc] = NULL;
    char lib_output_buffer[INPUT_BUFFER_SIZE]; lib_output_buffer[0] = '\0';
    int lib_status = target_func(lib_argc, lib_argv, lib_output_buffer, sizeof(lib_output_buffer));
    char status_str[12]; snprintf(status_str, sizeof(status_str), "%d", lib_status);
    set_variable_scoped("LAST_LIB_CALL_STATUS", status_str, false);
    set_variable_scoped("LAST_LIB_CALL_OUTPUT", lib_output_buffer, false);
}


// --- Block Management ---
void push_block_bf(BlockType type, bool condition_true, long loop_start_fpos, int loop_start_line_no) {
    if (block_stack_top_bf >= MAX_NESTING_DEPTH - 1) { fprintf(stderr, "Max block nesting depth exceeded.\n"); return; }
    block_stack_top_bf++;
    block_stack[block_stack_top_bf].type = type;
    block_stack[block_stack_top_bf].condition_true = condition_true;
    block_stack[block_stack_top_bf].loop_start_fpos = loop_start_fpos;
    block_stack[block_stack_top_bf].loop_start_line_no = loop_start_line_no;
    block_stack[block_stack_top_bf].prev_exec_state = current_exec_state;
}

BlockFrame* pop_block_bf() {
    if (block_stack_top_bf < 0) { /*fprintf(stderr, "Warning: Block stack underflow (pop_block_bf).\n");*/ return NULL; }
    return &block_stack[block_stack_top_bf--];
}

BlockFrame* peek_block_bf() {
    if (block_stack_top_bf < 0) return NULL;
    return &block_stack[block_stack_top_bf];
}

void handle_opening_brace_token(Token token) {
    BlockFrame* current_block_frame = peek_block_bf();
    if (!current_block_frame) {
        if (is_defining_function && current_function_definition && current_exec_state != STATE_BLOCK_SKIP) {
            push_block_bf(BLOCK_TYPE_FUNCTION_DEF, true, 0, 0); // True = collect body
            // current_exec_state is already STATE_DEFINE_FUNC_BODY or STATE_IMPORT_PARSING
            return;
        }
        fprintf(stderr, "Error: '{' found without a preceding statement expecting it.\n"); return;
    }
    if (current_block_frame->type == BLOCK_TYPE_FUNCTION_DEF) { /* Already handled by defunc */ }
    else if (current_block_frame->condition_true && current_exec_state != STATE_BLOCK_SKIP) current_exec_state = STATE_BLOCK_EXECUTE;
    else current_exec_state = STATE_BLOCK_SKIP;
}

void handle_closing_brace_token(Token token, FILE* input_source) {
    BlockFrame* closed_block_frame = pop_block_bf();
    if (!closed_block_frame) { fprintf(stderr, "Error: '}' found without a matching open block.\n"); current_exec_state = STATE_NORMAL; return; }

    ExecutionState state_before_closed_block = closed_block_frame->prev_exec_state;
    BlockFrame* parent_block = peek_block_bf(); // Parent block AFTER popping current one

    if (closed_block_frame->type == BLOCK_TYPE_WHILE && closed_block_frame->condition_true && current_exec_state != STATE_BLOCK_SKIP) {
        bool can_loop = false;
        if (input_source && input_source != stdin && closed_block_frame->loop_start_fpos != -1 && closed_block_frame->loop_start_fpos >= 0) {
            if (fseek(input_source, closed_block_frame->loop_start_fpos, SEEK_SET) == 0) can_loop = true;
            else perror("fseek failed for while loop");
        } else if (closed_block_frame->loop_start_line_no > 0 && !input_source) { // e.g. inside a function
             fprintf(stderr, "Warning: 'while' loop repetition inside function (line %d) requires memory-based re-evaluation (not fully implemented).\n", closed_block_frame->loop_start_line_no);
        } // Else cannot loop (interactive, or no valid loop point)

        if (can_loop) { current_exec_state = STATE_NORMAL; return; /* Allow execute_script to re-read */ }
    }

    // General state restoration
    if (!parent_block) current_exec_state = STATE_NORMAL; // Back to top level
    else { // Inside another block
        if (parent_block->type == BLOCK_TYPE_FUNCTION_DEF && is_defining_function) current_exec_state = STATE_DEFINE_FUNC_BODY;
        else if (parent_block->condition_true) current_exec_state = STATE_BLOCK_EXECUTE;
        else current_exec_state = STATE_BLOCK_SKIP;
    }

    if (closed_block_frame->type == BLOCK_TYPE_FUNCTION_DEF) {
        if (current_function_definition) { // This '}' closes the current function definition
            current_function_definition->next = function_list; function_list = current_function_definition;
            if (current_exec_state != STATE_IMPORT_PARSING && state_before_closed_block != STATE_IMPORT_PARSING) {
                 // printf("Function '%s' defined.\n", current_function_definition->name);
            }
            current_function_definition = NULL;
        }
        is_defining_function = false;
        current_exec_state = state_before_closed_block; // Restore state from before defunc started
        // If defunc was top-level, state_before_closed_block would be NORMAL.
        // If defunc was nested (not allowed usually, but for import parsing), restore outer import state.
        if (!parent_block && current_exec_state == STATE_DEFINE_FUNC_BODY) { // Exited top-level func def
            current_exec_state = STATE_NORMAL;
        }
    }
    // If after all popping, stack is empty and we are not in middle of defining a function, go to normal.
    if (block_stack_top_bf == -1 && current_exec_state != STATE_DEFINE_FUNC_BODY) {
        current_exec_state = STATE_NORMAL;
    }
}

// --- Utility Implementations ---
char* trim_whitespace(char *str) {
    if (!str) return NULL; char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str; // All spaces?
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = 0;
    return str;
}

void free_function_list() {
    UserFunction *current = function_list; UserFunction *next_func;
    while (current != NULL) {
        next_func = current->next;
        for (int i = 0; i < current->line_count; ++i) if(current->body[i]) free(current->body[i]);
        free(current); current = next_func;
    }
    function_list = NULL;
}

void free_operator_list() {
    OperatorDefinition *current = operator_list_head; OperatorDefinition *next_op;
    while (current) { next_op = current->next; free(current); current = next_op; }
    operator_list_head = NULL;
}

void free_loaded_libs() {
    DynamicLib *current = loaded_libs; DynamicLib *next_lib;
    while(current) {
        next_lib = current->next;
        if (current->handle) dlclose(current->handle);
        free(current); current = next_lib;
    }
    loaded_libs = NULL;
}

long get_file_pos(FILE* f) {
    if (!f || f == stdin || f == stdout || f == stderr) return -1L;
    long pos = ftell(f);
    if (pos == -1L) { /* perror("ftell failed"); */ return -1L; }
    return pos;
}

char* unescape_string(const char* input_raw, char* output_buffer, size_t buffer_size) {
    char* out = output_buffer; const char* p = input_raw; size_t out_len = 0;
    if (*p == '"') p++; // Skip leading quote if present in token text

    while (*p && out_len < buffer_size - 1) {
        // Stop at closing quote if not escaped and it's not the very first char (already skipped)
        if (*p == '"' && !(p > input_raw && *(p-1) == '\\' && (p-2 < input_raw || *(p-2) != '\\'))) {
             break;
        }
        if (*p == '\\') {
            p++; if (!*p) break; // Dangling escape
            switch (*p) {
                case 'n': *out++ = '\n'; break; case 't': *out++ = '\t'; break;
                case '"': *out++ = '"'; break;  case '\\': *out++ = '\\'; break;
                case '$': *out++ = '$'; break;  default: *out++ = '\\'; *out++ = *p; break;
            }
        } else { *out++ = *p; }
        if (*p) p++; // Move to next char in input
        out_len++;
    }
    *out = '\0';
    return output_buffer;
}

// --- execute_script (ensure it handles startup script context correctly) ---
void execute_script(const char *filename, bool is_import_call, bool is_startup_script) {
    FILE *script_file = fopen(filename, "r");
    if (!script_file) {
        if (!is_startup_script || errno != ENOENT) { // Report error unless it's a non-existent optional startup script
            fprintf(stderr, "Error opening script '%s': %s\n", filename, strerror(errno));
        }
        return;
    }

    if (is_startup_script) printf("Executing startup script: %s\n", filename);
    // else if (is_import_call) printf("Importing from script: %s\n", filename); // Can be verbose

    char line_buffer[INPUT_BUFFER_SIZE]; int line_no = 0;
    ExecutionState script_exec_mode = is_import_call ? STATE_IMPORT_PARSING : STATE_NORMAL;

    // Save outer context only for non-startup, non-import script calls that might be nested
    ExecutionState outer_exec_state_backup = current_exec_state;
    int outer_block_stack_top_bf_backup = block_stack_top_bf;
    bool restore_context = (!is_import_call && !is_startup_script);


    long current_fpos = -1; // For potential fseek in while loops

    while (true) {
        if (input_source_is_file(script_file)) current_fpos = get_file_pos(script_file); // Get fpos *before* reading line

        if (!fgets(line_buffer, sizeof(line_buffer), script_file)) {
            if (feof(script_file)) break; // End of file
            if (ferror(script_file)) { perror("Error reading script file"); break; }
        }
        line_no++;
        // Pass current_fpos to process_line if it's to be used by while for fseek
        // For now, process_line uses current_line_no primarily.
        process_line(line_buffer, script_file, line_no, script_exec_mode);

        // If a 'while' loop in this script file just decided to loop (via fseek in handle_closing_brace),
        // the file pointer is already repositioned. The next fgets will read from there.
    }
    fclose(script_file);

    if (is_import_call) { // Cleanup after import
        if (is_defining_function && current_function_definition) {
            fprintf(stderr, "Warning: Unterminated function definition '%s' at end of imported file '%s'.\n", current_function_definition->name, filename);
            for(int i=0; i < current_function_definition->line_count; ++i) if(current_function_definition->body[i]) free(current_function_definition->body[i]);
            free(current_function_definition); current_function_definition = NULL; is_defining_function = false;
            if (block_stack_top_bf >=0 && peek_block_bf() && peek_block_bf()->type == BLOCK_TYPE_FUNCTION_DEF) pop_block_bf();
        }
    } else if (restore_context) { // Restore context for normal nested script execution
        current_exec_state = outer_exec_state_backup;
        while(block_stack_top_bf > outer_block_stack_top_bf_backup) {
            BlockFrame* bf = pop_block_bf();
            fprintf(stderr, "Warning: Script '%s' ended with unclosed block (type %d).\n", filename, bf ? bf->type : -1);
        }
    }

    // For startup script, its state changes (vars, functions) persist.
    // Ensure execution state and block stack are clean for subsequent interactive session.
    if (is_startup_script) {
        current_exec_state = STATE_NORMAL;
        while(block_stack_top_bf > -1) { pop_block_bf(); } // Clear any blocks opened by startup script
    }
}

// Helper to check if FILE* is a regular file (and not stdin etc.)
// This is a simple check; a more robust one might involve fstat.
bool input_source_is_file(FILE* f) {
    if (!f || f == stdin || f == stdout || f == stderr) return false;
    // A simple heuristic: if fileno() is valid and not one of the standard streams.
    int fd = fileno(f);
    if (fd == -1) return false; // Error or not a stream with a descriptor
    return (fd != STDIN_FILENO && fd != STDOUT_FILENO && fd != STDERR_FILENO);
}

