#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <ctype.h>
#include <dlfcn.h> // For dynamic library loading
#include <errno.h>
#include <limits.h>

// --- Constants and Definitions ---
#define MAX_LINE_LENGTH 2048
#define MAX_ARGS 128
#define MAX_VAR_NAME_LEN 256
#define MAX_VAR_VALUE_LEN 2048 // Increased for potentially larger JSON strings
#define MAX_FULL_PATH_LEN 1024
#define TOKEN_STORAGE_SIZE (MAX_LINE_LENGTH * 2)
#define MAX_NESTING_DEPTH 32
#define MAX_FUNC_LINES 100
#define MAX_FUNC_PARAMS 10
#define MAX_OPERATOR_LEN 8
#define DEFAULT_STARTUP_SCRIPT ".bshrc"
#define MAX_KEYWORD_LEN 32 // Max length for a keyword or its alias
#define MAX_SCOPE_DEPTH 64   // Max depth for lexical scopes (functions)

// --- Tokenizer Types ---
typedef enum {
    TOKEN_EMPTY, TOKEN_WORD, TOKEN_STRING, TOKEN_VARIABLE, TOKEN_OPERATOR,
    TOKEN_LPAREN, TOKEN_RPAREN, TOKEN_LBRACE, TOKEN_RBRACE, TOKEN_LBRACKET, TOKEN_RBRACKET,
    TOKEN_ASSIGN, TOKEN_SEMICOLON, TOKEN_PIPE, TOKEN_AMPERSAND, TOKEN_COMMENT,
    TOKEN_EOF, TOKEN_ERROR
} TokenType;

typedef struct {
    TokenType type;
    const char *text;
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
    char *path;
    struct PathDirNode *next;
} PathDirNode;
PathDirNode *path_list_head = NULL;

// --- Variable Scoping and Management ---
typedef struct Variable {
    char name[MAX_VAR_NAME_LEN];
    char value[MAX_VAR_VALUE_LEN];
    bool is_array_element;
    int scope_id; // Identifier for the scope this variable belongs to
    struct Variable *next; // Next variable in the global list
} Variable;
Variable *variable_list_head = NULL; // Global list of all variables

typedef struct ScopeFrame {
    int scope_id;
    // Potentially store a pointer to the start of this scope's variables in variable_list_head
    // Or, variables are just tagged, and we clean them up by scope_id.
    // For simplicity, we'll tag variables and clean them up.
    // More complex: each ScopeFrame could have its own list of Variable* specific to that scope.
} ScopeFrame;

ScopeFrame scope_stack[MAX_SCOPE_DEPTH];
int scope_stack_top = -1; // -1 means global scope (scope_id 0)
int next_scope_id = 1;    // Counter for unique scope IDs (0 is global)
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
    STATE_DEFINE_FUNC_BODY, STATE_IMPORT_PARSING
} ExecutionState;
ExecutionState current_exec_state = STATE_NORMAL;

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
int block_stack_top_bf = -1; // Renamed to avoid conflict with scope_stack_top

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
void add_path_dir(const char* dir_path);
void free_path_list();

// Variable & Scope Management
int enter_scope();
void leave_scope(int scope_id_to_leave);
void cleanup_variables_for_scope(int scope_id);
char* get_variable_scoped(const char *name_raw);
void set_variable_scoped(const char *name_raw, const char *value, bool is_array_elem);
void expand_variables_in_string_advanced(const char *input_str, char *expanded_str, size_t expanded_str_size); // Will use get_variable_scoped
char* get_array_element_scoped(const char* array_base_name, const char* index_str_raw);
void set_array_element_scoped(const char* array_base_name, const char* index_str_raw, const char* value);

// Command Execution
bool find_command_in_path_dynamic(const char *command, char *full_path);
int execute_external_command(char *command_path, char **args, int arg_count, char *output_buffer, size_t output_buffer_size);
void execute_user_function(UserFunction* func, Token* call_arg_tokens, int call_arg_token_count, FILE* input_source_for_context);

// Built-in Commands
void handle_defkeyword_statement(Token *tokens, int num_tokens); // New built-in
// Other built-in handlers will use scoped variable functions.
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

// Block Management
void push_block_bf(BlockType type, bool condition_true, long loop_start_fpos, int loop_start_line_no); // Renamed
BlockFrame* pop_block_bf(); // Renamed
BlockFrame* peek_block_bf(); // Renamed
void handle_opening_brace_token(Token token);
void handle_closing_brace_token(Token token, FILE* input_source);

// Utility
char* trim_whitespace(char *str);
void free_all_variables(); // Replaces free_variable_list
void free_function_list();
void free_operator_list();
void free_loaded_libs();
long get_file_pos(FILE* f);
char* unescape_string(const char* input, char* output_buffer, size_t buffer_size);


// --- Main ---
int main(int argc, char *argv[]) {
    initialize_shell();

    char startup_script_path[MAX_FULL_PATH_LEN];
    char* home_dir = getenv("HOME");
    bool startup_executed = false;
    if (home_dir) {
        snprintf(startup_script_path, sizeof(startup_script_path), "%s/%s", home_dir, DEFAULT_STARTUP_SCRIPT);
        if (access(startup_script_path, F_OK) == 0) {
            execute_script(startup_script_path, false, true);
            startup_executed = true;
        }
    }
    if (!startup_executed && access(DEFAULT_STARTUP_SCRIPT, F_OK) == 0) { // Fallback to current dir
        execute_script(DEFAULT_STARTUP_SCRIPT, false, true);
    }

    if (argc > 1) {
        execute_script(argv[1], false, false);
    } else {
        char line[MAX_LINE_LENGTH];
        char prompt_buffer[MAX_VAR_NAME_LEN + 30];
        int line_counter_interactive = 0;

        while (1) {
            char* current_prompt_val = get_variable_scoped("PS1"); // Use scoped getter
            if (!current_prompt_val) current_prompt_val = "bsh";

            char state_indicator[25] = "";
            if (block_stack_top_bf >= 0) { // Use renamed block stack top
                BlockFrame* top_block = peek_block_bf(); // Use renamed
                // ... (prompt state indicator logic as before) ...
                 const char* block_type_str = "";
                if (top_block->type == BLOCK_TYPE_IF) block_type_str = "if";
                else if (top_block->type == BLOCK_TYPE_ELSE) block_type_str = "else";
                else if (top_block->type == BLOCK_TYPE_WHILE) block_type_str = "while";
                else if (top_block->type == BLOCK_TYPE_FUNCTION_DEF) block_type_str = "defunc";

                if (current_exec_state == STATE_BLOCK_SKIP) {
                    snprintf(state_indicator, sizeof(state_indicator), "(skip %s %d)", block_type_str, block_stack_top_bf + 1);
                } else if (current_exec_state == STATE_DEFINE_FUNC_BODY) {
                     snprintf(state_indicator, sizeof(state_indicator), "(defunc %s)", current_function_definition ? current_function_definition->name : "?");
                } else {
                    snprintf(state_indicator, sizeof(state_indicator), "(%s %d)", block_type_str, block_stack_top_bf + 1);
                }
            } else if (current_exec_state == STATE_DEFINE_FUNC_BODY && current_function_definition) {
                snprintf(state_indicator, sizeof(state_indicator), "(defunc %s...)", current_function_definition->name);
            }


            snprintf(prompt_buffer, sizeof(prompt_buffer), "%s%s> ", current_prompt_val, state_indicator);
            printf("%s", prompt_buffer);

            if (!fgets(line, sizeof(line), stdin)) {
                printf("\n"); break;
            }
            line_counter_interactive++;
            process_line(line, stdin, line_counter_interactive, STATE_NORMAL);
        }
    }
    cleanup_shell();
    return 0;
}

// --- Core Implementations ---
void initialize_shell() {
    scope_stack_top = -1; // Initialize scope stack for global scope (ID 0)
    enter_scope(); // Enter global scope (scope_id 0 will be pushed)

    char *path_env = getenv("PATH");
    if (path_env) {
        char *path_copy = strdup(path_env);
        if (path_copy) {
            char *token_path = strtok(path_copy, ":");
            while (token_path) { add_path_dir(token_path); token_path = strtok(NULL, ":"); }
            free(path_copy);
        } else { perror("strdup for PATH failed"); }
    }
    initialize_operators_dynamic();
    set_variable_scoped("SHELL_VERSION", "bsh-dynamic-0.4", false);
    set_variable_scoped("PS1", "bsh", false);
}

void cleanup_shell() {
    free_all_variables();
    free_function_list();
    free_operator_list();
    free_keyword_alias_list();
    free_path_list();
    free_loaded_libs();
    // Ensure all scopes are left (though free_all_variables should handle it)
    while(scope_stack_top >= 0) {
        leave_scope(scope_stack[scope_stack_top].scope_id);
    }
}

// --- Tokenizer & Keyword Aliasing ---
void add_keyword_alias(const char* original, const char* alias_name) {
    if (strlen(original) > MAX_KEYWORD_LEN || strlen(alias_name) > MAX_KEYWORD_LEN) {
        fprintf(stderr, "Keyword or alias too long.\n"); return;
    }
    // Check if alias already exists for a different original (or same)
    KeywordAlias* current = keyword_alias_head;
    while(current){
        if(strcmp(current->alias, alias_name) == 0){
            fprintf(stderr, "Warning: Alias '%s' already defined for '%s'. Overwriting with '%s'.\n", alias_name, current->original, original);
            strcpy(current->original, original); // Overwrite
            return;
        }
        current = current->next;
    }

    KeywordAlias *new_alias = (KeywordAlias*)malloc(sizeof(KeywordAlias));
    if (!new_alias) { perror("malloc for keyword alias failed"); return; }
    strcpy(new_alias->original, original);
    strcpy(new_alias->alias, alias_name);
    new_alias->next = keyword_alias_head;
    keyword_alias_head = new_alias;
}

const char* resolve_keyword_alias(const char* alias_name) {
    KeywordAlias *current = keyword_alias_head;
    while (current) {
        if (strcmp(current->alias, alias_name) == 0) {
            return current->original;
        }
        current = current->next;
    }
    return alias_name; // No alias found, return original text
}

void free_keyword_alias_list() {
    KeywordAlias *current = keyword_alias_head;
    KeywordAlias *next_ka;
    while (current) {
        next_ka = current->next;
        free(current);
        current = next_ka;
    }
    keyword_alias_head = NULL;
}

// (initialize_operators_dynamic, add_operator_dynamic, match_operator_dynamic, advanced_tokenize_line
//  add_path_dir, free_path_list remain largely the same as previous version)
void initialize_operators_dynamic() {
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
    if (strlen(op_str) > MAX_OPERATOR_LEN) { fprintf(stderr, "Warning: Operator '%s' too long.\n", op_str); return; }
    OperatorDefinition *new_op = (OperatorDefinition*)malloc(sizeof(OperatorDefinition));
    if (!new_op) { perror("malloc for new operator failed"); return; }
    strcpy(new_op->op_str, op_str); new_op->op_type = type;
    new_op->next = operator_list_head; operator_list_head = new_op;
}
int match_operator_dynamic(const char *input, const char **op_text, TokenType *matched_type) {
    OperatorDefinition *current = operator_list_head; const char* best_match_text = NULL;
    TokenType best_match_type = TOKEN_EMPTY; int longest_match_len = 0;
    while (current) {
        size_t op_len = strlen(current->op_str);
        if (strncmp(input, current->op_str, op_len) == 0) {
            if (op_len > longest_match_len) {
                longest_match_len = op_len; best_match_text = current->op_str;
                best_match_type = current->op_type;
            }
        }
        current = current->next;
    }
    if (longest_match_len > 0) {
        *op_text = best_match_text;
        if(matched_type) *matched_type = best_match_type;
        return longest_match_len;
    }
    return 0;
}
void add_path_dir(const char* dir_path) {
    PathDirNode *new_node = (PathDirNode*)malloc(sizeof(PathDirNode));
    if (!new_node) { perror("malloc for new path directory failed"); return; }
    new_node->path = strdup(dir_path);
    if (!new_node->path) { perror("strdup for path directory failed"); free(new_node); return; }
    new_node->next = NULL;
    if (!path_list_head) { path_list_head = new_node; }
    else { PathDirNode *current = path_list_head; while (current->next) current = current->next; current->next = new_node; }
}
void free_path_list() {
    PathDirNode *current = path_list_head; PathDirNode *next_node;
    while (current) { next_node = current->next; free(current->path); free(current); current = next_node; }
    path_list_head = NULL;
}
void free_operator_list() {
    OperatorDefinition *current = operator_list_head; OperatorDefinition *next_op;
    while (current) { next_op = current->next; free(current); current = next_op; }
    operator_list_head = NULL;
}
int advanced_tokenize_line(const char *line, Token *tokens, int max_tokens, char *token_storage, size_t storage_size) {
    int token_count = 0; const char *p = line; char *storage_ptr = token_storage;
    size_t remaining_storage = storage_size;
    while (*p && token_count < max_tokens) {
        while (isspace((unsigned char)*p)) p++;
        if (!*p || *p == '#') break;
        tokens[token_count].text = storage_ptr;
        const char *matched_op_text = NULL; TokenType matched_op_type = TOKEN_EMPTY;
        int op_len = match_operator_dynamic(p, &matched_op_text, &matched_op_type);
        if (op_len > 0) {
            tokens[token_count].type = matched_op_type; tokens[token_count].len = op_len;
            if (remaining_storage > op_len) {
                strncpy(storage_ptr, p, op_len); storage_ptr[op_len] = '\0';
                storage_ptr += (op_len + 1); remaining_storage -= (op_len + 1);
            } else { tokens[token_count].type = TOKEN_ERROR; break; }
            p += op_len;
        } else if (*p == '"') { /* String token logic as before */
            tokens[token_count].type = TOKEN_STRING; const char *start = p; p++;
            while (*p && (*p != '"' || (*(p-1) == '\\' && *(p-2) != '\\' ))) p++;
            if (*p == '"') p++; tokens[token_count].len = p - start;
            if (remaining_storage > (size_t)tokens[token_count].len) {
                strncpy(storage_ptr, start, tokens[token_count].len); storage_ptr[tokens[token_count].len] = '\0';
                storage_ptr += (tokens[token_count].len + 1); remaining_storage -= (tokens[token_count].len + 1);
            } else { tokens[token_count].type = TOKEN_ERROR; break; }
        } else if (*p == '$') { /* Variable token logic as before */
            tokens[token_count].type = TOKEN_VARIABLE; const char *start = p; p++;
            if (*p == '{') { p++; while (*p && *p != '}' && (isalnum((unsigned char)*p) || *p == '_' || *p == '[' || *p == ']' || *p == '"' )) p++; if (*p == '}') p++;
            } else { while (isalnum((unsigned char)*p) || *p == '_') p++;
                if (*p == '[') { p++; int bracket_depth = 1;
                    while(*p && bracket_depth > 0) { if (*p == '[') bracket_depth++; else if (*p == ']') bracket_depth--; if (bracket_depth == 0 && *(p) == ']') { p++; break; } p++; }
                }
            } tokens[token_count].len = p - start;
            if (remaining_storage > (size_t)tokens[token_count].len) {
                strncpy(storage_ptr, start, tokens[token_count].len); storage_ptr[tokens[token_count].len] = '\0';
                storage_ptr += (tokens[token_count].len + 1); remaining_storage -= (tokens[token_count].len + 1);
            } else { tokens[token_count].type = TOKEN_ERROR; break; }
        } else { /* Word token logic as before */
            tokens[token_count].type = TOKEN_WORD; const char *start = p;
            while (*p && !isspace((unsigned char)*p)) {
                const char* temp_op_text = NULL; TokenType temp_op_type;
                if (match_operator_dynamic(p, &temp_op_text, &temp_op_type) > 0) break;
                if (*p == '"' || *p == '$' || *p == '#') break;
                if (!isalnum((unsigned char)*p) && *p != '_') break;
                p++;
            } tokens[token_count].len = p - start;
            if (tokens[token_count].len == 0) continue;
            if (remaining_storage > (size_t)tokens[token_count].len) {
                strncpy(storage_ptr, start, tokens[token_count].len); storage_ptr[tokens[token_count].len] = '\0';
                storage_ptr += (tokens[token_count].len + 1); remaining_storage -= (tokens[token_count].len + 1);
            } else { tokens[token_count].type = TOKEN_ERROR; break; }
        } token_count++;
    }
    if (token_count < max_tokens) { tokens[token_count].type = TOKEN_EOF; tokens[token_count].text = "EOF"; tokens[token_count].len = 3; }
    return token_count;
}


// --- Variable & Scope Management ---
int enter_scope() {
    if (scope_stack_top + 1 >= MAX_SCOPE_DEPTH) {
        fprintf(stderr, "Error: Maximum scope depth exceeded.\n");
        return -1; // Or exit, or handle error appropriately
    }
    scope_stack_top++;
    scope_stack[scope_stack_top].scope_id = (scope_stack_top == 0) ? GLOBAL_SCOPE_ID : next_scope_id++;
    return scope_stack[scope_stack_top].scope_id;
}

void leave_scope(int scope_id_to_leave) {
    if (scope_stack_top < 0 || scope_stack[scope_stack_top].scope_id != scope_id_to_leave) {
        // This might happen if trying to leave a scope that's not the current top,
        // or if stack is empty. Global scope (0) should not be "left" this way usually.
        if (scope_id_to_leave != GLOBAL_SCOPE_ID) { // Don't error for trying to leave global scope if it's already gone.
             fprintf(stderr, "Error: Scope mismatch on leave_scope. Trying to leave %d, top is %d.\n",
                scope_id_to_leave, scope_stack_top >=0 ? scope_stack[scope_stack_top].scope_id : -1 );
        }
        // If scope_stack_top is already < 0, we can't pop further.
        if (scope_stack_top >=0 ) scope_stack_top--; // Pop anyway if possible, to attempt recovery
        return;
    }
    cleanup_variables_for_scope(scope_id_to_leave);
    scope_stack_top--;
}

void cleanup_variables_for_scope(int scope_id) {
    if (scope_id == GLOBAL_SCOPE_ID) return; // Global scope variables are not cleaned up this way

    Variable *current = variable_list_head;
    Variable *prev = NULL;
    while (current != NULL) {
        if (current->scope_id == scope_id) {
            Variable *to_delete = current;
            if (prev == NULL) { // Deleting head
                variable_list_head = current->next;
                current = variable_list_head; // prev remains NULL
            } else { // Deleting middle or tail
                prev->next = current->next;
                current = current->next; // prev remains same
            }
            // printf("Cleaning var '%s' from scope %d\n", to_delete->name, to_delete->scope_id);
            free(to_delete);
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
        free(current);
        current = next_var;
    }
    variable_list_head = NULL;
}

char* get_variable_scoped(const char *name_raw) {
    char clean_name[MAX_VAR_NAME_LEN];
    strncpy(clean_name, name_raw, MAX_VAR_NAME_LEN -1);
    clean_name[MAX_VAR_NAME_LEN-1] = '\0';
    trim_whitespace(clean_name);

    Variable *found_var = NULL;
    // Search from current scope outwards to global
    for (int i = scope_stack_top; i >= 0; i--) {
        int current_search_scope_id = scope_stack[i].scope_id;
        Variable *current_node = variable_list_head;
        while (current_node != NULL) {
            if (current_node->scope_id == current_search_scope_id && strcmp(current_node->name, clean_name) == 0) {
                return current_node->value; // Found in current or outer scope
            }
            current_node = current_node->next;
        }
    }
    return NULL; // Not found in any active scope
}

void set_variable_scoped(const char *name_raw, const char *value, bool is_array_elem) {
    if (scope_stack_top < 0) {
        fprintf(stderr, "Critical Error: No active scope to set variable '%s'.\n", name_raw);
        return; // Should not happen if global scope is always active
    }
    int current_scope = scope_stack[scope_stack_top].scope_id;

    char clean_name[MAX_VAR_NAME_LEN];
    strncpy(clean_name, name_raw, MAX_VAR_NAME_LEN -1);
    clean_name[MAX_VAR_NAME_LEN-1] = '\0';
    trim_whitespace(clean_name);

    if (strlen(clean_name) == 0) {
        fprintf(stderr, "Error: Cannot set variable with empty name.\n"); return;
    }

    // Try to update if variable already exists in the CURRENT scope
    Variable *current_node = variable_list_head;
    while (current_node != NULL) {
        if (current_node->scope_id == current_scope && strcmp(current_node->name, clean_name) == 0) {
            strncpy(current_node->value, value, MAX_VAR_VALUE_LEN - 1);
            current_node->value[MAX_VAR_VALUE_LEN - 1] = '\0';
            current_node->is_array_element = is_array_elem;
            return;
        }
        current_node = current_node->next;
    }

    // Not found in current scope, create new variable in current scope
    Variable *new_var = (Variable*)malloc(sizeof(Variable));
    if (!new_var) { perror("malloc for new variable failed"); return; }
    strncpy(new_var->name, clean_name, MAX_VAR_NAME_LEN - 1);
    new_var->name[MAX_VAR_NAME_LEN - 1] = '\0';
    strncpy(new_var->value, value, MAX_VAR_VALUE_LEN - 1);
    new_var->value[MAX_VAR_VALUE_LEN - 1] = '\0';
    new_var->is_array_element = is_array_elem;
    new_var->scope_id = current_scope;
    new_var->next = variable_list_head; // Prepend to global list
    variable_list_head = new_var;
}

// expand_variables_in_string_advanced, get_array_element_scoped, set_array_element_scoped
// need to use get_variable_scoped and set_variable_scoped respectively.
void expand_variables_in_string_advanced(const char *input_str, char *expanded_str, size_t expanded_str_size) {
    const char *p_in = input_str; char *p_out = expanded_str;
    size_t remaining_size = expanded_str_size - 1; expanded_str[0] = '\0';
    while (*p_in && remaining_size > 0) {
        if (*p_in == '$') {
            p_in++; char var_name_buffer[MAX_VAR_NAME_LEN * 2]; char *pv = var_name_buffer;
            if (*p_in == '{') { /* ... logic to extract content within ${...} into var_name_buffer ... */
                p_in++; int brace_level = 1;
                while (*p_in && brace_level > 0 && (pv - var_name_buffer < (long)sizeof(var_name_buffer) - 1)) {
                    if (*p_in == '{') brace_level++; else if (*p_in == '}') brace_level--;
                    if (brace_level > 0) *pv++ = *p_in; p_in++;
                } *pv = '\0';
            } else { /* ... logic for $var or $var[index] into var_name_buffer ... */
                while (isalnum((unsigned char)*p_in) || *p_in == '_') { if (pv - var_name_buffer < MAX_VAR_NAME_LEN -1) *pv++ = *p_in++; else break; } *pv = '\0';
                if (*p_in == '[') { *pv++ = *p_in++; int bracket_level = 1;
                    while (*p_in && bracket_level > 0 && (pv - var_name_buffer < (long)sizeof(var_name_buffer) - 1)) {
                        if (*p_in == '[') bracket_level++; else if (*p_in == ']') bracket_level--; *pv++ = *p_in++;
                    } *pv = '\0';
                }
            }
            char base_var_name[MAX_VAR_NAME_LEN]; char index_str_raw[MAX_VAR_NAME_LEN] = ""; bool is_array_access = false;
            char* bracket_ptr = strchr(var_name_buffer, '[');
            if (bracket_ptr) { /* ... parse base_var_name and index_str_raw ... */
                char* end_bracket_ptr = strrchr(bracket_ptr, ']');
                if (end_bracket_ptr && end_bracket_ptr > bracket_ptr) { is_array_access = true;
                    size_t base_len = bracket_ptr - var_name_buffer; strncpy(base_var_name, var_name_buffer, base_len); base_var_name[base_len] = '\0';
                    size_t index_len = end_bracket_ptr - (bracket_ptr + 1); strncpy(index_str_raw, bracket_ptr + 1, index_len); index_str_raw[index_len] = '\0';
                } else { strncpy(base_var_name, var_name_buffer, MAX_VAR_NAME_LEN -1); base_var_name[MAX_VAR_NAME_LEN -1] = '\0'; }
            } else { strncpy(base_var_name, var_name_buffer, MAX_VAR_NAME_LEN -1); base_var_name[MAX_VAR_NAME_LEN -1] = '\0'; }
            char *value_to_insert = NULL;
            if (is_array_access) {
                value_to_insert = get_array_element_scoped(base_var_name, index_str_raw); // USE SCOPED
            } else {
                value_to_insert = get_variable_scoped(base_var_name); // USE SCOPED
            }
            if (value_to_insert) { /* ... copy value_to_insert to p_out ... */
                size_t val_len = strlen(value_to_insert);
                if (val_len < remaining_size) { strcpy(p_out, value_to_insert); p_out += val_len; remaining_size -= val_len;
                } else { strncpy(p_out, value_to_insert, remaining_size); p_out += remaining_size; remaining_size = 0; }
            }
        } else if (*p_in == '\\' && *(p_in+1) == '$') { /* ... handle escaped $ ... */
            p_in++; if (remaining_size > 0) { *p_out++ = *p_in++; remaining_size--; }
        } else { *p_out++ = *p_in++; remaining_size--; }
    } *p_out = '\0';
}
char* get_array_element_scoped(const char* array_base_name, const char* index_str_raw) {
    char expanded_index_val[MAX_VAR_VALUE_LEN];
    if (index_str_raw[0] == '"' && index_str_raw[strlen(index_str_raw)-1] == '"') {
        unescape_string(index_str_raw, expanded_index_val, sizeof(expanded_index_val));
    } else if (index_str_raw[0] == '$') {
        expand_variables_in_string_advanced(index_str_raw, expanded_index_val, sizeof(expanded_index_val));
    } else { strncpy(expanded_index_val, index_str_raw, sizeof(expanded_index_val)-1); expanded_index_val[sizeof(expanded_index_val)-1] = '\0'; }
    char mangled_name[MAX_VAR_NAME_LEN * 2];
    snprintf(mangled_name, sizeof(mangled_name), "%s_ARRAYIDX_%s", array_base_name, expanded_index_val);
    return get_variable_scoped(mangled_name); // USE SCOPED
}
void set_array_element_scoped(const char* array_base_name, const char* index_str_raw, const char* value) {
    char expanded_index_val[MAX_VAR_VALUE_LEN];
    if (index_str_raw[0] == '"' && index_str_raw[strlen(index_str_raw)-1] == '"') {
        unescape_string(index_str_raw, expanded_index_val, sizeof(expanded_index_val));
    } else if (index_str_raw[0] == '$') {
        expand_variables_in_string_advanced(index_str_raw, expanded_index_val, sizeof(expanded_index_val));
    } else { strncpy(expanded_index_val, index_str_raw, sizeof(expanded_index_val)-1); expanded_index_val[sizeof(expanded_index_val)-1] = '\0'; }
    char mangled_name[MAX_VAR_NAME_LEN * 2];
    snprintf(mangled_name, sizeof(mangled_name), "%s_ARRAYIDX_%s", array_base_name, expanded_index_val);
    set_variable_scoped(mangled_name, value, true); // USE SCOPED
}

// --- Command Execution ---
// (find_command_in_path_dynamic, execute_external_command are largely same)
// execute_user_function needs to manage scopes
bool find_command_in_path_dynamic(const char *command, char *full_path) { /* As before */
    if (strchr(command, '/') != NULL) { if (access(command, X_OK) == 0) { strncpy(full_path, command, MAX_FULL_PATH_LEN -1); full_path[MAX_FULL_PATH_LEN-1] = '\0'; return true; } return false; }
    PathDirNode *current_path_node = path_list_head;
    while (current_path_node) { snprintf(full_path, MAX_FULL_PATH_LEN, "%s/%s", current_path_node->path, command); if (access(full_path, X_OK) == 0) return true; current_path_node = current_path_node->next; }
    return false;
}
int execute_external_command(char *command_path, char **args, int arg_count, char *output_buffer, size_t output_buffer_size) { /* As before */
    pid_t pid; int status; int pipefd[2] = {-1, -1};
    if (output_buffer) { if (pipe(pipefd) == -1) { perror("pipe failed"); return -1; } }
    pid = fork();
    if (pid == 0) { if (output_buffer) { close(pipefd[0]); dup2(pipefd[1], STDOUT_FILENO); dup2(pipefd[1], STDERR_FILENO); close(pipefd[1]); } execv(command_path, args); perror("execv failed"); exit(EXIT_FAILURE);
    } else if (pid < 0) { perror("fork failed"); if (output_buffer) { close(pipefd[0]); close(pipefd[1]); } return -1;
    } else { if (output_buffer) { close(pipefd[1]); ssize_t bytes_read; size_t total_bytes_read = 0; char read_buf[256]; output_buffer[0] = '\0';
            while((bytes_read = read(pipefd[0], read_buf, sizeof(read_buf)-1)) > 0) {
                if (total_bytes_read + bytes_read < output_buffer_size) { read_buf[bytes_read] = '\0'; strcat(output_buffer, read_buf); total_bytes_read += bytes_read;
                } else { strncat(output_buffer, read_buf, output_buffer_size - total_bytes_read -1); break; }
            } close(pipefd[0]); char* nl = strrchr(output_buffer, '\n'); while(nl && (nl == output_buffer + strlen(output_buffer) -1)) { *nl = '\0'; nl = strrchr(output_buffer, '\n'); }
        } do { waitpid(pid, &status, WUNTRACED); } while (!WIFEXITED(status) && !WIFSIGNALED(status)); return WEXITSTATUS(status);
    } return 0;
}

void execute_user_function(UserFunction* func, Token* call_arg_tokens, int call_arg_token_count, FILE* input_source_for_context) {
    if (!func) return;
    int function_scope_id = enter_scope();
    if (function_scope_id == -1) { /* Max scope depth reached */ return; }

    // Set parameters in the new function scope
    for (int i = 0; i < func->param_count; ++i) {
        if (i < call_arg_token_count) {
            char expanded_arg_val[MAX_VAR_VALUE_LEN];
            // (Expansion logic for call_arg_tokens[i] as before)
            if (call_arg_tokens[i].type == TOKEN_STRING) { char unescaped_temp[MAX_VAR_VALUE_LEN]; unescape_string(call_arg_tokens[i].text, unescaped_temp, sizeof(unescaped_temp)); expand_variables_in_string_advanced(unescaped_temp, expanded_arg_val, sizeof(expanded_arg_val));
            } else { expand_variables_in_string_advanced(call_arg_tokens[i].text, expanded_arg_val, sizeof(expanded_arg_val)); }
            set_variable_scoped(func->params[i], expanded_arg_val, false); // Set in current (function's) scope
        } else {
            set_variable_scoped(func->params[i], "", false); // Unprovided params are empty
        }
    }

    // Save execution context for blocks *within* the function
    int func_outer_block_stack_top_bf = block_stack_top_bf; // Use renamed block stack top
    ExecutionState func_outer_exec_state = current_exec_state;
    current_exec_state = STATE_NORMAL;

    for (int i = 0; i < func->line_count; ++i) {
        char line_copy[MAX_LINE_LENGTH];
        strncpy(line_copy, func->body[i], MAX_LINE_LENGTH-1); line_copy[MAX_LINE_LENGTH-1] = '\0';
        process_line(line_copy, NULL, 0, STATE_NORMAL); // NULL input_source for in-memory lines
    }

    // Restore block execution context
    while(block_stack_top_bf > func_outer_block_stack_top_bf) { // Use renamed
        pop_block_bf(); // Use renamed
    }
    current_exec_state = func_outer_exec_state;

    leave_scope(function_scope_id); // Clean up function's local variables
}

// --- Built-in Commands ---
void handle_defkeyword_statement(Token *tokens, int num_tokens) {
    if (num_tokens != 3 || tokens[1].type != TOKEN_WORD || tokens[2].type != TOKEN_WORD) {
        fprintf(stderr, "Syntax: defkeyword <original_keyword> <new_alias>\n");
        return;
    }
    if (current_exec_state == STATE_BLOCK_SKIP) return;
    add_keyword_alias(tokens[1].text, tokens[2].text);
    printf("Keyword alias defined: '%s' -> '%s'\n", tokens[2].text, tokens[1].text);
}

// Other handle_..._advanced functions will now use _scoped variable functions.
// For example, handle_assignment_advanced:
void handle_assignment_advanced(Token *tokens, int num_tokens) {
    if (num_tokens < 3 || tokens[0].type != TOKEN_VARIABLE || tokens[1].type != TOKEN_ASSIGN) { /* ... error ... */ return; }
    if (current_exec_state == STATE_BLOCK_SKIP) return;
    // (Parsing logic for var_token_text_copy, base_var_name, index_str_raw, is_array_assignment as before)
    // (Logic for value_to_set from RHS (command or literal) as before)
    char var_token_text_copy[MAX_VAR_NAME_LEN * 2]; strncpy(var_token_text_copy, tokens[0].text + 1, sizeof(var_token_text_copy) -1); var_token_text_copy[sizeof(var_token_text_copy)-1] = '\0';
    char base_var_name[MAX_VAR_NAME_LEN]; char index_str_raw[MAX_VAR_NAME_LEN] = ""; bool is_array_assignment = false;
    char* bracket_ptr = strchr(var_token_text_copy, '[');
    if (bracket_ptr) { /* ... parse base_var_name and index_str_raw ... */
        char* end_bracket_ptr = strrchr(bracket_ptr, ']');
        if (end_bracket_ptr && end_bracket_ptr > bracket_ptr) { is_array_assignment = true;
            size_t base_len = bracket_ptr - var_token_text_copy; strncpy(base_var_name, var_token_text_copy, base_len); base_var_name[base_len] = '\0';
            size_t index_len = end_bracket_ptr - (bracket_ptr + 1); strncpy(index_str_raw, bracket_ptr + 1, index_len); index_str_raw[index_len] = '\0';
        } else { fprintf(stderr, "Malformed array assignment: %s\n", tokens[0].text); return; }
    } else { strncpy(base_var_name, var_token_text_copy, MAX_VAR_NAME_LEN - 1); base_var_name[MAX_VAR_NAME_LEN - 1] = '\0'; }
    char value_to_set[MAX_VAR_VALUE_LEN]; value_to_set[0] = '\0'; bool is_rhs_command = false;
    if (num_tokens > 2 && tokens[2].type == TOKEN_WORD) { /* ... check if RHS is command ... */
        char expanded_first_rhs_token[MAX_VAR_VALUE_LEN]; expand_variables_in_string_advanced(tokens[2].text, expanded_first_rhs_token, sizeof(expanded_first_rhs_token));
        UserFunction* func = function_list; while(func) { if (strcmp(expanded_first_rhs_token, func->name) == 0) { is_rhs_command = true; break; } func = func->next; }
        if (!is_rhs_command) { char full_cmd_path_check[MAX_FULL_PATH_LEN]; if (find_command_in_path_dynamic(expanded_first_rhs_token, full_cmd_path_check)) is_rhs_command = true; }
    }
    if (is_rhs_command) { /* ... execute command and capture output to value_to_set ... */
        char *cmd_args[MAX_ARGS + 1]; char expanded_cmd_args_storage[MAX_ARGS][MAX_VAR_VALUE_LEN]; int cmd_arg_count = 0;
        for (int i = 2; i < num_tokens; i++) { if (tokens[i].type == TOKEN_WORD || tokens[i].type == TOKEN_STRING || tokens[i].type == TOKEN_VARIABLE) {
            if (tokens[i].type == TOKEN_STRING) { char unescaped_val[MAX_VAR_VALUE_LEN]; unescape_string(tokens[i].text, unescaped_val, sizeof(unescaped_val)); expand_variables_in_string_advanced(unescaped_val, expanded_cmd_args_storage[cmd_arg_count], MAX_VAR_VALUE_LEN);
            } else { expand_variables_in_string_advanced(tokens[i].text, expanded_cmd_args_storage[cmd_arg_count], MAX_VAR_VALUE_LEN); }
            cmd_args[cmd_arg_count] = expanded_cmd_args_storage[cmd_arg_count]; cmd_arg_count++; } } cmd_args[cmd_arg_count] = NULL;
        if (cmd_arg_count > 0) { char full_cmd_path_check[MAX_FULL_PATH_LEN]; bool is_user_func_rhs = false; UserFunction* user_func_check = function_list; while(user_func_check){ if(strcmp(cmd_args[0], user_func_check->name) == 0) {is_user_func_rhs = true; break;} user_func_check = user_func_check->next; }
            if(is_user_func_rhs){ fprintf(stderr, "Assigning output of user-defined functions not directly supported for capture.\n"); }
            else if (find_command_in_path_dynamic(cmd_args[0], full_cmd_path_check)) { execute_external_command(full_cmd_path_check, cmd_args, cmd_arg_count, value_to_set, sizeof(value_to_set)); }
            else { fprintf(stderr, "Command for assignment not found: %s\n", cmd_args[0]); } }
    } else { /* ... concatenate literal values to value_to_set ... */
        char combined_value[MAX_VAR_VALUE_LEN] = ""; size_t current_len = 0;
        for (int i = 2; i < num_tokens; i++) { char expanded_token_val[MAX_VAR_VALUE_LEN];
            if (tokens[i].type == TOKEN_STRING) { char unescaped_temp[MAX_VAR_VALUE_LEN]; unescape_string(tokens[i].text, unescaped_temp, sizeof(unescaped_temp)); expand_variables_in_string_advanced(unescaped_temp, expanded_token_val, sizeof(expanded_token_val));
            } else { expand_variables_in_string_advanced(tokens[i].text, expanded_token_val, sizeof(expanded_token_val)); }
            size_t token_len = strlen(expanded_token_val); if (current_len + token_len + (current_len > 0 ? 1 : 0) < MAX_VAR_VALUE_LEN) {
                if (current_len > 0) { strcat(combined_value, " "); current_len++; } strcat(combined_value, expanded_token_val); current_len += token_len;
            } else { fprintf(stderr, "Value too long for assignment.\n"); break; } }
        strncpy(value_to_set, combined_value, MAX_VAR_VALUE_LEN -1); value_to_set[MAX_VAR_VALUE_LEN-1] = '\0';
    }

    if (is_array_assignment) {
        set_array_element_scoped(base_var_name, index_str_raw, value_to_set); // USE SCOPED
    } else {
        set_variable_scoped(base_var_name, value_to_set, false); // USE SCOPED
    }
}
// (handle_echo_advanced, evaluate_condition_advanced, etc. as before, ensuring they use _scoped variable access)
void handle_echo_advanced(Token *tokens, int num_tokens) { /* As before, uses expand_variables_in_string_advanced */
    if (current_exec_state == STATE_BLOCK_SKIP) return; char expanded_arg[MAX_VAR_VALUE_LEN];
    for (int i = 1; i < num_tokens; i++) { if (tokens[i].type == TOKEN_STRING) { char unescaped_val[MAX_VAR_VALUE_LEN]; unescape_string(tokens[i].text, unescaped_val, sizeof(unescaped_val)); expand_variables_in_string_advanced(unescaped_val, expanded_arg, sizeof(expanded_arg));
        } else { expand_variables_in_string_advanced(tokens[i].text, expanded_arg, sizeof(expanded_arg)); }
        printf("%s%s", expanded_arg, (i == num_tokens - 1) ? "" : " "); } printf("\n");
}
bool evaluate_condition_advanced(Token* operand1_token, Token* operator_token, Token* operand2_token) { /* As before, uses expand_variables_in_string_advanced */
    if (!operand1_token || !operator_token || !operand2_token) return false; if (current_exec_state == STATE_BLOCK_SKIP) return false;
    char val1_expanded[MAX_VAR_VALUE_LEN]; char val2_expanded[MAX_VAR_VALUE_LEN];
    if (operand1_token->type == TOKEN_STRING) { char unescaped[MAX_VAR_VALUE_LEN]; unescape_string(operand1_token->text, unescaped, sizeof(unescaped)); expand_variables_in_string_advanced(unescaped, val1_expanded, sizeof(val1_expanded));
    } else { expand_variables_in_string_advanced(operand1_token->text, val1_expanded, sizeof(val1_expanded)); }
    if (operand2_token->type == TOKEN_STRING) { char unescaped[MAX_VAR_VALUE_LEN]; unescape_string(operand2_token->text, unescaped, sizeof(unescaped)); expand_variables_in_string_advanced(unescaped, val2_expanded, sizeof(val2_expanded));
    } else { expand_variables_in_string_advanced(operand2_token->text, val2_expanded, sizeof(val2_expanded)); }
    const char* op_str = operator_token->text;
    if (strcmp(op_str, "==") == 0) return strcmp(val1_expanded, val2_expanded) == 0; if (strcmp(op_str, "!=") == 0) return strcmp(val1_expanded, val2_expanded) != 0;
    long num1, num2; char *endptr1, *endptr2; errno = 0; num1 = strtol(val1_expanded, &endptr1, 10); bool num1_valid = (errno == 0 && val1_expanded[0] != '\0' && *endptr1 == '\0'); errno = 0; num2 = strtol(val2_expanded, &endptr2, 10); bool num2_valid = (errno == 0 && val2_expanded[0] != '\0' && *endptr2 == '\0');
    bool numeric_possible = num1_valid && num2_valid;
    if (numeric_possible) { if (strcmp(op_str, ">") == 0) return num1 > num2; if (strcmp(op_str, "<") == 0) return num1 < num2; if (strcmp(op_str, ">=") == 0) return num1 >= num2; if (strcmp(op_str, "<=") == 0) return num1 <= num2;
    } else { if (strcmp(op_str, ">") == 0) return strcmp(val1_expanded, val2_expanded) > 0; if (strcmp(op_str, "<") == 0) return strcmp(val1_expanded, val2_expanded) < 0; if (strcmp(op_str, ">=") == 0) return strcmp(val1_expanded, val2_expanded) >= 0; if (strcmp(op_str, "<=") == 0) return strcmp(val1_expanded, val2_expanded) <= 0; }
    fprintf(stderr, "Unsupported operator or type mismatch in condition: '%s' %s '%s'\n", val1_expanded, op_str, val2_expanded); return false;
}
void handle_if_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no) { /* As before, uses renamed block stack functions */
    if (num_tokens < 4) { /* error */ if (block_stack_top_bf < MAX_NESTING_DEPTH -1 && current_exec_state != STATE_BLOCK_SKIP) { push_block_bf(BLOCK_TYPE_IF, false, 0, current_line_no); current_exec_state = STATE_BLOCK_SKIP; } return; }
    bool condition_result = false; if (current_exec_state != STATE_BLOCK_SKIP) condition_result = evaluate_condition_advanced(&tokens[1], &tokens[2], &tokens[3]);
    push_block_bf(BLOCK_TYPE_IF, condition_result, 0, current_line_no);
    if (condition_result && current_exec_state != STATE_BLOCK_SKIP) current_exec_state = STATE_BLOCK_EXECUTE; else current_exec_state = STATE_BLOCK_SKIP;
    /* Check for brace on same line or expect on next */
}
void handle_else_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no) { /* As before, uses renamed block stack functions */
    BlockFrame* prev_block_frame = peek_block_bf();
    if (!prev_block_frame || (prev_block_frame->type != BLOCK_TYPE_IF && prev_block_frame->type != BLOCK_TYPE_ELSE)) { /* error */ if (current_exec_state != STATE_BLOCK_SKIP) { current_exec_state = STATE_BLOCK_SKIP; push_block_bf(BLOCK_TYPE_ELSE, false, 0, current_line_no); } return; }
    BlockFrame closed_if_or_else_if = *pop_block_bf(); bool execute_this_else_branch = false;
    if (closed_if_or_else_if.condition_true) execute_this_else_branch = false;
    else { if (num_tokens > 1 && tokens[1].type == TOKEN_WORD && strcmp(tokens[1].text, "if") == 0) { if (num_tokens < 5) { /* error */ execute_this_else_branch = false; } else { if (current_exec_state != STATE_BLOCK_SKIP) execute_this_else_branch = evaluate_condition_advanced(&tokens[2], &tokens[3], &tokens[4]); else execute_this_else_branch = false; }
        } else execute_this_else_branch = true;
    } push_block_bf(BLOCK_TYPE_ELSE, execute_this_else_branch, 0, current_line_no);
    if (execute_this_else_branch && current_exec_state != STATE_BLOCK_SKIP) current_exec_state = STATE_BLOCK_EXECUTE; else current_exec_state = STATE_BLOCK_SKIP; /* Check for brace */
}
void handle_while_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no) { /* As before, uses renamed block stack functions */
    if (num_tokens < 4) { /* error */ if (block_stack_top_bf < MAX_NESTING_DEPTH -1 && current_exec_state != STATE_BLOCK_SKIP) { push_block_bf(BLOCK_TYPE_WHILE, false, 0, current_line_no); current_exec_state = STATE_BLOCK_SKIP; } return; }
    bool condition_result = false; long loop_fpos_at_while_line = -1; /* TODO: get fpos if available */
    if (current_exec_state != STATE_BLOCK_SKIP) condition_result = evaluate_condition_advanced(&tokens[1], &tokens[2], &tokens[3]);
    push_block_bf(BLOCK_TYPE_WHILE, condition_result, loop_fpos_at_while_line, current_line_no);
    if (condition_result && current_exec_state != STATE_BLOCK_SKIP) current_exec_state = STATE_BLOCK_EXECUTE; else current_exec_state = STATE_BLOCK_SKIP; /* Check for brace */
}
void handle_defunc_statement_advanced(Token *tokens, int num_tokens) { /* As before, uses renamed block stack functions */
    if (num_tokens < 2 || tokens[1].type != TOKEN_WORD) { /* error */ return; }
    if (is_defining_function && current_exec_state != STATE_IMPORT_PARSING) { /* error */ return; }
    if (current_exec_state == STATE_BLOCK_SKIP && current_exec_state != STATE_IMPORT_PARSING) { push_block_bf(BLOCK_TYPE_FUNCTION_DEF, false, 0, 0); return; }
    current_function_definition = (UserFunction*)malloc(sizeof(UserFunction)); if (!current_function_definition) { perror("malloc"); return; } memset(current_function_definition, 0, sizeof(UserFunction)); strncpy(current_function_definition->name, tokens[1].text, MAX_VAR_NAME_LEN - 1);
    int token_idx = 2; if (token_idx < num_tokens && tokens[token_idx].type == TOKEN_LPAREN) { /* parse params */ token_idx++; while(token_idx < num_tokens && tokens[token_idx].type != TOKEN_RPAREN){ /* ... */ token_idx++;} if(token_idx < num_tokens && tokens[token_idx].type == TOKEN_RPAREN) token_idx++; else { /* error */ free(current_function_definition); current_function_definition=NULL; return;} }
    if (token_idx < num_tokens && tokens[token_idx].type == TOKEN_LBRACE) { is_defining_function = true; if (current_exec_state != STATE_IMPORT_PARSING) current_exec_state = STATE_DEFINE_FUNC_BODY; push_block_bf(BLOCK_TYPE_FUNCTION_DEF, true, 0, 0);
    } else if (token_idx == num_tokens) { is_defining_function = true; if (current_exec_state != STATE_IMPORT_PARSING) current_exec_state = STATE_DEFINE_FUNC_BODY;
    } else { /* error */ free(current_function_definition); current_function_definition = NULL; }
}
void handle_inc_dec_statement_advanced(Token *tokens, int num_tokens, bool increment) { /* As before, uses _scoped variable functions */
    if (num_tokens != 2 || (tokens[1].type != TOKEN_VARIABLE && tokens[1].type != TOKEN_WORD)) { /* error */ return; } if (current_exec_state == STATE_BLOCK_SKIP) return;
    const char* var_name_token_text = tokens[1].text; char var_name[MAX_VAR_NAME_LEN];
    if (tokens[1].type == TOKEN_VARIABLE) { /* ... handle $var and $arr[idx] ... */
        char temp_text[MAX_VAR_NAME_LEN]; strncpy(temp_text, var_name_token_text + 1, sizeof(temp_text)-1); temp_text[sizeof(temp_text)-1] = '\0';
        char* bracket = strchr(temp_text, '['); if (bracket) { /* ... array element logic using _scoped functions ... */ return; } else { strncpy(var_name, temp_text, MAX_VAR_NAME_LEN -1); }
    } else { strncpy(var_name, var_name_token_text, MAX_VAR_NAME_LEN -1); } var_name[MAX_VAR_NAME_LEN-1] = '\0';
    char* current_val_str = get_variable_scoped(var_name); long current_val = 0;
    if (current_val_str) { /* ... strtol ... */ char *endptr; errno = 0; current_val = strtol(current_val_str, &endptr, 10); if (errno != 0 || *current_val_str == '\0' || *endptr != '\0') current_val = 0; }
    current_val += (increment ? 1 : -1); char new_val_str[MAX_VAR_VALUE_LEN]; snprintf(new_val_str, sizeof(new_val_str), "%ld", current_val);
    set_variable_scoped(var_name, new_val_str, false);
}
void handle_loadlib_statement(Token *tokens, int num_tokens) { /* As before */ }
void handle_calllib_statement(Token *tokens, int num_tokens) { /* As before */ }
void handle_import_statement(Token *tokens, int num_tokens) { /* As before */ }


// --- Block Management (renamed functions) ---
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
    if (block_stack_top_bf < 0) { return NULL; }
    return &block_stack[block_stack_top_bf--];
}
BlockFrame* peek_block_bf() {
    if (block_stack_top_bf < 0) { return NULL; }
    return &block_stack[block_stack_top_bf];
}
// (handle_opening_brace_token, handle_closing_brace_token use renamed block stack functions)
void handle_opening_brace_token(Token token) { /* As before, uses renamed block stack functions */
    BlockFrame* current_block_frame = peek_block_bf();
    if (!current_block_frame) { if (is_defining_function && current_function_definition && current_exec_state != STATE_BLOCK_SKIP) { push_block_bf(BLOCK_TYPE_FUNCTION_DEF, true, 0, 0); return; } fprintf(stderr, "Error: '{' without preceding statement.\n"); return; }
    if (current_block_frame->type == BLOCK_TYPE_FUNCTION_DEF) { /* ok */ }
    else if (current_block_frame->condition_true && current_exec_state != STATE_BLOCK_SKIP) current_exec_state = STATE_BLOCK_EXECUTE; else current_exec_state = STATE_BLOCK_SKIP;
}
void handle_closing_brace_token(Token token, FILE* input_source) { /* As before, uses renamed block stack functions and scoped variable cleanup for functions */
    BlockFrame* closed_block_frame = pop_block_bf(); if (!closed_block_frame) { fprintf(stderr, "Error: '}' without matching open block.\n"); current_exec_state = STATE_NORMAL; return; }
    BlockFrame* parent_block = peek_block_bf(); ExecutionState state_before_closed_block = closed_block_frame->prev_exec_state;
    if (closed_block_frame->type == BLOCK_TYPE_WHILE && closed_block_frame->condition_true && current_exec_state != STATE_BLOCK_SKIP) { /* ... while loop repetition logic ... */
        bool can_loop = false; if (input_source && input_source != stdin && closed_block_frame->loop_start_fpos != -1 && closed_block_frame->loop_start_fpos > 0) { if (fseek(input_source, closed_block_frame->loop_start_fpos, SEEK_SET) == 0) can_loop = true; else perror("fseek failed for while"); }
        if (can_loop) { current_exec_state = STATE_NORMAL; return; }
    }
    if (!parent_block) current_exec_state = STATE_NORMAL;
    else { if (parent_block->type == BLOCK_TYPE_FUNCTION_DEF && is_defining_function) current_exec_state = STATE_DEFINE_FUNC_BODY; else if (parent_block->condition_true) current_exec_state = STATE_BLOCK_EXECUTE; else current_exec_state = STATE_BLOCK_SKIP; }
    if (closed_block_frame->type == BLOCK_TYPE_FUNCTION_DEF) {
        if (current_function_definition) { current_function_definition->next = function_list; function_list = current_function_definition;
            if (current_exec_state != STATE_IMPORT_PARSING && state_before_closed_block != STATE_IMPORT_PARSING) printf("Function '%s' defined.\n", current_function_definition->name);
            current_function_definition = NULL; }
        is_defining_function = false; current_exec_state = state_before_closed_block;
        if (!parent_block && current_exec_state == STATE_DEFINE_FUNC_BODY) current_exec_state = STATE_NORMAL;
    }
    if (block_stack_top_bf == -1 && current_exec_state != STATE_DEFINE_FUNC_BODY) current_exec_state = STATE_NORMAL;
}


// --- Utility Implementations ---
// (trim_whitespace, free_function_list, free_loaded_libs, get_file_pos, unescape_string are same)
char* trim_whitespace(char *str) { /* As before */ if (!str) return NULL; char *end; while (isspace((unsigned char)*str)) str++; if (*str == 0) return str; end = str + strlen(str) - 1; while (end > str && isspace((unsigned char)*end)) end--; *(end + 1) = 0; return str; }
void free_function_list() { /* As before */ UserFunction *current = function_list; UserFunction *next_func; while (current != NULL) { next_func = current->next; for (int i = 0; i < current->line_count; ++i) if(current->body[i]) free(current->body[i]); free(current); current = next_func; } function_list = NULL; }
void free_loaded_libs() { /* As before */ DynamicLib *current = loaded_libs; DynamicLib *next_lib; while(current) { next_lib = current->next; if (current->handle) dlclose(current->handle); free(current); current = next_lib; } loaded_libs = NULL; }
long get_file_pos(FILE* f) { /* As before */ if (!f || f == stdin || f == stdout || f == stderr) return -1; long pos = ftell(f); if (pos == -1L) return -1; return pos; }
char* unescape_string(const char* input_raw, char* output_buffer, size_t buffer_size) { /* As before */
    char* out = output_buffer; const char* p = input_raw; size_t out_len = 0;
    if (*p == '"') p++;
    while (*p && out_len < buffer_size - 1) {
        if (*p == '"' && !(p > input_raw && *(p-1) == '\\')) break;
        if (*p == '\\') { p++; if (!*p) break;
            switch (*p) { case 'n': *out++ = '\n'; break; case 't': *out++ = '\t'; break; case '"': *out++ = '"'; break; case '\\': *out++ = '\\'; break; case '$': *out++ = '$'; break; default: *out++ = '\\'; *out++ = *p; break; }
        } else *out++ = *p;
        if (*p) p++; out_len++;
    } *out = '\0'; return output_buffer;
}

// process_line needs to be updated for keyword aliasing
void process_line(char *line_orig, FILE *input_source, int current_line_no, ExecutionState exec_mode) {
    char line[MAX_LINE_LENGTH]; strncpy(line, line_orig, MAX_LINE_LENGTH - 1); line[MAX_LINE_LENGTH - 1] = '\0';
    char *first_char_ptr = line; while(*first_char_ptr && isspace((unsigned char)*first_char_ptr)) first_char_ptr++;
    if (*first_char_ptr == '#' || *first_char_ptr == '\0') return;

    if (is_defining_function && (current_exec_state == STATE_DEFINE_FUNC_BODY || exec_mode == STATE_IMPORT_PARSING) ) { /* ... function body collection logic ... */
        char temp_trimmed_line[MAX_LINE_LENGTH]; strncpy(temp_trimmed_line, line_orig, MAX_LINE_LENGTH -1); temp_trimmed_line[MAX_LINE_LENGTH-1] = '\0'; char* trimmed_body_line = trim_whitespace(temp_trimmed_line);
        bool is_just_closing_brace = false; char* p_brace = trimmed_body_line; if (*p_brace == '}') { p_brace++; while(*p_brace && isspace((unsigned char)*p_brace)) p_brace++; if (*p_brace == '\0' || *p_brace == '#') is_just_closing_brace = true; }
        if (is_just_closing_brace) { /* Tokenizer will handle */ }
        else if (current_function_definition && current_function_definition->line_count < MAX_FUNC_LINES) { current_function_definition->body[current_function_definition->line_count++] = strdup(line_orig); return; }
        else if (current_function_definition) { /* Error: func body too long, cleanup */ }
    }

    Token tokens[MAX_ARGS]; char token_storage[TOKEN_STORAGE_SIZE];
    int num_tokens = advanced_tokenize_line(line, tokens, MAX_ARGS, token_storage, TOKEN_STORAGE_SIZE);
    if (num_tokens == 0 || (num_tokens == 1 && tokens[0].type == TOKEN_EOF)) return;

    // Resolve keyword alias for the first token if it's a word
    const char* command_word = NULL;
    if (tokens[0].type == TOKEN_WORD) {
        command_word = resolve_keyword_alias(tokens[0].text);
    } else {
        command_word = tokens[0].text; // Not a word, or not an alias
    }
    // Note: command_word now points to either original token text or resolved original keyword.
    // The dispatcher below needs to use command_word instead of tokens[0].text for matching.

    if (exec_mode == STATE_IMPORT_PARSING) { /* ... import parsing logic using command_word ... */
        if (tokens[0].type == TOKEN_WORD && strcmp(command_word, "defunc") == 0) handle_defunc_statement_advanced(tokens, num_tokens);
        else if (tokens[0].type == TOKEN_LBRACE) { if (is_defining_function && current_function_definition) handle_opening_brace_token(tokens[0]); }
        else if (tokens[0].type == TOKEN_RBRACE) { if (is_defining_function && current_function_definition) handle_closing_brace_token(tokens[0], input_source); }
        return;
    }
    if (num_tokens == 1) { /* ... standalone brace handling ... */
        if (tokens[0].type == TOKEN_LBRACE) { handle_opening_brace_token(tokens[0]); return; }
        if (tokens[0].type == TOKEN_RBRACE) { handle_closing_brace_token(tokens[0], input_source); return; }
    }
    if (current_exec_state == STATE_BLOCK_SKIP && exec_mode != STATE_IMPORT_PARSING) { /* ... block skipping logic using command_word ... */
        if (tokens[0].type == TOKEN_WORD) {
            if (strcmp(command_word, "if") == 0) { push_block_bf(BLOCK_TYPE_IF, false, 0, 0); if (num_tokens > 1 && tokens[num_tokens-1].type == TOKEN_LBRACE) {} }
            else if (strcmp(command_word, "while") == 0) { push_block_bf(BLOCK_TYPE_WHILE, false, 0, 0); if (num_tokens > 1 && tokens[num_tokens-1].type == TOKEN_LBRACE) {} }
            else if (strcmp(command_word, "else") == 0) handle_else_statement_advanced(tokens, num_tokens, input_source, current_line_no);
        }
        if (!( (tokens[0].type == TOKEN_WORD && (strcmp(command_word, "if") == 0 || strcmp(command_word, "while") == 0 || strcmp(command_word, "else") == 0 )) || tokens[0].type == TOKEN_LBRACE || tokens[0].type == TOKEN_RBRACE) ) return;
    }

    // --- Command Dispatcher using command_word ---
    if (tokens[0].type == TOKEN_WORD) {
        if (strcmp(command_word, "exit") == 0 && block_stack_top_bf == -1) { cleanup_shell(); exit(0); }
        else if (strcmp(command_word, "defkeyword") == 0) { handle_defkeyword_statement(tokens, num_tokens); }
        else if (strcmp(command_word, "if") == 0) handle_if_statement_advanced(tokens, num_tokens, input_source, current_line_no);
        else if (strcmp(command_word, "else") == 0) handle_else_statement_advanced(tokens, num_tokens, input_source, current_line_no);
        else if (strcmp(command_word, "while") == 0) handle_while_statement_advanced(tokens, num_tokens, input_source, current_line_no);
        else if (strcmp(command_word, "echo") == 0) handle_echo_advanced(tokens, num_tokens);
        else if (strcmp(command_word, "inc") == 0) handle_inc_dec_statement_advanced(tokens, num_tokens, true);
        else if (strcmp(command_word, "dec") == 0) handle_inc_dec_statement_advanced(tokens, num_tokens, false);
        else if (strcmp(command_word, "defunc") == 0) handle_defunc_statement_advanced(tokens, num_tokens);
        else if (strcmp(command_word, "loadlib") == 0) handle_loadlib_statement(tokens, num_tokens);
        else if (strcmp(command_word, "calllib") == 0) handle_calllib_statement(tokens, num_tokens);
        else if (strcmp(command_word, "import") == 0) handle_import_statement(tokens, num_tokens);
        else { /* ... user function or external command logic ... */
            // Note: For assignment $var = value, tokens[0] is TOKEN_VARIABLE, not TOKEN_WORD.
            // The check for assignment should be separate or before this block.
            UserFunction* func_to_call = function_list; while(func_to_call) { if (strcmp(command_word, func_to_call->name) == 0) { execute_user_function(func_to_call, tokens + 1, num_tokens - 1, input_source); return; } func_to_call = func_to_call->next; }
            char expanded_args_storage[MAX_ARGS][MAX_VAR_VALUE_LEN]; char *expanded_argv[MAX_ARGS + 1]; int expanded_arg_count = 0;
            // First arg for execv should be the original token text if it's a path, or resolved command_word
            // This needs care: expanded_argv[0] should be based on tokens[0].text for path, but command_word for non-path.
            // For simplicity, assume command_word is what we search in PATH if tokens[0].text isn't a path.
            // The current expansion loop for args will use tokens[i].text
            // This part needs careful review for how command_word and tokens[0].text are used for argv[0]
            char first_arg_for_exec[MAX_FULL_PATH_LEN];
            if (strchr(tokens[0].text, '/') != NULL) { // If original token was a path
                 expand_variables_in_string_advanced(tokens[0].text, first_arg_for_exec, sizeof(first_arg_for_exec));
            } else { // Not a path, use command_word (which might be an alias resolution)
                 // This is tricky if command_word is an alias of an external command.
                 // find_command_in_path_dynamic should use command_word.
                 // For now, let's build argv from original tokens, and find_command_in_path uses command_word.
                 // This is slightly inconsistent and needs refinement.
                 // A better way: if command_word is different from tokens[0].text, use command_word for find_command_in_path,
                 // but original tokens[0].text for argv[0] if it was a path.
                 // For now, always expand tokens[0].text for argv[0]
                 expand_variables_in_string_advanced(tokens[0].text, expanded_args_storage[expanded_arg_count], MAX_VAR_VALUE_LEN);
                 expanded_argv[expanded_arg_count++] = expanded_args_storage[0];
            }


            for (int i = 1; i < num_tokens; i++) { /* ... expand other args ... */
                if (tokens[i].type == TOKEN_WORD || tokens[i].type == TOKEN_STRING || tokens[i].type == TOKEN_VARIABLE) {
                    if (tokens[i].type == TOKEN_STRING) { char unescaped_val[MAX_VAR_VALUE_LEN]; unescape_string(tokens[i].text, unescaped_val, sizeof(unescaped_val)); expand_variables_in_string_advanced(unescaped_val, expanded_args_storage[expanded_arg_count], MAX_VAR_VALUE_LEN);
                    } else { expand_variables_in_string_advanced(tokens[i].text, expanded_args_storage[expanded_arg_count], MAX_VAR_VALUE_LEN); }
                    expanded_argv[expanded_arg_count] = expanded_args_storage[expanded_arg_count]; expanded_arg_count++;
                }
            } expanded_argv[expanded_arg_count] = NULL;
            if (expanded_arg_count > 0) { char full_command_path[MAX_FULL_PATH_LEN];
                // Use command_word for searching in path if tokens[0].text is not a path itself
                const char* search_cmd = (strchr(tokens[0].text, '/') == NULL) ? command_word : expanded_argv[0];
                if (find_command_in_path_dynamic(search_cmd, full_command_path)) { execute_external_command(full_command_path, expanded_argv, expanded_arg_count, NULL, 0);
                } else { fprintf(stderr, "Command not found: %s (searched as '%s')\n", tokens[0].text, search_cmd); }
            }
        }
    } else if (tokens[0].type == TOKEN_VARIABLE && num_tokens > 1 && tokens[1].type == TOKEN_ASSIGN) {
        handle_assignment_advanced(tokens, num_tokens);
    } else { if (num_tokens > 0 && tokens[0].type != TOKEN_EOF && tokens[0].type != TOKEN_COMMENT) { fprintf(stderr, "Syntax error: Unexpected token '%s'.\n", tokens[0].text); } }
}

