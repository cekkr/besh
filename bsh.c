#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <ctype.h>
#include <dlfcn.h> // For dynamic library loading
#include <errno.h> // For strtol error checking
#include <limits.h> // For LONG_MIN, LONG_MAX

// --- Constants and Definitions ---
#define MAX_LINE_LENGTH 2048
#define MAX_ARGS 128
#define MAX_VAR_NAME_LEN 256
#define MAX_VAR_VALUE_LEN 1024
// #define MAX_PATH_DIRS 64 // Replaced by dynamic list
#define MAX_FULL_PATH_LEN 1024
#define TOKEN_STORAGE_SIZE (MAX_LINE_LENGTH * 2)
#define MAX_NESTING_DEPTH 32 // Kept fixed for now for block stack
#define MAX_FUNC_LINES 100   // Kept fixed within UserFunction struct for now
#define MAX_FUNC_PARAMS 10   // Kept fixed within UserFunction struct for now
// #define MAX_OPERATORS 50 // Replaced by dynamic list
#define MAX_OPERATOR_LEN 8
#define DEFAULT_STARTUP_SCRIPT ".bshrc" // Default startup script in home or current dir

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

// --- PATH Directories (Dynamic List) ---
typedef struct PathDirNode {
    char *path;
    struct PathDirNode *next;
} PathDirNode;
PathDirNode *path_list_head = NULL;

// --- Variable Management ---
typedef struct Variable {
    char name[MAX_VAR_NAME_LEN];
    char value[MAX_VAR_VALUE_LEN];
    bool is_array_element;
    struct Variable *next;
} Variable;
Variable *variable_list = NULL;

// --- User-Defined Functions ---
typedef struct UserFunction {
    char name[MAX_VAR_NAME_LEN];
    char params[MAX_FUNC_PARAMS][MAX_VAR_NAME_LEN];
    int param_count;
    char* body[MAX_FUNC_LINES]; // Lines of the function body
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
    int loop_start_line_no; // For non-fseekable sources or as primary loop reference
    bool condition_true;
    ExecutionState prev_exec_state;
} BlockFrame;
BlockFrame block_stack[MAX_NESTING_DEPTH];
int block_stack_top = -1;

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

// Tokenizer
void initialize_operators_dynamic();
void add_operator_dynamic(const char* op_str, TokenType type);
int match_operator_dynamic(const char *input, const char **op_text, TokenType *matched_type);
int advanced_tokenize_line(const char *line, Token *tokens, int max_tokens, char *token_storage, size_t storage_size);

// Path Management
void add_path_dir(const char* dir_path);
void free_path_list();

// Variable Management (prototypes mostly unchanged, implementation might be refined)
char* get_variable(const char *name_raw);
void set_variable(const char *name_raw, const char *value, bool is_array_elem);
void expand_variables_in_string_advanced(const char *input_str, char *expanded_str, size_t expanded_str_size);
char* get_array_element(const char* array_base_name, const char* index_str_raw);
void set_array_element(const char* array_base_name, const char* index_str_raw, const char* value);

// Command Execution
bool find_command_in_path_dynamic(const char *command, char *full_path);
int execute_external_command(char *command_path, char **args, int arg_count, char *output_buffer, size_t output_buffer_size);
void execute_user_function(UserFunction* func, Token* call_arg_tokens, int call_arg_token_count, FILE* input_source_for_context);

// Built-in Commands and Statements (prototypes mostly unchanged)
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

// Block Management (prototypes unchanged)
void push_block(BlockType type, bool condition_true, long loop_start_fpos, int loop_start_line_no);
BlockFrame* pop_block();
BlockFrame* peek_block();
void handle_opening_brace_token(Token token);
void handle_closing_brace_token(Token token, FILE* input_source);

// Utility
char* trim_whitespace(char *str);
void free_variable_list();
void free_function_list();
void free_operator_list();
void free_loaded_libs();
long get_file_pos(FILE* f);
char* unescape_string(const char* input, char* output_buffer, size_t buffer_size);


// --- Main ---
int main(int argc, char *argv[]) {
    initialize_shell();

    // Execute default startup script
    char startup_script_path[MAX_FULL_PATH_LEN];
    char* home_dir = getenv("HOME");
    if (home_dir) {
        snprintf(startup_script_path, sizeof(startup_script_path), "%s/%s", home_dir, DEFAULT_STARTUP_SCRIPT);
        if (access(startup_script_path, F_OK) == 0) {
            execute_script(startup_script_path, false, true);
        } else {
            // Try current directory as fallback for default script
            if (access(DEFAULT_STARTUP_SCRIPT, F_OK) == 0) {
                 execute_script(DEFAULT_STARTUP_SCRIPT, false, true);
            }
        }
    } else { // No HOME env, try current directory
         if (access(DEFAULT_STARTUP_SCRIPT, F_OK) == 0) {
            execute_script(DEFAULT_STARTUP_SCRIPT, false, true);
        }
    }


    if (argc > 1) {
        const char *filename = argv[1];
        execute_script(filename, false, false); // false: not import, false: not startup
    } else {
        char line[MAX_LINE_LENGTH];
        char prompt_buffer[MAX_VAR_NAME_LEN + 30];
        int line_counter_interactive = 0;

        while (1) {
            const char* base_prompt_val = get_variable("PS1");
            if (!base_prompt_val) base_prompt_val = "bsh"; // Default prompt

            char state_indicator[25] = "";
            // (Prompt state indicator logic remains the same)
            if (block_stack_top >= 0) {
                BlockFrame* top_block = peek_block();
                const char* block_type_str = "";
                if (top_block->type == BLOCK_TYPE_IF) block_type_str = "if";
                else if (top_block->type == BLOCK_TYPE_ELSE) block_type_str = "else";
                else if (top_block->type == BLOCK_TYPE_WHILE) block_type_str = "while";
                else if (top_block->type == BLOCK_TYPE_FUNCTION_DEF) block_type_str = "defunc";

                if (current_exec_state == STATE_BLOCK_SKIP) {
                    snprintf(state_indicator, sizeof(state_indicator), "(skip %s %d)", block_type_str, block_stack_top + 1);
                } else if (current_exec_state == STATE_DEFINE_FUNC_BODY) {
                     snprintf(state_indicator, sizeof(state_indicator), "(defunc %s)", current_function_definition ? current_function_definition->name : "?");
                } else {
                    snprintf(state_indicator, sizeof(state_indicator), "(%s %d)", block_type_str, block_stack_top + 1);
                }
            } else if (current_exec_state == STATE_DEFINE_FUNC_BODY && current_function_definition) {
                snprintf(state_indicator, sizeof(state_indicator), "(defunc %s...)", current_function_definition->name);
            }

            snprintf(prompt_buffer, sizeof(prompt_buffer), "%s%s> ", base_prompt_val, state_indicator);
            printf("%s", prompt_buffer);

            if (!fgets(line, sizeof(line), stdin)) {
                printf("\n");
                break;
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
    char *path_env = getenv("PATH");
    if (path_env != NULL) {
        char *path_copy = strdup(path_env);
        if (!path_copy) { perror("strdup for PATH failed"); return; }
        char *token_path = strtok(path_copy, ":");
        while (token_path != NULL) {
            add_path_dir(token_path);
            token_path = strtok(NULL, ":");
        }
        free(path_copy);
    }
    initialize_operators_dynamic();
    set_variable("SHELL_VERSION", "bsh-extensible-0.3", false);
    set_variable("PS1", "bsh", false); // Default prompt variable
}

void initialize_operators_dynamic() {
    // Define default operators. More can be added by startup script or 'defop' command (future)
    // Order for matching: longest first if not using a more complex matching like Trie
    add_operator_dynamic("==", TOKEN_OPERATOR);
    add_operator_dynamic("!=", TOKEN_OPERATOR);
    add_operator_dynamic(">=", TOKEN_OPERATOR);
    add_operator_dynamic("<=", TOKEN_OPERATOR);
    add_operator_dynamic("&&", TOKEN_OPERATOR);
    add_operator_dynamic("||", TOKEN_OPERATOR);
    add_operator_dynamic("=", TOKEN_ASSIGN);
    add_operator_dynamic(">", TOKEN_OPERATOR);
    add_operator_dynamic("<", TOKEN_OPERATOR);
    add_operator_dynamic("+", TOKEN_OPERATOR);
    add_operator_dynamic("-", TOKEN_OPERATOR);
    add_operator_dynamic("*", TOKEN_OPERATOR);
    add_operator_dynamic("/", TOKEN_OPERATOR);
    add_operator_dynamic("%", TOKEN_OPERATOR);
    add_operator_dynamic("!", TOKEN_OPERATOR);
    add_operator_dynamic("(", TOKEN_LPAREN);
    add_operator_dynamic(")", TOKEN_RPAREN);
    add_operator_dynamic("{", TOKEN_LBRACE);
    add_operator_dynamic("}", TOKEN_RBRACE);
    add_operator_dynamic("[", TOKEN_LBRACKET);
    add_operator_dynamic("]", TOKEN_RBRACKET);
    add_operator_dynamic(";", TOKEN_SEMICOLON);
    add_operator_dynamic("|", TOKEN_PIPE);
    add_operator_dynamic("&", TOKEN_AMPERSAND);
}

void add_operator_dynamic(const char* op_str, TokenType type) {
    if (strlen(op_str) > MAX_OPERATOR_LEN) {
        fprintf(stderr, "Warning: Operator '%s' too long (max %d chars).\n", op_str, MAX_OPERATOR_LEN);
        return;
    }
    OperatorDefinition *new_op = (OperatorDefinition*)malloc(sizeof(OperatorDefinition));
    if (!new_op) {
        perror("malloc for new operator failed");
        return;
    }
    strcpy(new_op->op_str, op_str);
    new_op->op_type = type;
    new_op->next = operator_list_head; // Prepend to list
    operator_list_head = new_op;
}

void add_path_dir(const char* dir_path) {
    PathDirNode *new_node = (PathDirNode*)malloc(sizeof(PathDirNode));
    if (!new_node) {
        perror("malloc for new path directory failed");
        return;
    }
    new_node->path = strdup(dir_path);
    if (!new_node->path) {
        perror("strdup for path directory failed");
        free(new_node);
        return;
    }
    new_node->next = NULL;

    if (!path_list_head) {
        path_list_head = new_node;
    } else {
        PathDirNode *current = path_list_head;
        while (current->next) {
            current = current->next;
        }
        current->next = new_node; // Append to list
    }
}


void cleanup_shell() {
    free_variable_list();
    free_function_list();
    free_operator_list();
    free_path_list();
    free_loaded_libs();
}

void free_path_list() {
    PathDirNode *current = path_list_head;
    PathDirNode *next_node;
    while (current) {
        next_node = current->next;
        free(current->path);
        free(current);
        current = next_node;
    }
    path_list_head = NULL;
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


void process_line(char *line_orig, FILE *input_source, int current_line_no, ExecutionState exec_mode) {
    // ... (process_line logic remains largely the same as previous version,
    //      key changes are in how it calls find_command_in_path_dynamic and match_operator_dynamic)
    //      Ensure all calls to old find_command_in_path and match_operator are updated.
    //      The overall structure of parsing tokens, handling blocks, and dispatching commands is similar.

    char line[MAX_LINE_LENGTH];
    strncpy(line, line_orig, MAX_LINE_LENGTH - 1);
    line[MAX_LINE_LENGTH - 1] = '\0';

    char *first_char_ptr = line;
    while(*first_char_ptr && isspace((unsigned char)*first_char_ptr)) first_char_ptr++;
    if (*first_char_ptr == '#' || *first_char_ptr == '\0') {
        return;
    }

    if (is_defining_function && (current_exec_state == STATE_DEFINE_FUNC_BODY || exec_mode == STATE_IMPORT_PARSING) ) {
        char temp_trimmed_line[MAX_LINE_LENGTH];
        strncpy(temp_trimmed_line, line_orig, MAX_LINE_LENGTH -1);
        temp_trimmed_line[MAX_LINE_LENGTH-1] = '\0';
        char* trimmed_body_line = trim_whitespace(temp_trimmed_line);

        bool is_just_closing_brace = false;
        char* p = trimmed_body_line;
        if (*p == '}') {
            p++;
            while(*p && isspace((unsigned char)*p)) p++;
            if (*p == '\0' || *p == '#') is_just_closing_brace = true;
        }

        if (is_just_closing_brace) {
            // Tokenizer will handle it
        } else if (current_function_definition && current_function_definition->line_count < MAX_FUNC_LINES) {
            current_function_definition->body[current_function_definition->line_count++] = strdup(line_orig); // Use original line
            return;
        } else if (current_function_definition) {
            fprintf(stderr, "Error: Function body for '%s' too long.\n", current_function_definition->name);
            for(int i=0; i < current_function_definition->line_count; ++i) free(current_function_definition->body[i]);
            free(current_function_definition);
            current_function_definition = NULL;
            is_defining_function = false;
            current_exec_state = (block_stack_top >=0 && peek_block()) ? peek_block()->prev_exec_state : STATE_NORMAL;
        }
    }

    Token tokens[MAX_ARGS];
    char token_storage[TOKEN_STORAGE_SIZE];
    int num_tokens = advanced_tokenize_line(line, tokens, MAX_ARGS, token_storage, TOKEN_STORAGE_SIZE);

    if (num_tokens == 0 || (num_tokens == 1 && tokens[0].type == TOKEN_EOF)) {
        return;
    }
    
    if (exec_mode == STATE_IMPORT_PARSING) {
        if (tokens[0].type == TOKEN_WORD && strcmp(tokens[0].text, "defunc") == 0) {
            handle_defunc_statement_advanced(tokens, num_tokens);
        } else if (tokens[0].type == TOKEN_LBRACE) {
            if (is_defining_function && current_function_definition) {
                 handle_opening_brace_token(tokens[0]);
            }
        } else if (tokens[0].type == TOKEN_RBRACE) {
            if (is_defining_function && current_function_definition) {
                handle_closing_brace_token(tokens[0], input_source);
            }
        }
        return;
    }

    if (num_tokens == 1) {
        if (tokens[0].type == TOKEN_LBRACE) {
            handle_opening_brace_token(tokens[0]);
            return;
        }
        if (tokens[0].type == TOKEN_RBRACE) {
            handle_closing_brace_token(tokens[0], input_source);
            return;
        }
    }

    if (current_exec_state == STATE_BLOCK_SKIP && exec_mode != STATE_IMPORT_PARSING) {
        if (tokens[0].type == TOKEN_WORD) {
            if (strcmp(tokens[0].text, "if") == 0) {
                push_block(BLOCK_TYPE_IF, false, 0, 0);
                if (num_tokens > 1 && tokens[num_tokens-1].type == TOKEN_LBRACE) { /* consumed */ }
            } else if (strcmp(tokens[0].text, "while") == 0) {
                push_block(BLOCK_TYPE_WHILE, false, 0, 0);
                 if (num_tokens > 1 && tokens[num_tokens-1].type == TOKEN_LBRACE) { /* consumed */ }
            } else if (strcmp(tokens[0].text, "else") == 0) {
                handle_else_statement_advanced(tokens, num_tokens, input_source, current_line_no);
            }
        }
        if (!( (tokens[0].type == TOKEN_WORD && (strcmp(tokens[0].text, "if") == 0 || strcmp(tokens[0].text, "while") == 0 || strcmp(tokens[0].text, "else") == 0 )) ||
               tokens[0].type == TOKEN_LBRACE || tokens[0].type == TOKEN_RBRACE) ) {
             return;
        }
    }

    if (tokens[0].type == TOKEN_WORD) {
        const char* cmd = tokens[0].text;
        if (strcmp(cmd, "exit") == 0 && block_stack_top == -1) {
            cleanup_shell();
            exit(0);
        } else if (strcmp(cmd, "if") == 0) {
            handle_if_statement_advanced(tokens, num_tokens, input_source, current_line_no);
        } else if (strcmp(cmd, "else") == 0) {
            handle_else_statement_advanced(tokens, num_tokens, input_source, current_line_no);
        } else if (strcmp(cmd, "while") == 0) {
            handle_while_statement_advanced(tokens, num_tokens, input_source, current_line_no);
        } else if (strcmp(cmd, "echo") == 0) {
            handle_echo_advanced(tokens, num_tokens);
        } else if (strcmp(cmd, "inc") == 0) {
            handle_inc_dec_statement_advanced(tokens, num_tokens, true);
        } else if (strcmp(cmd, "dec") == 0) {
            handle_inc_dec_statement_advanced(tokens, num_tokens, false);
        } else if (strcmp(cmd, "defunc") == 0) {
            handle_defunc_statement_advanced(tokens, num_tokens);
        } else if (strcmp(cmd, "loadlib") == 0) {
            handle_loadlib_statement(tokens, num_tokens);
        } else if (strcmp(cmd, "calllib") == 0) {
            handle_calllib_statement(tokens, num_tokens);
        } else if (strcmp(cmd, "import") == 0) {
            handle_import_statement(tokens, num_tokens);
        }
        else {
            if (tokens[0].type == TOKEN_VARIABLE && num_tokens > 1 && tokens[1].type == TOKEN_ASSIGN) {
                 handle_assignment_advanced(tokens, num_tokens);
                 return;
            }

            UserFunction* func_to_call = function_list;
            while(func_to_call) {
                if (strcmp(cmd, func_to_call->name) == 0) {
                    execute_user_function(func_to_call, tokens + 1, num_tokens - 1, input_source);
                    return;
                }
                func_to_call = func_to_call->next;
            }

            char expanded_args_storage[MAX_ARGS][MAX_VAR_VALUE_LEN];
            char *expanded_argv[MAX_ARGS + 1];
            int expanded_arg_count = 0;

            for (int i = 0; i < num_tokens; i++) {
                if (tokens[i].type == TOKEN_WORD || tokens[i].type == TOKEN_STRING || tokens[i].type == TOKEN_VARIABLE) {
                    if (tokens[i].type == TOKEN_STRING) {
                        char unescaped_val[MAX_VAR_VALUE_LEN];
                        unescape_string(tokens[i].text, unescaped_val, sizeof(unescaped_val));
                        expand_variables_in_string_advanced(unescaped_val, expanded_args_storage[expanded_arg_count], MAX_VAR_VALUE_LEN);
                    } else {
                        expand_variables_in_string_advanced(tokens[i].text, expanded_args_storage[expanded_arg_count], MAX_VAR_VALUE_LEN);
                    }
                    expanded_argv[expanded_arg_count] = expanded_args_storage[expanded_arg_count];
                    expanded_arg_count++;
                }
            }
            expanded_argv[expanded_arg_count] = NULL;

            if (expanded_arg_count > 0) {
                char full_command_path[MAX_FULL_PATH_LEN];
                if (find_command_in_path_dynamic(expanded_argv[0], full_command_path)) { // USE DYNAMIC VERSION
                    execute_external_command(full_command_path, expanded_argv, expanded_arg_count, NULL, 0);
                } else {
                    fprintf(stderr, "Command not found: %s\n", expanded_argv[0]);
                }
            }
        }
    } else if (tokens[0].type == TOKEN_VARIABLE && num_tokens > 1 && tokens[1].type == TOKEN_ASSIGN) {
        handle_assignment_advanced(tokens, num_tokens);
    } else {
        if (num_tokens > 0 && tokens[0].type != TOKEN_EOF && tokens[0].type != TOKEN_COMMENT) {
             fprintf(stderr, "Syntax error: Unexpected token '%s' (type %d) at start of command.\n", tokens[0].text, tokens[0].type);
        }
    }
}

void execute_script(const char *filename, bool is_import_call, bool is_startup_script) {
    FILE *script_file = fopen(filename, "r");
    if (!script_file) {
        if (!is_startup_script) { // Don't perror for optional startup script
            perror("Error opening script");
        } else if (errno != ENOENT && strcmp(filename, DEFAULT_STARTUP_SCRIPT) != 0 && (strchr(filename,'/') != NULL && strncmp(filename, getenv("HOME")?getenv("HOME"):"", strlen(getenv("HOME")?getenv("HOME"):"")) !=0) ) {
            // Print error if it's not "file not found" for a non-default path startup script
             fprintf(stderr, "Error opening startup script '%s': %s\n", filename, strerror(errno));
        }
        return;
    }

    if (is_startup_script) printf("Executing startup script: %s\n", filename);
    else if (is_import_call) printf("Importing from script: %s\n", filename);
    // else normal script execution, no specific message here

    char line_buffer[MAX_LINE_LENGTH];
    int line_no = 0;
    ExecutionState script_exec_mode = is_import_call ? STATE_IMPORT_PARSING : STATE_NORMAL;

    ExecutionState outer_exec_state = current_exec_state;
    int outer_block_stack_top = block_stack_top;

    while (fgets(line_buffer, sizeof(line_buffer), script_file)) {
        line_no++;
        process_line(line_buffer, script_file, line_no, script_exec_mode);
    }
    fclose(script_file);

    if (is_import_call) {
        if (is_defining_function && current_function_definition) {
            fprintf(stderr, "Warning: Unterminated function definition '%s' at end of imported file '%s'.\n", current_function_definition->name, filename);
            for(int i=0; i < current_function_definition->line_count; ++i) free(current_function_definition->body[i]);
            free(current_function_definition);
            current_function_definition = NULL;
            is_defining_function = false;
            if (block_stack_top >=0 && peek_block() && peek_block()->type == BLOCK_TYPE_FUNCTION_DEF) {
                pop_block();
            }
        }
        // printf("Finished importing from: %s\n", filename); // Can be verbose
    } else if (!is_startup_script) { // Restore context for normal script execution (not for startup script to avoid clobbering interactive state too early)
        current_exec_state = outer_exec_state;
        while(block_stack_top > outer_block_stack_top) {
            BlockFrame* bf = pop_block();
            fprintf(stderr, "Warning: Script '%s' ended with unclosed block (type %d).\n", filename, bf ? bf->type : -1);
        }
    }
    // For startup script, its state changes (vars, functions) persist, but execution flow context (blocks, current_exec_state) shouldn't bleed into interactive session incorrectly.
    // The `outer_exec_state` and `outer_block_stack_top` are more for nested script *calls* rather than startup.
    // Startup script should ideally leave `current_exec_state` as `STATE_NORMAL` and `block_stack_top` as -1.
    if (is_startup_script) {
        current_exec_state = STATE_NORMAL;
        while(block_stack_top > -1) { // Clear any blocks opened by startup script
            pop_block();
        }
    }
}

// --- Tokenizer Implementation ---
int match_operator_dynamic(const char *input, const char **op_text, TokenType *matched_type) {
    OperatorDefinition *current = operator_list_head;
    const char* best_match_text = NULL;
    TokenType best_match_type = TOKEN_EMPTY;
    int longest_match_len = 0;

    // Iterate through all defined operators to find the longest match at the current input position
    // This is important because operators can be prefixes of others (e.g., "<" and "<=").
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
        *op_text = best_match_text;
        if(matched_type) *matched_type = best_match_type;
        return longest_match_len;
    }
    return 0;
}

int advanced_tokenize_line(const char *line, Token *tokens, int max_tokens, char *token_storage, size_t storage_size) {
    // ... (tokenizer logic from previous version, but uses match_operator_dynamic)
    int token_count = 0;
    const char *p = line;
    char *storage_ptr = token_storage;
    size_t remaining_storage = storage_size;

    while (*p && token_count < max_tokens) {
        while (isspace((unsigned char)*p)) p++;
        if (!*p) break;
        if (*p == '#') break;

        tokens[token_count].text = storage_ptr;

        const char *matched_op_text = NULL;
        TokenType matched_op_type = TOKEN_EMPTY;
        int op_len = match_operator_dynamic(p, &matched_op_text, &matched_op_type); // USE DYNAMIC VERSION

        if (op_len > 0) {
            tokens[token_count].type = matched_op_type; // Use the specific type from definition
            tokens[token_count].len = op_len;
            if (remaining_storage > op_len) {
                strncpy(storage_ptr, p, op_len); // Copy the matched part of input
                storage_ptr[op_len] = '\0';
                storage_ptr += (op_len + 1);
                remaining_storage -= (op_len + 1);
            } else { tokens[token_count].type = TOKEN_ERROR; break; }
            p += op_len;
        } else if (*p == '"') {
            tokens[token_count].type = TOKEN_STRING;
            const char *start = p;
            p++; 
            while (*p && (*p != '"' || (*(p-1) == '\\' && *(p-2) != '\\' ))) {
                 p++;
            }
            if (*p == '"') p++;

            tokens[token_count].len = p - start;
            if (remaining_storage > (size_t)tokens[token_count].len) {
                strncpy(storage_ptr, start, tokens[token_count].len);
                storage_ptr[tokens[token_count].len] = '\0';
                storage_ptr += (tokens[token_count].len + 1);
                remaining_storage -= (tokens[token_count].len + 1);
            } else { tokens[token_count].type = TOKEN_ERROR; break; }

        } else if (*p == '$') {
            tokens[token_count].type = TOKEN_VARIABLE;
            const char *start = p;
            p++; 
            if (*p == '{') {
                p++; 
                while (*p && *p != '}' && (isalnum((unsigned char)*p) || *p == '_' || *p == '[' || *p == ']' || *p == '"' )) {
                    p++;
                }
                if (*p == '}') p++;
            } else { 
                while (isalnum((unsigned char)*p) || *p == '_') {
                    p++;
                }
                if (*p == '[') {
                    p++; 
                    int bracket_depth = 1;
                    while(*p && bracket_depth > 0) {
                        if (*p == '[') bracket_depth++;
                        else if (*p == ']') bracket_depth--;
                        if (bracket_depth == 0 && *(p) == ']') {
                             p++; 
                             break;
                        }
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

        } else { 
            tokens[token_count].type = TOKEN_WORD;
            const char *start = p;
            while (*p && !isspace((unsigned char)*p)) {
                const char* temp_op_text = NULL; TokenType temp_op_type;
                if (match_operator_dynamic(p, &temp_op_text, &temp_op_type) > 0) break;
                if (*p == '"' || *p == '$' || *p == '#') break;
                if (!isalnum((unsigned char)*p) && *p != '_') {
                    break; 
                }
                p++;
            }
            tokens[token_count].len = p - start;
            if (tokens[token_count].len == 0) continue;

            if (remaining_storage > (size_t)tokens[token_count].len) {
                strncpy(storage_ptr, start, tokens[token_count].len);
                storage_ptr[tokens[token_count].len] = '\0';
                storage_ptr += (tokens[token_count].len + 1);
                remaining_storage -= (tokens[token_count].len + 1);
            } else { tokens[token_count].type = TOKEN_ERROR; break; }
        }
        token_count++;
    }

    if (token_count < max_tokens) {
        tokens[token_count].type = TOKEN_EOF;
        tokens[token_count].text = "EOF";
        tokens[token_count].len = 3;
    }
    return token_count;
}


// --- Variable Management Implementations ---
// (get_variable, set_variable, expand_variables_in_string_advanced, get_array_element, set_array_element, unescape_string
//  remain largely the same as the previous version, ensure they are robust)
char* unescape_string(const char* input_raw, char* output_buffer, size_t buffer_size) {
    char* out = output_buffer;
    const char* p = input_raw;
    size_t out_len = 0;

    if (*p == '"') p++; // Skip leading quote

    while (*p && out_len < buffer_size - 1) {
        if (*p == '"' && !(p > input_raw && *(p-1) == '\\')) { // End quote not preceded by escape
             break;
        }
        if (*p == '\\') {
            p++; 
            if (!*p) break; // Dangling escape
            switch (*p) {
                case 'n': *out++ = '\n'; break;
                case 't': *out++ = '\t'; break;
                case '"': *out++ = '"'; break;
                case '\\': *out++ = '\\'; break;
                case '$': *out++ = '$'; break;
                default: *out++ = '\\'; *out++ = *p; 
                         break;
            }
        } else {
            *out++ = *p;
        }
        if (*p) p++; 
        out_len++;
    }
    *out = '\0';
    return output_buffer;
}

void expand_variables_in_string_advanced(const char *input_str, char *expanded_str, size_t expanded_str_size) {
    const char *p_in = input_str;
    char *p_out = expanded_str;
    size_t remaining_size = expanded_str_size - 1; 
    expanded_str[0] = '\0';

    while (*p_in && remaining_size > 0) {
        if (*p_in == '$') {
            p_in++; 
            char var_name_buffer[MAX_VAR_NAME_LEN * 2]; 
            char *pv = var_name_buffer;
            
            if (*p_in == '{') {
                p_in++; 
                int brace_level = 1;
                while (*p_in && brace_level > 0 && (pv - var_name_buffer < (long)sizeof(var_name_buffer) - 1)) {
                    if (*p_in == '{') brace_level++;
                    else if (*p_in == '}') brace_level--;
                    if (brace_level > 0) *pv++ = *p_in;
                    p_in++;
                }
                *pv = '\0';
            } else {
                while (isalnum((unsigned char)*p_in) || *p_in == '_') {
                    if (pv - var_name_buffer < MAX_VAR_NAME_LEN -1) *pv++ = *p_in++; else break;
                }
                *pv = '\0'; 
                if (*p_in == '[') {
                    // Reset pv to append the bracket part to var_name_buffer
                    // pv should point to the current end of var_name_buffer
                    *pv++ = *p_in++; 
                    int bracket_level = 1;
                    while (*p_in && bracket_level > 0 && (pv - var_name_buffer < (long)sizeof(var_name_buffer) - 1)) {
                        if (*p_in == '[') bracket_level++;
                        else if (*p_in == ']') bracket_level--;
                        *pv++ = *p_in++;
                    }
                    *pv = '\0'; 
                }
            }

            char base_var_name[MAX_VAR_NAME_LEN];
            char index_str_raw[MAX_VAR_NAME_LEN]; 
            bool is_array_access = false;

            char* bracket_ptr = strchr(var_name_buffer, '[');
            if (bracket_ptr) {
                char* end_bracket_ptr = strrchr(bracket_ptr, ']');
                if (end_bracket_ptr && end_bracket_ptr > bracket_ptr) {
                    is_array_access = true;
                    size_t base_len = bracket_ptr - var_name_buffer;
                    strncpy(base_var_name, var_name_buffer, base_len);
                    base_var_name[base_len] = '\0';

                    size_t index_len = end_bracket_ptr - (bracket_ptr + 1);
                    strncpy(index_str_raw, bracket_ptr + 1, index_len);
                    index_str_raw[index_len] = '\0';
                } else { 
                    strncpy(base_var_name, var_name_buffer, MAX_VAR_NAME_LEN -1);
                    base_var_name[MAX_VAR_NAME_LEN -1] = '\0';
                    index_str_raw[0] = '\0';
                }
            } else {
                strncpy(base_var_name, var_name_buffer, MAX_VAR_NAME_LEN -1);
                base_var_name[MAX_VAR_NAME_LEN -1] = '\0';
                index_str_raw[0] = '\0';
            }

            char *value_to_insert = NULL;
            if (is_array_access) {
                char expanded_index_val[MAX_VAR_VALUE_LEN];
                if (index_str_raw[0] == '"' && index_str_raw[strlen(index_str_raw)-1] == '"') {
                    unescape_string(index_str_raw, expanded_index_val, sizeof(expanded_index_val));
                } else if (index_str_raw[0] == '$') {
                    expand_variables_in_string_advanced(index_str_raw, expanded_index_val, sizeof(expanded_index_val)); 
                } else { 
                    strncpy(expanded_index_val, index_str_raw, sizeof(expanded_index_val)-1);
                    expanded_index_val[sizeof(expanded_index_val)-1] = '\0';
                }
                value_to_insert = get_array_element(base_var_name, expanded_index_val);
            } else {
                value_to_insert = get_variable(base_var_name);
            }

            if (value_to_insert) {
                size_t val_len = strlen(value_to_insert);
                if (val_len < remaining_size) {
                    strcpy(p_out, value_to_insert);
                    p_out += val_len;
                    remaining_size -= val_len;
                } else {
                    strncpy(p_out, value_to_insert, remaining_size);
                    p_out += remaining_size;
                    remaining_size = 0;
                }
            }
        } else if (*p_in == '\\' && *(p_in+1) == '$') { 
            p_in++; 
            if (remaining_size > 0) {
                *p_out++ = *p_in++; 
                remaining_size--;
            }
        } else {
            *p_out++ = *p_in++;
            remaining_size--;
        }
    }
    *p_out = '\0';
}

char* get_variable(const char *name_raw) {
    Variable *current = variable_list;
    char clean_name[MAX_VAR_NAME_LEN];
    strncpy(clean_name, name_raw, MAX_VAR_NAME_LEN -1);
    clean_name[MAX_VAR_NAME_LEN-1] = '\0';
    trim_whitespace(clean_name);

    while (current != NULL) {
        if (strcmp(current->name, clean_name) == 0) {
            return current->value;
        }
        current = current->next;
    }
    return NULL; 
}

void set_variable(const char *name_raw, const char *value, bool is_array_elem) {
    Variable *current = variable_list;
    Variable *prev = NULL;
    char clean_name[MAX_VAR_NAME_LEN];
    strncpy(clean_name, name_raw, MAX_VAR_NAME_LEN -1);
    clean_name[MAX_VAR_NAME_LEN-1] = '\0';
    trim_whitespace(clean_name);

    if (strlen(clean_name) == 0) {
        fprintf(stderr, "Error: Cannot set variable with empty name.\n");
        return;
    }

    while (current != NULL) {
        if (strcmp(current->name, clean_name) == 0) {
            strncpy(current->value, value, MAX_VAR_VALUE_LEN - 1);
            current->value[MAX_VAR_VALUE_LEN - 1] = '\0';
            current->is_array_element = is_array_elem;
            return;
        }
        prev = current;
        current = current->next;
    }

    Variable *new_var = (Variable*)malloc(sizeof(Variable));
    if (!new_var) {
        perror("malloc failed for new variable");
        return;
    }
    strncpy(new_var->name, clean_name, MAX_VAR_NAME_LEN - 1);
    new_var->name[MAX_VAR_NAME_LEN - 1] = '\0';
    strncpy(new_var->value, value, MAX_VAR_VALUE_LEN - 1);
    new_var->value[MAX_VAR_VALUE_LEN - 1] = '\0';
    new_var->is_array_element = is_array_elem;
    new_var->next = NULL;

    if (prev == NULL) { 
        variable_list = new_var;
    } else {
        prev->next = new_var;
    }
}

char* get_array_element(const char* array_base_name, const char* index_str_expanded) {
    char mangled_name[MAX_VAR_NAME_LEN * 2]; 
    snprintf(mangled_name, sizeof(mangled_name), "%s_ARRAYIDX_%s", array_base_name, index_str_expanded);
    return get_variable(mangled_name);
}

void set_array_element(const char* array_base_name, const char* index_str_raw, const char* value) {
    char expanded_index_val[MAX_VAR_VALUE_LEN];
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
    set_variable(mangled_name, value, true);
}


// --- Command Execution Implementations ---
bool find_command_in_path_dynamic(const char *command, char *full_path) {
    if (strchr(command, '/') != NULL) {
        if (access(command, X_OK) == 0) {
            strncpy(full_path, command, MAX_FULL_PATH_LEN -1);
            full_path[MAX_FULL_PATH_LEN-1] = '\0';
            return true;
        }
        return false;
    }

    PathDirNode *current_path_node = path_list_head;
    while (current_path_node) {
        snprintf(full_path, MAX_FULL_PATH_LEN, "%s/%s", current_path_node->path, command);
        if (access(full_path, X_OK) == 0) {
            return true;
        }
        current_path_node = current_path_node->next;
    }
    return false;
}

// (execute_external_command, execute_user_function, and all handle_..._advanced functions
//  remain largely the same as the previous version. Ensure they use dynamic path/operator functions where applicable)
int execute_external_command(char *command_path, char **args, int arg_count, char *output_buffer, size_t output_buffer_size) {
    pid_t pid;
    int status;
    int pipefd[2] = {-1, -1};

    if (output_buffer) {
        if (pipe(pipefd) == -1) {
            perror("pipe failed for command output capture");
            return -1;
        }
    }

    pid = fork();
    if (pid == 0) { 
        if (output_buffer) {
            close(pipefd[0]);    
            dup2(pipefd[1], STDOUT_FILENO); 
            dup2(pipefd[1], STDERR_FILENO); 
            close(pipefd[1]);    
        }
        execv(command_path, args);
        perror("execv failed"); 
        exit(EXIT_FAILURE);
    } else if (pid < 0) { 
        perror("fork failed");
        if (output_buffer) {
            close(pipefd[0]);
            close(pipefd[1]);
        }
        return -1;
    } else { 
        if (output_buffer) {
            close(pipefd[1]); 
            ssize_t bytes_read;
            size_t total_bytes_read = 0;
            char read_buf[256];
            output_buffer[0] = '\0'; 

            while((bytes_read = read(pipefd[0], read_buf, sizeof(read_buf)-1)) > 0) {
                if (total_bytes_read + bytes_read < output_buffer_size) {
                    read_buf[bytes_read] = '\0'; 
                    strcat(output_buffer, read_buf);
                    total_bytes_read += bytes_read;
                } else {
                    strncat(output_buffer, read_buf, output_buffer_size - total_bytes_read -1);
                    break; 
                }
            }
            close(pipefd[0]); 
            char* nl = strrchr(output_buffer, '\n');
            while(nl && (nl == output_buffer + strlen(output_buffer) -1)) {
                *nl = '\0';
                nl = strrchr(output_buffer, '\n');
            }
        }
        do {
            waitpid(pid, &status, WUNTRACED);
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        return WEXITSTATUS(status);
    }
    return 0; 
}

void execute_user_function(UserFunction* func, Token* call_arg_tokens, int call_arg_token_count, FILE* input_source_for_context) {
    if (!func) return;

    char old_param_values[MAX_FUNC_PARAMS][MAX_VAR_VALUE_LEN];
    bool param_was_present[MAX_FUNC_PARAMS] = {false};

    for (int i = 0; i < func->param_count; ++i) {
        char* existing_val = get_variable(func->params[i]);
        if (existing_val) {
            param_was_present[i] = true;
            strncpy(old_param_values[i], existing_val, MAX_VAR_VALUE_LEN-1);
            old_param_values[i][MAX_VAR_VALUE_LEN-1] = '\0';
        }

        if (i < call_arg_token_count) {
            char expanded_arg_val[MAX_VAR_VALUE_LEN];
            if (call_arg_tokens[i].type == TOKEN_STRING) {
                char unescaped_temp[MAX_VAR_VALUE_LEN];
                unescape_string(call_arg_tokens[i].text, unescaped_temp, sizeof(unescaped_temp));
                expand_variables_in_string_advanced(unescaped_temp, expanded_arg_val, sizeof(expanded_arg_val));
            } else {
                 expand_variables_in_string_advanced(call_arg_tokens[i].text, expanded_arg_val, sizeof(expanded_arg_val));
            }
            set_variable(func->params[i], expanded_arg_val, false);
        } else {
            set_variable(func->params[i], "", false); 
        }
    }

    int func_outer_block_stack_top = block_stack_top;
    ExecutionState func_outer_exec_state = current_exec_state;
    current_exec_state = STATE_NORMAL; 

    for (int i = 0; i < func->line_count; ++i) {
        char line_copy[MAX_LINE_LENGTH];
        strncpy(line_copy, func->body[i], MAX_LINE_LENGTH-1);
        line_copy[MAX_LINE_LENGTH-1] = '\0';
        process_line(line_copy, NULL, 0, STATE_NORMAL);
    }

    while(block_stack_top > func_outer_block_stack_top) {
        pop_block();
    }
    current_exec_state = func_outer_exec_state;

    for (int i = 0; i < func->param_count; ++i) {
        if (param_was_present[i]) {
            set_variable(func->params[i], old_param_values[i], false); 
        } else {
            // unset_variable(func->params[i]); // Future: implement unset
        }
    }
}

void handle_assignment_advanced(Token *tokens, int num_tokens) {
    if (num_tokens < 3 || tokens[0].type != TOKEN_VARIABLE || tokens[1].type != TOKEN_ASSIGN) {
        fprintf(stderr, "Assignment syntax: $variable = value_or_command OR $array[index] = value_or_command\n");
        return;
    }
    if (current_exec_state == STATE_BLOCK_SKIP) return;


    char var_token_text_copy[MAX_VAR_NAME_LEN * 2]; 
    strncpy(var_token_text_copy, tokens[0].text + 1, sizeof(var_token_text_copy) -1); 
    var_token_text_copy[sizeof(var_token_text_copy)-1] = '\0';

    char base_var_name[MAX_VAR_NAME_LEN];
    char index_str_raw[MAX_VAR_NAME_LEN] = "";
    bool is_array_assignment = false;

    char* bracket_ptr = strchr(var_token_text_copy, '[');
    if (bracket_ptr) {
        char* end_bracket_ptr = strrchr(bracket_ptr, ']');
        if (end_bracket_ptr && end_bracket_ptr > bracket_ptr) {
            is_array_assignment = true;
            size_t base_len = bracket_ptr - var_token_text_copy;
            strncpy(base_var_name, var_token_text_copy, base_len);
            base_var_name[base_len] = '\0';

            size_t index_len = end_bracket_ptr - (bracket_ptr + 1);
            strncpy(index_str_raw, bracket_ptr + 1, index_len);
            index_str_raw[index_len] = '\0';
        } else {
            fprintf(stderr, "Malformed array assignment: %s\n", tokens[0].text); return;
        }
    } else {
        strncpy(base_var_name, var_token_text_copy, MAX_VAR_NAME_LEN - 1);
        base_var_name[MAX_VAR_NAME_LEN - 1] = '\0';
    }

    char value_to_set[MAX_VAR_VALUE_LEN];
    value_to_set[0] = '\0';
    bool is_rhs_command = false;

    if (num_tokens > 2 && tokens[2].type == TOKEN_WORD) {
        char expanded_first_rhs_token[MAX_VAR_VALUE_LEN];
        expand_variables_in_string_advanced(tokens[2].text, expanded_first_rhs_token, sizeof(expanded_first_rhs_token));
        
        UserFunction* func = function_list;
        while(func) {
            if (strcmp(expanded_first_rhs_token, func->name) == 0) {
                is_rhs_command = true; break;
            }
            func = func->next;
        }
        if (!is_rhs_command) {
            char full_cmd_path_check[MAX_FULL_PATH_LEN];
            if (find_command_in_path_dynamic(expanded_first_rhs_token, full_cmd_path_check)) {
                is_rhs_command = true;
            }
        }
    }

    if (is_rhs_command) {
        char *cmd_args[MAX_ARGS + 1];
        char expanded_cmd_args_storage[MAX_ARGS][MAX_VAR_VALUE_LEN];
        int cmd_arg_count = 0;

        for (int i = 2; i < num_tokens; i++) { 
            if (tokens[i].type == TOKEN_WORD || tokens[i].type == TOKEN_STRING || tokens[i].type == TOKEN_VARIABLE) {
                 if (tokens[i].type == TOKEN_STRING) {
                    char unescaped_val[MAX_VAR_VALUE_LEN];
                    unescape_string(tokens[i].text, unescaped_val, sizeof(unescaped_val));
                    expand_variables_in_string_advanced(unescaped_val, expanded_cmd_args_storage[cmd_arg_count], MAX_VAR_VALUE_LEN);
                } else {
                    expand_variables_in_string_advanced(tokens[i].text, expanded_cmd_args_storage[cmd_arg_count], MAX_VAR_VALUE_LEN);
                }
                cmd_args[cmd_arg_count] = expanded_cmd_args_storage[cmd_arg_count];
                cmd_arg_count++;
            }
        }
        cmd_args[cmd_arg_count] = NULL;

        if (cmd_arg_count > 0) {
            char full_cmd_path_check[MAX_FULL_PATH_LEN];
            // Check if user function (no output capture for now) or external command
            bool is_user_func_rhs = false;
            UserFunction* user_func_check = function_list;
            while(user_func_check){
                if(strcmp(cmd_args[0], user_func_check->name) == 0) {is_user_func_rhs = true; break;}
                user_func_check = user_func_check->next;
            }

            if(is_user_func_rhs){
                 fprintf(stderr, "Assigning output of user-defined functions is not directly supported for capture. Execute separately.\n");
            } else if (find_command_in_path_dynamic(cmd_args[0], full_cmd_path_check)) {
                 execute_external_command(full_cmd_path_check, cmd_args, cmd_arg_count, value_to_set, sizeof(value_to_set));
            } else {
                 fprintf(stderr, "Command for assignment not found: %s\n", cmd_args[0]);
            }
        }
    } else { 
        char combined_value[MAX_VAR_VALUE_LEN] = "";
        size_t current_len = 0;
        for (int i = 2; i < num_tokens; i++) {
            char expanded_token_val[MAX_VAR_VALUE_LEN];
            if (tokens[i].type == TOKEN_STRING) { 
                char unescaped_temp[MAX_VAR_VALUE_LEN];
                unescape_string(tokens[i].text, unescaped_temp, sizeof(unescaped_temp));
                expand_variables_in_string_advanced(unescaped_temp, expanded_token_val, sizeof(expanded_token_val));
            } else { 
                expand_variables_in_string_advanced(tokens[i].text, expanded_token_val, sizeof(expanded_token_val));
            }

            size_t token_len = strlen(expanded_token_val);
            if (current_len + token_len + (current_len > 0 ? 1 : 0) < MAX_VAR_VALUE_LEN) {
                if (current_len > 0) { 
                    strcat(combined_value, " ");
                    current_len++;
                }
                strcat(combined_value, expanded_token_val);
                current_len += token_len;
            } else {
                fprintf(stderr, "Value too long for assignment.\n"); break;
            }
        }
        strncpy(value_to_set, combined_value, MAX_VAR_VALUE_LEN -1);
        value_to_set[MAX_VAR_VALUE_LEN-1] = '\0';
    }

    if (is_array_assignment) {
        set_array_element(base_var_name, index_str_raw, value_to_set);
    } else {
        set_variable(base_var_name, value_to_set, false);
    }
}

void handle_echo_advanced(Token *tokens, int num_tokens) {
    if (current_exec_state == STATE_BLOCK_SKIP) return;
    char expanded_arg[MAX_VAR_VALUE_LEN];
    for (int i = 1; i < num_tokens; i++) { 
        if (tokens[i].type == TOKEN_STRING) {
            char unescaped_val[MAX_VAR_VALUE_LEN];
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
    if (current_exec_state == STATE_BLOCK_SKIP) return false; // Should not happen if called correctly

    char val1_expanded[MAX_VAR_VALUE_LEN];
    char val2_expanded[MAX_VAR_VALUE_LEN];

    if (operand1_token->type == TOKEN_STRING) {
        char unescaped[MAX_VAR_VALUE_LEN];
        unescape_string(operand1_token->text, unescaped, sizeof(unescaped));
        expand_variables_in_string_advanced(unescaped, val1_expanded, sizeof(val1_expanded));
    } else {
        expand_variables_in_string_advanced(operand1_token->text, val1_expanded, sizeof(val1_expanded));
    }

    if (operand2_token->type == TOKEN_STRING) {
        char unescaped[MAX_VAR_VALUE_LEN];
        unescape_string(operand2_token->text, unescaped, sizeof(unescaped));
        expand_variables_in_string_advanced(unescaped, val2_expanded, sizeof(val2_expanded));
    } else {
        expand_variables_in_string_advanced(operand2_token->text, val2_expanded, sizeof(val2_expanded));
    }

    const char* op_str = operator_token->text;

    if (strcmp(op_str, "==") == 0) return strcmp(val1_expanded, val2_expanded) == 0;
    if (strcmp(op_str, "!=") == 0) return strcmp(val1_expanded, val2_expanded) != 0;

    long num1, num2;
    char *endptr1, *endptr2;
    errno = 0; 
    num1 = strtol(val1_expanded, &endptr1, 10);
    bool num1_valid = (errno == 0 && val1_expanded[0] != '\0' && *endptr1 == '\0');
    errno = 0;
    num2 = strtol(val2_expanded, &endptr2, 10);
    bool num2_valid = (errno == 0 && val2_expanded[0] != '\0' && *endptr2 == '\0');


    bool numeric_possible = num1_valid && num2_valid;

    if (numeric_possible) {
        if (strcmp(op_str, ">") == 0) return num1 > num2;
        if (strcmp(op_str, "<") == 0) return num1 < num2;
        if (strcmp(op_str, ">=") == 0) return num1 >= num2;
        if (strcmp(op_str, "<=") == 0) return num1 <= num2;
    } else { 
        // For non-numeric or mixed, use string comparison for >, <, >=, <=
        // This maintains consistency: all vars are strings, numeric ops are special cases.
        if (strcmp(op_str, ">") == 0) return strcmp(val1_expanded, val2_expanded) > 0;
        if (strcmp(op_str, "<") == 0) return strcmp(val1_expanded, val2_expanded) < 0;
        if (strcmp(op_str, ">=") == 0) return strcmp(val1_expanded, val2_expanded) >= 0;
        if (strcmp(op_str, "<=") == 0) return strcmp(val1_expanded, val2_expanded) <= 0;
    }
    
    // Here, one could add a hook to call a user-defined function for operator evaluation
    // e.g., if op_str is "is_type" or similar, call a function.
    // For now, stick to defined operators.

    fprintf(stderr, "Unsupported operator or type mismatch in condition: '%s' %s '%s'\n", val1_expanded, op_str, val2_expanded);
    return false;
}

// handle_if, handle_else, handle_while, handle_defunc, handle_inc_dec, handle_loadlib, handle_calllib, handle_import
// and block management functions (push, pop, peek, handle_opening/closing_brace)
// remain structurally similar to the previous version.
// Ensure they respect current_exec_state and manage block_stack correctly.
// Key is that their internal logic (like condition evaluation) uses the updated helper functions.
void handle_if_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no) {
    if (num_tokens < 4) {
        fprintf(stderr, "Syntax error for 'if'. Expected: if <operand1> <operator> <operand2> [{]\n");
        if (block_stack_top < MAX_NESTING_DEPTH -1 && current_exec_state != STATE_BLOCK_SKIP) {
           push_block(BLOCK_TYPE_IF, false, 0, 0); 
           current_exec_state = STATE_BLOCK_SKIP;
        }
        return;
    }

    bool condition_result = false;
    if (current_exec_state != STATE_BLOCK_SKIP) { 
         condition_result = evaluate_condition_advanced(&tokens[1], &tokens[2], &tokens[3]);
    }

    push_block(BLOCK_TYPE_IF, condition_result, 0, current_line_no); // Use current_line_no for context

    if (condition_result && current_exec_state != STATE_BLOCK_SKIP) {
        current_exec_state = STATE_BLOCK_EXECUTE;
    } else {
        current_exec_state = STATE_BLOCK_SKIP;
    }

    if (num_tokens > 4 && tokens[num_tokens-1].type == TOKEN_LBRACE) {
        // ok
    } else if (num_tokens == 4) {
        // ok, brace on next line
    } else if (num_tokens > 4 && tokens[num_tokens-1].type != TOKEN_LBRACE) {
        fprintf(stderr, "Syntax error for 'if': '{' expected after condition or on next line.\n");
    }
}

void handle_else_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no) {
    BlockFrame* prev_block_frame = peek_block();

    if (!prev_block_frame || (prev_block_frame->type != BLOCK_TYPE_IF && prev_block_frame->type != BLOCK_TYPE_ELSE)) {
        fprintf(stderr, "Error: 'else' without a preceding 'if' or 'else if' block.\n");
        if (current_exec_state != STATE_BLOCK_SKIP) {
            current_exec_state = STATE_BLOCK_SKIP; 
            push_block(BLOCK_TYPE_ELSE, false, 0, current_line_no); 
        }
        return;
    }

    BlockFrame closed_if_or_else_if = *pop_block(); 
    bool execute_this_else_branch = false;

    if (closed_if_or_else_if.condition_true) { 
        execute_this_else_branch = false; 
    } else { 
        if (num_tokens > 1 && tokens[1].type == TOKEN_WORD && strcmp(tokens[1].text, "if") == 0) { 
            if (num_tokens < 5) { 
                fprintf(stderr, "Syntax error for 'else if'. Expected: else if <op1> <op> <op2> [{]\n");
                execute_this_else_branch = false;
            } else {
                 if (current_exec_state != STATE_BLOCK_SKIP) { 
                    execute_this_else_branch = evaluate_condition_advanced(&tokens[2], &tokens[3], &tokens[4]);
                 } else { 
                    execute_this_else_branch = false;
                 }
            }
        } else { 
            execute_this_else_branch = true;
        }
    }

    push_block(BLOCK_TYPE_ELSE, execute_this_else_branch, 0, current_line_no);

    if (execute_this_else_branch && current_exec_state != STATE_BLOCK_SKIP) {
        current_exec_state = STATE_BLOCK_EXECUTE;
    } else {
        current_exec_state = STATE_BLOCK_SKIP;
    }
    
    int expected_brace_idx = 1; 
    if (num_tokens > 1 && tokens[1].type == TOKEN_WORD && strcmp(tokens[1].text, "if") == 0) {
        expected_brace_idx = 5; 
    }
    if (num_tokens > expected_brace_idx && tokens[num_tokens-1].type == TOKEN_LBRACE) {
        // ok
    } else if ( (strcmp(tokens[0].text,"else")==0 && num_tokens == 1) ||
                (strcmp(tokens[0].text,"else")==0 && tokens[1].type == TOKEN_WORD && strcmp(tokens[1].text,"if")==0 && num_tokens == (expected_brace_idx)) ) {
        // ok
    } else if (num_tokens > 0 && !(num_tokens == expected_brace_idx && tokens[num_tokens-1].type == TOKEN_LBRACE) ) {
         // This condition is a bit complex, ensure it correctly identifies missing braces
         // if there are other tokens on the line after "else" or "else if condition"
         if( (strcmp(tokens[0].text,"else")==0 && num_tokens > 1 && tokens[num_tokens-1].type != TOKEN_LBRACE) ||
             (strcmp(tokens[0].text,"else")==0 && tokens[1].type == TOKEN_WORD && strcmp(tokens[1].text,"if")==0 && num_tokens > expected_brace_idx && tokens[num_tokens-1].type != TOKEN_LBRACE) )
         {
            fprintf(stderr, "Syntax error for 'else'/'else if': '{' expected after statement or on next line, or unexpected tokens.\n");
         }
    }
}

void handle_while_statement_advanced(Token *tokens, int num_tokens, FILE* input_source, int current_line_no) {
    if (num_tokens < 4) {
        fprintf(stderr, "Syntax error for 'while'. Expected: while <op1> <op> <op2> [{]\n");
        if (block_stack_top < MAX_NESTING_DEPTH -1 && current_exec_state != STATE_BLOCK_SKIP) {
           push_block(BLOCK_TYPE_WHILE, false, 0, current_line_no);
           current_exec_state = STATE_BLOCK_SKIP;
        }
        return;
    }

    bool condition_result = false;
    long loop_fpos_at_while_line = -1; 

    if (input_source && input_source != stdin) {
        // Attempt to get fpos *before* this 'while' line was read.
        // This is hard to get accurately *here*. It's better if execute_script captures it.
        // For now, we'll primarily use current_line_no for loop control if fseek isn't perfect.
        // If execute_script is enhanced to pass the fpos of the start of the current line, use that.
        // loop_fpos_at_while_line = passed_fpos_of_while_line; 
    }


    if (current_exec_state != STATE_BLOCK_SKIP) {
        condition_result = evaluate_condition_advanced(&tokens[1], &tokens[2], &tokens[3]);
    }
    
    // Store the line number of the while statement itself.
    // If fseek is available and loop_fpos_at_while_line is correctly set by caller, that's preferred.
    push_block(BLOCK_TYPE_WHILE, condition_result, loop_fpos_at_while_line, current_line_no);


    if (condition_result && current_exec_state != STATE_BLOCK_SKIP) {
        current_exec_state = STATE_BLOCK_EXECUTE;
    } else {
        current_exec_state = STATE_BLOCK_SKIP;
    }

    if (! (num_tokens > 4 && tokens[num_tokens-1].type == TOKEN_LBRACE) &&
        ! (num_tokens == 4 && strcmp(tokens[0].text,"while")==0) ) {
         fprintf(stderr, "Syntax error for 'while': '{' expected after condition or on next line.\n");
    }
}

void handle_inc_dec_statement_advanced(Token *tokens, int num_tokens, bool increment) {
    if (num_tokens != 2 || (tokens[1].type != TOKEN_VARIABLE && tokens[1].type != TOKEN_WORD)) {
        fprintf(stderr, "Syntax: %s <$varname_or_varname>\n", increment ? "inc" : "dec");
        return;
    }
    if (current_exec_state == STATE_BLOCK_SKIP) return;

    const char* var_name_token_text = tokens[1].text;
    char var_name[MAX_VAR_NAME_LEN];

    if (tokens[1].type == TOKEN_VARIABLE) { 
        // Check if it's an array element like $arr[idx]
        char temp_text[MAX_VAR_NAME_LEN];
        strncpy(temp_text, var_name_token_text + 1, sizeof(temp_text)-1); // Skip $
        temp_text[sizeof(temp_text)-1] = '\0';

        char* bracket = strchr(temp_text, '[');
        if (bracket) { // It's an array element
            char base_name[MAX_VAR_NAME_LEN];
            char index_raw[MAX_VAR_NAME_LEN];
            char index_expanded[MAX_VAR_VALUE_LEN];

            size_t base_len = bracket - temp_text;
            strncpy(base_name, temp_text, base_len);
            base_name[base_len] = '\0';

            char* end_bracket = strrchr(bracket, ']');
            if (!end_bracket || end_bracket <= bracket + 1) {
                fprintf(stderr, "Malformed array index in %s: %s\n", increment ? "inc" : "dec", var_name_token_text);
                return;
            }
            size_t index_len = end_bracket - (bracket + 1);
            strncpy(index_raw, bracket + 1, index_len);
            index_raw[index_len] = '\0';

            if (index_raw[0] == '"' && index_raw[strlen(index_raw)-1] == '"') {
                unescape_string(index_raw, index_expanded, sizeof(index_expanded));
            } else if (index_raw[0] == '$') {
                expand_variables_in_string_advanced(index_raw, index_expanded, sizeof(index_expanded));
            } else {
                strncpy(index_expanded, index_raw, sizeof(index_expanded)-1);
                index_expanded[sizeof(index_expanded)-1] = '\0';
            }
            
            char* current_elem_val_str = get_array_element(base_name, index_expanded);
            long current_elem_val = 0;
            if(current_elem_val_str){
                char *endptr; errno = 0;
                current_elem_val = strtol(current_elem_val_str, &endptr, 10);
                if (errno != 0 || *current_elem_val_str == '\0' || *endptr != '\0') {
                    fprintf(stderr, "Warning: Array element %s[%s] ('%s') is not a valid integer for %s. Treating as 0.\n", base_name, index_expanded, current_elem_val_str, increment ? "inc" : "dec");
                    current_elem_val = 0;
                }
            }
            current_elem_val += (increment ? 1 : -1);
            char new_elem_val_str[MAX_VAR_VALUE_LEN];
            snprintf(new_elem_val_str, sizeof(new_elem_val_str), "%ld", current_elem_val);
            set_array_element(base_name, index_expanded, new_elem_val_str); // Note: set_array_element expands index again, could optimize
            return;

        } else { // Simple variable $var
             strncpy(var_name, temp_text, MAX_VAR_NAME_LEN -1);
        }
    } else { // var (unquoted word)
        strncpy(var_name, var_name_token_text, MAX_VAR_NAME_LEN -1);
    }
    var_name[MAX_VAR_NAME_LEN-1] = '\0';


    char* current_val_str = get_variable(var_name);
    long current_val = 0;
    if (current_val_str) {
        char *endptr; errno = 0;
        current_val = strtol(current_val_str, &endptr, 10);
        if (errno != 0 || *current_val_str == '\0' || *endptr != '\0') { 
            fprintf(stderr, "Warning: Variable '%s' ('%s') is not a valid integer for %s. Treating as 0.\n", var_name, current_val_str, increment ? "inc" : "dec");
            current_val = 0;
        }
    } 
    current_val += (increment ? 1 : -1);
    char new_val_str[MAX_VAR_VALUE_LEN];
    snprintf(new_val_str, sizeof(new_val_str), "%ld", current_val);
    set_variable(var_name, new_val_str, false);
}

void handle_defunc_statement_advanced(Token *tokens, int num_tokens) {
    if (num_tokens < 2 || tokens[1].type != TOKEN_WORD) {
        fprintf(stderr, "Syntax: defunc <funcname> [(param1 ...)] [{]\n");
        return;
    }
    if (is_defining_function && current_exec_state != STATE_IMPORT_PARSING) { 
        fprintf(stderr, "Error: Cannot nest function definitions during normal execution.\n");
        return;
    }
    if (current_exec_state == STATE_BLOCK_SKIP && current_exec_state != STATE_IMPORT_PARSING) { // Allow defunc during import even if outer block is skipping
        push_block(BLOCK_TYPE_FUNCTION_DEF, false, 0, 0); 
        return;
    }

    current_function_definition = (UserFunction*)malloc(sizeof(UserFunction));
    if (!current_function_definition) {
        perror("malloc for function definition failed");
        return;
    }
    memset(current_function_definition, 0, sizeof(UserFunction));
    strncpy(current_function_definition->name, tokens[1].text, MAX_VAR_NAME_LEN - 1);

    int token_idx = 2; 
    if (token_idx < num_tokens && tokens[token_idx].type == TOKEN_LPAREN) {
        token_idx++; 
        while(token_idx < num_tokens && tokens[token_idx].type != TOKEN_RPAREN) {
            if (tokens[token_idx].type == TOKEN_WORD) { 
                if (current_function_definition->param_count < MAX_FUNC_PARAMS) {
                    strncpy(current_function_definition->params[current_function_definition->param_count++],
                            tokens[token_idx].text, MAX_VAR_NAME_LEN -1);
                } else {
                    fprintf(stderr, "Too many parameters for function %s (max %d).\n", current_function_definition->name, MAX_FUNC_PARAMS);
                    free(current_function_definition); current_function_definition = NULL; return;
                }
            } else {
                fprintf(stderr, "Syntax error in function parameters: Expected word, got '%s' for %s\n", tokens[token_idx].text, current_function_definition->name);
                free(current_function_definition); current_function_definition = NULL; return;
            }
            token_idx++;
        }
        if (token_idx < num_tokens && tokens[token_idx].type == TOKEN_RPAREN) {
            token_idx++; 
        } else {
            fprintf(stderr, "Syntax error in function parameters: missing ')' for %s\n", current_function_definition->name);
            free(current_function_definition); current_function_definition = NULL; return;
        }
    }

    if (token_idx < num_tokens && tokens[token_idx].type == TOKEN_LBRACE) {
        is_defining_function = true;
        if (current_exec_state != STATE_IMPORT_PARSING) {
            current_exec_state = STATE_DEFINE_FUNC_BODY;
        }
        push_block(BLOCK_TYPE_FUNCTION_DEF, true, 0, 0); 
    } else if (token_idx == num_tokens) {
        is_defining_function = true;
        if (current_exec_state != STATE_IMPORT_PARSING) {
            current_exec_state = STATE_DEFINE_FUNC_BODY;
        }
    } else {
        fprintf(stderr, "Syntax error in function definition: '{' expected for %s, got '%s'\n", current_function_definition->name, tokens[token_idx].text);
        free(current_function_definition); current_function_definition = NULL;
    }
}

void handle_import_statement(Token *tokens, int num_tokens) {
    if (num_tokens != 2 || (tokens[1].type != TOKEN_STRING && tokens[1].type != TOKEN_WORD && tokens[1].type != TOKEN_VARIABLE)) {
        fprintf(stderr, "Syntax: import \"<filename.bsh>\" or import $filepath_var or import unquoted_path\n");
        return;
    }
    if (current_exec_state == STATE_BLOCK_SKIP) return; 

    char filename_to_import[MAX_LINE_LENGTH];
    if (tokens[1].type == TOKEN_STRING) { 
        unescape_string(tokens[1].text, filename_to_import, sizeof(filename_to_import));
    } else { 
        expand_variables_in_string_advanced(tokens[1].text, filename_to_import, sizeof(filename_to_import));
    }

    if (strlen(filename_to_import) == 0) {
        fprintf(stderr, "Import error: Filename is empty after expansion.\n");
        return;
    }

    bool outer_is_defining_function = is_defining_function;
    UserFunction* outer_current_function_definition = current_function_definition;
    ExecutionState outer_exec_state = current_exec_state; 

    is_defining_function = false;
    current_function_definition = NULL;
    
    execute_script(filename_to_import, true, false); // true: is_import, false: not_startup

    is_defining_function = outer_is_defining_function;
    current_function_definition = outer_current_function_definition;
    current_exec_state = outer_exec_state; 
}

void handle_loadlib_statement(Token *tokens, int num_tokens) {
    if (num_tokens != 3) {
        fprintf(stderr, "Syntax: loadlib <path_to_lib.so | $path_var> <alias | $alias_var>\n");
        return;
    }
    if (current_exec_state == STATE_BLOCK_SKIP) return;

    char lib_path[MAX_FULL_PATH_LEN];
    char alias[MAX_VAR_NAME_LEN];

    if(tokens[1].type == TOKEN_STRING) unescape_string(tokens[1].text, lib_path, sizeof(lib_path));
    else expand_variables_in_string_advanced(tokens[1].text, lib_path, sizeof(lib_path));

    if(tokens[2].type == TOKEN_STRING) unescape_string(tokens[2].text, alias, sizeof(alias));
    else expand_variables_in_string_advanced(tokens[2].text, alias, sizeof(alias));


    if (strlen(lib_path) == 0 || strlen(alias) == 0) {
        fprintf(stderr, "loadlib error: Library path or alias is empty after expansion.\n");
        return;
    }

    DynamicLib* current_lib = loaded_libs;
    while(current_lib) {
        if (strcmp(current_lib->alias, alias) == 0) {
            fprintf(stderr, "Error: Library alias '%s' already in use.\n", alias);
            return;
        }
        current_lib = current_lib->next;
    }

    void *handle = dlopen(lib_path, RTLD_LAZY | RTLD_GLOBAL); 
    if (!handle) {
        fprintf(stderr, "Error loading library '%s': %s\n", lib_path, dlerror());
        return;
    }

    DynamicLib *new_lib_entry = (DynamicLib*)malloc(sizeof(DynamicLib));
    if (!new_lib_entry) {
        perror("malloc for new_lib_entry failed");
        dlclose(handle);
        return;
    }
    strncpy(new_lib_entry->alias, alias, MAX_VAR_NAME_LEN -1);
    new_lib_entry->handle = handle;
    new_lib_entry->next = loaded_libs;
    loaded_libs = new_lib_entry;
    printf("Library '%s' loaded as alias '%s'.\n", lib_path, alias);
}

void handle_calllib_statement(Token *tokens, int num_tokens) {
    if (num_tokens < 3) {
        fprintf(stderr, "Syntax: calllib <alias | $var> <func_name | $var> [args...]\n");
        return;
    }
     if (current_exec_state == STATE_BLOCK_SKIP) return;

    char alias[MAX_VAR_NAME_LEN];
    char func_name[MAX_VAR_NAME_LEN]; 

    if(tokens[1].type == TOKEN_STRING) unescape_string(tokens[1].text, alias, sizeof(alias));
    else expand_variables_in_string_advanced(tokens[1].text, alias, sizeof(alias));
    
    if(tokens[2].type == TOKEN_STRING) unescape_string(tokens[2].text, func_name, sizeof(func_name));
    else expand_variables_in_string_advanced(tokens[2].text, func_name, sizeof(func_name));


    if (strlen(alias) == 0 || strlen(func_name) == 0) {
        fprintf(stderr, "calllib error: Library alias or function name is empty after expansion.\n");
        return;
    }

    DynamicLib* lib_entry = loaded_libs;
    void* lib_handle = NULL;
    while(lib_entry) {
        if (strcmp(lib_entry->alias, alias) == 0) {
            lib_handle = lib_entry->handle;
            break;
        }
        lib_entry = lib_entry->next;
    }

    if (!lib_handle) {
        fprintf(stderr, "Error: Library alias '%s' not found.\n", alias);
        return;
    }
    
    dlerror(); // Clear any existing error
    void* func_ptr = dlsym(lib_handle, func_name);
    char* dlsym_error = dlerror(); 
    if (dlsym_error != NULL) { 
        fprintf(stderr, "Error finding function '%s' in library '%s': %s\n", func_name, alias, dlsym_error);
        return;
    }
    if (!func_ptr) { 
         fprintf(stderr, "Error finding function '%s' in library '%s' (pointer is NULL, no error from dlerror).\n", func_name, alias);
        return;
    }

    typedef int (*lib_func_sig_t)(int, char**, char*, int);
    lib_func_sig_t target_func = (lib_func_sig_t)func_ptr;

    int lib_argc = num_tokens - 3;
    char* lib_argv_expanded_storage[MAX_ARGS][MAX_VAR_VALUE_LEN]; 
    char* lib_argv[MAX_ARGS + 1]; 

    for(int i=0; i < lib_argc; ++i) {
        if (tokens[i+3].type == TOKEN_STRING) {
            char unescaped[MAX_VAR_VALUE_LEN];
            unescape_string(tokens[i+3].text, unescaped, sizeof(unescaped));
            expand_variables_in_string_advanced(unescaped, lib_argv_expanded_storage[i], MAX_VAR_VALUE_LEN);
        } else {
            expand_variables_in_string_advanced(tokens[i+3].text, lib_argv_expanded_storage[i], MAX_VAR_VALUE_LEN);
        }
        lib_argv[i] = lib_argv_expanded_storage[i];
    }
    lib_argv[lib_argc] = NULL; 

    char lib_output_buffer[MAX_VAR_VALUE_LEN]; 
    lib_output_buffer[0] = '\0';

    // printf("Calling '%s' from library '%s'...\n", func_name, alias);
    int lib_status = target_func(lib_argc, lib_argv, lib_output_buffer, sizeof(lib_output_buffer));
    
    char status_str[12]; // For int to string
    snprintf(status_str, sizeof(status_str), "%d", lib_status);
    set_variable("LAST_LIB_CALL_STATUS", status_str, false); 
    set_variable("LAST_LIB_CALL_OUTPUT", lib_output_buffer, false);

    // printf("Library function '%s' returned status: %d. Output: %s\n", func_name, lib_status, lib_output_buffer);
    if (lib_status != 0) {
        // fprintf(stderr, "Warning: Library function '%s' indicated an error (status %d).\n", func_name, lib_status);
    }
}


// Block Management functions (push_block, pop_block, peek_block, handle_opening_brace_token, handle_closing_brace_token)
// are mostly the same as the previous version.
void push_block(BlockType type, bool condition_true, long loop_start_fpos, int loop_start_line_no) {
    if (block_stack_top >= MAX_NESTING_DEPTH - 1) {
        fprintf(stderr, "Error: Maximum nesting depth exceeded (%d).\n", MAX_NESTING_DEPTH);
        return;
    }
    block_stack_top++;
    block_stack[block_stack_top].type = type;
    block_stack[block_stack_top].condition_true = condition_true;
    block_stack[block_stack_top].loop_start_fpos = loop_start_fpos;
    block_stack[block_stack_top].loop_start_line_no = loop_start_line_no;
    block_stack[block_stack_top].prev_exec_state = current_exec_state;
}

BlockFrame* pop_block() {
    if (block_stack_top < 0) {
        // This can be normal if a startup script ends with an open block that we auto-close.
        // fprintf(stderr, "Error: Block stack underflow (pop_block).\n");
        return NULL; 
    }
    return &block_stack[block_stack_top--];
}

BlockFrame* peek_block() {
    if (block_stack_top < 0) {
        return NULL;
    }
    return &block_stack[block_stack_top];
}

void handle_opening_brace_token(Token token) { 
    BlockFrame* current_block_frame = peek_block();
    if (!current_block_frame) {
        if (is_defining_function && current_function_definition && current_exec_state != STATE_BLOCK_SKIP) {
            push_block(BLOCK_TYPE_FUNCTION_DEF, true, 0, 0); 
            return;
        }
        fprintf(stderr, "Error: '{' found without a preceding if/else/while/defunc statement expecting it.\n");
        return;
    }

    if (current_block_frame->type == BLOCK_TYPE_FUNCTION_DEF) {
        // Handled by defunc logic
    } else if (current_block_frame->condition_true && current_exec_state != STATE_BLOCK_SKIP) {
        current_exec_state = STATE_BLOCK_EXECUTE;
    } else { 
        current_exec_state = STATE_BLOCK_SKIP;
    }
}

void handle_closing_brace_token(Token token, FILE* input_source) { 
    BlockFrame* closed_block_frame = pop_block();
    if (!closed_block_frame) {
        fprintf(stderr, "Error: '}' found without a matching open block.\n");
        current_exec_state = STATE_NORMAL; 
        return;
    }

    BlockFrame* parent_block = peek_block();
    ExecutionState state_before_closed_block = closed_block_frame->prev_exec_state;


    if (closed_block_frame->type == BLOCK_TYPE_WHILE && closed_block_frame->condition_true && current_exec_state != STATE_BLOCK_SKIP) {
        // Attempt to re-evaluate the while condition.
        // This requires seeking back in the input file or re-processing from memory (for functions).
        // The `loop_start_fpos` is for file-based scripts, `loop_start_line_no` for others.
        bool can_loop = false;
        if (input_source && input_source != stdin && closed_block_frame->loop_start_fpos != -1 && closed_block_frame->loop_start_fpos > 0) { // Check fpos is valid
             // Ensure fpos is for the *start* of the while line. This needs to be set correctly when pushing.
            if (fseek(input_source, closed_block_frame->loop_start_fpos, SEEK_SET) == 0) {
                can_loop = true;
            } else {
                perror("fseek failed for while loop");
            }
        } else if (closed_block_frame->loop_start_line_no > 0 && !input_source) { // e.g. inside a function
             // TODO: Line-based looping for function bodies. This is complex.
             // For now, functions' while loops might not repeat correctly without file context.
             fprintf(stderr, "Warning: 'while' loop repetition inside function (line %d) requires memory-based re-evaluation (not fully implemented).\n", closed_block_frame->loop_start_line_no);
        } else {
             // Cannot loop (interactive, or no valid loop point)
        }

        if (can_loop) {
            // The next iteration of execute_script's fgets will re-read the 'while' line.
            // The state should allow the 'while' to be re-processed normally.
            current_exec_state = STATE_NORMAL; // Or state_before_closed_block if more appropriate
                                               // The 'while' handler will then set EXECUTE or SKIP.
            return; // Return to allow execute_script to re-read
        } else {
            // Cannot loop, so proceed to set state based on parent or normal.
        }
    }
    
    // General state restoration after closing a block
    if (!parent_block) { 
        current_exec_state = STATE_NORMAL;
    } else { 
        if (parent_block->type == BLOCK_TYPE_FUNCTION_DEF && is_defining_function) {
             current_exec_state = STATE_DEFINE_FUNC_BODY;
        } else if (parent_block->condition_true) {
            current_exec_state = STATE_BLOCK_EXECUTE;
        } else {
            current_exec_state = STATE_BLOCK_SKIP;
        }
    }


    if (closed_block_frame->type == BLOCK_TYPE_FUNCTION_DEF) {
        if (current_function_definition) { 
            current_function_definition->next = function_list;
            function_list = current_function_definition;
            if (current_exec_state != STATE_IMPORT_PARSING && state_before_closed_block != STATE_IMPORT_PARSING) { 
                printf("Function '%s' defined with %d parameters and %d lines.\n",
                       current_function_definition->name,
                       current_function_definition->param_count,
                       current_function_definition->line_count);
            }
            current_function_definition = NULL;
        }
        is_defining_function = false;
        // State after func def is determined by what was before it (state_before_closed_block), or normal if top level.
        current_exec_state = state_before_closed_block;
        if (!parent_block && current_exec_state == STATE_DEFINE_FUNC_BODY) { // Exited top-level func def
            current_exec_state = STATE_NORMAL;
        }
    }
    
    if (block_stack_top == -1 && current_exec_state != STATE_DEFINE_FUNC_BODY) { 
        current_exec_state = STATE_NORMAL;
    }
}


// --- Utility Implementations ---
char* trim_whitespace(char *str) {
    if (!str) return NULL;
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = 0;
    return str;
}

void free_variable_list() {
    Variable *current = variable_list;
    Variable *next_var;
    while (current != NULL) {
        next_var = current->next;
        free(current);
        current = next_var;
    }
    variable_list = NULL;
}

void free_function_list() {
    UserFunction *current = function_list;
    UserFunction *next_func;
    while (current != NULL) {
        next_func = current->next;
        for (int i = 0; i < current->line_count; ++i) {
            if(current->body[i]) free(current->body[i]);
        }
        free(current);
        current = next_func;
    }
    function_list = NULL;
}

void free_loaded_libs() {
    DynamicLib *current = loaded_libs;
    DynamicLib *next_lib;
    while(current) {
        next_lib = current->next;
        if (current->handle) {
            dlclose(current->handle);
        }
        free(current);
        current = next_lib;
    }
    loaded_libs = NULL;
}

long get_file_pos(FILE* f) {
    if (!f || f == stdin || f == stdout || f == stderr) return -1;
    long pos = ftell(f);
    if (pos == -1L) {
        return -1;
    }
    return pos;
}

