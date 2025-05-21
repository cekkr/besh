#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <ctype.h>
#include <dlfcn.h> // For dynamic library loading (dlopen, dlsym, dlclose)

// --- Constants and Definitions ---
#define MAX_LINE_LENGTH 2048
#define MAX_ARGS 64
#define MAX_VAR_NAME_LEN 256
#define MAX_VAR_VALUE_LEN 1024
#define MAX_PATH_DIRS 64
#define MAX_FULL_PATH_LEN 1024
#define TOKEN_BUFFER_SIZE MAX_LINE_LENGTH
#define MAX_NESTING_DEPTH 32
#define MAX_FUNC_LINES 100
#define MAX_FUNC_PARAMS 10

// --- Variable Management ---
typedef struct Variable {
    char name[MAX_VAR_NAME_LEN];
    char value[MAX_VAR_VALUE_LEN];
    struct Variable *next;
} Variable;
Variable *variable_list = NULL;

// --- User-Defined Functions (Macros) ---
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

// --- PATH Environment ---
char *path_dirs[MAX_PATH_DIRS];
int num_path_dirs = 0;

// --- Execution State and Block Management ---
typedef enum {
    STATE_NORMAL,                // Normal execution
    STATE_BLOCK_EXECUTE,         // Executing inside a block ({...}) that should run
    STATE_BLOCK_SKIP,            // Skipping commands inside a block ({...})
    STATE_DEFINE_FUNC_BODY       // Inside a function definition body
} ExecutionState;
ExecutionState current_exec_state = STATE_NORMAL;

typedef enum {
    BLOCK_TYPE_IF,
    BLOCK_TYPE_ELSE,
    BLOCK_TYPE_WHILE,
    BLOCK_TYPE_FUNCTION_DEF // For managing { } in function definitions
} BlockType;

typedef struct BlockFrame {
    BlockType type;
    long loop_start_fpos;        // File position for `while` loop start (for fseek)
    int loop_start_line_no;      // Line number for `while` loop start (for in-memory scripts/interactive)
    bool condition_true;         // Was the entry condition for if/while true?
    ExecutionState prev_exec_state; // Execution state before entering this block
} BlockFrame;

BlockFrame block_stack[MAX_NESTING_DEPTH];
int block_stack_top = -1; // -1 means stack is empty

// For dynamic library handles
typedef struct DynamicLib {
    char alias[MAX_VAR_NAME_LEN];
    void *handle;
    struct DynamicLib *next;
} DynamicLib;
DynamicLib *loaded_libs = NULL;


// --- Function Prototypes ---

// Core
void initialize_shell();
void process_line(char *line, FILE *input_source, int current_line_no /* for while loops without fseek */);
void execute_script(const char *filename);
void cleanup_shell();

// Variable Management
char* get_variable(const char *name_raw);
void set_variable(const char *name_raw, const char *value);
void expand_variables_in_string(const char *input_str, char *expanded_str, size_t expanded_str_size);
char* get_array_element(const char* array_base_name, const char* index_str_raw);
void set_array_element(const char* array_base_name, const char* index_str_raw, const char* value);

// Command Execution
bool find_command_in_path(const char *command, char *full_path);
int execute_external_command(char *command_path, char **args, int arg_count, char *output_buffer, size_t output_buffer_size);
void execute_user_function(UserFunction* func, char** call_args, int call_arg_count, FILE* input_source_for_context);


// Parsing and Tokenization
void tokenize_line(const char *line, char **tokens, int *num_tokens, char *token_storage);

// Built-in Commands and Statements
void handle_assignment(char **tokens, int num_tokens);
void handle_echo(char **tokens, int num_tokens);
bool evaluate_condition(const char* operand1_raw, const char* operator_str, const char* operand2_raw);
void handle_if_statement(char **tokens, int num_tokens, FILE* input_source, int current_line_no);
void handle_else_statement(char **tokens, int num_tokens, FILE* input_source, int current_line_no);
void handle_while_statement(char **tokens, int num_tokens, FILE* input_source, int current_line_no);
void handle_defunc_statement(char **tokens, int num_tokens);
void handle_inc_dec_statement(char **tokens, int num_tokens, bool increment);
void handle_loadlib_statement(char **tokens, int num_tokens);
void handle_calllib_statement(char **tokens, int num_tokens);


// Block Management
void push_block(BlockType type, bool condition_true, long loop_start_fpos, int loop_start_line_no);
BlockFrame* pop_block();
BlockFrame* peek_block();
void handle_opening_brace();
void handle_closing_brace(FILE* input_source);


// Utility
char* trim_whitespace(char *str);
void free_variable_list();
void free_function_list();
void free_loaded_libs();
long get_file_pos(FILE* f); // Helper for ftell with error check

// --- Main ---
int main(int argc, char *argv[]) {
    initialize_shell();

    if (argc > 1) {
        execute_script(argv[1]);
    } else {
        char line[MAX_LINE_LENGTH];
        char prompt_buffer[MAX_VAR_NAME_LEN + 20];
        int line_counter_interactive = 0; // For potential future use with interactive loops

        while (1) {
            const char* base_prompt = "bsh";
            char state_indicator[15] = "";

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
                     snprintf(state_indicator, sizeof(state_indicator), "(defunc %s)", current_function_definition ? current_function_definition->name : "");
                }
                else {
                    snprintf(state_indicator, sizeof(state_indicator), "(%s %d)", block_type_str, block_stack_top + 1);
                }
            }

            snprintf(prompt_buffer, sizeof(prompt_buffer), "%s%s> ", base_prompt, state_indicator);
            printf("%s", prompt_buffer);

            if (!fgets(line, sizeof(line), stdin)) {
                printf("\n"); // EOF (Ctrl+D)
                break;
            }
            line_counter_interactive++;
            process_line(line, stdin, line_counter_interactive);
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
        char *token = strtok(path_copy, ":");
        while (token != NULL && num_path_dirs < MAX_PATH_DIRS) {
            path_dirs[num_path_dirs++] = strdup(token);
            if (!path_dirs[num_path_dirs-1]) { perror("strdup for path_dir failed"); /* continue or exit */ }
            token = strtok(NULL, ":");
        }
        free(path_copy);
    }
}

void cleanup_shell() {
    free_variable_list();
    free_function_list();
    free_loaded_libs();
    for (int i = 0; i < num_path_dirs; i++) {
        free(path_dirs[i]);
    }
}


void process_line(char *line_orig, FILE *input_source, int current_line_no) {
    char line[MAX_LINE_LENGTH];
    strncpy(line, line_orig, MAX_LINE_LENGTH - 1);
    line[MAX_LINE_LENGTH - 1] = '\0';

    char *trimmed_line = trim_whitespace(line);

    if (strlen(trimmed_line) == 0 || trimmed_line[0] == '#') { // Empty line or comment
        return;
    }

    // Handle function definition body
    if (is_defining_function && current_exec_state == STATE_DEFINE_FUNC_BODY) {
        if (strcmp(trimmed_line, "}") == 0) {
            handle_closing_brace(input_source); // This will finalize function definition
            return;
        }
        if (current_function_definition && current_function_definition->line_count < MAX_FUNC_LINES) {
            current_function_definition->body[current_function_definition->line_count++] = strdup(trimmed_line);
        } else {
            fprintf(stderr, "Error: Function body too long or no active function definition.\n");
            is_defining_function = false; // Abort definition
            current_exec_state = (block_stack_top >=0) ? peek_block()->prev_exec_state : STATE_NORMAL; // Revert state
            if (current_function_definition) { /* cleanup partially defined func */ }
        }
        return;
    }


    char token_storage[TOKEN_BUFFER_SIZE];
    char *tokens[MAX_ARGS];
    int num_tokens = 0;
    tokenize_line(trimmed_line, tokens, &num_tokens, token_storage);

    if (num_tokens == 0) {
        return;
    }
    
    // Special handling for '{' and '}' as standalone tokens affecting blocks
    if (strcmp(tokens[0], "{") == 0 && num_tokens == 1) {
        handle_opening_brace();
        return;
    }
    if (strcmp(tokens[0], "}") == 0 && num_tokens == 1) {
        handle_closing_brace(input_source);
        // If state changed to cause re-evaluation (like for 'while'), return immediately.
        // The re-evaluation will be handled by the caller (execute_script loop).
        return;
    }

    // If currently skipping commands within a block
    if (current_exec_state == STATE_BLOCK_SKIP) {
        // Only care about block delimiters or nested structures that also need skipping
        if (strcmp(tokens[0], "if") == 0) {
            push_block(BLOCK_TYPE_IF, false, 0, 0); // Condition false, just for nesting
        } else if (strcmp(tokens[0], "while") == 0) {
            push_block(BLOCK_TYPE_WHILE, false, 0, 0); // Condition false, for nesting
        } else if (strcmp(tokens[0], "else") == 0) {
            BlockFrame* top_block = peek_block();
            if (top_block && top_block->type == BLOCK_TYPE_IF) {
                // If the 'if' was true, this 'else' is skipped. If 'if' was false, this 'else' might execute.
                // This logic is handled by handle_else_statement.
                // For skipping, we just need to ensure nesting is correct.
                // This part is tricky: if we are skipping, an 'else' for a skipped 'if'
                // should also be skipped until its '{'.
                // The `handle_else_statement` will set the state correctly.
                // Here, we just let it pass to the dispatcher if it's `else`.
            }
        } else if (strcmp(tokens[0], "{") == 0) { // Should be caught by standalone check above
            handle_opening_brace();
        } else if (strcmp(tokens[0], "}") == 0) { // Should be caught by standalone check above
            handle_closing_brace(input_source);
        }
        // If not a block control keyword, just ignore the line.
        // However, if/else/while need to be "parsed" to correctly find their '}'
        // So, we let them fall through to their handlers, which will respect STATE_BLOCK_SKIP.
        // The return for STATE_BLOCK_SKIP should be *after* checking these keywords.
        if (strcmp(tokens[0], "if") != 0 && strcmp(tokens[0], "else") != 0 &&
            strcmp(tokens[0], "while") != 0 && strcmp(tokens[0], "{") != 0 &&
            strcmp(tokens[0], "}") != 0) {
            return; // Skip this command
        }
    }


    // --- Command Dispatcher ---
    if (strcmp(tokens[0], "exit") == 0 && block_stack_top == -1) {
        cleanup_shell();
        exit(0);
    } else if (tokens[0][0] == '$' && num_tokens > 1 && strcmp(tokens[1], "=") == 0) {
        handle_assignment(tokens, num_tokens);
    } else if (strcmp(tokens[0], "if") == 0) {
        handle_if_statement(tokens, num_tokens, input_source, current_line_no);
    } else if (strcmp(tokens[0], "else") == 0) {
        handle_else_statement(tokens, num_tokens, input_source, current_line_no);
    } else if (strcmp(tokens[0], "while") == 0) {
        handle_while_statement(tokens, num_tokens, input_source, current_line_no);
    } else if (strcmp(tokens[0], "echo") == 0) {
        handle_echo(tokens, num_tokens);
    } else if (strcmp(tokens[0], "inc") == 0) {
        handle_inc_dec_statement(tokens, num_tokens, true);
    } else if (strcmp(tokens[0], "dec") == 0) {
        handle_inc_dec_statement(tokens, num_tokens, false);
    } else if (strcmp(tokens[0], "defunc") == 0) {
        handle_defunc_statement(tokens, num_tokens);
    } else if (strcmp(tokens[0], "loadlib") == 0) {
        handle_loadlib_statement(tokens, num_tokens);
    } else if (strcmp(tokens[0], "calllib") == 0) {
        handle_calllib_statement(tokens, num_tokens);
    }
    else {
        // Check for user-defined function call
        UserFunction* func_to_call = function_list;
        while(func_to_call) {
            if (strcmp(tokens[0], func_to_call->name) == 0) {
                execute_user_function(func_to_call, tokens + 1, num_tokens - 1, input_source);
                return;
            }
            func_to_call = func_to_call->next;
        }

        // External command
        char expanded_args_storage[MAX_ARGS][MAX_VAR_VALUE_LEN];
        char *expanded_argv[MAX_ARGS + 1];
        for (int i = 0; i < num_tokens; i++) {
            expand_variables_in_string(tokens[i], expanded_args_storage[i], MAX_VAR_VALUE_LEN);
            expanded_argv[i] = expanded_args_storage[i];
        }
        expanded_argv[num_tokens] = NULL;

        char full_command_path[MAX_FULL_PATH_LEN];
        if (find_command_in_path(expanded_argv[0], full_command_path)) {
            execute_external_command(full_command_path, expanded_argv, num_tokens, NULL, 0);
        } else {
            fprintf(stderr, "Command not found: %s\n", expanded_argv[0]);
        }
    }
}

void execute_script(const char *filename) {
    FILE *script_file = fopen(filename, "r");
    if (!script_file) {
        perror("Error opening script");
        return;
    }
    char line_buffer[MAX_LINE_LENGTH];
    long initial_fpos_stack[MAX_NESTING_DEPTH]; // To store fpos for while loops
    int line_no = 0;

    // Store current file position before reading each line for while loops
    long current_fpos = get_file_pos(script_file);

    while (fgets(line_buffer, sizeof(line_buffer), script_file)) {
        line_no++;
        process_line(line_buffer, script_file, line_no);

        // Check if a while loop needs to jump back
        if (block_stack_top >= 0) {
            BlockFrame* top_block = peek_block();
            if (top_block->type == BLOCK_TYPE_WHILE && top_block->condition_true && current_exec_state == STATE_BLOCK_EXECUTE) {
                 // This state indicates that a '}' of a true while loop was just processed
                 // and handle_closing_brace decided to loop.
                 // The fseek should have been done in handle_closing_brace.
                 // We just need to ensure the next fgets reads from the correct place.
                 // The current_exec_state might be reset by handle_closing_brace.
                 // Let's refine: handle_closing_brace, if it's a while loop end, will fseek.
                 // The next fgets will naturally read from there.
            }
        }
        current_fpos = get_file_pos(script_file); // Update for the next line
    }
    fclose(script_file);
}

// --- Variable Management Implementations ---

void expand_variables_in_string(const char *input_str, char *expanded_str, size_t expanded_str_size) {
    const char *p_in = input_str;
    char *p_out = expanded_str;
    size_t remaining_size = expanded_str_size - 1; // For \0
    expanded_str[0] = '\0';


    while (*p_in && remaining_size > 0) {
        if (*p_in == '$') {
            p_in++; // Skip '$'
            char var_name_buffer[MAX_VAR_NAME_LEN];
            char index_str_buffer[MAX_VAR_NAME_LEN]; 
            char *pv = var_name_buffer;
            bool is_array = false;
            char array_base_name[MAX_VAR_NAME_LEN];

            if (*p_in == '{') { // ${varname} or ${arr[idx]}
                p_in++; // Skip '{'
                char temp_name_or_expr[MAX_VAR_NAME_LEN];
                char *pt = temp_name_or_expr;
                int brace_level = 1;
                while(*p_in && brace_level > 0 && (pt - temp_name_or_expr < MAX_VAR_NAME_LEN -1)){
                    if(*p_in == '{') brace_level++;
                    else if (*p_in == '}') brace_level--;
                    if(brace_level > 0) *pt++ = *p_in;
                    p_in++;
                }
                *pt = '\0'; // temp_name_or_expr now holds "varname" or "arr[idx]"
                
                // Now parse temp_name_or_expr for array access
                char* bracket_ptr = strchr(temp_name_or_expr, '[');
                if (bracket_ptr) {
                    is_array = true;
                    size_t base_len = bracket_ptr - temp_name_or_expr;
                    strncpy(array_base_name, temp_name_or_expr, base_len);
                    array_base_name[base_len] = '\0';

                    char* end_bracket_ptr = strrchr(bracket_ptr, ']');
                    if (end_bracket_ptr && end_bracket_ptr > bracket_ptr + 1) {
                        size_t index_len = end_bracket_ptr - (bracket_ptr + 1);
                        strncpy(index_str_buffer, bracket_ptr + 1, index_len);
                        index_str_buffer[index_len] = '\0';
                    } else { /* invalid array syntax in ${} */ index_str_buffer[0] = '\0';}
                } else {
                    strncpy(var_name_buffer, temp_name_or_expr, MAX_VAR_NAME_LEN -1);
                    var_name_buffer[MAX_VAR_NAME_LEN-1] = '\0';
                }
            } else { // $varname or $arr[idx] (no curly braces)
                while (*p_in && (isalnum((unsigned char)*p_in) || *p_in == '_') && (pv - var_name_buffer < MAX_VAR_NAME_LEN - 1)) {
                    *pv++ = *p_in++;
                }
                *pv = '\0';
                
                if (*p_in == '[') { // Array access $arr[index]
                    is_array = true;
                    strncpy(array_base_name, var_name_buffer, MAX_VAR_NAME_LEN); 
                    p_in++; // Skip '['
                    char *pi = index_str_buffer;
                    int bracket_level = 1; 
                    while (*p_in && bracket_level > 0 && (pi - index_str_buffer < MAX_VAR_NAME_LEN -1)){
                        if (*p_in == '[') bracket_level++;
                        else if (*p_in == ']') bracket_level--;
                        
                        if (bracket_level > 0) { 
                             *pi++ = *p_in;
                        }
                        p_in++; 
                    }
                    *pi = '\0';
                }
            }


            char *value_to_insert = NULL;
            if (is_array) {
                char expanded_index_val[MAX_VAR_VALUE_LEN];
                expand_variables_in_string(index_str_buffer, expanded_index_val, sizeof(expanded_index_val)); // Recursive call for index
                value_to_insert = get_array_element(array_base_name, expanded_index_val);
            } else {
                value_to_insert = get_variable(var_name_buffer);
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
        } else if (*p_in == '\\' && *(p_in+1) == '$') { // Escaped dollar sign \$
            p_in++; // Skip '\'
            if (remaining_size > 0) {
                *p_out++ = *p_in++; // Copy '$'
                remaining_size--;
            }
        }
        else { 
            *p_out++ = *p_in++;
            remaining_size--;
        }
    }
    *p_out = '\0';
}

char* get_variable(const char *name_raw) {
    Variable *current = variable_list;
    while (current != NULL) {
        if (strcmp(current->name, name_raw) == 0) {
            return current->value;
        }
        current = current->next;
    }
    return NULL; 
}

void set_variable(const char *name_raw, const char *value) {
    Variable *current = variable_list;
    Variable *prev = NULL;

    while (current != NULL) {
        if (strcmp(current->name, name_raw) == 0) {
            strncpy(current->value, value, MAX_VAR_VALUE_LEN - 1);
            current->value[MAX_VAR_VALUE_LEN - 1] = '\0';
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
    strncpy(new_var->name, name_raw, MAX_VAR_NAME_LEN - 1);
    new_var->name[MAX_VAR_NAME_LEN - 1] = '\0';
    strncpy(new_var->value, value, MAX_VAR_VALUE_LEN - 1);
    new_var->value[MAX_VAR_VALUE_LEN - 1] = '\0';
    new_var->next = NULL;

    if (prev == NULL) { 
        variable_list = new_var;
    } else {
        prev->next = new_var;
    }
}

char* get_array_element(const char* array_base_name, const char* index_str_expanded) {
    char mangled_name[MAX_VAR_NAME_LEN];
    snprintf(mangled_name, MAX_VAR_NAME_LEN, "%s_ARRAYIDX_%s", array_base_name, index_str_expanded);
    return get_variable(mangled_name);
}

void set_array_element(const char* array_base_name, const char* index_str_raw, const char* value) {
    char expanded_index_val[MAX_VAR_VALUE_LEN];
    expand_variables_in_string(index_str_raw, expanded_index_val, sizeof(expanded_index_val));
    
    char mangled_name[MAX_VAR_NAME_LEN];
    snprintf(mangled_name, MAX_VAR_NAME_LEN, "%s_ARRAYIDX_%s", array_base_name, expanded_index_val);
    set_variable(mangled_name, value);
}

// --- Command Execution Implementations ---

bool find_command_in_path(const char *command, char *full_path) {
    if (strchr(command, '/') != NULL) { 
        if (access(command, X_OK) == 0) {
            strncpy(full_path, command, MAX_FULL_PATH_LEN -1);
            full_path[MAX_FULL_PATH_LEN-1] = '\0';
            return true;
        }
        return false;
    }

    for (int i = 0; i < num_path_dirs; i++) {
        snprintf(full_path, MAX_FULL_PATH_LEN, "%s/%s", path_dirs[i], command);
        if (access(full_path, X_OK) == 0) {
            return true;
        }
    }
    return false;
}

int execute_external_command(char *command_path, char **args, int arg_count, char *output_buffer, size_t output_buffer_size) {
    pid_t pid;
    int status;
    int pipefd[2]; 

    if (output_buffer) { 
        if (pipe(pipefd) == -1) {
            perror("pipe failed");
            return -1;
        }
    }

    pid = fork();
    if (pid == 0) { // Child process
        if (output_buffer) {
            close(pipefd[0]);    
            dup2(pipefd[1], STDOUT_FILENO); 
            dup2(pipefd[1], STDERR_FILENO); 
            close(pipefd[1]);    
        }
        execv(command_path, args);
        perror("execv failed"); 
        exit(EXIT_FAILURE);
    } else if (pid < 0) { // Fork error
        perror("fork failed");
        if (output_buffer) {
            close(pipefd[0]);
            close(pipefd[1]);
        }
        return -1;
    } else { // Parent process
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

void execute_user_function(UserFunction* func, char** call_args, int call_arg_count, FILE* input_source_for_context) {
    if (!func) return;

    // Create a temporary scope for function parameters
    Variable* old_vars[MAX_FUNC_PARAMS];
    char old_values[MAX_FUNC_PARAMS][MAX_VAR_VALUE_LEN];
    int shadowed_count = 0;

    for (int i = 0; i < func->param_count; ++i) {
        char* existing_val = get_variable(func->params[i]);
        if (existing_val) {
            old_vars[shadowed_count] = variable_list; // This is not quite right for individual vars.
                                                      // A better way is to store name and old value.
                                                      // For simplicity here: save the value if it exists.
            strncpy(old_values[shadowed_count], existing_val, MAX_VAR_VALUE_LEN-1);
            // We need to find the actual Variable* node to restore it later if it was modified,
            // or re-set it if it was deleted. This is complex.
            // A simpler parameter passing: set new vars, then unset them after call.
            // For now, just set them.
            shadowed_count++; // This count isn't used well yet.
        }
        if (i < call_arg_count) {
            char expanded_arg_val[MAX_VAR_VALUE_LEN];
            expand_variables_in_string(call_args[i], expanded_arg_val, sizeof(expanded_arg_val));
            set_variable(func->params[i], expanded_arg_val);
        } else {
            set_variable(func->params[i], ""); // Unprovided params are empty strings
        }
    }

    // Execute function body
    // Need to handle nesting within function calls correctly
    int func_outer_block_stack_top = block_stack_top;
    ExecutionState func_outer_exec_state = current_exec_state;

    current_exec_state = STATE_NORMAL; // Functions start in normal state internally

    for (int i = 0; i < func->line_count; ++i) {
        char line_copy[MAX_LINE_LENGTH];
        strncpy(line_copy, func->body[i], MAX_LINE_LENGTH-1);
        line_copy[MAX_LINE_LENGTH-1] = '\0';
        // Pass NULL for input_source and 0 for line_no as we are not using fseek for in-memory lines.
        // If functions could call 'while' that needs fseek, this would be problematic.
        // For now, assume 'while' in functions might not work with fseek (or needs memory buffering).
        process_line(line_copy, NULL, 0); 
                                           
        // If a 'while' loop inside the function needs to jump, it won't work with NULL input_source.
        // This is a limitation for 'while' inside functions unless we buffer lines.
    }
    
    // Restore state and pop any blocks opened *within* the function
    while(block_stack_top > func_outer_block_stack_top) {
        pop_block();
    }
    current_exec_state = func_outer_exec_state;


    // Clean up parameters (simple version: just unset them or restore, this is tricky)
    // For now, we don't automatically unset parameters after function call.
    // A more robust system would save/restore the exact previous state of parameter variables.
}


// --- Parsing and Tokenization Implementations ---
void tokenize_line(const char *line, char **tokens, int *num_tokens, char *token_storage) {
    *num_tokens = 0;
    const char *p = line;
    char *current_token_start = token_storage;
    size_t remaining_storage = TOKEN_BUFFER_SIZE;
    const char* operators[] = {"==", "!=", ">=", "<=", ">", "<", "{", "}", "(", ")", "="}; // "=" is tricky, only for assignment
    int num_operators = sizeof(operators)/sizeof(operators[0]);

    while (*p && *num_tokens < MAX_ARGS && remaining_storage > 1) {
        while (isspace((unsigned char)*p)) p++; 
        if (!*p) break;

        tokens[*num_tokens] = current_token_start;
        
        bool op_found = false;
        if (!isalnum((unsigned char)*p) && *p != '$' && *p != '"' && *p != '_') { // Potential operator
            for(int i=0; i<num_operators; ++i) {
                size_t op_len = strlen(operators[i]);
                if (strncmp(p, operators[i], op_len) == 0) {
                    if (current_token_start != tokens[*num_tokens]) { // Previous token exists, terminate it
                         // This case should not happen if spaces are handled correctly
                    } else { // Operator is the start of the current token
                        strncpy(current_token_start, operators[i], op_len);
                        current_token_start[op_len] = '\0';
                        p += op_len;
                        op_found = true;
                        (*num_tokens)++;
                        current_token_start += (op_len + 1);
                        remaining_storage -= (op_len + 1);
                        break;
                    }
                }
            }
        }


        if (op_found) continue; // Move to next token if operator was parsed

        // If not an operator handled above, parse as quoted string or general token
        (*num_tokens)++; // Increment here as we are sure it's a new token if not an operator that continued

        if (*p == '"') { 
            p++; 
            while (*p && *p != '"' && remaining_storage > 1) {
                if (*p == '\\' && *(p+1) == '"') { // Handle escaped quote \"
                    *current_token_start++ = *p++; // copy '\'
                    remaining_storage--;
                    if (remaining_storage <=1) break;
                }
                *current_token_start++ = *p++;
                remaining_storage--;
            }
            if (*p == '"') p++; 
        } else { 
             while (*p && !isspace((unsigned char)*p) && remaining_storage > 1) {
                bool is_next_char_operator_start = false;
                if (!isalnum((unsigned char)*p) && *p != '$' && *p != '_' && *p != '.') { // Current char could be start of an op
                    for(int i=0; i<num_operators; ++i) {
                        if (strncmp(p, operators[i], strlen(operators[i])) == 0) {
                            is_next_char_operator_start = true;
                            break;
                        }
                    }
                }
                if (is_next_char_operator_start && current_token_start != tokens[*num_tokens-1]) { // Break before operator
                    break;
                }
                *current_token_start++ = *p++;
                remaining_storage--;
             }
        }
        
        if (remaining_storage > 0) {
            *current_token_start++ = '\0';
            remaining_storage--;
        } else {
            if (*num_tokens > 0) (*num_tokens)--; 
            fprintf(stderr, "Token buffer full.\n");
            return;
        }
        if (tokens[*num_tokens-1][0] == '\0' && *num_tokens > 0) {
            (*num_tokens)--;
        }
    }
}

// --- Built-in Command and Statement Implementations ---

void handle_assignment(char **tokens, int num_tokens) {
    if (num_tokens < 3) {
        fprintf(stderr, "Assignment syntax: $var = value_or_command\n");
        return;
    }

    char var_name_raw[MAX_VAR_NAME_LEN]; 
    char index_str_raw[MAX_VAR_NAME_LEN] = ""; 
    bool is_array_assignment = false;

    const char* p_var_token = tokens[0];
    if (p_var_token[0] != '$') {
         fprintf(stderr, "Invalid variable name for assignment: %s\n", p_var_token);
         return;
    }
    const char* p_var = p_var_token + 1; 
    char* p_bracket = strchr(p_var, '[');

    if (p_bracket) {
        is_array_assignment = true;
        size_t base_len = p_bracket - p_var;
        if (base_len < MAX_VAR_NAME_LEN) {
            strncpy(var_name_raw, p_var, base_len);
            var_name_raw[base_len] = '\0';

            char* p_end_bracket = strrchr(p_bracket, ']');
            if (p_end_bracket && p_end_bracket > p_bracket + 1) {
                size_t index_len = p_end_bracket - (p_bracket + 1);
                if (index_len < MAX_VAR_NAME_LEN) {
                    strncpy(index_str_raw, p_bracket + 1, index_len);
                    index_str_raw[index_len] = '\0';
                } else {
                     fprintf(stderr, "Array index too long: %s\n", tokens[0]); return;
                }
            } else {
                 fprintf(stderr, "Malformed array syntax (missing ']' or empty index): %s\n", tokens[0]); return;
            }
        } else {
            fprintf(stderr, "Array base name too long: %s\n", tokens[0]); return;
        }
    } else {
        strncpy(var_name_raw, p_var, MAX_VAR_NAME_LEN - 1);
        var_name_raw[MAX_VAR_NAME_LEN - 1] = '\0';
    }


    char value_to_set[MAX_VAR_VALUE_LEN];
    value_to_set[0] = '\0';

    char full_command_path_check[MAX_FULL_PATH_LEN];
    bool is_rhs_command = false;
    if (num_tokens > 2) { 
        char expanded_first_rhs_token[MAX_VAR_VALUE_LEN];
        expand_variables_in_string(tokens[2], expanded_first_rhs_token, sizeof(expanded_first_rhs_token));
        // Also check if it's a user function
        UserFunction* func = function_list;
        while(func) {
            if (strcmp(expanded_first_rhs_token, func->name) == 0) {
                is_rhs_command = true; // Treat user function like a command for output capture
                break;
            }
            func = func->next;
        }
        if (!is_rhs_command && find_command_in_path(expanded_first_rhs_token, full_command_path_check)) {
            is_rhs_command = true;
        }
    }


    if (is_rhs_command) { 
        char *cmd_args[MAX_ARGS + 1];
        char expanded_cmd_args_storage[MAX_ARGS][MAX_VAR_VALUE_LEN];
        int cmd_arg_count = num_tokens - 2;

        for (int i = 0; i < cmd_arg_count; i++) {
            expand_variables_in_string(tokens[i + 2], expanded_cmd_args_storage[i], MAX_VAR_VALUE_LEN);
            cmd_args[i] = expanded_cmd_args_storage[i];
        }
        cmd_args[cmd_arg_count] = NULL;
        
        UserFunction* user_func = function_list;
        bool executed_user_func = false;
        while(user_func) {
            if (strcmp(cmd_args[0], user_func->name) == 0) {
                // Cannot directly capture output from user functions this way easily without pipes
                // For now, user function assignment would require the function to set a global variable
                fprintf(stderr, "Assigning output of user-defined functions is not directly supported yet.\n");
                // Or, we could implement output capture for user functions too.
                // For now, let's assume it's an external command if assignment is involved.
                // This part needs more thought for user function output capture.
                // Fallback to checking external command.
                break; 
            }
            user_func = user_func->next;
        }

        if (!executed_user_func && find_command_in_path(cmd_args[0], full_command_path_check)) {
             execute_external_command(full_command_path_check, cmd_args, cmd_arg_count, value_to_set, sizeof(value_to_set));
        } else if (!executed_user_func) {
            fprintf(stderr, "Command for assignment not found: %s\n", cmd_args[0]);
        }


    } else { 
        char combined_value[MAX_VAR_VALUE_LEN] = "";
        size_t current_len = 0;
        for (int i = 2; i < num_tokens; i++) {
            char expanded_token[MAX_VAR_VALUE_LEN];
            expand_variables_in_string(tokens[i], expanded_token, sizeof(expanded_token));
            
            size_t token_len = strlen(expanded_token);
            if (current_len + token_len + (i > 2 ? 1 : 0) < MAX_VAR_VALUE_LEN) {
                if (i > 2) { 
                    strcat(combined_value, " ");
                    current_len++;
                }
                strcat(combined_value, expanded_token);
                current_len += token_len;
            } else {
                fprintf(stderr, "Value too long for assignment.\n");
                break;
            }
        }
        size_t len = strlen(combined_value);
        if (len >= 2 && combined_value[0] == '"' && combined_value[len-1] == '"') {
            memmove(combined_value, combined_value + 1, len - 2);
            combined_value[len - 2] = '\0';
        }
        strncpy(value_to_set, combined_value, MAX_VAR_VALUE_LEN -1);
        value_to_set[MAX_VAR_VALUE_LEN-1] = '\0';
    }

    if (is_array_assignment) {
        set_array_element(var_name_raw, index_str_raw, value_to_set);
    } else {
        set_variable(var_name_raw, value_to_set);
    }
}


void handle_echo(char **tokens, int num_tokens) {
    char expanded_arg[MAX_VAR_VALUE_LEN];
    for (int i = 1; i < num_tokens; i++) {
        expand_variables_in_string(tokens[i], expanded_arg, sizeof(expanded_arg));
        printf("%s%s", expanded_arg, (i == num_tokens - 1) ? "" : " ");
    }
    printf("\n");
}

bool evaluate_condition(const char* operand1_raw, const char* operator_str, const char* operand2_raw) {
    char val1_expanded[MAX_VAR_VALUE_LEN];
    char val2_expanded[MAX_VAR_VALUE_LEN];

    expand_variables_in_string(operand1_raw, val1_expanded, sizeof(val1_expanded));
    expand_variables_in_string(operand2_raw, val2_expanded, sizeof(val2_expanded));
    
    // For string literals in condition, tokenizer might keep quotes if they were part of the token.
    // Or if user typed: if $name == "foo" -> operand2_raw is "foo" (quotes included by tokenizer)
    // expand_variables_in_string does not add quotes, but if they are there, they stay.
    // We need to compare the content.
    char val1[MAX_VAR_VALUE_LEN];
    char val2[MAX_VAR_VALUE_LEN];

    // Strip surrounding quotes if they are from the token itself, not part of the variable's value
    // This is tricky. Let's assume expand_variables_in_string gives the pure value.
    // If operand2_raw was "\"foo\"" (a token), expand_variables might give "foo" if "foo" is not a var.
    // If operand2_raw was just "foo" (a token), expand_variables gives "foo".
    // The tokenizer was changed to make "foo" a token, not "\"foo\"".
    strncpy(val1, val1_expanded, MAX_VAR_VALUE_LEN-1); val1[MAX_VAR_VALUE_LEN-1] = '\0';
    strncpy(val2, val2_expanded, MAX_VAR_VALUE_LEN-1); val2[MAX_VAR_VALUE_LEN-1] = '\0';


    if (strcmp(operator_str, "==") == 0) return strcmp(val1, val2) == 0;
    if (strcmp(operator_str, "!=") == 0) return strcmp(val1, val2) != 0;
    
    // For numerical comparisons, convert to long. Error check omitted for simplicity.
    // A more robust shell would use strtol and check for errors.
    // Or use an external 'expr' like command for reliable arithmetic.
    long num1, num2;
    bool numeric_compare = false;
    if ( (isdigit(val1[0]) || (val1[0] == '-' && isdigit(val1[1]))) &&
         (isdigit(val2[0]) || (val2[0] == '-' && isdigit(val2[1]))) ) {
        // Basic check if they look like numbers. A dedicated is_numeric function would be better.
        num1 = atol(val1);
        num2 = atol(val2);
        numeric_compare = true;
    }


    if (strcmp(operator_str, ">") == 0) return numeric_compare ? num1 > num2 : strcmp(val1, val2) > 0;
    if (strcmp(operator_str, "<") == 0) return numeric_compare ? num1 < num2 : strcmp(val1, val2) < 0;
    if (strcmp(operator_str, ">=") == 0) return numeric_compare ? num1 >= num2 : strcmp(val1, val2) >= 0;
    if (strcmp(operator_str, "<=") == 0) return numeric_compare ? num1 <= num2 : strcmp(val1, val2) <= 0;

    fprintf(stderr, "Unsupported operator in condition: %s\n", operator_str);
    return false;
}

void handle_if_statement(char **tokens, int num_tokens, FILE* input_source, int current_line_no) {
    // Expected: if <op1> <op> <op2> { OR if <op1> <op> <op2> then <newline> {
    if (num_tokens < 4) { // Needs at least "if", op1, op, op2
        fprintf(stderr, "Syntax error for 'if'. Expected: if <operand1> <operator> <operand2> [{]\n");
        if (block_stack_top < MAX_NESTING_DEPTH -1) { // Push a dummy block to skip
           push_block(BLOCK_TYPE_IF, false, 0, 0);
           current_exec_state = STATE_BLOCK_SKIP;
        }
        return;
    }
    
    bool condition_result = false;
    if (current_exec_state != STATE_BLOCK_SKIP) { // Don't evaluate if already skipping
         condition_result = evaluate_condition(tokens[1], tokens[2], tokens[3]);
    }


    push_block(BLOCK_TYPE_IF, condition_result, 0, 0); // fpos/line_no not used for if

    if (condition_result && current_exec_state != STATE_BLOCK_SKIP) {
        current_exec_state = STATE_BLOCK_EXECUTE;
    } else {
        current_exec_state = STATE_BLOCK_SKIP;
    }

    // Check if '{' is the last token on the same line
    if (num_tokens > 4 && strcmp(tokens[num_tokens-1], "{") == 0) {
        // '{' is handled by push_block implicitly increasing nesting.
        // No explicit call to handle_opening_brace needed here as it's part of the if.
    } else if (num_tokens == 4 && strcmp(tokens[0],"if")==0) {
        // '{' is expected on the next line
    } else if (num_tokens > 4 && strcmp(tokens[num_tokens-1], "{") != 0) {
        fprintf(stderr, "Syntax error for 'if': '{' expected after condition or on next line.\n");
        // State is already set to skip or execute based on (potentially false) condition
    }
}

void handle_else_statement(char **tokens, int num_tokens, FILE* input_source, int current_line_no) {
    BlockFrame* prev_block = peek_block();
    if (!prev_block || (prev_block->type != BLOCK_TYPE_IF && prev_block->type != BLOCK_TYPE_ELSE)) {
        fprintf(stderr, "Error: 'else' without a preceding 'if' or 'else if' block.\n");
        // To prevent runaway execution, go into skip mode if we are not already.
        current_exec_state = STATE_BLOCK_SKIP;
        push_block(BLOCK_TYPE_ELSE, false, 0, 0); // Push a dummy block
        return;
    }

    // Pop the 'if' or 'else if' block frame
    pop_block(); 

    bool execute_this_else = false;
    if (prev_block->condition_true) { // If the 'if' or 'else if' was true
        execute_this_else = false; // Skip this else
    } else { // If the 'if' or 'else if' was false
        if (num_tokens > 1 && strcmp(tokens[1], "if") == 0) { // This is an "else if"
            if (num_tokens < 5) { // else if op1 op op2
                fprintf(stderr, "Syntax error for 'else if'. Expected: else if <op1> <op> <op2> [{]\n");
                execute_this_else = false; // Skip on error
            } else {
                 if (current_exec_state != STATE_BLOCK_SKIP) { // Don't evaluate if parent was already skipping
                    execute_this_else = evaluate_condition(tokens[2], tokens[3], tokens[4]);
                 } else {
                    execute_this_else = false;
                 }
            }
        } else { // Simple "else"
            execute_this_else = true;
        }
    }
    
    push_block(BLOCK_TYPE_ELSE, execute_this_else, 0, 0);

    if (execute_this_else && current_exec_state != STATE_BLOCK_SKIP) {
        current_exec_state = STATE_BLOCK_EXECUTE;
    } else {
        current_exec_state = STATE_BLOCK_SKIP;
    }

    // Check for '{' on the same line for 'else {' or 'else if ... {'
    if (num_tokens > 0 && strcmp(tokens[num_tokens-1], "{") == 0) {
        // ok
    } else if ( (strcmp(tokens[0],"else")==0 && num_tokens == 1) || (strcmp(tokens[0],"else")==0 && strcmp(tokens[1],"if")==0 && num_tokens == 5) ) {
        // '{' expected on next line
    } else {
         fprintf(stderr, "Syntax error for 'else'/'else if': '{' expected after statement or on next line.\n");
    }
}

void handle_while_statement(char **tokens, int num_tokens, FILE* input_source, int current_line_no) {
    if (num_tokens < 4) {
        fprintf(stderr, "Syntax error for 'while'. Expected: while <op1> <op> <op2> [{]\n");
        if (block_stack_top < MAX_NESTING_DEPTH -1) {
           push_block(BLOCK_TYPE_WHILE, false, 0, 0);
           current_exec_state = STATE_BLOCK_SKIP;
        }
        return;
    }

    bool condition_result = false;
    long loop_fpos = -1;

    if (current_exec_state != STATE_BLOCK_SKIP) {
        condition_result = evaluate_condition(tokens[1], tokens[2], tokens[3]);
        if (input_source && input_source != stdin) { // Only store fpos for actual files
            // We need the position *before* the 'while' line was read by fgets.
            // This is tricky. We can ftell() *after* reading, then subtract strlen(line).
            // Or, ftell() before fgets in the main loop.
            // For now, current_line_no is a proxy if fseek is not available/reliable.
            // Let's assume `execute_script` provides the fpos of the *start* of the current line.
            // This requires `get_file_pos` before `fgets` in `execute_script`.
            // The `loop_start_fpos` passed to `push_block` should be the fpos of this `while` line.
            // This needs to be plumbed through `execute_script`.
            // For now, let's try to get it if possible.
            if (input_source != stdin) { // stdin cannot be fseek'd
                loop_fpos = get_file_pos(input_source); // This is pos *after* reading the while line
                                                        // We need pos *before*.
                // This is a placeholder. A robust solution needs careful fpos management.
                // For simplicity, we'll rely on the line number for non-fseek cases,
                // and assume fseek-based loops need the fpos of the line *containing* "while".
            }
        }
    }
    
    // The fpos should be the beginning of the "while" line.
    // This is hard to get accurately here. It's better if execute_script captures it before calling process_line.
    // For now, we pass current_line_no.
    // Let's assume `handle_closing_brace` will use `current_line_no` if `loop_start_fpos` is 0 or input is stdin.
    // If using `fseek`, `loop_start_fpos` must be correctly set to the start of the `while` line.
    // This requires `ftell()` *before* `fgets()` in `execute_script` and passing that `fpos`.
    // For now, this is a known simplification.
    long actual_loop_start_fpos = 0; // This should be passed in correctly.
    if (input_source != stdin) {
        // This is a conceptual placeholder. The `execute_script` loop should manage this.
        // `actual_loop_start_fpos` should be ftell() *before* fgets() reads the `while` line.
    }

    push_block(BLOCK_TYPE_WHILE, condition_result, actual_loop_start_fpos, current_line_no);

    if (condition_result && current_exec_state != STATE_BLOCK_SKIP) {
        current_exec_state = STATE_BLOCK_EXECUTE;
    } else {
        current_exec_state = STATE_BLOCK_SKIP;
    }

    if (! (num_tokens > 4 && strcmp(tokens[num_tokens-1], "{") == 0) &&
        ! (num_tokens == 4 && strcmp(tokens[0],"while")==0) ) {
         fprintf(stderr, "Syntax error for 'while': '{' expected after condition or on next line.\n");
    }
}

void handle_inc_dec_statement(char **tokens, int num_tokens, bool increment) {
    if (num_tokens != 2) {
        fprintf(stderr, "Syntax: %s <varname>\n", increment ? "inc" : "dec");
        return;
    }
    const char* var_name_token = tokens[1];
    char var_name[MAX_VAR_NAME_LEN];
    if (var_name_token[0] == '$') {
        strncpy(var_name, var_name_token + 1, MAX_VAR_NAME_LEN -1);
    } else {
        strncpy(var_name, var_name_token, MAX_VAR_NAME_LEN -1);
    }
    var_name[MAX_VAR_NAME_LEN-1] = '\0';

    char* current_val_str = get_variable(var_name);
    if (!current_val_str) {
        // Treat undefined var as 0 for inc/dec
        set_variable(var_name, increment ? "1" : "-1");
        return;
    }
    
    long current_val = atol(current_val_str); // Consider strtol for error checking
    if (increment) {
        current_val++;
    } else {
        current_val--;
    }

    char new_val_str[MAX_VAR_VALUE_LEN];
    snprintf(new_val_str, sizeof(new_val_str), "%ld", current_val);
    set_variable(var_name, new_val_str);
}

void handle_defunc_statement(char **tokens, int num_tokens) {
    if (num_tokens < 2) { // defunc funcname [{] or defunc funcname (p1 p2) [{]
        fprintf(stderr, "Syntax: defunc <funcname> [(param1 ...)] {\n");
        return;
    }
    if (is_defining_function) {
        fprintf(stderr, "Error: Cannot nest function definitions.\n");
        return;
    }

    current_function_definition = (UserFunction*)malloc(sizeof(UserFunction));
    if (!current_function_definition) {
        perror("malloc for function definition failed");
        return;
    }
    memset(current_function_definition, 0, sizeof(UserFunction));
    strncpy(current_function_definition->name, tokens[1], MAX_VAR_NAME_LEN - 1);

    int token_idx = 2;
    if (token_idx < num_tokens && strcmp(tokens[token_idx], "(") == 0) {
        token_idx++; // Skip '('
        while(token_idx < num_tokens && strcmp(tokens[token_idx], ")") != 0) {
            if (current_function_definition->param_count < MAX_FUNC_PARAMS) {
                strncpy(current_function_definition->params[current_function_definition->param_count++],
                        tokens[token_idx], MAX_VAR_NAME_LEN -1);
            } else {
                fprintf(stderr, "Too many parameters for function %s\n", current_function_definition->name);
                free(current_function_definition); current_function_definition = NULL; return;
            }
            token_idx++;
        }
        if (token_idx < num_tokens && strcmp(tokens[token_idx], ")") == 0) {
            token_idx++; // Skip ')'
        } else {
            fprintf(stderr, "Syntax error in function parameters: missing ')' for %s\n", current_function_definition->name);
            free(current_function_definition); current_function_definition = NULL; return;
        }
    }


    if (token_idx < num_tokens && strcmp(tokens[token_idx], "{") == 0) {
        // '{' on the same line
        is_defining_function = true;
        current_exec_state = STATE_DEFINE_FUNC_BODY;
        push_block(BLOCK_TYPE_FUNCTION_DEF, true, 0, 0);
    } else if (token_idx == num_tokens) {
        // Expect '{' on the next line
        is_defining_function = true;
        current_exec_state = STATE_DEFINE_FUNC_BODY;
        // The '{' on the next line will call handle_opening_brace which should push the block
    } else {
        fprintf(stderr, "Syntax error in function definition: '{' expected for %s\n", current_function_definition->name);
        free(current_function_definition); current_function_definition = NULL;
    }
}

void handle_loadlib_statement(char **tokens, int num_tokens) {
    if (num_tokens != 3) {
        fprintf(stderr, "Syntax: loadlib <path_to_lib.so> <alias>\n");
        return;
    }
    const char* lib_path = tokens[1];
    const char* alias = tokens[2];

    // Check if alias already exists
    DynamicLib* current_lib = loaded_libs;
    while(current_lib) {
        if (strcmp(current_lib->alias, alias) == 0) {
            fprintf(stderr, "Error: Library alias '%s' already in use.\n", alias);
            return;
        }
        current_lib = current_lib->next;
    }

    void *handle = dlopen(lib_path, RTLD_LAZY);
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

void handle_calllib_statement(char **tokens, int num_tokens) {
    if (num_tokens < 3) {
        fprintf(stderr, "Syntax: calllib <alias> <function_name> [args...]\n");
        return;
    }
    const char* alias = tokens[1];
    const char* func_name = tokens[2];

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

    void* func_ptr = dlsym(lib_handle, func_name);
    if (!func_ptr) {
        fprintf(stderr, "Error finding function '%s' in library '%s': %s\n", func_name, alias, dlerror());
        return;
    }

    // Argument preparation and calling is complex.
    // Assume a simple signature for now: char* func(int argc, char* argv[])
    // The returned char* must be free'd by the caller if allocated by the lib func, or static.
    // This is a major simplification. Real interop is much harder.
    typedef char* (*lib_func_type)(int, char**);
    lib_func_type target_func = (lib_func_type)func_ptr;

    int lib_argc = num_tokens - 3;
    char** lib_argv = tokens + 3; // Arguments start from tokens[3]

    // Expand variables in arguments before passing to library function
    char expanded_lib_args_storage[MAX_ARGS][MAX_VAR_VALUE_LEN];
    char* final_lib_argv[MAX_ARGS];

    for(int i=0; i < lib_argc; ++i) {
        expand_variables_in_string(lib_argv[i], expanded_lib_args_storage[i], MAX_VAR_VALUE_LEN);
        final_lib_argv[i] = expanded_lib_args_storage[i];
    }

    char* result_str = NULL;
    printf("Calling '%s' from library '%s' (conceptual call due to ABI complexity).\n", func_name, alias);
    // result_str = target_func(lib_argc, final_lib_argv); // Actual call commented out

    if (result_str) {
        // Typically, you'd set a special variable like $? or $CALL_RESULT
        set_variable("LAST_LIB_CALL_RESULT", result_str);
        printf("Library function returned (first 100 chars): %.100s\n", result_str);
        // If the library function malloc'd result_str, it should provide a way to free it,
        // or the shell needs a convention (e.g., lib always returns static buffer or uses a shell-provided buffer).
        // For now, we assume it's safe to use and not free here.
    } else {
        // set_variable("LAST_LIB_CALL_RESULT", "");
        // printf("Library function did not return a string or returned NULL.\n");
    }
    fprintf(stderr, "Note: Actual dynamic library call ABI (argument passing, return types) is complex.\n");
    fprintf(stderr, "This is a simplified demonstration of dlopen/dlsym.\n");
}


// --- Block Management Implementations ---

void push_block(BlockType type, bool condition_true, long loop_start_fpos, int loop_start_line_no) {
    if (block_stack_top >= MAX_NESTING_DEPTH - 1) {
        fprintf(stderr, "Error: Maximum nesting depth exceeded (%d).\n", MAX_NESTING_DEPTH);
        // Potentially try to recover or exit
        return;
    }
    block_stack_top++;
    block_stack[block_stack_top].type = type;
    block_stack[block_stack_top].condition_true = condition_true;
    block_stack[block_stack_top].loop_start_fpos = loop_start_fpos;
    block_stack[block_stack_top].loop_start_line_no = loop_start_line_no;
    block_stack[block_stack_top].prev_exec_state = current_exec_state; // Save current state
}

BlockFrame* pop_block() {
    if (block_stack_top < 0) {
        fprintf(stderr, "Error: Block stack underflow (pop_block).\n");
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

void handle_opening_brace() {
    // This is called when '{' is a standalone token.
    // It assumes a block (if, else, while, defunc) was just declared and is waiting for its body.
    BlockFrame* current_block_frame = peek_block();
    if (!current_block_frame) {
        fprintf(stderr, "Error: '{' found without a preceding if/else/while/defunc statement.\n");
        return;
    }

    if (current_block_frame->type == BLOCK_TYPE_FUNCTION_DEF) {
        current_exec_state = STATE_DEFINE_FUNC_BODY;
        is_defining_function = true; // Ensure this is set
    } else if (current_block_frame->condition_true) {
        current_exec_state = STATE_BLOCK_EXECUTE;
    } else {
        current_exec_state = STATE_BLOCK_SKIP;
    }
}

void handle_closing_brace(FILE* input_source) {
    BlockFrame* closed_block = pop_block();
    if (!closed_block) {
        fprintf(stderr, "Error: '}' found without a matching open block.\n");
        current_exec_state = STATE_NORMAL; // Try to recover
        return;
    }

    // Restore previous execution state if no outer block, or determined by outer block
    BlockFrame* parent_block = peek_block();
    if (!parent_block) {
        current_exec_state = STATE_NORMAL;
    } else {
        // The state should revert to what the parent block dictates.
        // If parent was skipping, we continue skipping.
        // If parent was executing, we continue executing.
        // This is subtle. The prev_exec_state on the *parent* might be more relevant.
        // For now, if parent exists, and it was skipping, this new state should be skip.
        // If parent was executing, this new state is execute.
        // This logic is mostly handled by the main dispatcher checking current_exec_state.
        // Here, we mainly focus on loop constructs.
        if (parent_block->type == BLOCK_TYPE_FUNCTION_DEF) { // Exiting a block within a func def body
             current_exec_state = STATE_DEFINE_FUNC_BODY;
        } else if (parent_block->condition_true) {
            current_exec_state = STATE_BLOCK_EXECUTE;
        } else {
            current_exec_state = STATE_BLOCK_SKIP;
        }
    }


    if (closed_block->type == BLOCK_TYPE_WHILE && closed_block->condition_true) {
        // Re-evaluate condition for the while loop
        if (input_source && input_source != stdin && closed_block->loop_start_fpos > 0) { // Check fpos is valid
            if (fseek(input_source, closed_block->loop_start_fpos, SEEK_SET) == 0) {
                // The next fgets in execute_script will re-read the 'while' line.
                // The process_line for that 'while' will re-evaluate and push a new block.
                // We need to ensure the state allows re-evaluation.
                current_exec_state = STATE_BLOCK_EXECUTE; // Or a special re-evaluate state
            } else {
                perror("fseek failed for while loop");
                current_exec_state = STATE_NORMAL; // Cannot loop, break out
            }
        } else if (input_source == stdin || closed_block->loop_start_fpos == 0) {
            // Cannot fseek stdin or no valid fpos. While loops in interactive mode or without fpos are not easily repeatable.
            // This shell version won't support fseek-less while loops effectively.
            fprintf(stderr, "Warning: 'while' loop cannot repeat in interactive mode or without script file context.\n");
            current_exec_state = STATE_NORMAL; // Break out of loop
        }
         // The actual re-processing of the 'while' line happens in the next iteration of execute_script's loop.
    } else if (closed_block->type == BLOCK_TYPE_FUNCTION_DEF) {
        if (current_function_definition) {
            // Add function to list
            current_function_definition->next = function_list;
            function_list = current_function_definition;
            printf("Function '%s' defined with %d parameters and %d lines.\n",
                   current_function_definition->name,
                   current_function_definition->param_count,
                   current_function_definition->line_count);
            current_function_definition = NULL;
        }
        is_defining_function = false;
        // State after func def is determined by what was before it, or normal if top level.
        if (!parent_block) current_exec_state = STATE_NORMAL;
        // else, current_exec_state was already set based on parent_block.
    }

    // If after popping, the stack is empty, we are back to normal top-level execution.
    if (block_stack_top == -1) {
        current_exec_state = STATE_NORMAL;
    }
}


// --- Utility Implementations ---

char* trim_whitespace(char *str) {
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
    Variable *next;
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
    variable_list = NULL;
}

void free_function_list() {
    UserFunction *current = function_list;
    UserFunction *next;
    while (current != NULL) {
        next = current->next;
        for (int i = 0; i < current->line_count; ++i) {
            free(current->body[i]);
        }
        free(current);
        current = next;
    }
    function_list = NULL;
}

void free_loaded_libs() {
    DynamicLib *current = loaded_libs;
    DynamicLib *next;
    while(current) {
        next = current->next;
        if (current->handle) {
            dlclose(current->handle);
        }
        free(current);
        current = next;
    }
    loaded_libs = NULL;
}


long get_file_pos(FILE* f) {
    if (!f || f == stdin || f == stdout || f == stderr) return -1; // Cannot ftell special streams reliably for seeking
    long pos = ftell(f);
    if (pos == -1L) {
        // perror("ftell failed"); // Optionally report error
        return -1; // Indicate error or unsuitability
    }
    return pos;
}

