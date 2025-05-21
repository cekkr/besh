#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <ctype.h>

// --- Costanti e Definizioni ---
#define MAX_LINE_LENGTH 2048      // Aumentato per linee potenzialmente lunghe con espansioni
#define MAX_ARGS 64
#define MAX_VAR_NAME_LEN 256
#define MAX_VAR_VALUE_LEN 1024
#define MAX_PATH_DIRS 64
#define MAX_FULL_PATH_LEN 1024
#define TOKEN_BUFFER_SIZE MAX_LINE_LENGTH // Buffer per i token di una singola riga

// Struttura per le variabili
typedef struct Variable {
    char name[MAX_VAR_NAME_LEN];
    char value[MAX_VAR_VALUE_LEN];
    struct Variable *next;
} Variable;
Variable *variable_list = NULL;

// Array per memorizzare le directory della PATH
char *path_dirs[MAX_PATH_DIRS];
int num_path_dirs = 0;

// Stato per la gestione dei blocchi if/else
typedef enum {
    STATE_NORMAL,          // Esecuzione normale
    STATE_IF_BLOCK_TRUE,   // Dentro un blocco if la cui condizione era vera
    STATE_IF_BLOCK_FALSE,  // Dentro un blocco if la cui condizione era falsa (salta comandi)
    STATE_ELSE_BLOCK_SKIP, // Dentro un blocco else che deve essere saltato (perché l'if era vero)
    STATE_ELSE_BLOCK_EXEC  // Dentro un blocco else che deve essere eseguito (perché l'if era falso)
} ExecutionState;

ExecutionState current_exec_state = STATE_NORMAL;
int conditional_nesting_level = 0; // Per gestire if annidati e trovare le { } corrispondenti

// --- Prototipi Funzioni ---

// Funzioni principali
void initialize_shell();
void process_line(char *line, FILE *input_source); // input_source per gestire blocchi da file
void execute_script(const char *filename);

// Funzioni per la gestione delle variabili
char* get_variable_value(const char *name_raw);
void set_variable(const char *name_raw, const char *value);
void expand_variables_in_string(const char *input_str, char *expanded_str, size_t expanded_str_size);
char* get_array_element_value(const char* array_base_name, const char* index_str_raw);
void set_array_element_value(const char* array_base_name, const char* index_str_raw, const char* value);


// Funzioni per l'esecuzione dei comandi
bool find_command_in_path(const char *command, char *full_path);
int execute_external_command(char *command_path, char **args, int arg_count, char *output_buffer, size_t output_buffer_size);

// Funzioni per il parsing e la tokenizzazione
void tokenize_line(const char *line, char **tokens, int *num_tokens, char *token_storage);

// Funzioni per i comandi built-in e statement
void handle_assignment(char **tokens, int num_tokens);
void handle_echo(char **tokens, int num_tokens);
bool evaluate_condition(const char* operand1_raw, const char* operator_str, const char* operand2_raw);
void handle_if_statement(char **tokens, int num_tokens, char* full_line, FILE* input_source);
void handle_else_statement(char **tokens, int num_tokens, FILE* input_source);
void handle_closing_brace();

// Funzioni di utilità
char* trim_whitespace(char *str);
void free_variables();


// --- Main ---
int main(int argc, char *argv[]) {
    initialize_shell();

    if (argc > 1) {
        execute_script(argv[1]);
    } else {
        char line[MAX_LINE_LENGTH];
        char prompt[MAX_VAR_NAME_LEN + 10]; // Per prompt dinamico
        
        while (1) {
            // Costruisci il prompt
            if (current_exec_state == STATE_IF_BLOCK_FALSE || current_exec_state == STATE_ELSE_BLOCK_SKIP) {
                 if (conditional_nesting_level > 0) {
                    snprintf(prompt, sizeof(prompt), "mysh (skip %d)> ", conditional_nesting_level);
                 } else {
                    snprintf(prompt, sizeof(prompt), "mysh (skip)> ");
                 }
            } else if (conditional_nesting_level > 0) {
                 snprintf(prompt, sizeof(prompt), "mysh (block %d)> ", conditional_nesting_level);
            }
            else {
                snprintf(prompt, sizeof(prompt), "mysh> ");
            }
            printf("%s", prompt);
            
            if (!fgets(line, sizeof(line), stdin)) {
                printf("\n"); // EOF (Ctrl+D)
                break;
            }
            process_line(line, stdin);
        }
    }

    free_variables();
    return 0;
}

// --- Implementazione Funzioni Principali ---

void initialize_shell() {
    // Inizializza PATH
    char *path_env = getenv("PATH");
    if (path_env != NULL) {
        char *path_copy = strdup(path_env); // Duplica perché strtok modifica la stringa
        char *token = strtok(path_copy, ":");
        while (token != NULL && num_path_dirs < MAX_PATH_DIRS) {
            path_dirs[num_path_dirs++] = strdup(token); // Memorizza una copia di ogni directory
            token = strtok(NULL, ":");
        }
        free(path_copy);
    }
}

void process_line(char *line_orig, FILE *input_source) {
    char line[MAX_LINE_LENGTH];
    strncpy(line, line_orig, MAX_LINE_LENGTH -1);
    line[MAX_LINE_LENGTH-1] = '\0';

    char *trimmed_line = trim_whitespace(line);

    if (strlen(trimmed_line) == 0 || trimmed_line[0] == '#') { // Riga vuota o commento
        return;
    }

    if (strcmp(trimmed_line, "exit") == 0 && conditional_nesting_level == 0) {
        free_variables();
        // Libera path_dirs se allocati dinamicamente
        for(int i=0; i<num_path_dirs; i++) free(path_dirs[i]);
        exit(0);
    }
    
    char token_storage[TOKEN_BUFFER_SIZE]; // Buffer per i token della riga corrente
    char *tokens[MAX_ARGS];
    int num_tokens = 0;

    tokenize_line(trimmed_line, tokens, &num_tokens, token_storage);

    if (num_tokens == 0) {
        return;
    }
    
    // Gestione preliminare delle parentesi graffe per il nesting level
    // Questo avviene prima di decidere se saltare o eseguire,
    // perché il nesting level è importante per sapere quando un blocco saltato termina.
    if (strcmp(tokens[0], "{") == 0) {
         // Non dovrebbe accadere se '{' è alla fine di 'if' o 'else'
         // Ma se è su una riga a sé, incrementa il livello.
         // La logica principale di '{' è gestita in if/else.
    } else if (strcmp(tokens[0], "}") == 0) {
        handle_closing_brace();
        // Se dopo la graffa chiusa lo stato torna normale, non fare altro su questa riga.
        // Altrimenti, se siamo ancora in uno stato di skip, non processare oltre.
        if (current_exec_state == STATE_NORMAL || 
            current_exec_state == STATE_IF_BLOCK_FALSE || 
            current_exec_state == STATE_ELSE_BLOCK_SKIP) {
            return; 
        }
    }


    // Se siamo in uno stato di "salto" comandi (dentro un if falso o un else da saltare)
    if (current_exec_state == STATE_IF_BLOCK_FALSE || current_exec_state == STATE_ELSE_BLOCK_SKIP) {
        // Controlliamo solo 'if', 'else', '{', '}' per gestire il nesting e trovare la fine del blocco da saltare.
        if (strcmp(tokens[0], "if") == 0) {
            // Se troviamo un 'if' annidato mentre stiamo saltando, dobbiamo incrementare il livello
            // per sapere che dobbiamo saltare anche il suo blocco.
            // La '{' associata all'if incrementerà conditional_nesting_level.
             size_t len = strlen(trimmed_line);
             if (len > 0 && trimmed_line[len-1] == '{') { // if ... {
                conditional_nesting_level++;
             }
        }
        // 'else' e '}' sono gestiti sopra o in funzioni dedicate che modificano lo stato.
        return; // Non eseguire altri comandi
    }


    // --- Dispatcher dei comandi ---
    // 1. Assegnazione Variabile: $var = ...
    if (tokens[0][0] == '$' && num_tokens > 1 && strcmp(tokens[1], "=") == 0) {
        handle_assignment(tokens, num_tokens);
    }
    // 2. Comando 'if'
    else if (strcmp(tokens[0], "if") == 0) {
        handle_if_statement(tokens, num_tokens, trimmed_line, input_source);
    }
    // 3. Comando 'else'
    else if (strcmp(tokens[0], "else") == 0) {
        handle_else_statement(tokens, num_tokens, input_source);
    }
    // 4. Comando 'echo'
    else if (strcmp(tokens[0], "echo") == 0) {
        handle_echo(tokens, num_tokens);
    }
    // 5. Comando esterno
    else {
        char expanded_args_storage[MAX_ARGS][MAX_VAR_VALUE_LEN]; // Storage per argomenti espansi
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
            fprintf(stderr, "Comando non trovato: %s\n", expanded_argv[0]);
        }
    }
}

void execute_script(const char *filename) {
    FILE *script_file = fopen(filename, "r");
    if (!script_file) {
        perror("Errore apertura script");
        return;
    }
    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), script_file)) {
        process_line(line, script_file);
    }
    fclose(script_file);
}


// --- Implementazione Gestione Variabili ---

void expand_variables_in_string(const char *input_str, char *expanded_str, size_t expanded_str_size) {
    const char *p_in = input_str;
    char *p_out = expanded_str;
    size_t remaining_size = expanded_str_size -1; // Per \0

    while (*p_in && remaining_size > 0) {
        if (*p_in == '$') {
            p_in++; // Salta '$'
            char var_name_buffer[MAX_VAR_NAME_LEN];
            char index_str_buffer[MAX_VAR_NAME_LEN]; // Per l'indice dell'array
            char *pv = var_name_buffer;
            bool is_array = false;
            char array_base_name[MAX_VAR_NAME_LEN];

            // Estrai il nome della variabile o la base dell'array
            while (*p_in && (isalnum((unsigned char)*p_in) || *p_in == '_') && (pv - var_name_buffer < MAX_VAR_NAME_LEN - 1)) {
                *pv++ = *p_in++;
            }
            *pv = '\0';
            strncpy(array_base_name, var_name_buffer, MAX_VAR_NAME_LEN); // Copia la base per l'array

            // Controlla se è un accesso ad array: $arr[index]
            if (*p_in == '[') {
                is_array = true;
                p_in++; // Salta '['
                char *pi = index_str_buffer;
                // Estrai la parte dell'indice (può contenere altre variabili)
                int bracket_level = 1; // Per gestire indici annidati tipo $arr[$idx[$key]] (semplificato: non supportato ora)
                while (*p_in && bracket_level > 0 && (pi - index_str_buffer < MAX_VAR_NAME_LEN -1)){
                    if (*p_in == '[') bracket_level++;
                    else if (*p_in == ']') bracket_level--;
                    
                    if (bracket_level > 0) { // Non copiare la parentesi chiusa finale dell'indice
                         *pi++ = *p_in;
                    }
                    p_in++;
                }
                *pi = '\0';
                // p_in ora punta dopo ']'
            }

            char *value_to_insert = NULL;
            if (is_array) {
                // L'indice stesso potrebbe contenere variabili, quindi espandilo
                char expanded_index_val[MAX_VAR_VALUE_LEN];
                expand_variables_in_string(index_str_buffer, expanded_index_val, sizeof(expanded_index_val));
                value_to_insert = get_array_element_value(array_base_name, expanded_index_val);
            } else {
                value_to_insert = get_variable_value(var_name_buffer);
            }
            
            if (value_to_insert) {
                size_t val_len = strlen(value_to_insert);
                if (val_len < remaining_size) {
                    strcpy(p_out, value_to_insert);
                    p_out += val_len;
                    remaining_size -= val_len;
                } else { // Non c'è abbastanza spazio
                    strncpy(p_out, value_to_insert, remaining_size);
                    p_out += remaining_size;
                    remaining_size = 0;
                }
            }
            // Se la variabile non esiste, non inserire nulla (o potresti inserire una stringa vuota)
        } else { // Carattere normale
            *p_out++ = *p_in++;
            remaining_size--;
        }
    }
    *p_out = '\0';
}


char* get_variable_value(const char *name_raw) {
    // Non espandere qui, il nome è già "pulito" o è un nome di variabile base
    Variable *current = variable_list;
    while (current != NULL) {
        if (strcmp(current->name, name_raw) == 0) {
            return current->value;
        }
        current = current->next;
    }
    return NULL; // O una stringa vuota se preferito
}

void set_variable(const char *name_raw, const char *value) {
    // Non espandere name_raw qui
    Variable *current = variable_list;
    Variable *prev = NULL;

    // Cerca se la variabile esiste già
    while (current != NULL) {
        if (strcmp(current->name, name_raw) == 0) {
            strncpy(current->value, value, MAX_VAR_VALUE_LEN - 1);
            current->value[MAX_VAR_VALUE_LEN - 1] = '\0';
            return;
        }
        prev = current;
        current = current->next;
    }

    // Se non esiste, crea una nuova variabile
    Variable *new_var = (Variable*)malloc(sizeof(Variable));
    if (!new_var) {
        perror("malloc fallito per nuova variabile");
        return;
    }
    strncpy(new_var->name, name_raw, MAX_VAR_NAME_LEN - 1);
    new_var->name[MAX_VAR_NAME_LEN - 1] = '\0';
    strncpy(new_var->value, value, MAX_VAR_VALUE_LEN - 1);
    new_var->value[MAX_VAR_VALUE_LEN - 1] = '\0';
    new_var->next = NULL;

    if (prev == NULL) { // Lista era vuota
        variable_list = new_var;
    } else {
        prev->next = new_var;
    }
}

char* get_array_element_value(const char* array_base_name, const char* index_str_expanded) {
    char mangled_name[MAX_VAR_NAME_LEN];
    snprintf(mangled_name, MAX_VAR_NAME_LEN, "%s_%s", array_base_name, index_str_expanded);
    return get_variable_value(mangled_name);
}

void set_array_element_value(const char* array_base_name, const char* index_str_raw, const char* value) {
    char expanded_index_val[MAX_VAR_VALUE_LEN];
    expand_variables_in_string(index_str_raw, expanded_index_val, sizeof(expanded_index_val));
    
    char mangled_name[MAX_VAR_NAME_LEN];
    snprintf(mangled_name, MAX_VAR_NAME_LEN, "%s_%s", array_base_name, expanded_index_val);
    set_variable(mangled_name, value);
}


// --- Implementazione Esecuzione Comandi ---

bool find_command_in_path(const char *command, char *full_path) {
    if (strchr(command, '/') != NULL) { // Se il comando contiene '/', è un percorso assoluto o relativo
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
    int pipefd[2]; // Per catturare l'output

    if (output_buffer) { // Se dobbiamo catturare l'output
        if (pipe(pipefd) == -1) {
            perror("pipe fallito");
            return -1;
        }
    }

    pid = fork();
    if (pid == 0) { // Processo figlio
        if (output_buffer) {
            close(pipefd[0]);    // Chiudi l'estremità di lettura nel figlio
            dup2(pipefd[1], STDOUT_FILENO); // Redirigi stdout alla pipe
            dup2(pipefd[1], STDERR_FILENO); // Opzionale: redirigi anche stderr
            close(pipefd[1]);    // Chiudi l'estremità di scrittura originale
        }
        execv(command_path, args);
        perror("execv fallito"); // Se execv ritorna, c'è stato un errore
        exit(EXIT_FAILURE);
    } else if (pid < 0) { // Errore nel fork
        perror("fork fallito");
        if (output_buffer) {
            close(pipefd[0]);
            close(pipefd[1]);
        }
        return -1;
    } else { // Processo padre
        if (output_buffer) {
            close(pipefd[1]); // Chiudi l'estremità di scrittura nel padre
            ssize_t bytes_read;
            size_t total_bytes_read = 0;
            char read_buf[256];
            output_buffer[0] = '\0'; // Inizia con un buffer vuoto

            while((bytes_read = read(pipefd[0], read_buf, sizeof(read_buf)-1)) > 0) {
                if (total_bytes_read + bytes_read < output_buffer_size) {
                    read_buf[bytes_read] = '\0';
                    strcat(output_buffer, read_buf);
                    total_bytes_read += bytes_read;
                } else {
                    // Buffer di output pieno, tronca
                    strncat(output_buffer, read_buf, output_buffer_size - total_bytes_read -1);
                    break; 
                }
            }
            close(pipefd[0]); // Chiudi l'estremità di lettura
            // Rimuovi newline finali dall'output catturato
            char* nl = strrchr(output_buffer, '\n');
            while(nl && (nl == output_buffer + strlen(output_buffer) -1)) {
                *nl = '\0';
                nl = strrchr(output_buffer, '\n');
            }

        }
        // Aspetta il figlio
        do {
            waitpid(pid, &status, WUNTRACED);
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        return WEXITSTATUS(status);
    }
    return 0; // Dovrebbe essere già ritornato
}


// --- Implementazione Parsing e Tokenizzazione ---

void tokenize_line(const char *line, char **tokens, int *num_tokens, char *token_storage) {
    *num_tokens = 0;
    const char *p = line;
    char *current_token_start = token_storage;
    size_t remaining_storage = TOKEN_BUFFER_SIZE;

    while (*p && *num_tokens < MAX_ARGS && remaining_storage > 1) {
        while (isspace((unsigned char)*p)) p++; // Salta spazi iniziali
        if (!*p) break;

        tokens[*num_tokens] = current_token_start;
        (*num_tokens)++;

        if (*p == '"') { // Stringa quotata
            p++; // Salta la virgoletta iniziale
            while (*p && *p != '"' && remaining_storage > 1) {
                *current_token_start++ = *p++;
                remaining_storage--;
            }
            if (*p == '"') p++; // Salta la virgoletta finale
        } else { // Token non quotato
            // Caratteri speciali che dovrebbero essere token separati
            // Per ora, li includiamo nei token se non sono spazi.
            // Una tokenizzazione più avanzata li separerebbe.
            // Es: if $var==val { -> 'if', '$var==val', '{'
            //     if $var == val { -> 'if', '$var', '==', 'val', '{'
            // La seconda è più facile da gestire. Assumiamo spazi.
             while (*p && !isspace((unsigned char)*p) && remaining_storage > 1) {
                // Gestione di '{' e '}' come token separati se attaccati
                if ((*p == '{' || *p == '}') && current_token_start != tokens[*num_tokens-1]) {
                    // Se '{' o '}' non è l'inizio del token corrente, termina il token precedente.
                    break; 
                }
                *current_token_start++ = *p++;
                remaining_storage--;
                // Se il carattere corrente è '{' o '}', e l'abbiamo appena aggiunto,
                // allora questo token è solo '{' o '}'. Termina qui.
                if ((*(current_token_start-1) == '{' || *(current_token_start-1) == '}') && current_token_start == tokens[*num_tokens-1]+1) {
                    break;
                }
            }
        }
        
        if (remaining_storage > 0) {
            *current_token_start++ = '\0';
            remaining_storage--;
        } else {
            // Buffer pieno per i token
            if (*num_tokens > 0) (*num_tokens)--; // Rimuovi l'ultimo token parziale
            fprintf(stderr, "Buffer token pieno.\n");
            return;
        }
        // Se il token è vuoto (es. due spazi consecutivi), rimuovilo
        if (tokens[*num_tokens-1][0] == '\0' && *num_tokens > 0) {
            (*num_tokens)--;
        }
    }
}


// --- Implementazione Comandi Built-in e Statement ---

void handle_assignment(char **tokens, int num_tokens) {
    if (num_tokens < 3) {
        fprintf(stderr, "Sintassi assegnazione: $var = valore_o_comando\n");
        return;
    }

    char var_name_raw[MAX_VAR_NAME_LEN]; // Nome variabile senza '$'
    char index_str_raw[MAX_VAR_NAME_LEN] = ""; // Per $arr[idx]
    bool is_array_assignment = false;

    // Estrai nome base e indice se è un array
    const char* p_var = tokens[0] + 1; // Salta '$'
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
                     fprintf(stderr, "Indice array troppo lungo: %s\n", tokens[0]); return;
                }
            } else {
                 fprintf(stderr, "Sintassi array errata (manca ']' o indice vuoto): %s\n", tokens[0]); return;
            }
        } else {
            fprintf(stderr, "Nome base array troppo lungo: %s\n", tokens[0]); return;
        }
    } else {
        strncpy(var_name_raw, p_var, MAX_VAR_NAME_LEN - 1);
        var_name_raw[MAX_VAR_NAME_LEN - 1] = '\0';
    }


    // Il valore da assegnare inizia da tokens[2]
    // Se tokens[2] è l'inizio di una stringa quotata che si estende su più token (improbabile con la tokenizzazione attuale)
    // o se è un comando da eseguire.

    char value_to_set[MAX_VAR_VALUE_LEN];
    value_to_set[0] = '\0';

    // Verifica se il valore è un comando da eseguire o una stringa letterale
    char full_command_path_check[MAX_FULL_PATH_LEN];
    bool is_rhs_command = false;
    if (num_tokens > 2) { // Almeno un token per il comando/valore
        // Espandi variabili nel primo token del RHS prima di cercare il comando
        char expanded_first_rhs_token[MAX_VAR_VALUE_LEN];
        expand_variables_in_string(tokens[2], expanded_first_rhs_token, sizeof(expanded_first_rhs_token));
        if (find_command_in_path(expanded_first_rhs_token, full_command_path_check)) {
            is_rhs_command = true;
        }
    }


    if (is_rhs_command) { // Esegui comando e cattura output
        char *cmd_args[MAX_ARGS + 1];
        char expanded_cmd_args_storage[MAX_ARGS][MAX_VAR_VALUE_LEN];
        int cmd_arg_count = num_tokens - 2;

        for (int i = 0; i < cmd_arg_count; i++) {
            expand_variables_in_string(tokens[i + 2], expanded_cmd_args_storage[i], MAX_VAR_VALUE_LEN);
            cmd_args[i] = expanded_cmd_args_storage[i];
        }
        cmd_args[cmd_arg_count] = NULL;
        
        // Il path del comando è già in full_command_path_check se is_rhs_command è true
        execute_external_command(full_command_path_check, cmd_args, cmd_arg_count, value_to_set, sizeof(value_to_set));

    } else { // Assegnazione di stringa letterale (o multipli token da concatenare)
        char combined_value[MAX_VAR_VALUE_LEN] = "";
        size_t current_len = 0;
        for (int i = 2; i < num_tokens; i++) {
            char expanded_token[MAX_VAR_VALUE_LEN];
            expand_variables_in_string(tokens[i], expanded_token, sizeof(expanded_token));
            
            size_t token_len = strlen(expanded_token);
            if (current_len + token_len + (i > 2 ? 1 : 0) < MAX_VAR_VALUE_LEN) {
                if (i > 2) { // Aggiungi spazio se non è il primo token del valore
                    strcat(combined_value, " ");
                    current_len++;
                }
                strcat(combined_value, expanded_token);
                current_len += token_len;
            } else {
                fprintf(stderr, "Valore troppo lungo per assegnazione.\n");
                break;
            }
        }
        // Rimuovi virgolette esterne se presenti (es. $var = "ciao mondo")
        size_t len = strlen(combined_value);
        if (len >= 2 && combined_value[0] == '"' && combined_value[len-1] == '"') {
            memmove(combined_value, combined_value + 1, len - 2);
            combined_value[len - 2] = '\0';
        }
        strncpy(value_to_set, combined_value, MAX_VAR_VALUE_LEN -1);
        value_to_set[MAX_VAR_VALUE_LEN-1] = '\0';
    }

    if (is_array_assignment) {
        set_array_element_value(var_name_raw, index_str_raw, value_to_set);
    } else {
        set_variable(var_name_raw, value_to_set);
    }
}


void handle_echo(char **tokens, int num_tokens) {
    char expanded_arg[MAX_VAR_VALUE_LEN];
    for (int i = 1; i < num_tokens; i++) {
        expand_variables_in_string(tokens[i], expanded_arg, sizeof(expanded_arg));
        // Rimuovi virgolette esterne se l'argomento originale era una stringa quotata
        // La tokenizzazione attuale le rimuove, ma se fossero preservate:
        size_t len = strlen(expanded_arg);
        if (len >=2 && tokens[i][0] == '"' && tokens[i][strlen(tokens[i])-1] == '"') {
             // Se l'originale era quotato, `expanded_arg` potrebbe non esserlo più se conteneva variabili.
             // Per echo "ciao", vogliamo stampare ciao, non "ciao".
             // Se tokens[i] è "\"ciao\"", expanded_arg è "ciao".
             // Se tokens[i] è "\"$x\"", expanded_arg è "valore_di_x".
             // Questa logica di rimozione virgolette qui potrebbe essere ridondante
             // o da affinare in base a come `expand_variables_in_string` gestisce le virgolette.
             // Per ora, stampiamo `expanded_arg` così com'è.
        }
        printf("%s%s", expanded_arg, (i == num_tokens - 1) ? "" : " ");
    }
    printf("\n");
}

bool evaluate_condition(const char* operand1_raw, const char* operator_str, const char* operand2_raw) {
    char val1[MAX_VAR_VALUE_LEN];
    char val2[MAX_VAR_VALUE_LEN];

    expand_variables_in_string(operand1_raw, val1, sizeof(val1));
    expand_variables_in_string(operand2_raw, val2, sizeof(val2));
    
    // Rimuovi virgolette da val2 se era un letterale stringa quotato
    // es. if $var == "ciao" -> operand2_raw è "\"ciao\"" (con virgolette)
    // expand_variables_in_string non dovrebbe aggiungere virgolette, ma se le riceve le mantiene.
    // Dobbiamo confrontare i contenuti.
    size_t len_val2 = strlen(val2);
    if (len_val2 >= 2 && val2[0] == '"' && val2[len_val2-1] == '"') {
        memmove(val2, val2 + 1, len_val2 - 2);
        val2[len_val2 - 2] = '\0';
    }
    // Stessa cosa per val1 se per caso fosse un letterale quotato (meno comune)
    size_t len_val1 = strlen(val1);
     if (len_val1 >= 2 && val1[0] == '"' && val1[len_val1-1] == '"') {
        memmove(val1, val1 + 1, len_val1 - 2);
        val1[len_val1 - 2] = '\0';
    }


    if (strcmp(operator_str, "==") == 0) {
        return strcmp(val1, val2) == 0;
    } else if (strcmp(operator_str, "!=") == 0) {
        return strcmp(val1, val2) != 0;
    }
    // Aggiungere altri operatori qui (>, <, >=, <=)
    // Per ora, trattando tutto come stringhe, > e < sono confronti lessicografici.
    else if (strcmp(operator_str, ">") == 0) {
        return strcmp(val1, val2) > 0;
    } else if (strcmp(operator_str, "<") == 0) {
        return strcmp(val1, val2) < 0;
    } else if (strcmp(operator_str, ">=") == 0) {
        return strcmp(val1, val2) >= 0;
    } else if (strcmp(operator_str, "<=") == 0) {
        return strcmp(val1, val2) <= 0;
    }

    fprintf(stderr, "Operatore non supportato: %s\n", operator_str);
    return false;
}

void handle_if_statement(char **tokens, int num_tokens, char* full_line, FILE* input_source) {
    // Formato atteso: if $var op val {  (o if $var op val) e '{' sulla riga dopo
    // La tokenizzazione attuale dovrebbe separare '{' se c'è uno spazio prima.
    // if $val == "ciao" { -> tokens: "if", "$val", "==", "\"ciao\"", "{"
    // num_tokens dovrebbe essere almeno 5 per questo.
    // O se la { è sulla riga dopo, num_tokens è 4.

    bool has_brace_on_same_line = false;
    if (num_tokens > 0 && strcmp(tokens[num_tokens-1], "{") == 0) {
        has_brace_on_same_line = true;
    }
    
    // La condizione è tokens[1] tokens[2] tokens[3]
    if (num_tokens < (has_brace_on_same_line ? 5 : 4)) {
        fprintf(stderr, "Sintassi 'if' errata. Atteso: if $var op val { oppure if $var op val\n");
        current_exec_state = STATE_IF_BLOCK_FALSE; // Entra in modalità skip per sicurezza
        if (has_brace_on_same_line) conditional_nesting_level++;
        return;
    }

    bool condition_result = evaluate_condition(tokens[1], tokens[2], tokens[3]);

    if (condition_result) {
        current_exec_state = STATE_IF_BLOCK_TRUE;
    } else {
        current_exec_state = STATE_IF_BLOCK_FALSE;
    }
    
    if (has_brace_on_same_line) {
        conditional_nesting_level++;
    } else {
        // La '{' deve essere sulla riga successiva. Leggila e verifica.
        // Questa parte è complessa se si mescola input interattivo e da file.
        // Per semplicità, assumiamo che '{' sia sulla stessa riga o la prima cosa non vuota sulla successiva.
        // Se si usa un file, potremmo leggere la riga successiva.
        // Per ora, la logica di process_line gestirà '{' se è su una riga a sé.
        // Se '{' non è sulla stessa riga, conditional_nesting_level sarà incrementato
        // quando la riga con '{' verrà processata.
        // Questo richiede che '{' sia il primo token non vuoto sulla sua riga.
    }
}

void handle_else_statement(char **tokens, int num_tokens, FILE* input_source) {
    if (conditional_nesting_level == 0) {
        fprintf(stderr, "Errore: 'else' senza 'if' corrispondente.\n");
        return;
    }

    bool has_brace_on_same_line = (num_tokens > 1 && strcmp(tokens[num_tokens-1], "{") == 0);
    if (num_tokens > 1 && strcmp(tokens[1], "if") == 0) { // else if
        // Simile a handle_if_statement, ma solo se lo stato precedente era IF_BLOCK_FALSE
        if (current_exec_state == STATE_IF_BLOCK_FALSE) { // Solo se l'if precedente era falso
            // Valuta la condizione dell' "else if"
            // tokens per "else if": "else", "if", "$var", "op", "val", "{" (opzionale)
            int if_token_start_idx = 1; // "if" è tokens[1]
            bool else_if_has_brace = (num_tokens > if_token_start_idx && strcmp(tokens[num_tokens-1], "{") == 0);
            
            if (num_tokens < (else_if_has_brace ? if_token_start_idx + 5 : if_token_start_idx + 4)) {
                 fprintf(stderr, "Sintassi 'else if' errata.\n");
                 current_exec_state = STATE_ELSE_BLOCK_SKIP; // Salta per sicurezza
                 if (else_if_has_brace) { /* conditional_nesting_level non cambia qui, gestito da { */ }
                 return;
            }

            bool condition_result = evaluate_condition(tokens[if_token_start_idx+1], tokens[if_token_start_idx+2], tokens[if_token_start_idx+3]);
            if (condition_result) {
                current_exec_state = STATE_IF_BLOCK_TRUE; // Trattalo come un if vero
            } else {
                current_exec_state = STATE_IF_BLOCK_FALSE; // Continua a saltare
            }
            // Il nesting level per la '{' dell'else if è gestito dalla '{' stessa
            // Non decrementiamo e re-incrementiamo qui.
        } else { // L'if precedente era vero, o siamo in un altro stato, quindi salta questo else if
            current_exec_state = STATE_ELSE_BLOCK_SKIP;
        }

    } else { // 'else' semplice
        if (current_exec_state == STATE_IF_BLOCK_TRUE || current_exec_state == STATE_ELSE_BLOCK_EXEC) {
            // L'if precedente (o un else if) era vero, quindi questo 'else' deve essere saltato
            current_exec_state = STATE_ELSE_BLOCK_SKIP;
        } else if (current_exec_state == STATE_IF_BLOCK_FALSE) {
            // L'if precedente era falso, quindi questo 'else' deve essere eseguito
            current_exec_state = STATE_ELSE_BLOCK_EXEC;
        }
        // Se STATE_ELSE_BLOCK_SKIP, rimane tale (es. if true {} else if true {} else {})
    }
    
    // La '{' associata all'else (o else if) incrementerà il conditional_nesting_level
    // quando la riga con '{' (o la fine della riga 'else ... {') viene processata.
    // Se la { è sulla stessa riga dell'else:
    if ( (num_tokens > 0 && strcmp(tokens[num_tokens-1],"{") == 0) ||
         (num_tokens > 1 && strcmp(tokens[0],"else")==0 && strcmp(tokens[1],"{")==0) ) {
        // Non incrementare qui, la '{' come token separato lo farà,
        // o la logica di fine riga in process_line per if/else con { attaccata.
        // Questo è complicato. Per ora, la gestione di '{' è un po' sparsa.
        // Assumiamo che process_line chiami handle_closing_brace per '}',
        // e if/else gestiscano l'incremento per la loro '{'.
        // Se `else {` è tokenizzato come `else` e `{`, allora `process_line`
        // vedrà `{` dopo aver gestito `else`.
        // Se `else {` è `else` e `tokens[num_tokens-1]` è `{`, allora `conditional_nesting_level`
        // dovrebbe essere incrementato qui.
        // La gestione attuale di '{' in process_line è solo se è l'UNICO token.
        // Meglio che if/else/etc gestiscano il loro '{'.
        // La logica di `handle_if_statement` e `handle_else_statement` già considera `has_brace_on_same_line`.
        // E `conditional_nesting_level` viene aggiornato lì.
    }
     // Se la { è sulla stessa riga dell'else:
    if (has_brace_on_same_line || (num_tokens > 1 && strcmp(tokens[0],"else")==0 && strcmp(tokens[1],"{")==0) ) {
        // La gestione del nesting level per la '{' dell'else è un po' delicata.
        // Se 'else {' è tokenizzato in 'else' e '{', allora il token '{' sarà gestito separatamente.
        // Se 'else {' è un token 'else' e l'ultimo token della riga è '{', allora incrementiamo qui.
        // La mia tokenizzazione attuale dovrebbe fare `else` e `{` token separati se c'è spazio.
        // Se è `else{`, allora `else{` è un token.
        // Per `else ... {`, l'ultimo token è `{`.
        // Questa parte della gestione del nesting per `{` deve essere consistente.
        // Se `tokens[num_tokens-1]` è `{`, allora è parte di questo costrutto.
        // `conditional_nesting_level` dovrebbe essere già stato incrementato in `handle_if_statement`
        // se la graffa era lì. Per `else`, se la graffa è con lui, incrementa.
        // No, la gestione del nesting è meglio centralizzarla con l'apparire di '{' e '}'.
        // Le funzioni if/else impostano lo STATO. L'apparire di '{' aumenta il livello.
        // L'apparire di '}' lo diminuisce.
        // La logica attuale in process_line per '{' e '}' è troppo semplice.
        
        // Rivediamo: quando `if ... {` o `else ... {` viene parsato, e la `{` è riconosciuta
        // come parte del costrutto, `conditional_nesting_level` DEVE essere incrementato
        // da quella funzione (handle_if, handle_else).
        // `handle_if_statement` lo fa. `handle_else_statement` deve farlo.
        if (has_brace_on_same_line && !(num_tokens > 1 && strcmp(tokens[1], "if") == 0)) { // Solo per 'else {', non 'else if ... {' (già gestito)
             // conditional_nesting_level++; // Questo potrebbe essere un doppio conteggio se '{' è anche un token separato.
        }
        // Se l'ultimo token è '{', allora è associato.
        // La gestione del nesting level è critica.
        // Ogni volta che si entra in un blocco (if vero, if falso, else vero, else falso), il livello aumenta.
        // Quando si esce con '}', il livello diminuisce.
    }
}


void handle_closing_brace() {
    if (conditional_nesting_level > 0) {
        conditional_nesting_level--;
        if (conditional_nesting_level == 0) {
            // Siamo usciti da tutti i blocchi if/else
            current_exec_state = STATE_NORMAL;
        } else {
            // Siamo usciti da un blocco annidato, ma siamo ancora dentro un blocco esterno.
            // Lo stato (es. STATE_IF_BLOCK_FALSE) dovrebbe persistere se il blocco esterno lo richiede.
            // Questa parte è delicata. Se esco da un if annidato vero dentro un if esterno falso,
            // devo tornare a saltare.
            // Per ora, la semplice uscita da un livello resetta lo stato solo a livello 0.
            // Questo non è corretto per if annidati in blocchi saltati.
            // Serve uno stack di stati o una logica più complessa.
            // Per "ipersemplificato", questo potrebbe essere un limite accettabile.
            // Se current_exec_state era IF_BLOCK_TRUE o ELSE_BLOCK_EXEC, e usciamo dal suo blocco,
            // torniamo a NORMAL (se nesting level è 0).
            // Se era IF_BLOCK_FALSE o ELSE_BLOCK_SKIP, e usciamo dal suo blocco,
            // e nesting_level > 0, significa che il blocco esterno era anche da saltare.
            // Se nesting_level == 0, allora torniamo a normal.
            // Quindi, il reset a STATE_NORMAL solo a livello 0 è corretto.
        }
    } else {
        fprintf(stderr, "Errore: '}' non corrispondente.\n");
    }
}


// --- Implementazione Funzioni Utilità ---

char* trim_whitespace(char *str) {
    char *end;
    // Trim leading space
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str; // All spaces?

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = 0;

    return str;
}

void free_variables() {
    Variable *current = variable_list;
    Variable *next;
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
    variable_list = NULL;
}

