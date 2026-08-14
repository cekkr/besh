/* A C extension in the fixed B[e]SH library ABI, used by tests/native_lib.bsh.
 *
 *   int func(int argc, char* argv[], char* output_buffer, int buffer_size)
 *
 * argv holds the arguments the script passed to 'calllib'. The return value
 * becomes $LAST_LIB_CALL_STATUS and whatever the function writes into
 * output_buffer becomes $LAST_LIB_CALL_OUTPUT. The buffer belongs to the
 * caller: honour buffer_size, null-terminate, and do not keep the pointer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int demo_twice(int argc, char *argv[], char *out, int n) {
    long v = (argc > 0) ? strtol(argv[0], NULL, 10) : 0;
    snprintf(out, (size_t)n, "%ld", v * 2);
    return 0;
}

int demo_join(int argc, char *argv[], char *out, int n) {
    out[0] = '\0';
    for (int i = 0; i < argc; i++) {
        if (i > 0) strncat(out, "-", (size_t)n - strlen(out) - 1);
        strncat(out, argv[i], (size_t)n - strlen(out) - 1);
    }
    return 0;
}

/* A non-zero return is the library's way of reporting failure to the script. */
int demo_fail(int argc, char *argv[], char *out, int n) {
    (void)argc; (void)argv;
    snprintf(out, (size_t)n, "deliberate failure");
    return 3;
}
