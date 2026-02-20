// c_linux_dynamic.c
// C language, dynamically linked with libc (default GCC behavior)
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    printf(
        "Payload Test - C Linux Dynamic\n\n"
        "Language:  C\n"
        "Compiler:  GCC\n"
        "Linking:   Dynamic (glibc)\n"
        "CRT:       Yes (shared libc.so)\n"
    );
    fflush(stdout);
    return 0;
}
