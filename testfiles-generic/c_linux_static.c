// c_linux_static.c
// C language, statically linked (no shared runtime dependency)
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    printf(
        "Payload Test - C Linux Static\n\n"
        "Language:  C\n"
        "Compiler:  GCC\n"
        "Linking:   Static (musl or glibc static)\n"
        "CRT:       Yes (embedded libc)\n"
    );
    fflush(stdout);
    return 0;
}
