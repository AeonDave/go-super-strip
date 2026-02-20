// c_linux_pie.c
// C language with PIE (Position Independent Executable) enabled
// gcc -fpie -pie produces a position-independent binary, a common
// hardening technique that enables ASLR for the main executable.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    // Capture the address of main to show ASLR is active
    uintptr_t addr = (uintptr_t)&main;
    printf(
        "Payload Test - C Linux PIE\n\n"
        "Language:  C\n"
        "Compiler:  GCC\n"
        "Linking:   Dynamic\n"
        "PIE:       Enabled (-fpie -pie)\n"
        "main():    0x%lx (will differ each run with ASLR)\n",
        (unsigned long)addr
    );
    fflush(stdout);
    return 0;
}
