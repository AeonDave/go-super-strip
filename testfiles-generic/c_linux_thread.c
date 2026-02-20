// c_linux_thread.c
// C with pthread TLS and __attribute__((constructor)) — Linux analogue
// of the Windows TLS callback technique: code that runs before main().
#include <stdio.h>
#include <pthread.h>

// Thread-local variable (compiler TLS via __thread keyword)
static __thread int tls_value = 0;

// Constructor attribute: runs automatically before main(), analogous
// to a Windows TLS callback with DLL_PROCESS_ATTACH reason.
__attribute__((constructor))
static void pre_main_ctor(void) {
    tls_value = 42;
}

// A simple thread worker demonstrating that TLS is per-thread.
static void *worker(void *arg) {
    (void)arg;
    tls_value = 99;
    return NULL;
}

int main(void) {
    pthread_t th;
    pthread_create(&th, NULL, worker, NULL);
    pthread_join(th, NULL);

    printf(
        "Payload Test - C Linux Thread\n\n"
        "Language:   C\n"
        "Compiler:   GCC\n"
        "Feature:    pthread + __thread TLS + constructor\n"
        "TLS (main): %d (set by constructor before main)\n",
        tls_value
    );
    fflush(stdout);
    return 0;
}
