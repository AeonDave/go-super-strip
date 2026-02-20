// c_mingw_tls.c
// C language with MinGW, TLS callback demonstration
#include <windows.h>

// TLS callback function - executes before main()
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        MessageBoxW(
            NULL,
            L"TLS Callback executed!\n\n"
            L"This runs BEFORE main()\n"
            L"Language: C\n"
            L"Compiler: MinGW-w64 GCC\n"
            L"Feature: TLS Callback",
            L"Payload Test - TLS Callback (Before main)",
            MB_OK | MB_ICONWARNING
        );
    }
}

// Register TLS callback in .CRT$XLB section
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:tls_callback_func")
#pragma const_seg(".CRT$XLB")
EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback_func = TlsCallback;
#pragma const_seg()
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_tls_callback_func")
#pragma data_seg(".CRT$XLB")
EXTERN_C PIMAGE_TLS_CALLBACK tls_callback_func = TlsCallback;
#pragma data_seg()
#endif

int main(void) {
    MessageBoxW(
        NULL,
        L"Hello from C/MinGW/TLS\n\n"
        L"Language: C\n"
        L"Compiler: MinGW-w64 GCC\n"
        L"Feature: TLS Callback\n\n"
        L"(TLS callback already executed)",
        L"Payload Test - C MinGW TLS (main)",
        MB_OK | MB_ICONINFORMATION
    );
    return 0;
}
