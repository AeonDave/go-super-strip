// c_msvc_tls.c
// C language with MSVC, TLS callback demonstration
#include <windows.h>

// TLS callback function - executes before main()
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        MessageBoxW(
            NULL,
            L"TLS Callback executed!\n\n"
            L"This runs BEFORE main()\n"
            L"Language: C\n"
            L"Compiler: MSVC (cl.exe)\n"
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

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance;
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;
    
    MessageBoxW(
        NULL,
        L"Hello from C/MSVC/TLS\n\n"
        L"Language: C\n"
        L"Compiler: MSVC (cl.exe)\n"
        L"Feature: TLS Callback\n\n"
        L"(TLS callback already executed)",
        L"Payload Test - C MSVC TLS (main)",
        MB_OK | MB_ICONINFORMATION
    );
    return 0;
}
