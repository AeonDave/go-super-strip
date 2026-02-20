// c_msvc_nocrt.c
// C language with MSVC compiler, no CRT, custom entry point
#include <windows.h>

void __stdcall WinMainCRTStartup(void) {
    MessageBoxW(
        NULL,
        L"Hello from C/MSVC/Static/NoCRT\n\n"
        L"Language: C\n"
        L"Compiler: MSVC (cl.exe)\n"
        L"Linking: Static (/Zl /NODEFAULTLIB)\n"
        L"CRT: No (custom entry)",
        L"Payload Test - C MSVC NoCRT",
        MB_OK | MB_ICONINFORMATION
    );
    ExitProcess(0);
}
