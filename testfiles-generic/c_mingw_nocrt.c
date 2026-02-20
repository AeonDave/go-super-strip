// c_mingw_nocrt.c
// C language with MinGW compiler, no CRT, custom entry point
#include <windows.h>

void __stdcall WinMainCRTStartup(void) {
    MessageBoxW(
        NULL,
        L"Hello from C/MinGW/Static/NoCRT\n\n"
        L"Language: C\n"
        L"Compiler: MinGW-w64 GCC\n"
        L"Linking: Static\n"
        L"CRT: No (custom entry)",
        L"Payload Test - C MinGW NoCRT",
        MB_OK | MB_ICONINFORMATION
    );
    ExitProcess(0);
}
