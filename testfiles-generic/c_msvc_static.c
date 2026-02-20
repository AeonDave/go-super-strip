// c_msvc_static.c
// C language with MSVC compiler, statically linked with CRT (/MT)
#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance;
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;
    
    MessageBoxW(
        NULL,
        L"Hello from C/MSVC/Static/CRT\n\n"
        L"Language: C\n"
        L"Compiler: MSVC (cl.exe)\n"
        L"Linking: Static (/MT)\n"
        L"CRT: Yes (libcmt.lib)",
        L"Payload Test - C MSVC Static",
        MB_OK | MB_ICONINFORMATION
    );
    return 0;
}
