// c_msvc_dynamic.c
// C language with MSVC compiler, dynamically linked with CRT (/MD)
#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance;
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;
    MessageBoxW(
        NULL,
        L"Hello from C/MSVC/Dynamic/CRT\n\n"
        L"Language: C\n"
        L"Compiler: MSVC (cl.exe)\n"
        L"Linking: Dynamic (/MD)\n"
        L"CRT: Yes (vcruntime140.dll)",
        L"Payload Test - C MSVC Dynamic",
        MB_OK | MB_ICONINFORMATION
    );
    return 0;
}
