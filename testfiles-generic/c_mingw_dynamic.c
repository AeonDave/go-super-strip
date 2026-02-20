// c_mingw_dynamic.c
// C language with MinGW compiler, dynamically linked with CRT
#include <windows.h>

int main(void) {
    MessageBoxW(
        NULL,
        L"Hello from C/MinGW/Dynamic/CRT\n\n"
        L"Language: C\n"
        L"Compiler: MinGW-w64 GCC\n"
        L"Linking: Dynamic\n"
        L"CRT: Yes (msvcrt.dll)",
        L"Payload Test - C MinGW Dynamic",
        MB_OK | MB_ICONINFORMATION
    );
    return 0;
}
