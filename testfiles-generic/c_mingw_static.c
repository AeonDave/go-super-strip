// c_mingw_static.c
// C language with MinGW compiler, statically linked with CRT
#include <windows.h>

int main(void) {
    MessageBoxW(
        NULL,
        L"Hello from C/MinGW/Static/CRT\n\n"
        L"Language: C\n"
        L"Compiler: MinGW-w64 GCC\n"
        L"Linking: Static\n"
        L"CRT: Yes (libgcc static)",
        L"Payload Test - C MinGW Static",
        MB_OK | MB_ICONINFORMATION
    );
    return 0;
}
