// cpp_msvc_static.cpp
// C++ language with MSVC compiler, statically linked with CRT (/MT)
#include <windows.h>
#include <string>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance;
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;
    std::wstring message = 
        L"Hello from C++/MSVC/Static/CRT\n\n"
        L"Language: C++\n"
        L"Compiler: MSVC (cl.exe)\n"
        L"Linking: Static (/MT)\n"
        L"CRT: Yes (libcmt.lib)\n"
        L"Features: STL enabled";
    
    MessageBoxW(
        NULL,
        message.c_str(),
        L"Payload Test - C++ MSVC Static",
        MB_OK | MB_ICONINFORMATION
    );
    return 0;
}
