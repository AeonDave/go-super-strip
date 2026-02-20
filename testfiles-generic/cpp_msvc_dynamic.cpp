// cpp_msvc_dynamic.cpp
// C++ language with MSVC compiler, dynamically linked with CRT (/MD)
#include <windows.h>
#include <string>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance;
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;
    std::wstring message = 
        L"Hello from C++/MSVC/Dynamic/CRT\n\n"
        L"Language: C++\n"
        L"Compiler: MSVC (cl.exe)\n"
        L"Linking: Dynamic (/MD)\n"
        L"CRT: Yes (msvcp140.dll)\n"
        L"Features: STL enabled";
    
    MessageBoxW(
        NULL,
        message.c_str(),
        L"Payload Test - C++ MSVC Dynamic",
        MB_OK | MB_ICONINFORMATION
    );
    return 0;
}
