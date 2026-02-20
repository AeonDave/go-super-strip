// cpp_mingw_static.cpp
// C++ language with MinGW compiler, statically linked with CRT
#include <windows.h>
#include <string>

int main() {
    std::wstring message = 
        L"Hello from C++/MinGW/Static/CRT\n\n"
        L"Language: C++\n"
        L"Compiler: MinGW-w64 G++\n"
        L"Linking: Static\n"
        L"CRT: Yes (libstdc++ static)\n"
        L"Features: STL enabled";
    
    MessageBoxW(
        NULL,
        message.c_str(),
        L"Payload Test - C++ MinGW Static",
        MB_OK | MB_ICONINFORMATION
    );
    return 0;
}
