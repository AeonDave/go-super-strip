// cpp_mingw_dynamic.cpp
// C++ language with MinGW compiler, dynamically linked with CRT
#include <windows.h>
#include <string>

int main() {
    std::wstring message = 
        L"Hello from C++/MinGW/Dynamic/CRT\n\n"
        L"Language: C++\n"
        L"Compiler: MinGW-w64 G++\n"
        L"Linking: Dynamic\n"
        L"CRT: Yes (libstdc++-6.dll)\n"
        L"Features: STL enabled";
    
    MessageBoxW(
        NULL,
        message.c_str(),
        L"Payload Test - C++ MinGW Dynamic",
        MB_OK | MB_ICONINFORMATION
    );
    return 0;
}
