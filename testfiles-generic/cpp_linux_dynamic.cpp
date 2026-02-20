// cpp_linux_dynamic.cpp
// C++ language dynamically linked with libstdc++
#include <cstdio>
#include <string>
#include <vector>

int main() {
    std::string lang    = "C++";
    std::string compiler = "GCC g++";
    std::string linking  = "Dynamic (libstdc++.so)";

    std::vector<std::string> features = {
        "STL containers", "exceptions", "RTTI", "virtual dispatch"
    };

    std::printf(
        "Payload Test - C++ Linux Dynamic\n\n"
        "Language:  %s\n"
        "Compiler:  %s\n"
        "Linking:   %s\n"
        "Features:  ",
        lang.c_str(), compiler.c_str(), linking.c_str()
    );
    for (std::size_t i = 0; i < features.size(); ++i) {
        if (i) std::printf(", ");
        std::printf("%s", features[i].c_str());
    }
    std::printf("\n");
    std::fflush(stdout);
    return 0;
}
