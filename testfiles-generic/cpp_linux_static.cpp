// cpp_linux_static.cpp
// C++ language statically linked (libstdc++ + libgcc embedded)
#include <cstdio>
#include <string>
#include <vector>
#include <algorithm>

int main() {
    std::vector<int> nums = {5, 3, 1, 4, 2};
    std::sort(nums.begin(), nums.end());

    std::printf(
        "Payload Test - C++ Linux Static\n\n"
        "Language:  C++\n"
        "Compiler:  GCC g++\n"
        "Linking:   Static (-static-libgcc -static-libstdc++ -static)\n"
        "STL sort:  "
    );
    for (std::size_t i = 0; i < nums.size(); ++i) {
        if (i) std::printf(", ");
        std::printf("%d", nums[i]);
    }
    std::printf("\n");
    std::fflush(stdout);
    return 0;
}
