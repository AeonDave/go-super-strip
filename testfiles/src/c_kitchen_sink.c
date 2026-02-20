#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// Function prototypes
static void print_banner(void);
static void test_math_operations(void);
static void test_string_operations(void);
static void test_file_operations(void);
static void test_memory_operations(void);
static void calculate_hash(const char *data, size_t len);
static int validate_email(const char *email);
static void generate_random_data(unsigned char *buffer, size_t size);

// Global variables to test symbol stripping
static const char *APP_NAME = "C Fixture: kitchen sink";
static const char *VERSION = "2.0.0";
static int global_counter = 0;

int main(int argc, char *argv[]) {
    printf("=== %s v%s ===\n", APP_NAME, VERSION);
    printf("Compiled: %s %s\n", __DATE__, __TIME__);
    printf("Arguments: %d\n", argc);

    if (argc > 1) {
        printf("First argument: %s\n", argv[1]);
    }

    print_banner();
    test_math_operations();
    test_string_operations();
    test_file_operations();
    test_memory_operations();

    printf("\n=== Fixture completed successfully ===\n");
    return 0;
}

static void print_banner(void) {
    printf("\n");
    printf("  ╔══════════════════════════════════╗\n");
    printf("  ║         C Fixture Runner         ║\n");
    printf("  ║    Testing various libraries     ║\n");
    printf("  ╚══════════════════════════════════╝\n");
    printf("\n");
}

static void test_math_operations(void) {
    printf("=== Math Operations Test ===\n");

    double x = 42.5;
    double y = 13.7;

    printf("x = %.2f, y = %.2f\n", x, y);
    printf("x + y = %.2f\n", x + y);
    printf("x * y = %.2f\n", x * y);
    printf("sqrt(x) = %.2f\n", sqrt(x));
    printf("sin(x) = %.2f\n", sin(x));
    printf("log(x) = %.2f\n", log(x));
    printf("pow(x, 2) = %.2f\n", pow(x, 2.0));

    srand((unsigned int)time(NULL));
    for (int i = 0; i < 5; i++) {
        printf("Random number %d: %d\n", i + 1, rand() % 100);
    }

    global_counter += 10;
    printf("Global counter: %d\n", global_counter);
}

static void test_string_operations(void) {
    printf("\n=== String Operations Test ===\n");

    char buffer[256];
    const char *test_string = "Hello, World! This is a TEST string with Numbers 12345";

    strcpy(buffer, test_string);
    printf("Original: %s\n", buffer);
    printf("Length: %zu\n", strlen(buffer));

    for (int i = 0; buffer[i]; i++) {
        buffer[i] = (char)toupper((unsigned char)buffer[i]);
    }
    printf("Uppercase: %s\n", buffer);

    const char *emails[] = {
        "test@example.com",
        "invalid.email",
        "user@domain.org",
        "bad@email@test.com",
    };

    for (int i = 0; i < 4; i++) {
        printf("Email '%s' is %s\n", emails[i], validate_email(emails[i]) ? "valid" : "invalid");
    }

    calculate_hash(test_string, strlen(test_string));
}

static void test_file_operations(void) {
    printf("\n=== File Operations Test ===\n");

    char filename[512];
#ifdef _WIN32
    DWORD pid = GetCurrentProcessId();
    snprintf(filename, sizeof(filename), "gosstrip_fixture_c_%lu.txt", (unsigned long)pid);
#else
    snprintf(filename, sizeof(filename), "gosstrip_fixture_c_%ld.txt", (long)getpid());
#endif

    const char *content = "This is a fixture file created by the C program.\n"
                          "It contains multiple lines of text.\n"
                          "Testing file I/O operations.\n";

    FILE *file = fopen(filename, "w");
    if (file) {
        fprintf(file, "%s", content);
        fclose(file);
        printf("Created file: %s\n", filename);
    } else {
        printf("Failed to create file\n");
        return;
    }

    file = fopen(filename, "r");
    if (file) {
        char line[256];
        int line_num = 1;
        printf("File contents:\n");
        while (fgets(line, sizeof(line), file)) {
            printf("  %d: %s", line_num++, line);
        }
        fclose(file);
    }

    file = fopen(filename, "rb");
    if (file) {
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        fclose(file);
        printf("File size: %ld bytes\n", size);
    }

    if (remove(filename) == 0) {
        printf("File removed successfully\n");
    } else {
        printf("Failed to remove file\n");
    }
}

static void test_memory_operations(void) {
    printf("\n=== Memory Operations Test ===\n");

    size_t size = 1024;
    unsigned char *buffer = (unsigned char *)malloc(size);
    if (!buffer) {
        printf("Failed to allocate memory\n");
        return;
    }

    printf("Allocated %zu bytes of memory\n", size);

    generate_random_data(buffer, size);
    printf("Filled buffer with random data\n");

    unsigned int checksum = 0;
    for (size_t i = 0; i < size; i++) {
        checksum += buffer[i];
    }
    printf("Buffer checksum: 0x%08X\n", checksum);

    size *= 2;
    unsigned char *b2 = (unsigned char *)realloc(buffer, size);
    if (b2) {
        buffer = b2;
        printf("Reallocated to %zu bytes\n", size);
    }

    memset(buffer, 0, size);
    printf("Memory cleared\n");

    free(buffer);
    printf("Memory freed\n");
}

static void calculate_hash(const char *data, size_t len) {
    unsigned int hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + (unsigned char)data[i];
    }
    printf("String hash: 0x%08X\n", hash);
}

static int validate_email(const char *email) {
    if (!email) {
        return 0;
    }

    const char *at_pos = strchr(email, '@');
    if (!at_pos) {
        return 0;
    }

    if (strchr(at_pos + 1, '@')) {
        return 0;
    }

    const char *dot_pos = strchr(at_pos, '.');
    if (!dot_pos) {
        return 0;
    }

    if (at_pos == email) {
        return 0;
    }
    if (dot_pos == at_pos + 1) {
        return 0;
    }
    if (strlen(dot_pos) < 3) {
        return 0;
    }

    return 1;
}

static void generate_random_data(unsigned char *buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (unsigned char)(rand() % 256);
    }
}
