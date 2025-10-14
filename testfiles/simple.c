#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <ctype.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

// Function prototypes
void print_banner(void);
void test_math_operations(void);
void test_string_operations(void);
void test_file_operations(void);
void test_memory_operations(void);
void calculate_hash(const char* data, size_t len);
int validate_email(const char* email);
void generate_random_data(unsigned char* buffer, size_t size);

// Global variables to test symbol stripping
static const char* APP_NAME = "Simple C Test Application";
static const char* VERSION = "1.2.3";
static int global_counter = 0;

int main(int argc, char* argv[]) {
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
    
    printf("\n=== Test completed successfully! ===\n");
    return 0;
}

void print_banner(void) {
    printf("\n");
    printf("  ╔══════════════════════════════════╗\n");
    printf("  ║       C Test Application         ║\n");
    printf("  ║    Testing various libraries     ║\n");
    printf("  ╚══════════════════════════════════╝\n");
    printf("\n");
}

void test_math_operations(void) {
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
    
    // Test random numbers
    srand((unsigned int)time(NULL));
    for (int i = 0; i < 5; i++) {
        printf("Random number %d: %d\n", i + 1, rand() % 100);
    }
    
    global_counter += 10;
    printf("Global counter: %d\n", global_counter);
}

void test_string_operations(void) {
    printf("\n=== String Operations Test ===\n");
    
    char buffer[256];
    const char* test_string = "Hello, World! This is a TEST string with Numbers 12345";
    
    strcpy(buffer, test_string);
    printf("Original: %s\n", buffer);
    printf("Length: %zu\n", strlen(buffer));
    
    // Convert to uppercase
    for (int i = 0; buffer[i]; i++) {
        buffer[i] = (char)toupper(buffer[i]);
    }
    printf("Uppercase: %s\n", buffer);
    
    // Test email validation
    const char* emails[] = {
        "test@example.com",
        "invalid.email",
        "user@domain.org",
        "bad@email@test.com"
    };
    
    for (int i = 0; i < 4; i++) {
        printf("Email '%s' is %s\n", emails[i], 
               validate_email(emails[i]) ? "valid" : "invalid");
    }
    
    // Calculate hash of string
    calculate_hash(test_string, strlen(test_string));
}

void test_file_operations(void) {
    printf("\n=== File Operations Test ===\n");
    
    const char* filename = "test_temp_file.txt";
    const char* content = "This is a test file created by the C application.\n"
                         "It contains multiple lines of text.\n"
                         "Testing file I/O operations.\n";
    
    // Write file
    FILE* file = fopen(filename, "w");
    if (file) {
        fprintf(file, "%s", content);
        fclose(file);
        printf("Created file: %s\n", filename);
    } else {
        printf("Failed to create file\n");
        return;
    }
    
    // Read file
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
    
    // Get file size
    file = fopen(filename, "rb");
    if (file) {
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        fclose(file);
        printf("File size: %ld bytes\n", size);
    }
    
    // Remove file
    if (remove(filename) == 0) {
        printf("File removed successfully\n");
    } else {
        printf("Failed to remove file\n");
    }
}

void test_memory_operations(void) {
    printf("\n=== Memory Operations Test ===\n");
    
    // Allocate dynamic memory
    size_t size = 1024;
    unsigned char* buffer = (unsigned char*)malloc(size);
    if (!buffer) {
        printf("Failed to allocate memory\n");
        return;
    }
    
    printf("Allocated %zu bytes of memory\n", size);
    
    // Fill with random data
    generate_random_data(buffer, size);
    printf("Filled buffer with random data\n");
    
    // Calculate checksum
    unsigned int checksum = 0;
    for (size_t i = 0; i < size; i++) {
        checksum += buffer[i];
    }
    printf("Buffer checksum: 0x%08X\n", checksum);
    
    // Test realloc
    size *= 2;
    buffer = (unsigned char*)realloc(buffer, size);
    if (buffer) {
        printf("Reallocated to %zu bytes\n", size);
    }
    
    // Clear memory
    memset(buffer, 0, size);
    printf("Memory cleared\n");
    
    free(buffer);
    printf("Memory freed\n");
}

void calculate_hash(const char* data, size_t len) {
    // Simple hash function (not cryptographic)
    unsigned int hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + (unsigned char)data[i];
    }
    printf("String hash: 0x%08X\n", hash);
}

int validate_email(const char* email) {
    if (!email) return 0;
    
    const char* at_pos = strchr(email, '@');
    if (!at_pos) return 0;
    
    // Check for exactly one @
    if (strchr(at_pos + 1, '@')) return 0;
    
    // Check for at least one . after @
    const char* dot_pos = strchr(at_pos, '.');
    if (!dot_pos) return 0;
    
    // Basic length checks
    if (at_pos == email) return 0;  // @ at start
    if (dot_pos == at_pos + 1) return 0;  // . immediately after @
    if (strlen(dot_pos) < 3) return 0;  // need at least .xx
    
    return 1;
}

void generate_random_data(unsigned char* buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (unsigned char)(rand() % 256);
    }
}
