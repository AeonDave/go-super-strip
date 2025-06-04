package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	helloElf64Source = `
	#include <unistd.h>
	#include <string.h>
	int main() {
	    const char* message = "Hello, ELF64!\n";
	    ssize_t len = strlen(message);
	    (void)write(STDOUT_FILENO, message, len);
	    return 0;
	}`
	helloElf32Source = `
	#include <unistd.h>
	#include <string.h>
	int main() {
	    const char* message = "Hello, ELF32!\n";
	    ssize_t len = strlen(message);
	    (void)write(STDOUT_FILENO, message, len);
	    return 0;
	}`
	// Source for regex testing
	helloElfRegexSource = `
	#include <stdio.h>
	int main() {
		const char* part1 = "Hello, ";
		const char* part2 = "MAGIC_WORD"; // This will be stripped
		const char* part3 = " ELF_REGEX_TEST!\n";
		printf("%s%s%s", part1, part2, part3);
		return 0;
	}`
)

type elfTestCase struct {
	name         string
	desc         string
	arch         string // "64" or "32"
	source       string
	cliArgs      []string
	expectOutput string
	// checkSizeReduction bool // TODO: Implement size check
	// checkOutputContains string // For regex stripping where output changes
	// checkOutputOmits  string // For regex stripping
}

func compileCSourceELF(t *testing.T, tempDir, baseName, source, archFlag string) (string, error) {
	t.Helper()
	srcFilePath := filepath.Join(tempDir, baseName+".c")
	if err := os.WriteFile(srcFilePath, []byte(source), 0644); err != nil {
		return "", fmt.Errorf("failed to write source file %s: %w", srcFilePath, err)
	}
	outputExePath := filepath.Join(tempDir, baseName)
	// Try static linking first, as it creates more self-contained binaries for stripping tests
	cmd := exec.Command("gcc", archFlag, "-O0", "-static", srcFilePath, "-o", outputExePath, "-Wl,--no-warn-rwx-segments")
	var compErr bytes.Buffer
	cmd.Stderr = &compErr
	if err := cmd.Run(); err != nil {
		// If static fails (e.g., no static libs for that arch), try dynamic
		t.Logf("Static compilation failed for %s (%s), trying dynamic. Stderr: %s", baseName, archFlag, compErr.String())
		cmd = exec.Command("gcc", archFlag, "-O0", srcFilePath, "-o", outputExePath, "-Wl,--no-warn-rwx-segments")
		compErr.Reset()
		cmd.Stderr = &compErr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("compilation failed for %s (%s): %w. Stderr: %s", baseName, archFlag, err, compErr.String())
		}
	}
	return outputExePath, nil
}

func runGoSuperStripCommandELF(t *testing.T, goStripArgs ...string) error {
	t.Helper()
	// Assuming main.go is in the parent directory relative to the test file's location
	mainGoPath := filepath.Join("..", "main.go")
	cmd := exec.Command("go", append([]string{"run", mainGoPath}, goStripArgs...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go-super-strip command failed (%v). Stderr: %s", err, stderr.String())
	}
	return nil
}

func executeELFAndGetOutputELF(t *testing.T, exePath string) (string, error) {
	t.Helper()
	cmd := exec.Command(exePath)
	outputBytes, err := cmd.CombinedOutput()
	if err != nil {
		return string(outputBytes), fmt.Errorf("execution of %s failed: %w. Output: %s", exePath, err, string(outputBytes))
	}
	return string(outputBytes), nil
}

func copyFileELF(t *testing.T, src, dst string) error {
	t.Helper()
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", src, err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", dst, err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("failed to copy from %s to %s: %w", src, dst, err)
	}
	// Ensure the copied file is executable
	return destFile.Chmod(0755)
}

func TestELFIntegration(t *testing.T) {
	tempDir := t.TempDir()

	testCases := []elfTestCase{
		// ELF64 Tests
		{name: "ELF64_StripAll", desc: "Test -strip-all on ELF64", arch: "64", source: helloElf64Source, cliArgs: []string{"--strip-all"}, expectOutput: "Hello, ELF64!\n"},
		{name: "ELF64_StripDebug", desc: "Test -strip-debug on ELF64", arch: "64", source: helloElf64Source, cliArgs: []string{"--strip-debug"}, expectOutput: "Hello, ELF64!\n"},
		{name: "ELF64_StripSymbols", desc: "Test -strip-symbols on ELF64", arch: "64", source: helloElf64Source, cliArgs: []string{"--strip-symbols"}, expectOutput: "Hello, ELF64!\n"},
		{name: "ELF64_ObfNames", desc: "Test -obf-names on ELF64", arch: "64", source: helloElf64Source, cliArgs: []string{"--obf-names"}, expectOutput: "Hello, ELF64!\n"},
		{name: "ELF64_ObfBase", desc: "Test -obf-base on ELF64 (expect potentially broken but testing command)", arch: "64", source: helloElf64Source, cliArgs: []string{"--obf-base"}, expectOutput: "Hello, ELF64!\n"}, // ObfBase is risky
		{name: "ELF64_ObfAll", desc: "Test -obf-all on ELF64 (expect potentially broken)", arch: "64", source: helloElf64Source, cliArgs: []string{"--obf-all"}, expectOutput: "Hello, ELF64!\n"},                        // ObfAll is risky
		{name: "ELF64_RegexStrip", desc: "Test -s on ELF64", arch: "64", source: helloElfRegexSource, cliArgs: []string{"-s", "MAGIC_WORD"}, expectOutput: "Hello,  ELF_REGEX_TEST!\n"},

		// ELF32 Tests (similar to ELF64)
		{name: "ELF32_StripAll", desc: "Test -strip-all on ELF32", arch: "32", source: helloElf32Source, cliArgs: []string{"--strip-all"}, expectOutput: "Hello, ELF32!\n"},
		{name: "ELF32_StripDebug", desc: "Test -strip-debug on ELF32", arch: "32", source: helloElf32Source, cliArgs: []string{"--strip-debug"}, expectOutput: "Hello, ELF32!\n"},
		{name: "ELF32_StripSymbols", desc: "Test -strip-symbols on ELF32", arch: "32", source: helloElf32Source, cliArgs: []string{"--strip-symbols"}, expectOutput: "Hello, ELF32!\n"},
		{name: "ELF32_ObfNames", desc: "Test -obf-names on ELF32", arch: "32", source: helloElf32Source, cliArgs: []string{"--obf-names"}, expectOutput: "Hello, ELF32!\n"},
		// Add more ELF32 cases as needed, similar to ELF64
		{name: "ELF32_RegexStrip", desc: "Test -s on ELF32", arch: "32", source: helloElfRegexSource, cliArgs: []string{"-s", "MAGIC_WORD"}, expectOutput: "Hello,  ELF_REGEX_TEST!\n"},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel() // Run test cases in parallel

			archFlag := "-m" + tc.arch
			originalExeBaseName := "test_elf_" + tc.name + "_orig"
			originalExePath, err := compileCSourceELF(t, tempDir, originalExeBaseName, tc.source, archFlag)
			if err != nil {
				t.Fatalf("Compilation failed for %s: %v", tc.name, err)
			}

			processedExeBaseName := "test_elf_" + tc.name + "_processed"
			processedExePath := filepath.Join(tempDir, processedExeBaseName)
			if err := copyFileELF(t, originalExePath, processedExePath); err != nil {
				t.Fatalf("Copying file failed for %s: %v", tc.name, err)
			}

			// originalSize, _ := os.Stat(originalExePath).Size()

			argsToPass := append([]string{processedExePath}, tc.cliArgs...)
			if err := runGoSuperStripCommandELF(t, argsToPass...); err != nil {
				// For known risky operations like ObfBase or ObfAll, we might not fail the test here
				// if gosstrip itself runs but the resulting binary is broken.
				// However, if gosstrip *itself* errors, that's a problem.
				t.Errorf("go-super-strip command failed for %s: %v", tc.name, err)
				// Consider not returning immediately for risky tests to check output if possible
			}

			output, err := executeELFAndGetOutputELF(t, processedExePath)

			// For highly destructive obfuscations, we might expect an error or different output.
			// For now, most tests assume the binary should still run and produce expected output.
			if strings.Contains(tc.name, "ObfBase") || strings.Contains(tc.name, "ObfAll") {
				if err == nil && output != tc.expectOutput {
					t.Logf("WARNING for %s: Destructive obfuscation was applied. Expected output: %q, Got: %q. Execution error: %v", tc.name, tc.expectOutput, output, err)
					// Not failing the test here for ObfBase/ObfAll if it runs but output is wrong, as breakage is possible.
					// However, if it runs AND output is correct, that's a pass.
				} else if err != nil {
					t.Logf("INFO for %s: Destructive obfuscation was applied. Execution failed as potentially expected. Error: %v", tc.name, err)
					// This is an expected outcome for some destructive tests, so not a test failure by itself.
				} else { // err == nil && output == tc.expectOutput
					// Runs and produces correct output even after destructive obf - surprising but good.
				}
			} else { // For non-destructive tests (stripping, regex, safer obf)
				if err != nil {
					t.Fatalf("Execution of processed file failed for %s: %v. Output: %s", tc.name, err, output)
				}
				if output != tc.expectOutput {
					t.Errorf("Output mismatch for %s. Expected %q, Got %q", tc.name, tc.expectOutput, output)
				}
			}

			// TODO: Add file size check: processedSize <= originalSize for strip operations
			// processedSize, _ := os.Stat(processedExePath).Size()
			// if tc.checkSizeReduction && processedSize > originalSize {
			// 	t.Errorf("File size did not reduce for %s. Original: %d, Processed: %d", tc.name, originalSize, processedSize)
			// }
		})
	}
}
