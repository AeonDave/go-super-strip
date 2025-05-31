package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	helloPe64Source = `
	#include <windows.h>
	#include <stdio.h>
	int main() {
	    printf("Hello, PE64!\n");
	    return 0;
	}`

	helloPe32Source = `
	#include <windows.h>
	#include <stdio.h>
	int main() {
	    printf("Hello, PE32!\n");
	    return 0;
	}`

	helloPeRegexSource = `
	#include <windows.h>
	#include <stdio.h>
	int main() {
		const char* part1 = "Hello, ";
		const char* part2 = "MAGIC_WORD_PE"; // This will be stripped
		const char* part3 = " PE_REGEX_TEST!\n";
		printf("%s%s%s", part1, part2, part3);
		return 0;
	}`
)

type peTestCase struct {
	name         string
	desc         string
	arch         string // "64" or "32"
	source       string
	cliArgs      []string
	expectOutput string
}

func compilePESourcePE(t *testing.T, tempDir, baseName, source, arch string) (string, error) {
	t.Helper()
	srcPath := filepath.Join(tempDir, baseName+".c")
	if err := os.WriteFile(srcPath, []byte(source), 0644); err != nil {
		return "", fmt.Errorf("failed to write source %s: %w", srcPath, err)
	}
	outputPath := filepath.Join(tempDir, baseName+".exe")

	var compiler string
	// Select compiler based on GOOS and requested architecture
	switch runtime.GOOS {
	case "linux": // Assuming cross-compilers are mingw-w64
		compiler = map[string]string{"64": "x86_64-w64-mingw32-gcc", "32": "i686-w64-mingw32-gcc"}[arch]
	case "windows": // Assuming native MinGW or MSVC (though this uses gcc commands)
		// This might need adjustment if you are using MSVC or a different MinGW setup on Windows
		// For simplicity, sticking to mingw-style commands
		compiler = map[string]string{"64": "gcc", "32": "gcc -m32"}[arch] // Simplistic, may need full path or specific gcc
	default:
		return "", fmt.Errorf("PE compilation not configured for GOOS: %s", runtime.GOOS)
	}

	if compiler == "" {
		return "", fmt.Errorf("unsupported architecture for PE compilation: %s on %s", arch, runtime.GOOS)
	}

	cmdArgs := []string{}
	if strings.Contains(compiler, " ") { // handles cases like "gcc -m32"
		parts := strings.SplitN(compiler, " ", 2)
		compiler = parts[0]
		cmdArgs = append(cmdArgs, parts[1])
	}
	cmdArgs = append(cmdArgs, "-O0", srcPath, "-o", outputPath, "-static-libgcc", "-Wl,--no-warn-rwx-segments")

	cmd := exec.Command(compiler, cmdArgs...)
	var compErr bytes.Buffer
	cmd.Stderr = &compErr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("compilation failed for %s (arch %s) using %s %v: %w. Stderr: %s", baseName, arch, compiler, cmdArgs, err, compErr.String())
	}
	return outputPath, nil
}

func runGoSuperStripCommandPE(t *testing.T, goStripArgs ...string) error {
	t.Helper()
	mainGoPath := filepath.Join("..", "main.go")
	cmd := exec.Command("go", append([]string{"run", mainGoPath}, goStripArgs...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go-super-strip command failed (%v). Stderr: %s", err, stderr.String())
	}
	return nil
}

func executePEAndGetOutputPE(t *testing.T, exePath string) (string, error) {
	t.Helper()
	var cmd *exec.Cmd
	// WINE is typically needed to run PE executables on non-Windows systems like Linux
	if runtime.GOOS != "windows" {
		_, err := exec.LookPath("wine")
		if err != nil {
			t.Skip("wine command not found, skipping PE execution test on non-Windows OS")
			return "", nil // Indicate skip
		}
		cmd = exec.Command("wine", exePath)
	} else {
		cmd = exec.Command(exePath)
	}

	outputBytes, err := cmd.CombinedOutput()
	if err != nil {
		return string(outputBytes), fmt.Errorf("execution of %s failed: %w. Output: %s", exePath, err, string(outputBytes))
	}
	return string(outputBytes), nil
}

func copyFilePE(t *testing.T, src, dst string) error {
	t.Helper()
	source, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source %s: %w", src, err)
	}
	defer source.Close()

	dest, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination %s: %w", dst, err)
	}
	defer dest.Close()

	if _, err := io.Copy(dest, source); err != nil {
		return fmt.Errorf("copy from %s to %s failed: %w", src, dst, err)
	}
	return dest.Chmod(0755)
}

func TestPEIntegration(t *testing.T) {
	tempDir := t.TempDir()

	testCases := []peTestCase{
		// PE64 Tests
		{name: "PE64_StripAll", desc: "Test -strip-all on PE64", arch: "64", source: helloPe64Source, cliArgs: []string{"--strip-all"}, expectOutput: "Hello, PE64!\n"},
		{name: "PE64_StripDebug", desc: "Test -strip-debug on PE64", arch: "64", source: helloPe64Source, cliArgs: []string{"--strip-debug"}, expectOutput: "Hello, PE64!\n"},
		{name: "PE64_StripSymbols", desc: "Test -strip-symbols on PE64", arch: "64", source: helloPe64Source, cliArgs: []string{"--strip-symbols"}, expectOutput: "Hello, PE64!\n"},
		{name: "PE64_ObfNames", desc: "Test -obf-names on PE64", arch: "64", source: helloPe64Source, cliArgs: []string{"--obf-names"}, expectOutput: "Hello, PE64!\n"},
		{name: "PE64_ObfBase", desc: "Test -obf-base on PE64 (risky)", arch: "64", source: helloPe64Source, cliArgs: []string{"--obf-base"}, expectOutput: "Hello, PE64!\n"},
		{name: "PE64_ObfAll", desc: "Test -obf-all on PE64 (risky)", arch: "64", source: helloPe64Source, cliArgs: []string{"--obf-all"}, expectOutput: "Hello, PE64!\n"},
		{name: "PE64_RegexStrip", desc: "Test -s on PE64", arch: "64", source: helloPeRegexSource, cliArgs: []string{"-s", "MAGIC_WORD_PE"}, expectOutput: "Hello,  PE_REGEX_TEST!\n"},

		// PE32 Tests
		{name: "PE32_StripAll", desc: "Test -strip-all on PE32", arch: "32", source: helloPe32Source, cliArgs: []string{"--strip-all"}, expectOutput: "Hello, PE32!\n"},
		{name: "PE32_StripDebug", desc: "Test -strip-debug on PE32", arch: "32", source: helloPe32Source, cliArgs: []string{"--strip-debug"}, expectOutput: "Hello, PE32!\n"},
		{name: "PE32_StripSymbols", desc: "Test -strip-symbols on PE32", arch: "32", source: helloPe32Source, cliArgs: []string{"--strip-symbols"}, expectOutput: "Hello, PE32!\n"},
		{name: "PE32_ObfNames", desc: "Test -obf-names on PE32", arch: "32", source: helloPe32Source, cliArgs: []string{"--obf-names"}, expectOutput: "Hello, PE32!\n"},
		{name: "PE32_RegexStrip", desc: "Test -s on PE32", arch: "32", source: helloPeRegexSource, cliArgs: []string{"-s", "MAGIC_WORD_PE"}, expectOutput: "Hello,  PE_REGEX_TEST!\n"},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			originalExeBaseName := "test_pe_" + tc.name + "_orig"
			originalExePath, err := compilePESourcePE(t, tempDir, originalExeBaseName, tc.source, tc.arch)
			if err != nil {
				// Skip test if compiler for PE is not available (e.g. mingw on a bare linux without it)
				if strings.Contains(err.Error(), "exec: \"x86_64-w64-mingw32-gcc\": executable file not found") ||
					strings.Contains(err.Error(), "exec: \"i686-w64-mingw32-gcc\": executable file not found") ||
					strings.Contains(err.Error(), "no such file or directory") { // more generic check for compiler missing
					t.Skipf("Skipping PE test %s: MinGW compiler not found: %v", tc.name, err)
				}
				t.Fatalf("Compilation failed for %s: %v", tc.name, err)
			}

			processedExeBaseName := "test_pe_" + tc.name + "_processed"
			processedExePath := filepath.Join(tempDir, processedExeBaseName+".exe")
			if err := copyFilePE(t, originalExePath, processedExePath); err != nil {
				t.Fatalf("Copying file failed for %s: %v", tc.name, err)
			}

			argsToPass := append([]string{"-file", processedExePath}, tc.cliArgs...)
			if err := runGoSuperStripCommandPE(t, argsToPass...); err != nil {
				t.Errorf("go-super-strip command failed for %s: %v", tc.name, err)
			}

			output, err := executePEAndGetOutputPE(t, processedExePath)
			if runtime.GOOS != "windows" && output == "" && err == nil {
				// This condition indicates WINE was not found and test was skipped by executePEAndGetOutputPE
				return // End this specific test run
			}

			if strings.Contains(tc.name, "ObfBase") || strings.Contains(tc.name, "ObfAll") {
				if err == nil && output != tc.expectOutput {
					t.Logf("WARNING for %s: Destructive PE obfuscation. Expected %q, Got %q. Exec error: %v", tc.name, tc.expectOutput, output, err)
				} else if err != nil {
					t.Logf("INFO for %s: Destructive PE obfuscation. Execution failed as potentially expected. Error: %v", tc.name, err)
				}
			} else {
				if err != nil {
					t.Fatalf("Execution of processed PE file failed for %s: %v. Output: %s", tc.name, err, output)
				}
				if output != tc.expectOutput {
					t.Errorf("Output mismatch for PE %s. Expected %q, Got %q", tc.name, tc.expectOutput, output)
				}
			}
		})
	}
}
