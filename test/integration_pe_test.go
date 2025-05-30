package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const (
	helloPe64Source = `
	#include <windows.h>
	#include <string.h>
	int main() {
	    const char* message = "Hello, PE64!\n";
	    DWORD bytesWritten;
	    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	    if (hStdout == INVALID_HANDLE_VALUE) return 1;
	    WriteFile(hStdout, message, (DWORD)strlen(message), &bytesWritten, NULL);
	    return 0;
	}`

	helloPe32Source = `
	#include <windows.h>
	#include <string.h>
	int main() {
	    const char* message = "Hello, PE32!\n";
	    DWORD bytesWritten;
	    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	    if (hStdout == INVALID_HANDLE_VALUE) return 1;
	    WriteFile(hStdout, message, (DWORD)strlen(message), &bytesWritten, NULL);
	    return 0;
	}`
)

func compilePESource(t *testing.T, tempDir, baseName, source, arch string) (string, error) {
	t.Helper()
	srcPath := filepath.Join(tempDir, baseName+".c")
	if err := os.WriteFile(srcPath, []byte(source), 0644); err != nil {
		return "", fmt.Errorf("failed to write source: %w", err)
	}
	outputPath := filepath.Join(tempDir, baseName+".exe")
	compiler := map[string]string{"64": "x86_64-w64-mingw32-gcc", "32": "i686-w64-mingw32-gcc"}[arch]
	if compiler == "" {
		return "", fmt.Errorf("unsupported architecture: %s", arch)
	}
	cmd := exec.Command(compiler, "-O2", srcPath, "-o", outputPath)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("compilation failed: %w", err)
	}
	return outputPath, nil
}

func runGoStripCommandPE(t *testing.T, args ...string) error {
	t.Helper()
	cmd := exec.Command("go", append([]string{"run", "../main.go"}, args...)...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gosstrip failed: %w", err)
	}
	return nil
}

func executePEAndGetOutput(t *testing.T, exePath string) (string, error) {
	t.Helper()
	output, err := exec.Command("wine", exePath).CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("execution failed: %w", err)
	}
	return string(output), nil
}

func copyFilePE(t *testing.T, src, dst string) error {
	t.Helper()
	source, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source: %w", err)
	}
	defer func(source *os.File) {
		_ = source.Close()
	}(source)
	dest, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination: %w", err)
	}
	defer func(dest *os.File) {
		_ = dest.Close()
	}(dest)
	if _, err := io.Copy(dest, source); err != nil {
		return fmt.Errorf("copy failed: %w", err)
	}
	return dest.Chmod(0755)
}

func TestPEIntegration_StripAll_PE64(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	exePath, err := compilePESource(t, tempDir, "hello_pe64", helloPe64Source, "64")
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	processedPath := filepath.Join(tempDir, "hello_pe64_processed.exe")
	if err := copyFilePE(t, exePath, processedPath); err != nil {
		t.Fatalf("Copy failed: %v", err)
	}
	if err := runGoStripCommandPE(t, "-file", processedPath, "-cmd", "strip", "-strip", "all"); err != nil {
		t.Fatalf("gosstrip failed: %v", err)
	}
	output, err := executePEAndGetOutput(t, processedPath)
	if err != nil {
		t.Fatalf("Execution failed: %v", err)
	}
	if output != "Hello, PE64!\n" {
		t.Errorf("Unexpected output: %q", output)
	}
}
