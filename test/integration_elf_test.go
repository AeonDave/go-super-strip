package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
)

func compileCSource(t *testing.T, tempDir, baseName, source, archFlag string) (string, error) {
	t.Helper()
	srcFilePath := filepath.Join(tempDir, baseName+".c")
	if err := os.WriteFile(srcFilePath, []byte(source), 0644); err != nil {
		return "", fmt.Errorf("failed to write source file: %w", err)
	}
	outputExePath := filepath.Join(tempDir, baseName)
	cmd := exec.Command("gcc", archFlag, "-O2", "-static", srcFilePath, "-o", outputExePath, "-Wl,--no-warn-rwx-segments")
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("gcc", archFlag, "-O2", srcFilePath, "-o", outputExePath, "-Wl,--no-warn-rwx-segments")
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("compilation failed: %w", err)
		}
	}
	return outputExePath, nil
}

func runGoStripCommand(t *testing.T, args ...string) error {
	t.Helper()
	mainGoPath := "../main.go"
	cmd := exec.Command("go", append([]string{"run", mainGoPath}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go run failed: %w\nStderr: %s", err, stderr.String())
	}
	return nil
}

func executeELFAndGetOutput(t *testing.T, exePath string) (string, error) {
	t.Helper()
	output, err := exec.Command(exePath).CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("execution failed: %w. Output: %s", err, string(output))
	}
	return string(output), nil
}

func copyFile(t *testing.T, src, dst string) error {
	t.Helper()
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}
	return destFile.Chmod(0755)
}

func TestELFIntegration_StripAll_ELF64(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	originalExePath, err := compileCSource(t, tempDir, "hello_elf64_strip_all", helloElf64Source, "-m64")
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	processedExePath := filepath.Join(tempDir, "hello_elf64_strip_all_processed")
	if err := copyFile(t, originalExePath, processedExePath); err != nil {
		t.Fatalf("Copy failed: %v", err)
	}
	if err := runGoStripCommand(t, "-file", processedExePath, "-cmd", "strip", "-strip", "all"); err != nil {
		t.Fatalf("gosstrip failed: %v", err)
	}
	output, err := executeELFAndGetOutput(t, processedExePath)
	if err != nil {
		t.Fatalf("Execution failed: %v", err)
	}
	if expected := "Hello, ELF64!\n"; output != expected {
		t.Errorf("Output mismatch. Expected %q, Got %q", expected, output)
	}
}
