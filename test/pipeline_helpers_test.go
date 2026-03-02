package test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"gosstrip/common"
)

func runSimpleAnalysis(t *testing.T, run func() (*common.AnalysisResult, error)) *common.AnalysisResult {
	t.Helper()
	result, err := run()
	if err != nil {
		t.Fatalf("analysis failed: %v", err)
	}
	return result
}
func assertAnalysisLooksComprehensive(t *testing.T, result *common.AnalysisResult, stage string) {
	t.Helper()
	if result == nil {
		t.Fatalf("analysis result is nil during %s stage", stage)
	}
	if len(result.Blocks) == 0 {
		t.Fatalf("analysis result missing structured blocks during %s stage", stage)
	}
	requiredTitles := []string{"Binary Summary", "Section Overview", "Linkage Summary"}
	titleSet := make(map[string]bool)
	for _, block := range result.Blocks {
		titleSet[block.Title] = true
	}
	for _, title := range requiredTitles {
		if !titleSet[title] {
			t.Fatalf("analysis output missing %q block during %s stage", title, stage)
		}
	}
}

func appendPatternToBinary(t *testing.T, path, pattern string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read binary for append: %v", err)
	}
	data = append(data, []byte(pattern)...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to append pattern to %s: %v", path, err)
	}
}

func ensureBytesPresence(t *testing.T, path, payload, context string, expectPresent bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s for %s: %v", path, context, err)
	}
	contains := bytes.Contains(data, []byte(payload))
	if expectPresent && !contains {
		t.Fatalf("expected to find %q during %s", payload, context)
	}
	if !expectPresent && contains {
		t.Fatalf("did not expect %q to remain during %s", payload, context)
	}
}

func runPEBinary(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("PE pipeline execution verification requires a Windows host")
	}
	cmd := exec.Command(path)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("PE binary execution failed: %v\n%s", err, out)
	}
}

func runELFBinary(t *testing.T, path string) {
	t.Helper()
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command(path)
		cmd.Env = os.Environ()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("ELF binary execution failed: %v\n%s", err, out)
		}
	case "windows":
		if !hasWSL() {
			t.Skip("ELF pipeline execution requires WSL on Windows hosts")
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			t.Fatalf("failed to resolve ELF path: %v", err)
		}
		cmd := fmt.Sprintf("'%s'", toWSLPath(abs))
		if err := wslRun(cmd); err != nil {
			t.Fatalf("failed to run ELF via WSL: %v", err)
		}
	default:
		t.Skipf("ELF execution not supported on %s", runtime.GOOS)
	}
}

func runPEBinaryExpect(t *testing.T, path, expected string) {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("PE pipeline execution verification requires a Windows host")
	}
	cmd := exec.Command(path)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("PE binary execution failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte(expected)) {
		t.Fatalf("PE binary output missing %q\nOutput:\n%s", expected, out)
	}
}

func runELFBinaryExpect(t *testing.T, path, expected string) {
	t.Helper()
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command(path)
		cmd.Env = os.Environ()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("ELF binary execution failed: %v\n%s", err, out)
		}
		if !bytes.Contains(out, []byte(expected)) {
			t.Fatalf("ELF binary output missing %q\nOutput:\n%s", expected, out)
		}
	case "windows":
		if !hasWSL() {
			t.Skip("ELF pipeline execution requires WSL on Windows hosts")
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			t.Fatalf("failed to resolve ELF path: %v", err)
		}
		cmd := fmt.Sprintf("'%s'", toWSLPath(abs))
		if err := wslRunExpect(cmd, expected); err != nil {
			t.Fatalf("failed to run ELF via WSL: %v", err)
		}
	default:
		t.Skipf("ELF execution not supported on %s", runtime.GOOS)
	}
}
