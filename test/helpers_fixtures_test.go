package test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

var (
	peFixtureOnce sync.Once
	peFixtureData []byte
	peFixtureErr  error

	elfFixtureOnce sync.Once
	elfFixtureData []byte
	elfFixtureErr  error
)

func buildPEFixture() {
	tmpDir, err := os.MkdirTemp("", "pe_fixture_build")
	if err != nil {
		peFixtureErr = err
		return
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	output := filepath.Join(tmpDir, "simple.exe")
	cmd := exec.Command("go", "build", "-o", output, filepath.Join("..", "testfiles", "simple_go.go"))
	cmd.Env = append(os.Environ(),
		"GOOS=windows",
		"GOARCH="+runtime.GOARCH,
		"CGO_ENABLED=0",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		peFixtureErr = fmt.Errorf("go build failed: %v\n%s", err, out)
		return
	}
	data, err := os.ReadFile(output)
	if err != nil {
		peFixtureErr = err
		return
	}
	peFixtureData = data
}

func copyPEFixture(t *testing.T, name string) string {
	t.Helper()
	peFixtureOnce.Do(buildPEFixture)
	if peFixtureErr != nil {
		t.Fatalf("failed to prepare PE fixture %q: %v", name, peFixtureErr)
	}
	dst := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(dst, peFixtureData, 0o600); err != nil {
		t.Fatalf("failed to create temp PE fixture: %v", err)
	}
	return dst
}

func buildELFFixture() {
	tmpDir, err := os.MkdirTemp("", "elf_fixture_build")
	if err != nil {
		elfFixtureErr = err
		return
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	output := filepath.Join(tmpDir, "simple")
	cmd := exec.Command("go", "build", "-o", output, filepath.Join("..", "testfiles", "simple_go.go"))
	cmd.Env = append(os.Environ(),
		"GOOS=linux",
		"GOARCH="+runtime.GOARCH,
		"CGO_ENABLED=0",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		elfFixtureErr = fmt.Errorf("go build failed: %v\n%s", err, out)
		return
	}
	data, err := os.ReadFile(output)
	if err != nil {
		elfFixtureErr = err
		return
	}
	elfFixtureData = data
}

func copyELFFixture(t *testing.T, name string) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("ELF tests require Linux host; current OS: %s", runtime.GOOS)
	}
	elfFixtureOnce.Do(buildELFFixture)
	if elfFixtureErr != nil {
		t.Fatalf("failed to prepare ELF fixture %q: %v", name, elfFixtureErr)
	}
	dst := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(dst, elfFixtureData, 0o700); err != nil {
		t.Fatalf("failed to create temp ELF fixture: %v", err)
	}
	return dst
}

func buildGoPEBinary(t *testing.T, outName string) string {
	t.Helper()
	tmpDir := t.TempDir()
	output := filepath.Join(tmpDir, outName)
	cmd := exec.Command("go", "build", "-o", output, filepath.Join("..", "testfiles", "simple_go.go"))
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, string(out))
	}
	return output
}

func hasWSL() bool {
	_, err := exec.LookPath("wsl.exe")
	return err == nil
}

func toWSLPath(p string) string {
	if len(p) < 3 || p[1] != ':' {
		return p
	}
	drive := strings.ToLower(string(p[0]))
	clean := strings.ReplaceAll(p[2:], "\\", "/")
	return "/mnt/" + drive + clean
}

func wslRun(cmd string) error {
	c := exec.Command("wsl.exe", "bash", "-lc", cmd)
	c.Env = os.Environ()
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("WSL command failed: %v\n%s", err, string(out))
	}
	return nil
}
