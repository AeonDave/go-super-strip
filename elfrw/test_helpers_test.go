package elfrw

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

var (
	elfFixtureOnce sync.Once
	elfFixtureData []byte
	elfFixtureErr  error
)

func buildDynamicELFFixture() ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "elf_dynamic_fixture")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	output := filepath.Join(tmpDir, "dynamic")
	cmd := exec.Command("gcc", "-O2", "-o", output, "./testfiles/simple.c")
	cmd.Dir = ".."
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("gcc failed: %v\n%s", err, out)
	}
	return os.ReadFile(output)
}

func buildELFFixture() {
	tmpDir, err := os.MkdirTemp("", "elf_fixture_build")
	if err != nil {
		elfFixtureErr = err
		return
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	output := filepath.Join(tmpDir, "simple")

	cmd := exec.Command("go", "build", "-o", output, "./testfiles/simple_go.go")
	cmd.Dir = ".."
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
	T := t
	T.Helper()

	// ELF fixtures are only available and valid on Linux. Skip on other OSes (e.g., Windows).
	if runtime.GOOS != "linux" {
		T.Skipf("ELF tests require Linux environment; current OS: %s", runtime.GOOS)
	}

	elfFixtureOnce.Do(buildELFFixture)
	if elfFixtureErr != nil {
		T.Fatalf("failed to prepare ELF fixture %q: %v", name, elfFixtureErr)
	}

	dst := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(dst, elfFixtureData, 0o700); err != nil {
		T.Fatalf("failed to create temp fixture %q: %v", name, err)
	}

	return dst
}

func copyDynamicELFFixture(t *testing.T, name string) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("dynamic ELF fixtures require Linux")
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skipf("gcc not available: %v", err)
	}
	data, err := buildDynamicELFFixture()
	if err != nil {
		t.Fatalf("failed to build dynamic ELF: %v", err)
	}
	dst := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(dst, data, 0o700); err != nil {
		t.Fatalf("failed to write dynamic ELF: %v", err)
	}
	return dst
}
