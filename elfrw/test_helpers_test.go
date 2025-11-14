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
