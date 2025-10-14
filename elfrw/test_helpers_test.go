package elfrw

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func copyELFFixture(t *testing.T, name string) string {
	T := t
	T.Helper()

	// ELF fixtures are only available and valid on Linux. Skip on other OSes (e.g., Windows).
	if runtime.GOOS != "linux" {
		T.Skipf("ELF tests require Linux environment; current OS: %s", runtime.GOOS)
	}

	src := filepath.Join("..", "testfiles", name)
	data, err := os.ReadFile(src)
	if err != nil {
		T.Fatalf("failed to read source test file %q: %v", name, err)
	}

	dst := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(dst, data, 0o700); err != nil {
		T.Fatalf("failed to create temp fixture %q: %v", name, err)
	}

	return dst
}
