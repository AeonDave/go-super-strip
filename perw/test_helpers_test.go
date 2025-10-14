package perw

import (
	"os"
	"path/filepath"
	"testing"
)

func copyPEFixture(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join("..", "testfiles", name)

	// Skip test if PE test file doesn't exist (Linux-focused project)
	if _, err := os.Stat(src); os.IsNotExist(err) {
		t.Skipf("PE test file %q not found - skipping (Linux-focused project)", name)
	}

	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("failed to read source test file %q: %v", name, err)
	}

	dst := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatalf("failed to create temp fixture %q: %v", name, err)
	}

	return dst
}
