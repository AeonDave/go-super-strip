package elfrw

import (
	"os"
	"path/filepath"
	"testing"
)

func copyELFFixture(t *testing.T, name string) string {
	t.Helper()

	src := filepath.Join("..", "testfiles", name)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("failed to read source test file %q: %v", name, err)
	}

	dst := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(dst, data, 0o700); err != nil {
		t.Fatalf("failed to create temp fixture %q: %v", name, err)
	}

	return dst
}
