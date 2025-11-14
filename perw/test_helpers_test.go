package perw

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
	peFixtureOnce sync.Once
	peFixtureData []byte
	peFixtureErr  error
)

func buildPEFixture() {
	tmpDir, err := os.MkdirTemp("", "pe_fixture_build")
	if err != nil {
		peFixtureErr = err
		return
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	output := filepath.Join(tmpDir, "simple.exe")

	cmd := exec.Command("go", "build", "-o", output, "./testfiles/simple_go.go")
	cmd.Dir = ".."
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
	dst := filepath.Join(t.TempDir(), name)

	peFixtureOnce.Do(buildPEFixture)
	if peFixtureErr != nil {
		t.Fatalf("failed to prepare PE fixture %q: %v", name, peFixtureErr)
	}

	if err := os.WriteFile(dst, peFixtureData, 0o600); err != nil {
		t.Fatalf("failed to create temp fixture %q: %v", name, err)
	}

	return dst
}
