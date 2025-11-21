package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func buildGoFixture(t *testing.T, targetOS, baseName string) string {
	return buildFixtureFromSource(t, targetOS, baseName, "./testfiles/simple_go.go")
}

func buildProbeFixture(t *testing.T, targetOS, baseName string) string {
	return buildFixtureFromSource(t, targetOS, baseName, "./testfiles/probe_payload.go")
}

func buildFixtureFromSource(t *testing.T, targetOS, baseName, source string) string {
	t.Helper()

	name := baseName
	if targetOS == "windows" && !strings.HasSuffix(strings.ToLower(name), ".exe") {
		name += ".exe"
	}

	tmpDir := t.TempDir()
	output := filepath.Join(tmpDir, name)

	cmd := exec.Command("go", "build", "-o", output, source)
	cmd.Dir = ".."
	env := append(os.Environ(),
		"GOOS="+targetOS,
		"GOARCH="+runtime.GOARCH,
		"CGO_ENABLED=0",
	)
	cmd.Env = env

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build %s test fixture: %v\n%s", targetOS, err, out)
	}

	if targetOS != "windows" {
		if err := os.Chmod(output, 0o700); err != nil {
			t.Fatalf("failed to make fixture executable: %v", err)
		}
	}

	return output
}
