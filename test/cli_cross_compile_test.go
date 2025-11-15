package test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type compiledFixture struct {
	Name string
	Path string
	IsPE bool
}

type cliScenario struct {
	Name    string
	Args    []string
	Prepare func(t *testing.T, fixture compiledFixture, binaryPath string)
	Verify  func(t *testing.T, fixture compiledFixture, binaryPath, output string)
}

const testStubPrefix = "gosstrip-test-stub"

func TestCLIOptionsOnCompiledFixtures(t *testing.T) {
	cliBinary := buildCLIBinary(t)
	ensureTool(t, "gcc")
	ensureTool(t, "x86_64-w64-mingw32-gcc")
	fixtures := compileAllFixtures(t)
	if len(fixtures) == 0 {
		t.Fatal("no fixtures compiled")
	}

	scenarios := []cliScenario{
		{
			Name: "analyze",
			Args: []string{"-a"},
			Verify: func(t *testing.T, fixture compiledFixture, _ string, output string) {
				expectedType := "ELF"
				if fixture.IsPE {
					expectedType = "PE"
				}
				assertContains(t, output, "=== File Analysis ===")
				assertContains(t, output, "File type: "+expectedType)
			},
		},
		{
			Name: "strip",
			Args: []string{"-s"},
			Verify: func(t *testing.T, _ compiledFixture, _ string, output string) {
				assertContains(t, output, "Completed operations: strip")
			},
		},
		{
			Name: "compact",
			Args: []string{"-c"},
			Verify: func(t *testing.T, _ compiledFixture, _ string, output string) {
				assertContains(t, output, "Completed operations: compact")
			},
		},
		{
			Name: "obfuscate",
			Args: []string{"-o"},
			Verify: func(t *testing.T, _ compiledFixture, _ string, output string) {
				assertContains(t, output, "Completed operations: obfuscate")
			},
		},
		{
			Name: "insert",
			Args: []string{"-i=.agg:.section_marker"},
			Verify: func(t *testing.T, _ compiledFixture, binaryPath string, output string) {
				assertContains(t, output, "Completed operations: insert")
				data := readFile(t, binaryPath)
				if !bytes.Contains(data, []byte(".section_marker")) {
					t.Fatalf("expected inserted marker to be present in %s", binaryPath)
				}
			},
		},
		{
			Name: "overlay",
			Args: []string{"-l=OVERLAY_PAYLOAD"},
			Verify: func(t *testing.T, _ compiledFixture, binaryPath string, output string) {
				assertContains(t, output, "Completed operations: overlay")
				data := readFile(t, binaryPath)
				if !bytes.Contains(data, []byte("OVERLAY_PAYLOAD")) {
					t.Fatalf("expected overlay payload to be present in %s", binaryPath)
				}
			},
		},
		{
			Name: "regex",
			Args: []string{"-r=APPENDED_PATTERN"},
			Prepare: func(t *testing.T, _ compiledFixture, binaryPath string) {
				updated := append(readFile(t, binaryPath), []byte("APPENDED_PATTERN")...)
				if err := os.WriteFile(binaryPath, updated, 0o600); err != nil {
					t.Fatalf("failed to append pattern: %v", err)
				}
			},
			Verify: func(t *testing.T, _ compiledFixture, binaryPath string, output string) {
				assertContains(t, output, "Completed operations: regex")
				data := readFile(t, binaryPath)
				if bytes.Contains(data, []byte("APPENDED_PATTERN")) {
					t.Fatalf("expected regex pattern to be removed in %s", binaryPath)
				}
			},
		},
		{
			Name: "pack",
			Args: []string{"-p=compression=none,encryption=none,polymorphic=false,padding=false"},
			Verify: func(t *testing.T, fixture compiledFixture, binaryPath string, output string) {
				assertContains(t, output, "=== Pack Operations ===")
				packedPath := binaryPath + ".packed"
				if fixture.IsPE {
					packedPath += ".exe"
				}
				data := readFile(t, packedPath)
				if !bytes.HasPrefix(data, []byte(testStubPrefix)) {
					t.Fatalf("expected packed stub to start with %q, got %q", testStubPrefix, data[:min(16, len(data))])
				}
			},
		},
		{
			Name: "pipeline",
			Args: []string{
				"-s",
				"-c",
				"-o",
				"-i=.combo:SECTION_COMBO",
				"-l=OVERLAY_COMBO",
				"-r=SECTION_COMBO",
			},
			Verify: func(t *testing.T, _ compiledFixture, binaryPath string, output string) {
				assertContains(t, output, "Completed operations: strip, compact, obfuscate, insert, overlay, regex")
				data := readFile(t, binaryPath)
				if bytes.Contains(data, []byte("SECTION_COMBO")) {
					t.Fatalf("expected SECTION_COMBO to be removed after regex")
				}
				if !bytes.Contains(data, []byte("OVERLAY_COMBO")) {
					t.Fatalf("expected overlay data to be present after pipeline")
				}
			},
		},
	}

	for _, fixture := range fixtures {
		fixture := fixture
		for _, scenario := range scenarios {
			scenario := scenario
			t.Run(fmt.Sprintf("%s/%s", fixture.Name, scenario.Name), func(t *testing.T) {
				runScenario(t, cliBinary, fixture, scenario)
			})
		}
	}
}

func runScenario(t *testing.T, cliBinary string, fixture compiledFixture, scenario cliScenario) {
	t.Helper()
	binaryPath := copyBinary(t, fixture.Path)
	if scenario.Prepare != nil {
		scenario.Prepare(t, fixture, binaryPath)
	}
	args := append([]string{}, scenario.Args...)
	args = append(args, binaryPath)
	cmd := exec.Command(cliBinary, args...)
	cmd.Env = append(os.Environ(), "GOSSTRIP_TEST_STUB="+testStubPrefix)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed for %s %s: %v\n%s", fixture.Name, scenario.Name, err, output)
	}
	if scenario.Verify != nil {
		scenario.Verify(t, fixture, binaryPath, string(output))
	}
}

func buildCLIBinary(t *testing.T) string {
	t.Helper()
	output := filepath.Join(t.TempDir(), "gosstrip-test-binary")
	if runtime.GOOS == "windows" {
		output += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", output, "./")
	cmd.Dir = ".."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build CLI: %v\n%s", err, out)
	}
	return output
}

func compileAllFixtures(t *testing.T) []compiledFixture {
	t.Helper()
	var fixtures []compiledFixture

	goSources, err := filepath.Glob(filepath.Join("..", "testfiles", "*.go"))
	if err != nil {
		t.Fatalf("failed to glob go fixtures: %v", err)
	}
	for _, source := range goSources {
		base := filepath.Base(source)
		name := strings.TrimSuffix(base, filepath.Ext(base))
		for _, target := range []string{"linux", "windows"} {
			path := buildGoSource(t, base, target)
			fixtures = append(fixtures, compiledFixture{
				Name: fmt.Sprintf("%s-%s", name, target),
				Path: path,
				IsPE: target == "windows",
			})
		}
	}

	cSources, err := filepath.Glob(filepath.Join("..", "testfiles", "*.c"))
	if err != nil {
		t.Fatalf("failed to glob c fixtures: %v", err)
	}
	for _, source := range cSources {
		base := filepath.Base(source)
		name := strings.TrimSuffix(base, filepath.Ext(base))
		for _, target := range []string{"linux", "windows"} {
			path := buildCSource(t, base, target)
			fixtures = append(fixtures, compiledFixture{
				Name: fmt.Sprintf("%s-%s", name, target),
				Path: path,
				IsPE: target == "windows",
			})
		}
	}

	return fixtures
}

func buildGoSource(t *testing.T, baseName, targetOS string) string {
	t.Helper()
	tmpDir := t.TempDir()
	trimmed := strings.TrimSuffix(baseName, ".go")
	output := filepath.Join(tmpDir, trimmed)
	if targetOS == "windows" {
		output += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", output, filepath.Join("./testfiles", baseName))
	cmd.Dir = ".."
	env := append(os.Environ(),
		"GOOS="+targetOS,
		"GOARCH="+runtime.GOARCH,
		"CGO_ENABLED=0",
	)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build go fixture %s for %s: %v\n%s", baseName, targetOS, err, out)
	}
	if targetOS != "windows" {
		if err := os.Chmod(output, 0o700); err != nil {
			t.Fatalf("failed to make go fixture executable: %v", err)
		}
	}
	return output
}

func buildCSource(t *testing.T, baseName, targetOS string) string {
	t.Helper()
	tmpDir := t.TempDir()
	outputName := strings.TrimSuffix(baseName, filepath.Ext(baseName))
	output := filepath.Join(tmpDir, outputName)
	var compiler string
	if targetOS == "windows" {
		compiler = "x86_64-w64-mingw32-gcc"
		output += ".exe"
	} else {
		compiler = "gcc"
	}
	if targetOS == "linux" && runtime.GOOS == "windows" && hasWSL() {
		sourceAbs, err := filepath.Abs(filepath.Join("..", "testfiles", baseName))
		if err != nil {
			t.Fatalf("failed to resolve source path: %v", err)
		}
		outputAbs, err := filepath.Abs(output)
		if err != nil {
			t.Fatalf("failed to resolve output path: %v", err)
		}
		cmd := fmt.Sprintf("gcc -O2 '%s' -o '%s' -lm", toWSLPath(sourceAbs), toWSLPath(outputAbs))
		if err := runWSLCommand(cmd); err != nil {
			t.Fatalf("failed to build c fixture %s via WSL: %v", baseName, err)
		}
		if err := os.Chmod(output, 0o700); err != nil {
			t.Fatalf("failed to make c fixture executable: %v", err)
		}
		return output
	}
	if _, err := exec.LookPath(compiler); err != nil {
		t.Fatalf("required compiler %s not found in PATH", compiler)
	}
	sourcePath := filepath.Join("testfiles", baseName)
	args := []string{"-O2", "-o", output, sourcePath}
	cmd := exec.Command(compiler, args...)
	cmd.Dir = ".."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build c fixture %s for %s: %v\n%s", baseName, targetOS, err, out)
	}
	if targetOS != "windows" {
		if _, err := os.Stat(output); os.IsNotExist(err) {
			alt := output + ".exe"
			if _, altErr := os.Stat(alt); altErr == nil {
				if renameErr := os.Rename(alt, output); renameErr != nil {
					t.Fatalf("failed to normalize linux fixture name: %v", renameErr)
				}
			}
		}
	}
	if targetOS != "windows" {
		if err := os.Chmod(output, 0o700); err != nil {
			t.Fatalf("failed to make c fixture executable: %v", err)
		}
	}
	return output
}

func copyBinary(t *testing.T, src string) string {
	t.Helper()
	dstDir := t.TempDir()
	dst := filepath.Join(dstDir, filepath.Base(src))
	srcFile, err := os.Open(src)
	if err != nil {
		t.Fatalf("failed to open source binary: %v", err)
	}
	defer func(srcFile *os.File) {
		_ = srcFile.Close()
	}(srcFile)
	dstFile, err := os.Create(dst)
	if err != nil {
		t.Fatalf("failed to create destination binary: %v", err)
	}
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		_ = dstFile.Close()
		t.Fatalf("failed to copy binary: %v", err)
	}
	if err := dstFile.Close(); err != nil {
		t.Fatalf("failed to close destination binary: %v", err)
	}
	if err := os.Chmod(dst, 0o700); err == nil {
		// ignore chmod failures on non-POSIX filesystems
	}
	return dst
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file %s: %v", path, err)
	}
	return data
}

func assertContains(t *testing.T, output, expected string) {
	t.Helper()
	if !strings.Contains(output, expected) {
		t.Fatalf("expected output to contain %q, got:\n%s", expected, output)
	}
}

func ensureTool(t *testing.T, tool string) {
	t.Helper()
	if _, err := exec.LookPath(tool); err != nil {
		t.Skipf("required tool %s not available: %v", tool, err)
	}
}

func hasWSL() bool {
	_, err := exec.LookPath("wsl.exe")
	return err == nil
}

func toWSLPath(win string) string {
	if len(win) < 3 || win[1] != ':' {
		return win
	}
	drive := strings.ToLower(string(win[0]))
	path := strings.ReplaceAll(win[2:], "\\", "/")
	return "/mnt/" + drive + path
}

func runWSLCommand(cmd string) error {
	c := exec.Command("wsl.exe", "bash", "-lc", cmd)
	c.Env = os.Environ()
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("WSL command failed: %v\n%s", err, string(out))
	}
	return nil
}
