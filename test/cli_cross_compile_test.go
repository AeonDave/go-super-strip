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
	"time"

	"gosstrip/common"
	"gosstrip/elfrw"
	"gosstrip/perw"
)

type compiledFixture struct {
	Name string
	Path string
	IsPE bool
}

type cliScenario struct {
	Name        string
	Args        []string
	ArgsBuilder func(t *testing.T, fixture compiledFixture, binaryPath string) []string
	Prepare     func(t *testing.T, fixture compiledFixture, binaryPath string)
	Verify      func(t *testing.T, fixture compiledFixture, binaryPath, output string)
}

const testStubPrefix = "gosstrip-test-stub"
const (
	cliSectionName    = ".clisec"
	cliSectionPayload = "CLI_SECTION_PAYLOAD"
	cliSectionPass    = "cli-section-pass"
	cliOverlayPayload = "CLI_OVERLAY_PAYLOAD"
	cliOverlayPass    = "cli-overlay-pass"
	cliFullRegex      = "CLI_FULL_PIPELINE_PATTERN"
)

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
				assertContains(t, output, expectedType+" ANALYSIS (SIMPLE mode)")
				assertContains(t, output, "Binary Summary")
			},
		},
		{
			Name: "strip",
			Args: []string{"-s"},
			Verify: func(t *testing.T, _ compiledFixture, _ string, output string) {
				assertContains(t, output, "• strip:")
			},
		},
		{
			Name: "strip_fill_random",
			Args: []string{"-s=fill=random"},
			Verify: func(t *testing.T, _ compiledFixture, _ string, output string) {
				assertContains(t, output, "• strip:")
			},
		},
		{
			Name: "compact",
			Args: []string{"-c"},
			Verify: func(t *testing.T, _ compiledFixture, _ string, output string) {
				assertContains(t, output, "• compact:")
			},
		},
		{
			Name: "obfuscate",
			Args: []string{"-o"},
			Verify: func(t *testing.T, _ compiledFixture, _ string, output string) {
				assertContains(t, output, "• obfuscation:")
			},
		},
		{
			Name: "insert",
			Args: []string{"-i=name=.agg,data=.section_marker"},
			Verify: func(t *testing.T, _ compiledFixture, binaryPath string, output string) {
				assertContains(t, output, "• insert:")
				data := readFile(t, binaryPath)
				if !bytes.Contains(data, []byte(".section_marker")) {
					t.Fatalf("expected inserted marker to be present in %s", binaryPath)
				}
			},
		},
		{
			Name: "overlay",
			Args: []string{"-l=data=OVERLAY_PAYLOAD"},
			Verify: func(t *testing.T, _ compiledFixture, binaryPath string, output string) {
				assertContains(t, output, "• overlay:")
				data := readFile(t, binaryPath)
				if !bytes.Contains(data, []byte("OVERLAY_PAYLOAD")) {
					t.Fatalf("expected overlay payload to be present in %s", binaryPath)
				}
			},
		},
		{
			Name: "extract_section",
			ArgsBuilder: func(t *testing.T, fixture compiledFixture, _ string) []string {
				return []string{fmt.Sprintf("-ei=name=%s,password=%s", sectionNameForFixture(fixture), cliSectionPass)}
			},
			Prepare: func(t *testing.T, fixture compiledFixture, binaryPath string) {
				insertCLITestSection(t, fixture, binaryPath)
			},
			Verify: func(t *testing.T, _ compiledFixture, binaryPath string, output string) {
				assertContains(t, output, "• extract-section:")
				extracted := readFile(t, binaryPath+".extracted")
				if string(extracted) != cliSectionPayload {
					t.Fatalf("expected extracted section payload %q, got %q", cliSectionPayload, string(extracted))
				}
			},
		},
		{
			Name: "extract_overlay",
			Args: []string{fmt.Sprintf("-el=password=%s", cliOverlayPass)},
			Prepare: func(t *testing.T, fixture compiledFixture, binaryPath string) {
				addCLITestOverlay(t, fixture, binaryPath)
			},
			Verify: func(t *testing.T, _ compiledFixture, binaryPath string, output string) {
				assertContains(t, output, "• extract-overlay:")
				extracted := readFile(t, binaryPath+".extracted")
				if string(extracted) != cliOverlayPayload {
					t.Fatalf("expected extracted overlay payload %q, got %q", cliOverlayPayload, string(extracted))
				}
			},
		},
		{
			Name: "regex",
			ArgsBuilder: func(t *testing.T, _ compiledFixture, _ string) []string {
				patternDir := t.TempDir()
				patternFile := filepath.Join(patternDir, "patterns.txt")
				content := "# comment line should be ignored\n\nAPPENDED_PATTERN\n"
				if err := os.WriteFile(patternFile, []byte(content), 0o600); err != nil {
					t.Fatalf("failed to write pattern file: %v", err)
				}
				return []string{fmt.Sprintf("-r=fill=random,pattern=%s", patternFile)}
			},
			Prepare: func(t *testing.T, _ compiledFixture, binaryPath string) {
				updated := append(readFile(t, binaryPath), []byte("APPENDED_PATTERN")...)
				if err := os.WriteFile(binaryPath, updated, 0o600); err != nil {
					t.Fatalf("failed to append pattern: %v", err)
				}
			},
			Verify: func(t *testing.T, _ compiledFixture, binaryPath string, output string) {
				assertContains(t, output, "• regex:")
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
				assertContains(t, output, "• pack:")
				data := readFile(t, binaryPath)
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
				"-r=pattern=PIPELINE_REGEX_TARGET",
				"-i=name=.combo,data=SECTION_COMBO",
				"-l=data=OVERLAY_COMBO",
			},
			Prepare: func(t *testing.T, _ compiledFixture, binaryPath string) {
				data := append(readFile(t, binaryPath), []byte("PIPELINE_REGEX_TARGET")...)
				if err := os.WriteFile(binaryPath, data, 0o600); err != nil {
					t.Fatalf("failed to append pipeline regex target: %v", err)
				}
			},
			Verify: func(t *testing.T, _ compiledFixture, binaryPath string, output string) {
				assertContains(t, output, "• strip:")
				assertContains(t, output, "• compact:")
				assertContains(t, output, "• obfuscation:")
				assertContains(t, output, "• regex:")
				assertContains(t, output, "• insert:")
				assertContains(t, output, "• overlay:")
				data := readFile(t, binaryPath)
				if bytes.Contains(data, []byte("PIPELINE_REGEX_TARGET")) {
					t.Fatalf("expected PIPELINE_REGEX_TARGET to be removed after regex")
				}
				if !bytes.Contains(data, []byte("SECTION_COMBO")) {
					t.Fatalf("expected inserted section data to be present after pipeline")
				}
				if !bytes.Contains(data, []byte("OVERLAY_COMBO")) {
					t.Fatalf("expected overlay data to be present after pipeline")
				}
			},
		},
		{
			Name: "pipeline_full",
			ArgsBuilder: func(t *testing.T, fixture compiledFixture, binaryPath string) []string {
				appendPatternToBinary(t, binaryPath, cliFullRegex)
				return buildFullPipelineArgs(fixture, binaryPath)
			},
			Verify: func(t *testing.T, fixture compiledFixture, binaryPath string, output string) {
				ensureBytesPresence(t, binaryPath, cliFullRegex, "pipeline regex removal", false)
				sectionPayload := readFile(t, pipelineSectionDest(binaryPath))
				if string(sectionPayload) != cliSectionPayload {
					t.Fatalf("expected pipeline section payload %q, got %q", cliSectionPayload, string(sectionPayload))
				}
				overlayPayload := readFile(t, pipelineOverlayDest(binaryPath))
				if string(overlayPayload) != cliOverlayPayload {
					t.Fatalf("expected pipeline overlay payload %q, got %q", cliOverlayPayload, string(overlayPayload))
				}
				if fixture.IsPE {
					assertContains(t, output, "PE pipeline summary")
				} else {
					assertContains(t, output, "ELF pipeline summary")
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

func sectionNameForFixture(fixture compiledFixture) string {
	if fixture.IsPE {
		return common.SanitizeSectionName(cliSectionName)
	}
	return cliSectionName
}

func insertCLITestSection(t *testing.T, fixture compiledFixture, binaryPath string) {
	t.Helper()
	name := sectionNameForFixture(fixture)
	var result *common.OperationResult
	if fixture.IsPE {
		result = perw.InsertPE(binaryPath, name, cliSectionPayload, cliSectionPass)
	} else {
		result = elfrw.InsertELF(binaryPath, name, cliSectionPayload, cliSectionPass)
	}
	requireCLIResult(t, "insert", result)
}

func addCLITestOverlay(t *testing.T, fixture compiledFixture, binaryPath string) {
	t.Helper()
	if fixture.IsPE {
		requireCLIResult(t, "compact", perw.CompactPE(binaryPath, true, true))
	} else {
		requireCLIResult(t, "compact", elfrw.CompactELF(binaryPath, true, true))
	}
	tmp := filepath.Join(t.TempDir(), "overlay.bin")
	if err := os.WriteFile(tmp, []byte(cliOverlayPayload), 0o600); err != nil {
		t.Fatalf("failed to write overlay payload: %v", err)
	}
	var result *common.OperationResult
	if fixture.IsPE {
		result = perw.OverlayPE(binaryPath, tmp, cliOverlayPass)
	} else {
		result = elfrw.OverlayELF(binaryPath, tmp, cliOverlayPass)
	}
	requireCLIResult(t, "overlay", result)
}

func requireCLIResult(t *testing.T, name string, result *common.OperationResult) {
	t.Helper()
	if result == nil || !result.Applied {
		t.Fatalf("expected %s operation to apply: %#v", name, result)
	}
}

func runScenario(t *testing.T, cliBinary string, fixture compiledFixture, scenario cliScenario) {
	t.Helper()
	binaryPath := copyBinary(t, fixture.Path)
	if scenario.Prepare != nil {
		scenario.Prepare(t, fixture, binaryPath)
	}
	var args []string
	if scenario.ArgsBuilder != nil {
		args = scenario.ArgsBuilder(t, fixture, binaryPath)
	} else {
		args = append([]string{}, scenario.Args...)
	}
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
		if err := wslRun(cmd); err != nil {
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
	dstDir, err := os.MkdirTemp("", "gosstrip-pack-matrix-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		for i := 0; i < 5; i++ {
			if remErr := os.RemoveAll(dstDir); remErr == nil {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	})
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

func buildFullPipelineArgs(fixture compiledFixture, binaryPath string) []string {
	sectionDest := pipelineSectionDest(binaryPath)
	overlayDest := pipelineOverlayDest(binaryPath)
	sectionName := sectionNameForFixture(fixture)
	return []string{
		"-s=fill=random",
		"-c",
		"-o",
		fmt.Sprintf("-r=pattern=%s", cliFullRegex),
		fmt.Sprintf("-i=name=%s,data=%s,password=%s", sectionName, cliSectionPayload, cliSectionPass),
		fmt.Sprintf("-l=data=%s,password=%s", cliOverlayPayload, cliOverlayPass),
		fmt.Sprintf("-ei=name=%s,password=%s,destination=%s", sectionName, cliSectionPass, sectionDest),
		fmt.Sprintf("-el=password=%s,destination=%s", cliOverlayPass, overlayDest),
	}
}

func pipelineSectionDest(binaryPath string) string {
	return binaryPath + ".pipeline_section"
}

func pipelineOverlayDest(binaryPath string) string {
	return binaryPath + ".pipeline_overlay"
}
