package test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"gosstrip/common"
)

type fixtureKind string

const (
	kindPE  fixtureKind = "pe"
	kindELF fixtureKind = "elf"
)

type prebuiltFixture struct {
	Name string
	Path string
	Kind fixtureKind
	UPX  bool
}

func TestCLIFixtureMatrix_NoInPlaceMutation(t *testing.T) {
	cli := buildCLIBinaryLocal(t)

	fixtures := discoverPrebuiltFixtures(t)
	if len(fixtures) == 0 {
		t.Skip("no prebuilt fixtures found under testfiles/prebuilt")
	}

	// Always run deterministic order so failures are stable.
	sort.Slice(fixtures, func(i, j int) bool { return fixtures[i].Name < fixtures[j].Name })

	combos := [][]string{
		{"-s"},
		{"-c"},
		{"-o"},
		{"-s", "-c"},
		{"-s", "-o"},
		{"-c", "-o"},
		{"-s", "-c", "-o"},
	}

	for _, fx := range fixtures {
		fx := fx
		t.Run(fx.Name, func(t *testing.T) {
			// Work on a temp input so this test can never dirty the repo, but still
			// validates the CLI contract: when an output is supplied, the input must
			// remain unchanged.
			workDir := t.TempDir()
			input := filepath.Join(workDir, filepath.Base(fx.Path))
			copyFileBytes(t, fx.Path, input, 0o700)

			inputHash := sha256File(t, input)
			inputSize := fileSize(t, input)

			inputAnalysis := analyzeJSON(t, cli, input)
			if len(inputAnalysis.Errors) != 0 {
				t.Fatalf("input analysis reported errors: %v", inputAnalysis.Errors)
			}

			for _, combo := range combos {
				combo := combo
				name := strings.Join(combo, "")
				t.Run(name, func(t *testing.T) {
					outPath := filepath.Join(workDir, fmt.Sprintf("%s_%s", filepath.Base(fx.Path), name))
					if fx.Kind == kindPE && !strings.HasSuffix(strings.ToLower(outPath), ".exe") {
						outPath += ".exe"
					}

					args := append([]string{}, combo...)
					args = append(args, input, outPath)

					out := runCLI(t, cli, args...)
					if !fileExists(outPath) {
						t.Fatalf("expected output file to exist: %s\nCLI output:\n%s", outPath, out)
					}

					if got := sha256File(t, input); got != inputHash {
						t.Fatalf("input mutated even though output path was provided: %s\nwant=%s\ngot=%s", input, inputHash, got)
					}

					res := analyzeJSON(t, cli, outPath)
					if len(res.Errors) != 0 {
						t.Fatalf("output analysis reported errors: %v\nCLI output:\n%s", res.Errors, out)
					}

					outSize := fileSize(t, outPath)
					if outSize <= 0 {
						t.Fatalf("output file size invalid: %d", outSize)
					}

					// Verify that non-UPX inputs actually change under SCO operations.
					// (UPX-packed binaries can be resistant to some transformations, so be lenient there.)
					if !fx.UPX {
						outHash := sha256File(t, outPath)
						if outHash == inputHash {
							t.Fatalf("expected output to differ from input for non-UPX fixture; size %d -> %d", inputSize, outSize)
						}
					}
				})
			}

			// Insert/overlay/extract verification (single scenario per fixture).
			insertOverlayMatrix(t, cli, fx, input, workDir)
		})
	}
}

func insertOverlayMatrix(t *testing.T, cli string, fx prebuiltFixture, input, workDir string) {
	t.Helper()

	// Skip encrypted insert on PE when name is too long is handled by SanitizeSectionName in CLI,
	// but still keep it short for PE safety.
	sectionName := "cfg"
	sectionPayload := "CLI_MATRIX_SECTION_PAYLOAD_123"
	sectionPass := "pass123"
	overlayPayload := "CLI_MATRIX_OVERLAY_PAYLOAD_456"
	overlayPass := "pass456"

	outPath := filepath.Join(workDir, filepath.Base(fx.Path)+"_io")
	if fx.Kind == kindPE && !strings.HasSuffix(strings.ToLower(outPath), ".exe") {
		outPath += ".exe"
	}

	sectionOut := filepath.Join(workDir, fx.Name+".section.extracted")
	overlayOut := filepath.Join(workDir, fx.Name+".overlay.extracted")

	// CLI parsing (and some log renderers) can misinterpret backslash sequences like "\n".
	// Pass destination paths using forward slashes to keep things stable on Windows.
	sectionOutArg := filepath.ToSlash(sectionOut)
	overlayOutArg := filepath.ToSlash(overlayOut)
	outPathArg := filepath.ToSlash(outPath)
	inputArg := filepath.ToSlash(input)

	// UPX-packed ELF binaries typically do not have a section header table, so section insertion/extraction
	// is expected to fail. Overlay operations still work there.
	allowSectionInsert := !(fx.Kind == kindELF && fx.UPX)

	// Step 1: mutate output (insert section + overlay) using canonical order.
	mutateArgs := []string{}
	if allowSectionInsert {
		mutateArgs = append(mutateArgs,
			"-i=name="+sectionName+",data="+sectionPayload+",password="+sectionPass,
		)
	}
	mutateArgs = append(mutateArgs,
		"-l=data="+overlayPayload+",password="+overlayPass,
		inputArg,
		outPathArg,
	)

	inputHash := sha256File(t, input)
	out := runCLI(t, cli, mutateArgs...)
	if !fileExists(outPath) {
		t.Fatalf("expected output file to exist: %s\nCLI output:\n%s", outPath, out)
	}
	if got := sha256File(t, input); got != inputHash {
		t.Fatalf("input mutated even though output path was provided (insert/overlay run)")
	}

	// Step 2: extract section (extract-only pipeline) from the mutated output.
	if allowSectionInsert {
		extractSectionArgs := []string{
			"-ei=name=" + sectionName + ",password=" + sectionPass + ",destination=" + sectionOutArg,
			filepath.ToSlash(outPath),
		}
		out2 := runCLI(t, cli, extractSectionArgs...)
		if !fileExists(sectionOut) {
			t.Fatalf("expected section extraction output to exist: %s\nCLI output:\n%s", sectionOut, out2)
		}
		secBytes := mustReadFile(t, sectionOut)
		if string(secBytes) != sectionPayload {
			t.Fatalf("extracted section payload mismatch: got %q want %q", string(secBytes), sectionPayload)
		}
	}

	// Step 3: extract overlay (extract-only pipeline) from the mutated output.
	extractOverlayArgs := []string{
		"-el=password=" + overlayPass + ",destination=" + overlayOutArg,
		filepath.ToSlash(outPath),
	}
	out3 := runCLI(t, cli, extractOverlayArgs...)
	if !fileExists(overlayOut) {
		t.Fatalf("expected overlay extraction output to exist: %s\nCLI output:\n%s", overlayOut, out3)
	}
	overBytes := mustReadFile(t, overlayOut)
	if string(overBytes) != overlayPayload {
		t.Fatalf("extracted overlay payload mismatch: got %q want %q", string(overBytes), overlayPayload)
	}

	// Output should still be analyzable.
	res := analyzeJSON(t, cli, outPath)
	if len(res.Errors) != 0 {
		t.Fatalf("output analysis reported errors after insert/overlay: %v\nCLI output:\n%s", res.Errors, out)
	}
}

func buildCLIBinaryLocal(t *testing.T) string {
	t.Helper()
	outName := "gosstrip"
	if runtime.GOOS == "windows" {
		outName += ".exe"
	}
	path := filepath.Join(t.TempDir(), outName)
	cmd := exec.Command("go", "build", "-o", path, ".")
	cmd.Env = os.Environ()
	cmd.Dir = ".." // test package lives in ./test
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build CLI: %v\n%s", err, string(b))
	}
	return path
}

func discoverPrebuiltFixtures(t *testing.T) []prebuiltFixture {
	t.Helper()
	var out []prebuiltFixture

	addDir := func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			p := filepath.Join(dir, e.Name())
			kind := detectKind(t, p)
			if kind == "" {
				continue
			}
			out = append(out, prebuiltFixture{
				Name: e.Name(),
				Path: p,
				Kind: kind,
				UPX:  strings.Contains(strings.ToLower(e.Name()), "upx"),
			})
		}
	}

	addDir(filepath.Join("..", "testfiles", "prebuilt", "win"))
	addDir(filepath.Join("..", "testfiles", "prebuilt", "linux"))
	// Linux ELF fixtures compiled by build_all_payloads.ps1 -Linux
	// Subdirectories (e.g. out/linux/so/) are skipped by addDir automatically.
	addDir(filepath.Join("..", "testfiles-generic", "out", "linux"))

	return out
}

func detectKind(t *testing.T, path string) fixtureKind {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(f, buf); err != nil {
		return ""
	}
	if buf[0] == 0x4D && buf[1] == 0x5A {
		return kindPE
	}
	if buf[0] == 0x7F && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F' {
		return kindELF
	}
	return ""
}

func runCLI(t *testing.T, cli string, args ...string) string {
	t.Helper()

	cmd := exec.Command(cli, args...)
	cmd.Env = os.Environ()
	cmd.Dir = t.TempDir() // isolate any working-directory side effects
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI failed: %v\nargs=%v\n%s", err, args, string(out))
	}
	return string(out)
}

func analyzeJSON(t *testing.T, cli, target string) *common.AnalysisResult {
	t.Helper()
	cmd := exec.Command(cli, "-a=format=json,mode=deep", target)
	cmd.Env = os.Environ()
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("analyze failed: %v\n%s", err, string(out))
	}
	var res common.AnalysisResult
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("failed to parse analysis JSON: %v\nRaw:\n%s", err, string(out))
	}
	return &res
}

func analysisHasSubstring(res *common.AnalysisResult, needle string) bool {
	if res == nil {
		return false
	}
	for _, b := range res.Blocks {
		if strings.Contains(b.Title, needle) {
			return true
		}
		for _, line := range b.Lines {
			if strings.Contains(line, needle) {
				return true
			}
		}
	}
	for _, w := range res.Warnings {
		if strings.Contains(w, needle) {
			return true
		}
	}
	for _, e := range res.Errors {
		if strings.Contains(e, needle) {
			return true
		}
	}
	return false
}

func analysisSemanticallyEqual(a, b *common.AnalysisResult) bool {
	// We compare the rendered text blocks ignoring volatile tokens like hashes/addresses.
	// This is a coarse check: obfuscation should generally reorder/rename something.
	clean := func(r *common.AnalysisResult) string {
		if r == nil {
			return ""
		}
		var parts []string
		for _, blk := range r.Blocks {
			parts = append(parts, blk.Title)
			for _, line := range blk.Lines {
				// Drop obvious volatile patterns.
				if strings.Contains(line, "SHA256") || strings.Contains(line, "MD5") {
					continue
				}
				parts = append(parts, line)
			}
		}
		return strings.Join(parts, "\n")
	}
	return clean(a) == clean(b)
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	b := mustReadFile(t, path)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file %s: %v", path, err)
	}
	return b
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st.Size()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func containsFlag(flags []string, flag string) bool {
	for _, f := range flags {
		if f == flag {
			return true
		}
	}
	return false
}

func copyFileBytes(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read src: %v", err)
	}
	if err := os.WriteFile(dst, b, mode); err != nil {
		t.Fatalf("write dst: %v", err)
	}
}

func TestCLIFixtureMatrix_ExecutesAfterSCO(t *testing.T) {
	cli := buildCLIBinaryLocal(t)
	fixtures := discoverPrebuiltFixtures(t)
	if len(fixtures) == 0 {
		t.Skip("no prebuilt fixtures found under testfiles/prebuilt")
	}

	for _, fx := range fixtures {
		fx := fx
		if fx.UPX {
			continue
		}
		t.Run(fx.Name, func(t *testing.T) {
			workDir := t.TempDir()
			input := filepath.Join(workDir, filepath.Base(fx.Path))
			copyFileBytes(t, fx.Path, input, 0o700)
			outPath := filepath.Join(workDir, filepath.Base(fx.Path)+"_sco")
			if fx.Kind == kindPE && !strings.HasSuffix(strings.ToLower(outPath), ".exe") {
				outPath += ".exe"
			}

			runCLI(t, cli, "-s", "-c", "-o", input, outPath)

			// Verify the resulting binary still executes (best effort).
			switch fx.Kind {
			case kindPE:
				runPEBinaryInDir(t, outPath, workDir)
			case kindELF:
				runELFBinaryInDir(t, outPath, workDir)
			}
		})
	}
}

func runPEBinaryInDir(t *testing.T, path, dir string) {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("PE execution requires Windows host")
	}
	ctx, cancel := contextWithTimeout(t, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path)
	cmd.Env = os.Environ()
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("PE execution failed: %v\n%s", err, string(out))
	}
}

func runELFBinaryInDir(t *testing.T, path, dir string) {
	t.Helper()
	switch runtime.GOOS {
	case "linux":
		ctx, cancel := contextWithTimeout(t, 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, path)
		cmd.Env = os.Environ()
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("ELF execution failed: %v\n%s", err, string(out))
		}
	case "windows":
		if !hasWSL() {
			t.Skip("ELF execution requires WSL")
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			t.Fatalf("abs: %v", err)
		}
		cmd := fmt.Sprintf("cd '%s' && '%s'", toWSLPath(dir), toWSLPath(abs))
		if err := wslRun(cmd); err != nil {
			t.Fatalf("ELF execution via WSL failed: %v", err)
		}
	default:
		t.Skipf("ELF execution not supported on %s", runtime.GOOS)
	}
}

func contextWithTimeout(t *testing.T, d time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), d)
}
