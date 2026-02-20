package pack

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gosstrip/pack/strategies"
)

//go:embed strategies/runtime/pe_base_runtime.go
var peBaseGoSource string

//go:embed strategies/runtime/elf_base_runtime.go
var elfBaseGoSource string

// GetPEBaseSource returns the PE stub base runtime source with the
// //go:build ignore tag stripped, ready to write to a temp directory.
func GetPEBaseSource() string {
	return strategies.StripBuildIgnoreTag(peBaseGoSource)
}

// GetELFBaseSource returns the ELF stub base runtime source with the
// //go:build ignore tag stripped, ready to write to a temp directory.
func GetELFBaseSource() string {
	return strategies.StripBuildIgnoreTag(elfBaseGoSource)
}

// CompileStub compiles the base runtime + selected strategy into a self-contained
// stub binary, then appends the encrypted payload and metadata.
//
// The compilation uses a two-file approach inside a temp directory:
//   - stub_base.go    – the PE or ELF base runtime (crypto, decompress, executeFromTemp, …)
//   - stub_strategy.go – the selected strategy (executeStrategy entry point)
//
// Both files share package main, so they resolve each other's symbols freely.
// An optional third file (stub_poly.go) carries polymorphic junk code.
func CompileStub(config *PackConfig, metadata *PayloadMetadata, payload []byte) ([]byte, error) {
	// ── Determine target triple ───────────────────────────────────────────────
	targetOS := metadata.TargetOS
	if targetOS == "" {
		// fall back to output-path heuristic for backward compatibility
		if strings.Contains(config.OutputPath, ".exe") || strings.Contains(config.OutputPath, "windows") {
			targetOS = "windows"
		} else {
			targetOS = "linux"
		}
	}
	targetArch := metadata.StubArch
	if targetArch == "" {
		targetArch = "amd64"
	}

	// ── Resolve strategy source ───────────────────────────────────────────────
	strat, err := strategies.Resolve(metadata.Strategy, targetOS)
	if err != nil {
		return nil, fmt.Errorf("strategy resolve: %w", err)
	}
	strategySource, err := strat.RuntimeSource(targetArch)
	if err != nil {
		return nil, fmt.Errorf("strategy runtime source: %w", err)
	}

	// ── Select base runtime ───────────────────────────────────────────────────
	var baseSource string
	if targetOS == "windows" {
		baseSource = GetPEBaseSource()
	} else {
		baseSource = GetELFBaseSource()
	}

	// ── Create temp build directory ───────────────────────────────────────────
	tmpDir, err := os.MkdirTemp("", "stub-build-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// ── Write source files ────────────────────────────────────────────────────
	if err := os.WriteFile(filepath.Join(tmpDir, "stub_base.go"), []byte(baseSource), 0644); err != nil {
		return nil, fmt.Errorf("failed to write stub_base.go: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "stub_strategy.go"), []byte(strategySource), 0644); err != nil {
		return nil, fmt.Errorf("failed to write stub_strategy.go: %w", err)
	}

	// Polymorphic junk variant injected as a third file.
	if config.PolymorphicStub {
		gen := NewStubTemplateGenerator()
		variant := gen.GenerateVariant(randomInt(1_000_000))
		code := variant.SourceCode
		funcName := extractFirstFuncName(code)
		var polySource string
		if funcName != "" {
			polySource = "package main\n\n" +
				"// === Polymorphic variant (auto-generated) ===\n" +
				code +
				"\n\nfunc init() {\n" +
				"\t_ = 0\n" +
				"\tbuf := []byte{0}\n" +
				"\t" + funcName + "(buf, byte(0))\n" +
				"}\n"
		} else {
			polySource = "package main\n\n// === Polymorphic variant ===\n" + code + "\n"
		}
		if err := os.WriteFile(filepath.Join(tmpDir, "stub_poly.go"), []byte(polySource), 0644); err != nil {
			return nil, fmt.Errorf("failed to write stub_poly.go: %w", err)
		}
	}

	// ── Write go.mod ─────────────────────────────────────────────────────────
	goModContent := "module stub\ngo 1.24\n\nrequire (\n\tgithub.com/ulikunitz/xz v0.5.15\n\tgolang.org/x/crypto v0.47.0\n)\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goModContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write go.mod: %w", err)
	}

	// ── Download dependencies ─────────────────────────────────────────────────
	modTidy := exec.Command("go", "mod", "tidy")
	modTidy.Dir = tmpDir
	var modErr bytes.Buffer
	modTidy.Stderr = &modErr
	modTidy.Env = append(os.Environ(),
		fmt.Sprintf("GOOS=%s", targetOS),
		fmt.Sprintf("GOARCH=%s", targetArch),
	)
	if err := modTidy.Run(); err != nil {
		return nil, fmt.Errorf("go mod tidy: %w\n%s", err, modErr.String())
	}

	// ── Compile stub ─────────────────────────────────────────────────────────
	outputPath := filepath.Join(tmpDir, "stub")
	if targetOS == "windows" {
		outputPath += ".exe"
	}

	ldflags := "-s -w"
	if targetOS == "windows" && metadata.StubWindowsGUI {
		ldflags += " -H=windowsgui"
	}

	cmd := exec.Command("go", "build",
		"-ldflags", ldflags,
		"-o", outputPath,
		".",
	)
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GOOS=%s", targetOS),
		fmt.Sprintf("GOARCH=%s", targetArch),
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("compile stub: %w\n%s", err, stderr.String())
	}

	// ── Read compiled binary ──────────────────────────────────────────────────
	stubBinary, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read compiled stub: %w", err)
	}

	// ── Assemble final output: stub + payload + metadata + metadata-size ──────
	metadataBytes := serializeMetadataForStub(metadata)

	result := stubBinary
	result = append(result, payload...)
	result = append(result, metadataBytes...)

	sizeBuf := make([]byte, 8)
	for i := 0; i < 8; i++ {
		sizeBuf[i] = byte(uint64(len(metadataBytes)) >> (i * 8))
	}
	result = append(result, sizeBuf...)

	if config.Verbose {
		fmt.Printf("   Compiled stub: %d bytes (%s/%s, strategy: %s)\n",
			len(stubBinary), targetOS, targetArch, strat.Name())
		fmt.Printf("   Appended payload: %d bytes\n", len(payload))
		fmt.Printf("   Appended metadata: %d bytes\n", len(metadataBytes))
		fmt.Printf("   Final packed size: %d bytes\n", len(result))
	}

	return result, nil
}

// serializeMetadataForStub serializes payload metadata into the binary format
// expected by the stub's parseMetadata() function at runtime.
//
// Format (little-endian):
//
//	[8]OriginalSize + [8]CompressedSize + [8]EncryptedSize +
//	[16]CompressionAlgo + [16]EncryptionAlgo +
//	[4]KeyLen + Key + [4]NonceLen + Nonce +
//	[1]UseInMemory + [16]Strategy +
//	[4]ParamsLen + Params
func serializeMetadataForStub(m *PayloadMetadata) []byte {
	result := make([]byte, 0, 128)

	result = appendUint64(result, m.OriginalSize)
	result = appendUint64(result, m.CompressedSize)
	result = appendUint64(result, m.EncryptedSize)

	result = appendFixedString(result, m.CompressionAlgo, 16)
	result = appendFixedString(result, m.EncryptionAlgo, 16)

	result = appendUint32(result, uint32(len(m.EncryptionKey)))
	result = append(result, m.EncryptionKey...)

	result = appendUint32(result, uint32(len(m.EncryptionNonce)))
	result = append(result, m.EncryptionNonce...)

	if m.UseInMemory {
		result = append(result, 1)
	} else {
		result = append(result, 0)
	}
	result = appendFixedString(result, m.Strategy, 16)

	if len(m.UserParams) > 0 {
		result = appendUint32(result, uint32(len(m.UserParams)))
		result = append(result, []byte(m.UserParams)...)
	} else {
		result = appendUint32(result, 0)
	}

	return result
}

// extractFirstFuncName attempts to find the first function name in Go source.
func extractFirstFuncName(src string) string {
	idx := strings.Index(src, "func ")
	if idx == -1 {
		return ""
	}
	i := idx + len("func ")
	for i < len(src) && (src[i] == ' ' || src[i] == '\n' || src[i] == '\t') {
		i++
	}
	if i < len(src) && src[i] == '(' {
		depth := 1
		i++
		for i < len(src) && depth > 0 {
			switch src[i] {
			case '(':
				depth++
			case ')':
				depth--
			}
			i++
		}
		for i < len(src) && (src[i] == ' ' || src[i] == '\n' || src[i] == '\t') {
			i++
		}
	}
	j := i
	for j < len(src) {
		c := src[j]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			j++
			continue
		}
		break
	}
	if j > i {
		return src[i:j]
	}
	return ""
}
