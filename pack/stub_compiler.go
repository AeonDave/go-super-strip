package pack

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CompileStub compila il template stub Go in un binario eseguibile
func CompileStub(config *PackConfig, metadata *PayloadMetadata, payload []byte) ([]byte, error) {
	// Determina OS/Arch target
	targetOS := "linux"
	targetArch := "amd64"
	stubSource := GetELFStubSource()

	if strings.Contains(config.OutputPath, ".exe") || strings.Contains(config.OutputPath, "windows") {
		targetOS = "windows"
		stubSource = GetPEStubSource()
	}

	// Crea directory temporanea per build
	tmpDir, err := os.MkdirTemp("", "stub-build-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer func(path string) {
		_ = os.RemoveAll(path)
	}(tmpDir)

	// Scrivi stub source (con eventuale iniezione di variante polimorfica)
	stubPath := filepath.Join(tmpDir, "stub.go")

	// Integra generatore di varianti avanzato nel codice stub se abilitato
	if config.PolymorphicStub {
		gen := NewStubTemplateGenerator()
		variant := gen.GenerateVariant(randomInt(1_000_000))
		// Prova ad estrarre il nome della funzione generata per ancorarla ed evitare DCE
		funcName := extractFirstFuncName(variant.SourceCode)
		if funcName != "" {
			anchor := "\n\n// === Polymorphic variant injection (auto-generated) ===\n" +
				variant.SourceCode +
				"\n\n// Anchor the variant to prevent dead-code elimination\n" +
				"func init() {\n" +
				"\t_ = 0\n" +
				"\tbuf := []byte{0} // dummy buffer\n" +
				"\t" + funcName + "(buf, byte(0))\n" +
				"}\n"
			stubSource += anchor
		} else {
			// In caso non si riesca ad estrarre il nome, includi comunque il codice (potrebbe ancora influire sull'hash)
			stubSource += "\n\n// === Polymorphic variant (unanchored) ===\n" + variant.SourceCode + "\n"
		}
	}

	if err := os.WriteFile(stubPath, []byte(stubSource), 0644); err != nil {
		return nil, fmt.Errorf("failed to write stub source: %w", err)
	}

	// Scrivi go.mod
	goModPath := filepath.Join(tmpDir, "go.mod")
	goModContent := `module stub
go 1.20

require (
	github.com/ulikunitz/xz v0.5.11
	golang.org/x/crypto v0.43.0
)
`
	if err := os.WriteFile(goModPath, []byte(goModContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write go.mod: %w", err)
	}

	// Scarica dipendenze con go mod tidy
	modTidy := exec.Command("go", "mod", "tidy")
	modTidy.Dir = tmpDir
	var modErr bytes.Buffer
	modTidy.Stderr = &modErr
	if err := modTidy.Run(); err != nil {
		return nil, fmt.Errorf("failed to tidy modules: %w\nStderr: %s", err, modErr.String())
	}

	// Compila lo stub
	outputPath := filepath.Join(tmpDir, "stub")
	if targetOS == "windows" {
		outputPath += ".exe"
	}

	ldflags := "-s -w"
	if targetOS == "windows" {
		// Build as GUI subsystem to avoid opening a console window for GUI apps
		ldflags += " -H=windowsgui"
	}

	cmd := exec.Command("go", "build",
		"-ldflags", ldflags, // Strip symbols and set subsystem
		"-o", outputPath,
		stubPath,
	)
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GOOS=%s", targetOS),
		fmt.Sprintf("GOARCH=%s", targetArch),
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to compile stub: %w\nStderr: %s", err, stderr.String())
	}

	// Leggi il binario compilato
	stubBinary, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read compiled stub: %w", err)
	}

	// NON applichiamo più trasformazioni polimorfiche a livello binario
	// perché possono corrompere il binario ELF/PE compilato.
	// Le trasformazioni vengono applicate solo in GenerateStub (aggiungendo dati dopo il codice).

	// Serializza metadata
	metadataBytes := serializeMetadataForStub(metadata, config)

	// Appendi: [stub binary][encrypted payload][metadata][metadata size]
	result := stubBinary
	result = append(result, payload...)
	result = append(result, metadataBytes...)

	// Scrivi metadata size (uint64, little-endian)
	sizeBuf := make([]byte, 8)
	for i := 0; i < 8; i++ {
		sizeBuf[i] = byte(uint64(len(metadataBytes)) >> (i * 8))
	}
	result = append(result, sizeBuf...)

	if config.Verbose {
		fmt.Printf("   Compiled stub: %d bytes (%s/%s)\n", len(stubBinary), targetOS, targetArch)
		fmt.Printf("   Appended payload: %d bytes\n", len(payload))
		fmt.Printf("   Appended metadata: %d bytes\n", len(metadataBytes))
		fmt.Printf("   Final packed size: %d bytes\n", len(result))
	}

	return result, nil
}

// serializeMetadataForStub serializza i metadata in formato binario per lo stub
func serializeMetadataForStub(m *PayloadMetadata, config *PackConfig) []byte {
	result := make([]byte, 0, 128)

	// Sizes (3 x uint64 = 24 bytes)
	result = appendUint64(result, m.OriginalSize)
	result = appendUint64(result, m.CompressedSize)
	result = appendUint64(result, m.EncryptedSize)

	// Algorithms (2 x 16 bytes = 32 bytes)
	result = appendFixedString(result, m.CompressionAlgo, 16)
	result = appendFixedString(result, m.EncryptionAlgo, 16)

	// Key (4 bytes size + N bytes data)
	result = appendUint32(result, uint32(len(m.EncryptionKey)))
	result = append(result, m.EncryptionKey...)

	// Nonce (4 bytes size + M bytes data)
	result = appendUint32(result, uint32(len(m.EncryptionNonce)))
	result = append(result, m.EncryptionNonce...)

	// InMemory flag (1 byte)
	if config.InMemoryExecution {
		result = append(result, 1)
	} else {
		result = append(result, 0)
	}

	return result
}

// extractFirstFuncName attempts to find the first function name declared in the provided Go source.
// It looks for a pattern starting with "func " and extracts the identifier before the opening parenthesis.
func extractFirstFuncName(src string) string {
	idx := strings.Index(src, "func ")
	if idx == -1 {
		return ""
	}
	start := idx + len("func ")
	// skip optional receiver: look for first identifier followed by '('; if next char is '(', it's a receiver
	// We implement a simple scan: if the first non-space after 'func ' is '(', skip the receiver '(...)' then read name
	i := start
	for i < len(src) && (src[i] == ' ' || src[i] == '\n' || src[i] == '\t') {
		i++
	}
	if i < len(src) && src[i] == '(' {
		// skip receiver
		depth := 1
		i++
		for i < len(src) && depth > 0 {
			if src[i] == '(' {
				depth++
			} else if src[i] == ')' {
				depth--
			}
			i++
		}
		for i < len(src) && (src[i] == ' ' || src[i] == '\n' || src[i] == '\t') {
			i++
		}
	}
	// now i at start of name
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
