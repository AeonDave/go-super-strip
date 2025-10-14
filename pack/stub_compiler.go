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
	defer os.RemoveAll(tmpDir)

	// Scrivi stub source (NON embeddiamo i dati, li appenderemo dopo)
	stubPath := filepath.Join(tmpDir, "stub.go")
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

	cmd := exec.Command("go", "build",
		"-ldflags", "-s -w", // Strip symbols
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

// injectMetadata sostituisce i placeholder nel codice stub con i dati reali
func injectMetadata(source string, metadata *PayloadMetadata, payload []byte, config *PackConfig) string {
	// Converti payload in formato Go byte slice literal
	payloadLiteral := bytesToGoLiteral(payload)

	// Converti key e nonce
	keyLiteral := bytesToGoLiteral(metadata.EncryptionKey)
	nonceLiteral := bytesToGoLiteral(metadata.EncryptionNonce)

	// Converti padding offsets
	paddingLiteral := intsToGoLiteral(metadata.PaddingOffsets)

	// Sostituzioni
	replacements := map[string]string{
		"/* PAYLOAD_PLACEHOLDER */":           payloadLiteral,
		"/* KEY_PLACEHOLDER */":               keyLiteral,
		"/* NONCE_PLACEHOLDER */":             nonceLiteral,
		"/* SIZE_PLACEHOLDER */":              fmt.Sprintf("%d", metadata.OriginalSize),
		"/* COMP_ALGO_PLACEHOLDER */":         metadata.CompressionAlgo,
		"/* ENC_ALGO_PLACEHOLDER */":          metadata.EncryptionAlgo,
		"/* PADDING_PLACEHOLDER */":           paddingLiteral,
		"false // /* INMEMORY_PLACEHOLDER */": fmt.Sprintf("%t", config.InMemoryExecution),
	}

	result := source
	for placeholder, value := range replacements {
		result = strings.ReplaceAll(result, placeholder, value)
	}

	return result
}

// bytesToGoLiteral converte []byte in stringa literal Go (solo contenuto, senza []byte{})
func bytesToGoLiteral(data []byte) string {
	if len(data) == 0 {
		// Per slice vuoto, usa syntax  che funziona sia con `= []byte{}` che `= []byte{nil}`
		return ""
	}

	// Usa formato hex per compattezza: 0x12, 0x34, 0x56, ...
	var buf strings.Builder

	for i, b := range data {
		if i > 0 {
			buf.WriteString(", ")
		}
		if i%16 == 0 && i > 0 {
			buf.WriteString("\n\t\t")
		}
		buf.WriteString(fmt.Sprintf("0x%02x", b))
	}

	return buf.String()
}

// intsToGoLiteral converte []int in stringa literal Go (solo contenuto, senza []int{})
func intsToGoLiteral(data []int) string {
	if len(data) == 0 {
		return ""
	}

	var buf strings.Builder

	for i, val := range data {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(fmt.Sprintf("%d", val))
	}

	return buf.String()
}
