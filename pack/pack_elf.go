package pack

import (
	"fmt"
	"os"
)

// PackELF packa un eseguibile ELF
func PackELF(inputPath string, config *PackConfig) (*PackResult, error) {
	// 1. Leggi file originale
	originalData, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read input file: %w", err)
	}

	originalSize := int64(len(originalData))
	originalHash := ComputeHash(originalData)

	if config.Verbose {
		fmt.Printf("📦 Packing ELF: %s (%d bytes)\n", inputPath, originalSize)
		fmt.Printf("   Hash: %x\n", originalHash[:8])
	}

	// 2. Aggiungi padding casuale (se abilitato)
	dataWithPadding, paddingOffsets, err := AddRandomPadding(originalData, config)
	if err != nil {
		return nil, fmt.Errorf("failed to add padding: %w", err)
	}

	if config.Verbose && config.RandomPadding {
		fmt.Printf("   Added %d bytes of random padding\n", len(dataWithPadding)-len(originalData))
	}

	// 3. Comprimi
	compressed, err := CompressPayload(dataWithPadding, config)
	if err != nil {
		return nil, fmt.Errorf("failed to compress payload: %w", err)
	}

	compressionRatio := float64(len(compressed)) / float64(len(dataWithPadding)) * 100.0
	if config.Verbose {
		fmt.Printf("   Compressed: %d -> %d bytes (%.1f%%)\n", len(dataWithPadding), len(compressed), compressionRatio)
	}

	// 4. Cifra
	encrypted, key, nonce, err := EncryptPayload(compressed, config)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt payload: %w", err)
	}

	if config.Verbose {
		fmt.Printf("   Encrypted: %d bytes (algorithm: %s)\n", len(encrypted), config.EncryptionAlgorithm)
	}

	// 5. Crea metadata
	metadata := &PayloadMetadata{
		OriginalSize:    uint64(len(originalData)),
		CompressedSize:  uint64(len(compressed)),
		EncryptedSize:   uint64(len(encrypted)),
		CompressionAlgo: config.CompressionAlgorithm,
		EncryptionAlgo:  config.EncryptionAlgorithm,
		EncryptionKey:   key,
		EncryptionNonce: nonce,
		PaddingOffsets:  paddingOffsets,
		Checksum:        originalHash,
	}

	// 6. Compila stub con metadata embedded
	stubBinary, err := CompileStub(config, metadata, encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to compile stub: %w", err)
	}

	// 7. Applica tecniche polimorfiche al binario (se abilitato)
	var finalStub []byte
	var stubHash [32]byte
	var techniques []string

	if config.PolymorphicStub {
		engine := NewPolymorphicEngine(config)
		template := &StubTemplate{
			Name:       "ELF_Compiled_Stub",
			TargetArch: "amd64",
			TargetOS:   "linux",
			BaseCode:   stubBinary,
		}
		polyStub, err := engine.GenerateStub(template, encrypted, metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to apply polymorphism: %w", err)
		}
		finalStub = polyStub.Code
		stubHash = polyStub.Hash
		techniques = polyStub.Techniques

		if config.Verbose {
			fmt.Printf("   Applied polymorphism: %v\n", techniques)
		}
	} else {
		finalStub = stubBinary
		stubHash = ComputeHash(stubBinary)
		techniques = []string{"none"}
	}

	if config.Verbose {
		fmt.Printf("   Final stub: %d bytes (hash: %x)\n", len(finalStub), stubHash[:8])
	}

	// 8. Stub è già autocontenuto, nessun assemblaggio necessario
	packedData := finalStub

	// 9. Scrivi output
	outputPath := config.OutputPath
	if outputPath == "" {
		outputPath = inputPath + ".packed"
	}

	if err := os.WriteFile(outputPath, packedData, 0755); err != nil {
		return nil, fmt.Errorf("failed to write output file: %w", err)
	}

	packedSize := int64(len(packedData))
	packedHash := ComputeHash(packedData)

	// 10. Crea risultato
	result := NewPackResult(originalSize, packedSize, originalHash, packedHash, stubHash)
	result.AddDetail(fmt.Sprintf("Compression: %s (level %d)", config.CompressionAlgorithm, config.CompressionLevel))
	result.AddDetail(fmt.Sprintf("Encryption: %s", config.EncryptionAlgorithm))
	result.AddDetail(fmt.Sprintf("Execution mode: %s", executionModeString(config)))
	result.AddDetail(fmt.Sprintf("Polymorphic techniques: %v", techniques))
	result.AddDetail(fmt.Sprintf("Output: %s", outputPath))

	if config.Verbose {
		fmt.Printf("\n%s\n", result.String())
	}

	return result, nil
}

// getELFStubTemplate ritorna il template stub per ELF
func getELFStubTemplate(config *PackConfig) *StubTemplate {
	// Questo è un placeholder - il template vero verrebbe caricato da templates/elf_stub.go
	return &StubTemplate{
		Name:       "ELF_Stub_v1",
		TargetArch: "amd64",
		TargetOS:   "linux",
		BaseCode:   []byte("ELF_STUB_PLACEHOLDER"), // Sostituito dal vero codice
		PlaceholderOffset: map[string]int{
			"PAYLOAD_OFFSET":   0,
			"PAYLOAD_SIZE":     8,
			"ENCRYPTION_KEY":   16,
			"ENCRYPTION_NONCE": 48,
		},
	}
}

// assemblePackedELF assembla lo stub + payload + metadata in un ELF packed
func assemblePackedELF(stub *PolymorphicStub, payload []byte, metadata *PayloadMetadata) []byte {
	// Header: Stub code
	result := stub.Code

	// Metadata section
	metadataBytes := serializeMetadata(metadata)
	result = append(result, metadataBytes...)

	// Payload section
	result = append(result, payload...)

	return result
}

// serializeMetadata serializza i metadata in byte
func serializeMetadata(m *PayloadMetadata) []byte {
	// Formato semplificato:
	// [8 bytes: OriginalSize]
	// [8 bytes: CompressedSize]
	// [8 bytes: EncryptedSize]
	// [16 bytes: CompressionAlgo name]
	// [16 bytes: EncryptionAlgo name]
	// [N bytes: EncryptionKey]
	// [M bytes: EncryptionNonce]
	// [32 bytes: Checksum]

	result := make([]byte, 0, 128)

	// Sizes
	result = appendUint64(result, m.OriginalSize)
	result = appendUint64(result, m.CompressedSize)
	result = appendUint64(result, m.EncryptedSize)

	// Algorithms (fixed 16 bytes each)
	result = appendFixedString(result, m.CompressionAlgo, 16)
	result = appendFixedString(result, m.EncryptionAlgo, 16)

	// Key size + key
	result = appendUint32(result, uint32(len(m.EncryptionKey)))
	result = append(result, m.EncryptionKey...)

	// Nonce size + nonce
	result = appendUint32(result, uint32(len(m.EncryptionNonce)))
	result = append(result, m.EncryptionNonce...)

	// Checksum
	result = append(result, m.Checksum[:]...)

	return result
}

func executionModeString(config *PackConfig) string {
	if config.InMemoryExecution {
		return "in-memory (memfd_create)"
	}
	return "temporary file"
}
