package pack

import (
	"fmt"
	"os"

	winstrat "gosstrip/pack/strategies/windows"
)

// PackPE packa un eseguibile PE (Windows)
func PackPE(inputPath string, config *PackConfig) (*PackResult, error) {
	// 1. Leggi file originale
	originalData, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read input file: %w", err)
	}

	originalSize := int64(len(originalData))
	originalHash := ComputeHash(originalData)

	if config.Verbose {
		fmt.Printf("📦 Packing PE: %s (%d bytes)\n", inputPath, originalSize)
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

	stubArch, err := detectPEArchitecture(originalData)
	if err != nil {
		return nil, err
	}
	subsystem, err := detectPESubsystem(originalData)
	if err != nil {
		return nil, err
	}
	useGuiStub := subsystem == imageSubsystemWindowsGUI || subsystem == imageSubsystemWindowsCeGUI
	requestedMode := config.InMemoryMode
	resolvedMode, err := winstrat.Resolve(requestedMode)
	if err != nil {
		return nil, err
	}
	inMemoryEnabled := resolvedMode.Enabled()

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
		InMemoryMode:    resolvedMode,
		UseInMemory:     inMemoryEnabled,
		UserParams:      config.Params,
		Checksum:        originalHash,
		StubArch:        stubArch,
		StubWindowsGUI:  useGuiStub,
	}

	// 6. Compila stub con metadata embedded
	// Assicura che il compilatore selezioni correttamente il target Windows impostando OutputPath di default prima della compilazione
	if config.OutputPath == "" {
		config.OutputPath = inputPath
	}
	stubBinary, err := compileStubFunc(config, metadata, encrypted)
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
			Name:       "PE_Compiled_Stub",
			TargetArch: "amd64",
			TargetOS:   "windows",
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
		outputPath = inputPath
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
	result.AddDetail(fmt.Sprintf("Execution mode: %s", winstrat.Describe(resolvedMode)))
	result.AddDetail(fmt.Sprintf("Polymorphic techniques: %v", techniques))
	result.AddDetail(fmt.Sprintf("Output: %s", outputPath))
	if config.Params != "" {
		result.AddDetail(fmt.Sprintf("Params: %s", config.Params))
	}
	if config.Verbose {
		fmt.Printf("\n%s\n", result.String())
	}

	return result, nil
}
