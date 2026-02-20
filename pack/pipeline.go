package pack

import (
	"encoding/binary"
	"fmt"
	"os"

	"gosstrip/elfrw"
	"gosstrip/pack/strategies"
	"gosstrip/perw"
)

// PackPE packs a Windows PE executable into a self-extracting stub.
func PackPE(inputPath string, config *PackConfig) (*PackResult, error) {
	originalData, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read input file: %w", err)
	}

	originalSize := int64(len(originalData))
	originalHash := ComputeHash(originalData)

	if config.Verbose {
		fmt.Printf("Packing PE: %s (%d bytes)\n", inputPath, originalSize)
	}

	dataWithPadding, paddingOffsets, err := AddRandomPadding(originalData, config)
	if err != nil {
		return nil, fmt.Errorf("failed to add padding: %w", err)
	}

	compressed, err := CompressPayload(dataWithPadding, config)
	if err != nil {
		return nil, fmt.Errorf("failed to compress payload: %w", err)
	}

	encrypted, key, nonce, err := EncryptPayload(compressed, config)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt payload: %w", err)
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

	strat, err := strategies.Resolve(config.Strategy, "windows")
	if err != nil {
		return nil, fmt.Errorf("strategy: %w", err)
	}

	metadata := &PayloadMetadata{
		OriginalSize:    uint64(len(originalData)),
		CompressedSize:  uint64(len(compressed)),
		EncryptedSize:   uint64(len(encrypted)),
		CompressionAlgo: config.CompressionAlgorithm,
		EncryptionAlgo:  config.EncryptionAlgorithm,
		EncryptionKey:   key,
		EncryptionNonce: nonce,
		PaddingOffsets:  paddingOffsets,
		Strategy:        strat.Name(),
		UseInMemory:     isInMemoryStrategy(strat.Name()),
		UserParams:      config.Params,
		Checksum:        originalHash,
		StubArch:        stubArch,
		StubWindowsGUI:  useGuiStub,
		TargetOS:        "windows",
	}

	if config.OutputPath == "" {
		config.OutputPath = inputPath
	}

	stubBinary, err := compileStubFunc(config, metadata, encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to compile stub: %w", err)
	}

	finalStub, stubHash, techniques := applyPolymorphism(config, "PE_Compiled_Stub", "amd64", "windows", stubBinary, encrypted, metadata)

	if config.Verbose {
		fmt.Printf("   Strategy: %s, arch: %s, gui: %v\n", strat.Name(), stubArch, useGuiStub)
		fmt.Printf("   Final stub: %d bytes (hash: %x)\n", len(finalStub), stubHash[:8])
		fmt.Printf("   Techniques: %v\n", techniques)
	}

	if err := os.WriteFile(config.OutputPath, finalStub, 0755); err != nil {
		return nil, fmt.Errorf("failed to write output: %w", err)
	}

	packedSize := int64(len(finalStub))
	packedHash := ComputeHash(finalStub)
	result := NewPackResult(originalSize, packedSize, originalHash, packedHash, stubHash)
	for _, t := range techniques {
		result.AddDetail(t)
	}
	return result, nil
}

// PackELF packs a Linux ELF executable into a self-extracting stub.
func PackELF(inputPath string, config *PackConfig) (*PackResult, error) {
	originalData, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read input file: %w", err)
	}

	originalSize := int64(len(originalData))
	originalHash := ComputeHash(originalData)

	if config.Verbose {
		fmt.Printf("Packing ELF: %s (%d bytes)\n", inputPath, originalSize)
	}

	dataWithPadding, paddingOffsets, err := AddRandomPadding(originalData, config)
	if err != nil {
		return nil, fmt.Errorf("failed to add padding: %w", err)
	}

	compressed, err := CompressPayload(dataWithPadding, config)
	if err != nil {
		return nil, fmt.Errorf("failed to compress payload: %w", err)
	}

	encrypted, key, nonce, err := EncryptPayload(compressed, config)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt payload: %w", err)
	}

	strat, err := strategies.Resolve(config.Strategy, "linux")
	if err != nil {
		return nil, fmt.Errorf("strategy: %w", err)
	}

	metadata := &PayloadMetadata{
		OriginalSize:    uint64(len(originalData)),
		CompressedSize:  uint64(len(compressed)),
		EncryptedSize:   uint64(len(encrypted)),
		CompressionAlgo: config.CompressionAlgorithm,
		EncryptionAlgo:  config.EncryptionAlgorithm,
		EncryptionKey:   key,
		EncryptionNonce: nonce,
		PaddingOffsets:  paddingOffsets,
		Strategy:        strat.Name(),
		UseInMemory:     isInMemoryStrategy(strat.Name()),
		UserParams:      config.Params,
		Checksum:        originalHash,
		StubArch:        "amd64",
		TargetOS:        "linux",
	}

	stubBinary, err := compileStubFunc(config, metadata, encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to compile stub: %w", err)
	}

	finalStub, stubHash, techniques := applyPolymorphism(config, "ELF_Compiled_Stub", "amd64", "linux", stubBinary, encrypted, metadata)

	if config.Verbose {
		fmt.Printf("   Strategy: %s\n", strat.Name())
		fmt.Printf("   Final stub: %d bytes (hash: %x)\n", len(finalStub), stubHash[:8])
	}

	if err := os.WriteFile(config.OutputPath, finalStub, 0755); err != nil {
		return nil, fmt.Errorf("failed to write output: %w", err)
	}

	packedSize := int64(len(finalStub))
	packedHash := ComputeHash(finalStub)
	result := NewPackResult(originalSize, packedSize, originalHash, packedHash, stubHash)
	for _, t := range techniques {
		result.AddDetail(t)
	}
	return result, nil
}

// applyPolymorphism optionally applies polymorphic mutations to the stub binary.
// Returns (finalBinary, hash, techniqueNames).
func applyPolymorphism(config *PackConfig, name, arch, targetOS string, stubBinary, encrypted []byte, metadata *PayloadMetadata) ([]byte, [32]byte, []string) {
	if config.PolymorphicStub {
		engine := NewPolymorphicEngine(config)
		template := &StubTemplate{
			Name:       name,
			TargetArch: arch,
			TargetOS:   targetOS,
			BaseCode:   stubBinary,
		}
		polyStub, err := engine.GenerateStub(template, encrypted, metadata)
		if err == nil {
			return polyStub.Code, polyStub.Hash, polyStub.Techniques
		}
	}
	hash := ComputeHash(stubBinary)
	return stubBinary, hash, []string{"none"}
}

// isInMemoryStrategy returns true when the selected strategy runs the payload
// without writing it to disk (i.e. not base_exec / off / empty).
func isInMemoryStrategy(name string) bool {
	switch name {
	case "", "off", "base_exec":
		return false
	default:
		return true
	}
}

// ─── PE helpers ───────────────────────────────────────────────────────────────

const (
	peMachineI386  = 0x014c
	peMachineAMD64 = 0x8664

	imageSubsystemWindowsGUI   = 0x2
	imageSubsystemWindowsCeGUI = 0x9
)

// detectPEArchitecture inspects the PE headers to determine whether the payload
// is 32-bit or 64-bit. Returns the Go architecture string ("386" or "amd64").
func detectPEArchitecture(data []byte) (string, error) {
	if len(data) < 0x40 {
		return "", fmt.Errorf("file too small to contain DOS header")
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return "", fmt.Errorf("input is not a PE executable")
	}
	peOffset := binary.LittleEndian.Uint32(data[0x3C:])
	if peOffset+6 > uint32(len(data)) {
		return "", fmt.Errorf("invalid PE header offset")
	}
	if string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		return "", fmt.Errorf("missing PE signature")
	}
	machine := binary.LittleEndian.Uint16(data[peOffset+4 : peOffset+6])
	switch machine {
	case peMachineAMD64:
		return "amd64", nil
	case peMachineI386:
		return "386", nil
	default:
		return "", fmt.Errorf("unsupported PE machine 0x%X", machine)
	}
}

// detectPESubsystem reads the optional header to discover which Windows
// subsystem the PE targets.
func detectPESubsystem(data []byte) (uint16, error) {
	if len(data) < 0x40 {
		return 0, fmt.Errorf("file too small to contain DOS header")
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return 0, fmt.Errorf("input is not a PE executable")
	}
	peOffset := binary.LittleEndian.Uint32(data[0x3C:])
	if peOffset+0x5C > uint32(len(data)) {
		return 0, fmt.Errorf("invalid PE header offset")
	}
	if string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		return 0, fmt.Errorf("missing PE signature")
	}
	optHeaderOffset := peOffset + 24
	if optHeaderOffset+2 > uint32(len(data)) {
		return 0, fmt.Errorf("missing optional header")
	}
	magic := binary.LittleEndian.Uint16(data[optHeaderOffset:])
	var subsystemOffset uint32
	switch magic {
	case 0x10b: // PE32
		subsystemOffset = 68
	case 0x20b: // PE32+
		subsystemOffset = 88
	default:
		return 0, fmt.Errorf("unsupported optional header magic 0x%X", magic)
	}
	fieldOffset := optHeaderOffset + subsystemOffset
	if fieldOffset+2 > uint32(len(data)) {
		return 0, fmt.Errorf("optional header truncated")
	}
	return binary.LittleEndian.Uint16(data[fieldOffset : fieldOffset+2]), nil
}

// Pack è la funzione principale per il packing basata su stringhe di configurazione.
func Pack(filePath string, optionsString string, outputPath string) error {
	config, err := ParseOptions(optionsString)
	if err != nil {
		return fmt.Errorf("failed to parse options: %w", err)
	}
	return runPackWithConfig(filePath, config, outputPath)
}

// PackWithConfig consente di riutilizzare una configurazione già parseata.
func PackWithConfig(filePath string, config *PackConfig, outputPath string) error {
	if config == nil {
		return fmt.Errorf("pack configuration cannot be nil")
	}
	return runPackWithConfig(filePath, config, outputPath)
}

func runPackWithConfig(filePath string, config *PackConfig, outputPath string) error {
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	if outputPath != "" {
		config.OutputPath = outputPath
	}

	if config.Verbose {
		fmt.Println(config.String())
	}

	isPE, isELF, err := determineFileType(filePath)
	if err != nil {
		return err
	}

	if !isPE && !isELF {
		return fmt.Errorf("unsupported file type: %s (must be ELF or PE)", filePath)
	}

	var result *PackResult

	if isELF {
		fmt.Println("🐧 Packing ELF executable...")
		result, err = PackELF(filePath, config)
	} else {
		fmt.Println("🪟 Packing PE executable...")
		result, err = PackPE(filePath, config)
	}

	if err != nil {
		return fmt.Errorf("packing failed: %w", err)
	}

	if !config.Verbose {
		fmt.Println(result.String())
	}

	return nil
}

// determineFileType determina se il file è ELF o PE.
func determineFileType(filePath string) (bool, bool, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false, false, fmt.Errorf("file does not exist: %s", filePath)
	}

	isPE, err := perw.IsPEFile(filePath)
	if err != nil {
		return false, false, fmt.Errorf("error checking PE file type: %v", err)
	}

	isELF := false
	if !isPE {
		isELF, err = elfrw.IsELFFile(filePath)
		if err != nil {
			return false, false, fmt.Errorf("error checking ELF file type: %v", err)
		}
	}

	return isPE, isELF, nil
}
