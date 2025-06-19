package elfrw

import (
	"fmt"
	"gosstrip/common"
	"os"
	"regexp"
	"strings"
)

// AnalyzeELF analyzes an ELF file and prints detailed information
func AnalyzeELF(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return err
	}

	return elfFile.Analyze()
}

// ObfuscateSectionNamesDetailed obfuscates section names in an ELF file with detailed result
func ObfuscateSectionNamesDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}
	result := elfFile.RandomizeSectionNames()
	if !result.Applied {
		return result
	}

	if err := elfFile.CommitChanges(uint64(len(elfFile.RawData))); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// StripRegexBytes strips bytes matching a regex pattern from an ELF file
func StripRegexBytes(filePath string, regex *regexp.Regexp) error {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return err
	}

	count, err := elfFile.StripByteRegex(regex, false)
	if err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("no matches found")
	}

	return elfFile.CommitChanges(uint64(len(elfFile.RawData)))
}

// AddHexSection adds a hex section to an ELF file (with optional encryption)
func AddHexSection(filePath, sectionName, sourceFile, password string) error {
	result := AddHexSectionDetailed(filePath, sectionName, sourceFile, password)
	if !result.Applied {
		return fmt.Errorf("%s", result.Message)
	}
	return nil
}

// AddHexSectionDetailed adds a hex section to an ELF file with detailed result
func AddHexSectionDetailed(filePath, sectionName, sourceFile, password string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}

	// Check if section with same name already exists
	for _, section := range elfFile.Sections {
		if section.Name == sectionName {
			return common.NewSkipped(fmt.Sprintf("section '%s' already exists", sectionName))
		}
	}

	// Add hex section
	if err := elfFile.AddHexSection(sectionName, sourceFile, password); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to add hex section: %v", err))
	}

	// Commit changes
	if err := elfFile.CommitChanges(uint64(len(elfFile.RawData))); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to commit changes: %v", err))
	}

	message := fmt.Sprintf("added hex section '%s'", sectionName)
	if password != "" {
		message += " (encrypted)"
	}
	return common.NewApplied(message, 1)
}

// ObfuscateAllDetailed applies all obfuscation techniques to an ELF file with detailed result
func ObfuscateAllDetailed(filePath string, force bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}
	result := elfFile.ObfuscateAll(force)
	if !result.Applied {
		return result
	}

	if err := elfFile.CommitChanges(uint64(len(elfFile.RawData))); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// ObfuscateBaseAddressesDetailed obfuscates base addresses in an ELF file with detailed result
func ObfuscateBaseAddressesDetailed(filePath string, force bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}

	// Check if this is a Go binary before obfuscation
	if elfFile.isGoBinary() {
		if force {
			fmt.Printf("WARNING: Go binary detected, but force flag enabled. Proceeding with base address obfuscation.\n")
		} else {
			return common.NewSkipped("skipping base address randomization for Go binary (would break runtime, use -f to force)")
		}
	}

	result := elfFile.ObfuscateBaseAddresses(force)
	if !result.Applied {
		return result
	}

	if err := elfFile.CommitChanges(uint64(len(elfFile.RawData))); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// IsGoBinary checks if an ELF file is a Go binary without opening for write
func IsGoBinary(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return false, err
	}

	return elfFile.isGoBinary(), nil
}

// AdvancedStripELFDetailed performs comprehensive ELF stripping with optional size reduction
func AdvancedStripELFDetailed(filePath string, compact bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}

	result := elfFile.AdvancedStripDetailed(compact)
	if !result.Applied {
		return result
	}

	if err := elfFile.CommitChanges(uint64(len(elfFile.RawData))); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// CompactELFDetailed performs aggressive ELF compaction with section removal
func CompactELFDetailed(filePath string, removeNonEssential bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}

	result, err := elfFile.CompactAndStrip(removeNonEssential)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("compaction failed: %v", err))
	}

	if !result.Applied {
		return result
	}

	if err := elfFile.CommitChanges(uint64(len(elfFile.RawData))); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// StripELFDetailed performs unified ELF stripping operations with atomic behavior
// This function always applies comprehensive stripping (including debug, symbols, etc.)
// - compact=true: Apply additional size reduction via section removal
// - force=true: Allow risky operations (Go binary modifications)
func StripELFDetailed(filePath string, compact bool, force bool) *common.OperationResult {
	// Get initial file size for compaction calculation
	initialFileInfo, err := os.Stat(filePath)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to get file size: %v", err))
	}
	initialSize := initialFileInfo.Size()

	// Check if this is a Go binary before operations
	isGoBinary, err := IsGoBinary(filePath)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to check binary type: %v", err))
	}

	if isGoBinary && !force {
		return common.NewSkipped("Go binary detected (use -f to force risky operations)")
	}

	// Use the existing AdvancedStripELFDetailed function for comprehensive stripping
	// This includes debug sections, symbol tables, and optional compaction
	result := AdvancedStripELFDetailed(filePath, compact)

	if result.Applied {
		// Calculate final file size and compaction percentage
		finalFileInfo, err := os.Stat(filePath)
		finalSize := initialSize // fallback to initial size if we can't get new size
		compressionInfo := ""

		if err == nil {
			finalSize = finalFileInfo.Size()
			if finalSize < initialSize {
				savedBytes := initialSize - finalSize
				percentage := float64(savedBytes) / float64(initialSize) * 100
				compressionInfo = fmt.Sprintf(" (%.1f%% reduction: %d → %d bytes, saved %d bytes)",
					percentage, initialSize, finalSize, savedBytes)
			} else if compact {
				compressionInfo = fmt.Sprintf(" (no size reduction: %d bytes)", finalSize)
			}
		}

		// Update result message with compaction info
		result.Message += compressionInfo

		if isGoBinary && force {
			// Add warning message for forced Go binary operations
			result.Message = fmt.Sprintf("WARNING: Go binary forced - %s", result.Message)
		}
	}

	return result
}

// ApplyRiskyOperationsDetailed applies only risky stripping operations for ELF files
// This function is designed to be called after obfuscation to avoid corrupting structures needed for obfuscation
func ApplyRiskyOperationsDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}

	totalOperations := 0
	results := []string{}

	// Apply risky operations for ELF - exception and relocation sections
	exceptionResult := elfFile.StripExceptionSections(false)
	if exceptionResult.Applied {
		totalOperations += exceptionResult.Count
		results = append(results, fmt.Sprintf("✓ %s", exceptionResult.Message))
	} else {
		results = append(results, fmt.Sprintf("⚠️ exception handling: %s", exceptionResult.Message))
	}

	relocationResult := elfFile.StripRelocationSections(false)
	if relocationResult.Applied {
		totalOperations += relocationResult.Count
		results = append(results, fmt.Sprintf("✓ %s", relocationResult.Message))
	} else {
		results = append(results, fmt.Sprintf("⚠️ relocation tables: %s", relocationResult.Message))
	}

	// Commit changes
	if err := elfFile.CommitChanges(0); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	if totalOperations == 0 {
		return common.NewSkipped("no risky operations applied")
	}

	message := fmt.Sprintf("🔥 Risky Operations Applied:\n%s\n✅ Total: %d risky operations completed",
		strings.Join(results, "\n"), totalOperations)

	return common.NewApplied(message, totalOperations)
}
