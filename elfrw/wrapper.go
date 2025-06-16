package elfrw

import (
	"fmt"
	"gosstrip/common"
	"os"
	"regexp"
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
func ObfuscateAllDetailed(filePath string) *common.OperationResult {
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
	result := elfFile.ObfuscateAll()
	if !result.Applied {
		return result
	}

	if err := elfFile.CommitChanges(uint64(len(elfFile.RawData))); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// ObfuscateBaseAddressesDetailed obfuscates base addresses in an ELF file with detailed result
func ObfuscateBaseAddressesDetailed(filePath string) *common.OperationResult {
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
		return common.NewSkipped("skipping base address randomization for Go binary (would break runtime)")
	}

	result := elfFile.ObfuscateBaseAddresses()
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
