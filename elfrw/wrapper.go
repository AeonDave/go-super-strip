package elfrw

import (
	"fmt"
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

// StripDebugSectionsDetailed strips debug sections from an ELF file with detailed result
func StripDebugSectionsDetailed(filePath string) *OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}
	result := elfFile.StripDebugSections(false)
	if !result.Applied {
		return result
	}

	if err := elfFile.CommitChanges(uint64(len(elfFile.RawData))); err != nil {
		return NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// StripSymbolSectionsDetailed strips symbol sections from an ELF file with detailed result
func StripSymbolSectionsDetailed(filePath string) *OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}
	result := elfFile.StripSymbolTables(false)
	if !result.Applied {
		return result
	}

	if err := elfFile.CommitChanges(uint64(len(elfFile.RawData))); err != nil {
		return NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// ObfuscateSectionNamesDetailed obfuscates section names in an ELF file with detailed result
func ObfuscateSectionNamesDetailed(filePath string) *OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}
	result := elfFile.RandomizeSectionNames()
	if !result.Applied {
		return result
	}

	if err := elfFile.CommitChanges(uint64(len(elfFile.RawData))); err != nil {
		return NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
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

// AddSection adds a new section to an ELF file
func AddSection(filePath, sectionName, sourceFile string) error {
	result := AddSectionDetailed(filePath, sectionName, sourceFile)
	if !result.Applied {
		return fmt.Errorf("%s", result.Message)
	}
	return nil
}

// AddSectionDetailed adds a new section to an ELF file with detailed result
func AddSectionDetailed(filePath, sectionName, sourceFile string) *OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}

	// Check if section with same name already exists
	for _, section := range elfFile.Sections {
		if section.Name == sectionName {
			return NewSkipped(fmt.Sprintf("section '%s' already exists", sectionName))
		}
	}

	// Get source file size for reporting
	info, err := os.Stat(sourceFile)
	if err != nil {
		return NewSkipped(fmt.Sprintf("failed to stat source file: %v", err))
	}

	if err := elfFile.AddSection(sectionName, sourceFile); err != nil {
		return NewSkipped(fmt.Sprintf("failed to add section: %v", err))
	}

	if err := elfFile.CommitChanges(uint64(len(elfFile.RawData))); err != nil {
		return NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	message := fmt.Sprintf("added section '%s' (%d bytes) from '%s'", sectionName, info.Size(), sourceFile)
	return NewApplied(message, 1)
}

// ObfuscateAllDetailed applies all obfuscation techniques to an ELF file with detailed result
func ObfuscateAllDetailed(filePath string) *OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}
	result := elfFile.ObfuscateAll()
	if !result.Applied {
		return result
	}

	if err := elfFile.CommitChanges(uint64(len(elfFile.RawData))); err != nil {
		return NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// ObfuscateBaseAddressesDetailed obfuscates base addresses in an ELF file with detailed result
func ObfuscateBaseAddressesDetailed(filePath string) *OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return NewSkipped(fmt.Sprintf("failed to read ELF file: %v", err))
	}

	// Check if this is a Go binary before obfuscation
	if elfFile.isGoBinary() {
		return NewSkipped("skipping base address randomization for Go binary (would break runtime)")
	}

	result := elfFile.ObfuscateBaseAddresses()
	if !result.Applied {
		return result
	}

	if err := elfFile.CommitChanges(uint64(len(elfFile.RawData))); err != nil {
		return NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
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
