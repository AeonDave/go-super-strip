package perw

import (
	"fmt"
	"gosstrip/common"
	"os"
	"regexp"
)

// Wrapper functions provide the main API for PE file operations
// These functions handle file opening, operation execution, and file closing

// AnalyzePE analyzes a PE file and prints information about it
func AnalyzePE(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return err
	}

	return peFile.Analyze()
}

// ObfuscateBaseAddressesDetailed obfuscates base addresses in a PE file with detailed result
func ObfuscateBaseAddressesDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read PE file: %v", err))
	}

	result := peFile.ObfuscateBaseAddresses()
	if !result.Applied {
		return result
	}

	if err := peFile.CommitChangesSimple(-1); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// StripRegexBytes strips bytes matching a regex pattern from a PE file
func StripRegexBytes(filePath string, regex *regexp.Regexp) error {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return err
	}

	if _, err := peFile.StripBytePattern(regex, RandomFill); err != nil {
		return err
	}

	return peFile.CommitChangesSimple(-1)
}

// AddHexSection adds a hex section to a PE file (with optional encryption)
func AddHexSection(filePath, sectionName, sourceFile, password string) error {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return err
	}

	if err := peFile.AddHexSection(sectionName, sourceFile, password); err != nil {
		return err
	}

	return peFile.CommitChanges(-1)
}

// --- New detailed wrapper functions that return OperationResult ---

// StripDebugSectionsDetailed strips debug sections and returns detailed results
func StripDebugSectionsDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read PE: %v", err))
	}

	result := peFile.StripDebugSections(false)
	if !result.Applied {
		return result
	}

	if err := peFile.CommitChangesSimple(-1); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// StripSymbolSectionsDetailed strips symbol sections and returns detailed results
func StripSymbolSectionsDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read PE: %v", err))
	}

	result := peFile.StripSymbolTables(false)
	if !result.Applied {
		return result
	}

	if err := peFile.CommitChangesSimple(-1); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// ObfuscateSectionNamesDetailed obfuscates section names and returns detailed results
func ObfuscateSectionNamesDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read PE: %v", err))
	}

	result := peFile.RandomizeSectionNames()
	if !result.Applied {
		return result
	}

	if err := peFile.CommitChangesSimple(-1); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// ObfuscateLoadConfigurationDetailed obfuscates load configuration with detailed result
func ObfuscateLoadConfigurationDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read PE file: %v", err))
	}

	result := peFile.ObfuscateLoadConfig()
	if !result.Applied {
		return result
	}

	if err := peFile.CommitChangesSimple(-1); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// ObfuscateImportTableDetailed obfuscates import table with detailed result
func ObfuscateImportTableDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read PE file: %v", err))
	}

	result := peFile.ObfuscateImportTable()
	if !result.Applied {
		return result
	}

	if err := peFile.CommitChangesSimple(-1); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// ObfuscateImportNamesDetailed obfuscates import names with detailed result
func ObfuscateImportNamesDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read PE file: %v", err))
	}

	result := peFile.ObfuscateImportNames()
	if !result.Applied {
		return result
	}

	if err := peFile.CommitChangesSimple(-1); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// ObfuscateRichHeaderDetailed obfuscates Rich header with detailed result
func ObfuscateRichHeaderDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read PE file: %v", err))
	}

	result := peFile.ObfuscateRichHeader()
	if !result.Applied {
		return result
	}

	if err := peFile.CommitChangesSimple(-1); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// ObfuscateResourceDirectoryDetailed obfuscates resource directory with detailed result
func ObfuscateResourceDirectoryDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read PE file: %v", err))
	}

	result := peFile.ObfuscateResourceDirectory()
	if !result.Applied {
		return result
	}

	if err := peFile.CommitChangesSimple(-1); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}

// ObfuscateExportTableDetailed obfuscates export table with detailed result
func ObfuscateExportTableDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to open file: %v", err))
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read PE file: %v", err))
	}

	result := peFile.ObfuscateExportTable()
	if !result.Applied {
		return result
	}

	if err := peFile.CommitChangesSimple(-1); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to save changes: %v", err))
	}

	return result
}
