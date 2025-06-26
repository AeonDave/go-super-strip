package perw

import (
	"gosstrip/common"
	"os"
)

// Global wrapper functions for PE file manipulation

// AnalyzePE performs comprehensive analysis of a PE file
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

	return peFile.Analyze() // Use the comprehensive analysis function
}

// StripPEDetailed performs comprehensive PE stripping (no compaction)
func StripPEDetailed(filePath string, force bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to open file: " + err.Error(),
		}
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to read PE file: " + err.Error(),
		}
	}

	result := peFile.AdvancedStripPEDetailed(force)

	// Save the modified file
	if result.Applied {
		if err := peFile.Save(true, 0); err != nil {
			return &common.OperationResult{
				Applied: false,
				Message: "Stripping succeeded but failed to save file: " + err.Error(),
			}
		}
	}

	return result
}

// CompactPEDetailed performs PE file compaction (no stripping)
func CompactPEDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to open file: " + err.Error(),
		}
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to read PE file: " + err.Error(),
		}
	}

	result, _ := peFile.CompactPE()

	// Save the modified file
	if result.Applied {
		if err := peFile.Save(true, 0); err != nil {
			return &common.OperationResult{
				Applied: false,
				Message: "Compaction succeeded but failed to save file: " + err.Error(),
			}
		}
	}

	return result
}

// StripPEDetailedWithObfuscation performs PE stripping considering obfuscation needs
func StripPEDetailedWithObfuscation(filePath string, force bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to open file: " + err.Error(),
		}
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to read PE file: " + err.Error(),
		}
	}

	// For now, use the same function but could be extended for obfuscation-aware stripping
	result := peFile.AdvancedStripPEDetailed(force)

	// Save the modified file
	if result.Applied {
		if err := peFile.Save(true, 0); err != nil {
			return &common.OperationResult{
				Applied: false,
				Message: "Stripping succeeded but failed to save file: " + err.Error(),
			}
		}
	}

	return result
}

// ObfuscateSectionNamesDetailed obfuscates section names in PE file
func ObfuscateSectionNamesDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to open file: " + err.Error(),
		}
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to read PE file: " + err.Error(),
		}
	}

	result := peFile.RandomizeSectionNames()

	// Save the modified file
	if result.Applied {
		if err := peFile.Save(true, 0); err != nil {
			return &common.OperationResult{
				Applied: false,
				Message: "Obfuscation succeeded but failed to save file: " + err.Error(),
			}
		}
	}

	return result
}

// ObfuscateBaseAddressesDetailed obfuscates base addresses in PE file
func ObfuscateBaseAddressesDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to open file: " + err.Error(),
		}
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to read PE file: " + err.Error(),
		}
	}

	result := peFile.ObfuscateBaseAddresses()

	// Save the modified file
	if result.Applied {
		if err := peFile.Save(true, 0); err != nil {
			return &common.OperationResult{
				Applied: false,
				Message: "Obfuscation succeeded but failed to save file: " + err.Error(),
			}
		}
	}

	return result
}

// ObfuscateLoadConfigurationDetailed obfuscates load configuration in PE file
func ObfuscateLoadConfigurationDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to open file: " + err.Error(),
		}
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to read PE file: " + err.Error(),
		}
	}

	result := peFile.ObfuscateLoadConfig()

	// Save the modified file
	if result.Applied {
		if err := peFile.Save(true, 0); err != nil {
			return &common.OperationResult{
				Applied: false,
				Message: "Obfuscation succeeded but failed to save file: " + err.Error(),
			}
		}
	}

	return result
}

// ObfuscateImportTableDetailed obfuscates import table in PE file
func ObfuscateImportTableDetailed(filePath string, force bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to open file: " + err.Error(),
		}
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to read PE file: " + err.Error(),
		}
	}

	result := peFile.ObfuscateImportTable(force)

	// Save the modified file
	if result.Applied {
		if err := peFile.Save(true, 0); err != nil {
			return &common.OperationResult{
				Applied: false,
				Message: "Obfuscation succeeded but failed to save file: " + err.Error(),
			}
		}
	}

	return result
}

// ObfuscateImportNamesDetailed obfuscates import names in PE file
func ObfuscateImportNamesDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to open file: " + err.Error(),
		}
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to read PE file: " + err.Error(),
		}
	}

	result := peFile.ObfuscateImportNames()

	// Save the modified file
	if result.Applied {
		if err := peFile.Save(true, 0); err != nil {
			return &common.OperationResult{
				Applied: false,
				Message: "Obfuscation succeeded but failed to save file: " + err.Error(),
			}
		}
	}

	return result
}

// ObfuscateResourceDirectoryDetailed obfuscates resource directory in PE file
func ObfuscateResourceDirectoryDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to open file: " + err.Error(),
		}
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to read PE file: " + err.Error(),
		}
	}

	result := peFile.ObfuscateResourceDirectory()

	// Save the modified file
	if result.Applied {
		if err := peFile.Save(true, 0); err != nil {
			return &common.OperationResult{
				Applied: false,
				Message: "Obfuscation succeeded but failed to save file: " + err.Error(),
			}
		}
	}

	return result
}

// ObfuscateExportTableDetailed obfuscates export table in PE file
func ObfuscateExportTableDetailed(filePath string, force bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to open file: " + err.Error(),
		}
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to read PE file: " + err.Error(),
		}
	}

	result := peFile.ObfuscateExportTable(force)

	// Save the modified file
	if result.Applied {
		if err := peFile.Save(true, 0); err != nil {
			return &common.OperationResult{
				Applied: false,
				Message: "Obfuscation succeeded but failed to save file: " + err.Error(),
			}
		}
	}

	return result
}

// ObfuscateRuntimeStringsDetailed obfuscates runtime strings in PE file
func ObfuscateRuntimeStringsDetailed(filePath string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to open file: " + err.Error(),
		}
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to read PE file: " + err.Error(),
		}
	}

	result := peFile.ObfuscateRuntimeStrings()

	// Save the modified file
	if result.Applied {
		if err := peFile.Save(true, 0); err != nil {
			return &common.OperationResult{
				Applied: false,
				Message: "Obfuscation succeeded but failed to save file: " + err.Error(),
			}
		}
	}

	return result
}

// StripPostObfuscationSections removes sections that were preserved for obfuscation
func StripPostObfuscationSections() *common.OperationResult {
	// Placeholder implementation - return not applied for now
	return &common.OperationResult{
		Applied: false,
		Message: "Post-obfuscation section stripping not implemented yet",
	}
}

// ApplyRiskyOperationsDetailed applies risky operations to PE file
func ApplyRiskyOperationsDetailed() *common.OperationResult {
	// Placeholder implementation - return not applied for now
	return &common.OperationResult{
		Applied: false,
		Message: "Risky operations not implemented yet",
	}
}

// StripAllRegexRulesDetailed applica tutte le regole regex centralizzate e salva il file
func StripAllRegexRulesDetailed(filePath string, force bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to open file: " + err.Error(),
		}
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return &common.OperationResult{
			Applied: false,
			Message: "Failed to read PE file: " + err.Error(),
		}
	}

	result := peFile.StripAllRegexRules(force)

	if result.Applied {
		if err := peFile.Save(true, 0); err != nil {
			return &common.OperationResult{
				Applied: false,
				Message: "Regex stripping succeeded but failed to save file: " + err.Error(),
			}
		}
	}

	return result
}

// AddHexSection adds a hexadecimal section to PE file
func AddHexSection(filePath string, sectionName string, sourceFile string, password string) error {
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

	return peFile.AddHexSection(sectionName, sourceFile, password)
}

// StripAllMetadata strips all types of metadata from a PE file
func StripAllMetadata(filePath string, useRandomFill bool, force bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return &common.OperationResult{
			Message: "Failed to open file: " + err.Error(),
			Applied: false,
		}
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return &common.OperationResult{
			Message: "Failed to read PE file: " + err.Error(),
			Applied: false,
		}
	}

	if err := peFile.StripAllMetadata(useRandomFill, force); err != nil {
		return &common.OperationResult{
			Message: "Failed to strip all metadata: " + err.Error(),
			Applied: false,
		}
	}

	if err := peFile.Save(true, 0); err != nil {
		return &common.OperationResult{
			Message: "Failed to save file: " + err.Error(),
			Applied: false,
		}
	}

	return &common.OperationResult{
		Message: "Successfully stripped all metadata",
		Applied: true,
	}
}
