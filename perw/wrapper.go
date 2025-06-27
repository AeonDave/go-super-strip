package perw

import (
	"fmt"
	"gosstrip/common"
	"os"
)

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

func StripPE(filePath string, force bool) *common.OperationResult {
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

func CompactPE(filePath string) *common.OperationResult {
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

func ObfuscateSectionNames(filePath string) *common.OperationResult {
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

func ObfuscateBaseAddresses(filePath string) *common.OperationResult {
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

func ObfuscateRuntimeStrings(filePath string) *common.OperationResult {
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

func StripAllRegexRules(filePath string, force bool) *common.OperationResult {
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

func AddHexSection(filePath, sectionName, sourceFile, password string) *common.OperationResult {
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

	if err := peFile.AddHexSection(sectionName, sourceFile, password); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to add hex section: %v", err))
	}

	// For fallback mode (corrupted files), data was already written directly to file
	// Skip Save() to avoid any potential corruption
	if !peFile.usedFallbackMode {
		updateHeaders := true
		if err := peFile.Save(updateHeaders, int64(len(peFile.RawData))); err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to write changes: %v", err))
		}
	}

	message := fmt.Sprintf("added hex section '%s'", sectionName)
	if password != "" {
		message += " (encrypted)"
	}
	return common.NewApplied(message, 1)
}

func AddHexSectionFromString(filePath, sectionName, data, password string) *common.OperationResult {
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

	if err := peFile.AddHexSectionFromString(sectionName, data, password); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to add hex section from string: %v", err))
	}

	// For fallback mode (corrupted files), data was already written directly to file
	// Skip Save() to avoid any potential corruption
	if !peFile.usedFallbackMode {
		updateHeaders := true
		if err := peFile.Save(updateHeaders, int64(len(peFile.RawData))); err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to write changes: %v", err))
		}
	}

	message := fmt.Sprintf("added hex section '%s' from string data", sectionName)
	if password != "" {
		message += " (encrypted)"
	}
	return common.NewApplied(message, 1)
}
