package elfrw

import (
	"fmt"
	"gosstrip/common"
	"os"
)

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

func StripELF(filePath string, force bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped("Failed to open file: " + err.Error())
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return common.NewSkipped("Failed to read ELF file: " + err.Error())
	}

	result := elfFile.StripAll(force)
	if result.Applied && elfFile.Save(true, int64(len(elfFile.RawData))) != nil {
		return common.NewSkipped("Stripping succeeded but failed to save file")
	}

	return result
}

func CompactELF(filePath string, force bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped("Failed to open file: " + err.Error())
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return common.NewSkipped("Failed to read ELF file: " + err.Error())
	}

	result := elfFile.Compact(force)
	if result.Applied && elfFile.Save(true, int64(len(elfFile.RawData))) != nil {
		return common.NewSkipped("Compaction succeeded but failed to save file")
	}

	return result
}

func RegexELF(filePath string, regex string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped("Failed to open file: " + err.Error())
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return common.NewSkipped("Failed to read ELF file: " + err.Error())
	}

	result := elfFile.StripSingleRegexRule(regex)

	if result.Applied && elfFile.Save(true, int64(len(elfFile.RawData))) != nil {
		return common.NewSkipped("Regex stripping succeeded but failed to save file")
	}

	return result
}

func ObfuscateELF(filePath string, force bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped("Failed to open file: " + err.Error())
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	elfFile, err := ReadELF(file)
	if err != nil {
		return common.NewSkipped("Failed to read ELF file: " + err.Error())
	}

	result := elfFile.ObfuscateAll(force)
	if result.Applied && elfFile.Save(true, int64(len(elfFile.RawData))) != nil {
		return common.NewSkipped("Obfuscation succeeded but failed to save file")
	}

	return result
}

func InsertELF(filePath, sectionName, dataOrFile, password string) *common.OperationResult {
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

	insertErr := elfFile.AddHexSection(sectionName, dataOrFile, password)
	if insertErr != nil {
		return common.NewSkipped(fmt.Sprintf("failed to insert section: %v", insertErr))
	}

	if err := elfFile.Save(true, int64(len(elfFile.RawData))); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to write changes: %v", err))
	}

	message := fmt.Sprintf("added hex section '%s'", sectionName)
	if password != "" {
		message += " (encrypted)"
	}
	return common.NewApplied(message, 1)
}

func OverlayELF(filePath, dataOrFile, password string) *common.OperationResult {
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

	overlayErr := elfFile.AddOverlay(dataOrFile, password)
	if overlayErr != nil {
		return common.NewSkipped(fmt.Sprintf("failed to add overlay: %v", overlayErr))
	}

	message := "added overlay data"
	if password != "" {
		message += " (encrypted)"
	}
	return common.NewApplied(message, 1)
}
