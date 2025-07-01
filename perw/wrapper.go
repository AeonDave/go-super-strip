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
		return common.NewSkipped("Failed to open file: " + err.Error())
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return common.NewSkipped("Failed to read PE file: " + err.Error())
	}

	result := peFile.StripAll(force)
	if result.Applied && peFile.Save(true, 0) != nil {
		return common.NewSkipped("Stripping succeeded but failed to save file")
	}

	return result
}

func CompactPE(filePath string, force bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped("Failed to open file: " + err.Error())
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return common.NewSkipped("Failed to read PE file: " + err.Error())
	}

	result, _ := peFile.Compact(force)
	if result.Applied && peFile.Save(true, int64(len(peFile.RawData))) != nil {
		return common.NewSkipped("Compaction succeeded but failed to save file")
	}

	return result
}

func RegexPE(filePath string, regex string) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped("Failed to open file: " + err.Error())
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return common.NewSkipped("Failed to read PE file: " + err.Error())
	}

	result := peFile.StripSingleRegexRule(regex)

	if result.Applied && peFile.Save(true, 0) != nil {
		return common.NewSkipped("Regex stripping succeeded but failed to save file")
	}

	return result
}

func ObfuscatePE(filePath string, force bool) *common.OperationResult {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0755)
	if err != nil {
		return common.NewSkipped("Failed to open file: " + err.Error())
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	peFile, err := ReadPE(file)
	if err != nil {
		return common.NewSkipped("Failed to read PE file: " + err.Error())
	}

	result := peFile.ObfuscateAll(force)
	if result.Applied && peFile.Save(true, 0) != nil {
		return common.NewSkipped("Obfuscation succeeded but failed to save file")
	}

	return result
}

func InsertPE(filePath, sectionName, dataOrFile, password string) *common.OperationResult {
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
	insertErr := peFile.AddHexSection(sectionName, dataOrFile, password)
	if insertErr != nil {
		return common.NewSkipped(fmt.Sprintf("failed to insert section: %v", insertErr))
	}
	if !peFile.usedFallbackMode {
		if err := peFile.Save(true, int64(len(peFile.RawData))); err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to write changes: %v", err))
		}
	}
	message := fmt.Sprintf("added hex section '%s'", sectionName)
	if password != "" {
		message += " (encrypted)"
	}
	return common.NewApplied(message, 1)
}
