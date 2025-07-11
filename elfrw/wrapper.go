package elfrw

import (
	"fmt"
	"gosstrip/common"
	"os"
)

func readElf(filePath string, flags int) (*ELFFile, error) {
	file, err := common.OpenFile(filePath, flags)
	if err != nil {
		return nil, err
	}
	return ReadELF(file)
}

func processELF(file string, flags int, operation func(*ELFFile) *common.OperationResult) *common.OperationResult {
	elfFile, err := readElf(file, flags)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("Failed to read ELF file: %v", err))
	}
	defer func(elfFile *ELFFile) {
		_ = elfFile.Close()
	}(elfFile)

	result := operation(elfFile)
	if result.Applied && elfFile.Save(true, int64(len(elfFile.RawData))) != nil {
		return common.NewSkipped("Operation succeeded but failed to save file")
	}

	return result
}

func AnalyzeELF(file string) error {
	elfFile, err := readElf(file, os.O_RDONLY)
	if err != nil {
		return err
	}

	return elfFile.Analyze()
}

func StripELF(filePath string, force bool) *common.OperationResult {
	return processELF(filePath, os.O_RDWR, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.StripAll(force)
	})
}

func CompactELF(filePath string, force bool) *common.OperationResult {
	return processELF(filePath, os.O_RDWR, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.Compact(force)
	})
}

func RegexELF(filePath string, regex string) *common.OperationResult {
	return processELF(filePath, os.O_RDWR, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.StripSingleRegexRule(regex)
	})
}

func ObfuscateELF(filePath string, force bool) *common.OperationResult {
	return processELF(filePath, os.O_RDWR, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.ObfuscateAll(force)
	})
}

func InsertELF(filePath, sectionName, dataOrFile, password string) *common.OperationResult {
	return processELF(filePath, os.O_RDWR, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.AddSection(sectionName, dataOrFile, password)
	})
}

func OverlayELF(filePath, dataOrFile, password string) *common.OperationResult {
	return processELF(filePath, os.O_RDWR, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.AddOverlay(dataOrFile, password)
	})
}
