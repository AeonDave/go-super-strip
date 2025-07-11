package perw

import (
	"fmt"
	"gosstrip/common"
	"os"
)

func readPe(filePath string, flags int) (*PEFile, error) {
	file, err := common.OpenFile(filePath, flags)
	if err != nil {
		return nil, err
	}
	return ReadPE(file)
}

func processPE(filePath string, flags int, operation func(*PEFile) *common.OperationResult) *common.OperationResult {
	peFile, err := readPe(filePath, flags)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("Failed to read PE file: %v", err))
	}
	defer func(peFile *PEFile) {
		_ = peFile.Close()
	}(peFile)

	result := operation(peFile)
	if result.Applied && peFile.Save(true, int64(len(peFile.RawData))) != nil {
		return common.NewSkipped("Operation succeeded but failed to save file")
	}

	return result
}

func AnalyzePE(filePath string) error {
	peFile, err := readPe(filePath, os.O_RDONLY)
	if err != nil {
		return err
	}
	return peFile.Analyze()
}

func StripPE(filePath string, force bool) *common.OperationResult {
	return processPE(filePath, os.O_RDWR, func(peFile *PEFile) *common.OperationResult {
		return peFile.StripAll(force)
	})
}

func CompactPE(filePath string, force bool) *common.OperationResult {
	return processPE(filePath, os.O_RDWR, func(peFile *PEFile) *common.OperationResult {
		return peFile.Compact(force)
	})
}

func RegexPE(filePath string, regex string) *common.OperationResult {
	return processPE(filePath, os.O_RDWR, func(peFile *PEFile) *common.OperationResult {
		return peFile.StripSingleRegexRule(regex)
	})
}

func ObfuscatePE(filePath string, force bool) *common.OperationResult {
	return processPE(filePath, os.O_RDWR, func(peFile *PEFile) *common.OperationResult {
		return peFile.ObfuscateAll(force)
	})
}

func InsertPE(filePath, sectionName, dataOrFile, password string) *common.OperationResult {
	return processPE(filePath, os.O_RDWR, func(peFile *PEFile) *common.OperationResult {
		return peFile.AddSection(sectionName, dataOrFile, password)
	})
}

func OverlayPE(filePath, dataOrFile, password string) *common.OperationResult {
	return processPE(filePath, os.O_RDWR, func(peFile *PEFile) *common.OperationResult {
		return peFile.AddOverlay(dataOrFile, password)
	})
}
