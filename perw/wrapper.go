package perw

import (
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

func AnalyzePE(filePath string, opts common.AnalysisOptions) (*common.AnalysisResult, error) {
	peFile, err := readPe(filePath, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = peFile.Close()
	}()
	peFile.calculateSectionEntropy()
	peFile.IsPacked = peFile.detectPacking()
	switch opts.Mode {
	case common.AnalysisModeDeep:
		return peFile.buildDeepReport(), nil
	default:
		return peFile.buildSimpleReport(), nil
	}
}

func StripPE(filePath string, force bool, fillOverride *bool) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "PE", readPe, func(peFile *PEFile) error {
		return peFile.Save(true, int64(len(peFile.RawData)))
	}, func(peFile *PEFile) *common.OperationResult {
		return peFile.StripAll(force, fillOverride)
	})
}

func CompactPE(filePath string, force bool, keepResources bool) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "PE", readPe, func(peFile *PEFile) error {
		return peFile.Save(true, int64(len(peFile.RawData)))
	}, func(peFile *PEFile) *common.OperationResult {
		return peFile.Compact(force, keepResources)
	})
}

func RegexPE(filePath string, fillOverride *bool, patterns []string) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "PE", readPe, func(peFile *PEFile) error {
		return peFile.Save(true, int64(len(peFile.RawData)))
	}, func(peFile *PEFile) *common.OperationResult {
		return peFile.ApplyRegexPatterns(patterns, fillOverride)
	})
}

func ObfuscatePE(filePath string, force bool) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "PE", readPe, func(peFile *PEFile) error {
		return peFile.Save(true, int64(len(peFile.RawData)))
	}, func(peFile *PEFile) *common.OperationResult {
		return peFile.ObfuscateAll(force)
	})
}

func InsertPE(filePath, sectionName, dataOrFile, password string) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "PE", readPe, func(peFile *PEFile) error {
		return peFile.Save(true, int64(len(peFile.RawData)))
	}, func(peFile *PEFile) *common.OperationResult {
		return peFile.AddSection(sectionName, dataOrFile, password)
	})
}

func OverlayPE(filePath, dataOrFile, password string) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "PE", readPe, func(peFile *PEFile) error {
		return peFile.Save(true, int64(len(peFile.RawData)))
	}, func(peFile *PEFile) *common.OperationResult {
		return peFile.AddOverlay(dataOrFile, password)
	})
}

func ExtractOverlay(filePath string) ([]byte, error) {
	peFile, err := readPe(filePath, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { _ = peFile.Close() }()
	return peFile.ExtractOverlay()
}
