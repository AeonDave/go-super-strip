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

// AnalyzePE loads a PE file and generates an analysis report using the provided options.
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

// StripPE removes PE metadata (debug info, Rich header, etc.) according to the provided settings.
func StripPE(filePath string, force bool, fillOverride *bool) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "PE", readPe, func(peFile *PEFile) error {
		return peFile.Save(true, int64(len(peFile.RawData)))
	}, func(peFile *PEFile) *common.OperationResult {
		return peFile.StripAll(force, fillOverride)
	})
}

// CompactPE trims unused sections and recalculates PE headers.
func CompactPE(filePath string, force bool, keepResources bool) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "PE", readPe, func(peFile *PEFile) error {
		return peFile.Save(true, int64(len(peFile.RawData)))
	}, func(peFile *PEFile) *common.OperationResult {
		return peFile.Compact(force, keepResources)
	})
}

// RegexPE applies byte-pattern removals across the PE image.
func RegexPE(filePath string, fillOverride *bool, patterns []string) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "PE", readPe, func(peFile *PEFile) error {
		return peFile.Save(true, int64(len(peFile.RawData)))
	}, func(peFile *PEFile) *common.OperationResult {
		return peFile.ApplyRegexPatterns(patterns, fillOverride)
	})
}

// ObfuscatePE renames sections, mutates headers, and shuffles metadata.
func ObfuscatePE(filePath string, force bool) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "PE", readPe, func(peFile *PEFile) error {
		return peFile.Save(true, int64(len(peFile.RawData)))
	}, func(peFile *PEFile) *common.OperationResult {
		return peFile.ObfuscateAll(force)
	})
}

// InsertPE appends a new section with the given payload (string or file), optionally encrypting it.
func InsertPE(filePath, sectionName, dataOrFile, password string) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "PE", readPe, func(peFile *PEFile) error {
		return peFile.Save(true, int64(len(peFile.RawData)))
	}, func(peFile *PEFile) *common.OperationResult {
		return peFile.AddSection(sectionName, dataOrFile, password)
	})
}

// OverlayPE writes payload bytes beyond the structured portion of the PE file.
func OverlayPE(filePath, dataOrFile, password string) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "PE", readPe, func(peFile *PEFile) error {
		return peFile.Save(true, int64(len(peFile.RawData)))
	}, func(peFile *PEFile) *common.OperationResult {
		return peFile.AddOverlay(dataOrFile, password)
	})
}

// ExtractOverlay returns the raw overlay bytes from a PE file.
func ExtractOverlay(filePath string) ([]byte, error) {
	peFile, err := readPe(filePath, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { _ = peFile.Close() }()
	return peFile.ExtractOverlay()
}
