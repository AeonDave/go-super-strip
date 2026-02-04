package elfrw

import (
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

// AnalyzeELF loads an ELF binary and produces an analysis report based on the selected mode.
func AnalyzeELF(file string, opts common.AnalysisOptions) (*common.AnalysisResult, error) {
	elfFile, err := readElf(file, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = elfFile.Close()
	}()

	elfFile.calculateSectionEntropy()
	elfFile.IsPacked = elfFile.detectPacking()
	switch opts.Mode {
	case common.AnalysisModeDeep:
		return elfFile.buildDeepReport(), nil
	default:
		return elfFile.buildSimpleReport(), nil
	}
}

// StripELF removes note/symbol metadata and other targeted sections.
func StripELF(filePath string, force bool, fillOverride *bool) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "ELF", readElf, func(elfFile *ELFFile) error {
		return elfFile.Save(true, int64(len(elfFile.RawData)))
	}, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.StripAll(force, fillOverride)
	})
}

// CompactELF trims unused regions and rebuilds the section header table when needed.
func CompactELF(filePath string, force bool, _ bool) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "ELF", readElf, func(elfFile *ELFFile) error {
		return elfFile.Save(true, int64(len(elfFile.RawData)))
	}, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.Compact(force)
	})
}

// RegexELF applies regex removals across ELF sections and segments.
func RegexELF(filePath string, fillOverride *bool, patterns []string, force bool) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "ELF", readElf, func(elfFile *ELFFile) error {
		return elfFile.Save(true, int64(len(elfFile.RawData)))
	}, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.ApplyRegexPatterns(patterns, fillOverride, force)
	})
}

// ObfuscateELF renames sections/symbols and randomizes metadata to hinder static analysis.
// When preserveLoadOrder is true, PT_LOAD entries keep their original ordering/alignment
// to remain compatible with post-processing packers like UPX.
func ObfuscateELF(filePath string, force bool, preserveLoadOrder bool) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "ELF", readElf, func(elfFile *ELFFile) error {
		return elfFile.Save(true, int64(len(elfFile.RawData)))
	}, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.ObfuscateAll(force, preserveLoadOrder)
	})
}

// InsertELF appends a new ELF section containing either inline data or file contents.
func InsertELF(filePath, sectionName, dataOrFile, password string) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "ELF", readElf, func(elfFile *ELFFile) error {
		return elfFile.Save(true, int64(len(elfFile.RawData)))
	}, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.AddSection(sectionName, dataOrFile, password)
	})
}

// OverlayELF writes payload bytes after the structured ELF image, optionally encrypting them.
func OverlayELF(filePath, dataOrFile, password string) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "ELF", readElf, func(elfFile *ELFFile) error {
		return elfFile.Save(true, int64(len(elfFile.RawData)))
	}, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.AddOverlay(dataOrFile, password)
	})
}

// ExtractOverlay returns the trailing overlay data from an ELF binary.
func ExtractOverlay(filePath string) ([]byte, error) {
	elfFile, err := readElf(filePath, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { _ = elfFile.Close() }()
	return elfFile.ExtractOverlay()
}
