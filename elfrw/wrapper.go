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

func StripELF(filePath string, force bool, fillOverride *bool) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "ELF", readElf, func(elfFile *ELFFile) error {
		return elfFile.Save(true, int64(len(elfFile.RawData)))
	}, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.StripAll(force, fillOverride)
	})
}

func CompactELF(filePath string, force bool, _ bool) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "ELF", readElf, func(elfFile *ELFFile) error {
		return elfFile.Save(true, int64(len(elfFile.RawData)))
	}, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.Compact(force)
	})
}

func RegexELF(filePath string, fillOverride *bool, patterns []string) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "ELF", readElf, func(elfFile *ELFFile) error {
		return elfFile.Save(true, int64(len(elfFile.RawData)))
	}, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.ApplyRegexPatterns(patterns, fillOverride)
	})
}

func ObfuscateELF(filePath string, force bool) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "ELF", readElf, func(elfFile *ELFFile) error {
		return elfFile.Save(true, int64(len(elfFile.RawData)))
	}, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.ObfuscateAll(force)
	})
}

func InsertELF(filePath, sectionName, dataOrFile, password string) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "ELF", readElf, func(elfFile *ELFFile) error {
		return elfFile.Save(true, int64(len(elfFile.RawData)))
	}, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.AddSection(sectionName, dataOrFile, password)
	})
}

func OverlayELF(filePath, dataOrFile, password string) *common.OperationResult {
	return common.ProcessBinary(filePath, os.O_RDWR, "ELF", readElf, func(elfFile *ELFFile) error {
		return elfFile.Save(true, int64(len(elfFile.RawData)))
	}, func(elfFile *ELFFile) *common.OperationResult {
		return elfFile.AddOverlay(dataOrFile, password)
	})
}

func ExtractOverlay(filePath string) ([]byte, error) {
	elfFile, err := readElf(filePath, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { _ = elfFile.Close() }()
	return elfFile.ExtractOverlay()
}
