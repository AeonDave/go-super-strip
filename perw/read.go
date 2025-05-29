package perw

import (
	"bytes"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"strings"
)

type Section struct {
	Name   string
	Offset int64
	Size   int64
	Index  int
	Flags  uint32
	RVA    uint32
}

type PEFile struct {
	File     *os.File
	PE       *pe.File
	Is64Bit  bool
	FileName string
	Sections []Section
	RawData  []byte
}

func ReadPE(file *os.File) (*PEFile, error) {
	rawData, err := readFileData(file)
	if err != nil {
		return nil, err
	}

	if len(rawData) < 2 || rawData[0] != 'M' || rawData[1] != 'Z' {
		return nil, fmt.Errorf("invalid file: missing DOS signature")
	}

	peLibFile, err := pe.NewFile(bytes.NewReader(rawData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse PE file: %w", err)
	}

	pf := &PEFile{
		File:     file,
		PE:       peLibFile,
		FileName: file.Name(),
		RawData:  rawData,
		Is64Bit:  isPE64Bit(peLibFile),
		Sections: parseSections(peLibFile),
	}

	return pf, nil
}

func (p *PEFile) IsExecutableOrShared() bool {
	if p.PE == nil {
		return false
	}
	c := p.PE.FileHeader.Characteristics
	return (c&pe.IMAGE_FILE_EXECUTABLE_IMAGE) != 0 || (c&pe.IMAGE_FILE_DLL) != 0
}

func (p *PEFile) CalculatePhysicalFileSize() (uint64, error) {
	if p.PE == nil || p.PE.OptionalHeader == nil {
		return 0, fmt.Errorf("missing OptionalHeader")
	}

	sizeOfHeaders := getSizeOfHeaders(p.PE.OptionalHeader)
	maxSize := uint64(sizeOfHeaders)

	for _, s := range p.Sections {
		if s.Size > 0 {
			end := uint64(s.Offset) + uint64(s.Size)
			if end > maxSize {
				maxSize = end
			}
		}
	}

	return maxSize, nil
}

func (p *PEFile) TruncateZeros(size uint64) (uint64, error) {
	if size > uint64(len(p.RawData)) {
		size = uint64(len(p.RawData))
	}

	for size > 0 && p.RawData[size-1] == 0 {
		size--
	}
	return size, nil
}

func (p *PEFile) GetImports() ([]string, error) {
	if p.PE == nil {
		return nil, fmt.Errorf("PE file not initialized")
	}
	return p.PE.ImportedSymbols()
}

func (p *PEFile) GetImportedLibraries() ([]string, error) {
	imports, err := p.GetImports()
	if err != nil {
		return nil, err
	}

	libSet := make(map[string]struct{})
	for _, imp := range imports {
		if parts := strings.SplitN(imp, ":", 2); len(parts) > 0 {
			libSet[strings.ToLower(parts[0])] = struct{}{}
		}
	}

	return mapKeysToSlice(libSet), nil
}

func (p *PEFile) Close() error {
	if p.PE != nil {
		return p.PE.Close()
	}
	return nil
}

func readFileData(file *os.File) ([]byte, error) {
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	rawData := make([]byte, fileInfo.Size())
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to reset file pointer: %w", err)
	}
	if _, err := io.ReadFull(file, rawData); err != nil {
		return nil, fmt.Errorf("failed to read file data: %w", err)
	}

	return rawData, nil
}

func isPE64Bit(peFile *pe.File) bool {
	_, is64 := peFile.OptionalHeader.(*pe.OptionalHeader64)
	return is64
}

func parseSections(peFile *pe.File) []Section {
	sections := make([]Section, 0, len(peFile.Sections))
	for i, s := range peFile.Sections {
		sections = append(sections, Section{
			Name:   strings.TrimRight(s.Name, "\x00"),
			Offset: int64(s.Offset),
			Size:   int64(s.Size),
			Index:  i,
			Flags:  s.Characteristics,
			RVA:    s.VirtualAddress,
		})
	}
	return sections
}

func getSizeOfHeaders(header interface{}) uint32 {
	switch oh := header.(type) {
	case *pe.OptionalHeader32:
		return oh.SizeOfHeaders
	case *pe.OptionalHeader64:
		return oh.SizeOfHeaders
	default:
		return 0
	}
}

func mapKeysToSlice(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
