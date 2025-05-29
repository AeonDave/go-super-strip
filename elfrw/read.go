package elfrw

import (
	"fmt"
	"github.com/yalue/elf_reader"
	"io"
	"os"
)

type Section struct {
	Name   string
	Offset uint64
	Size   uint64
	Type   uint32
	Flags  uint64
	Index  uint16
}

type Segment struct {
	Offset   uint64
	Size     uint64
	Type     uint32
	Flags    uint32
	Loadable bool
	Index    uint16
}

type ELFFile struct {
	File     *os.File
	RawData  []byte
	ELF      elf_reader.ELFFile
	Is64Bit  bool
	FileName string
	Sections []Section
	Segments []Segment
}

func ReadELF(file *os.File) (*ELFFile, error) {
	rawData, err := readFileData(file)
	if err != nil {
		return nil, err
	}

	is64Bit := len(rawData) > 4 && rawData[4] == 2
	elfFile, err := elf_reader.ParseELFFile(rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ELF file: %w", err)
	}

	ef := &ELFFile{
		File:     file,
		RawData:  rawData,
		ELF:      elfFile,
		Is64Bit:  is64Bit,
		FileName: file.Name(),
	}

	ef.Sections = parseSections(ef)
	ef.Segments = parseSegments(ef)

	return ef, nil
}

func (e *ELFFile) IsExecutableOrShared() bool {
	fileType := e.ELF.GetFileType()
	return fileType == elf_reader.ELFFileType(2) || fileType == elf_reader.ELFFileType(3)
}

func (e *ELFFile) CalculateMemorySize() (uint64, error) {
	var size uint64
	headerSize := map[bool]uint64{true: 64, false: 52}[e.Is64Bit]
	size = headerSize

	for i := uint16(0); i < e.ELF.GetSegmentCount(); i++ {
		phdr, err := e.ELF.GetProgramHeader(i)
		if err != nil {
			return 0, fmt.Errorf("failed to read program header %d: %w", i, err)
		}
		if phdr.GetType() != elf_reader.ProgramHeaderType(0) {
			segmentEnd := phdr.GetFileOffset() + phdr.GetFileSize()
			if segmentEnd > size {
				size = segmentEnd
			}
		}
	}
	return size, nil
}

func (e *ELFFile) TruncateZeros(size uint64) (uint64, error) {
	if size > uint64(len(e.RawData)) {
		return size, fmt.Errorf("specified size exceeds file size")
	}
	for size > 0 && e.RawData[size-1] == 0 {
		size--
	}
	return size, nil
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

func parseSections(ef *ELFFile) []Section {
	count := ef.ELF.GetSectionCount()
	sections := make([]Section, 0, count)
	for i := uint16(0); i < count; i++ {
		header, err := ef.ELF.GetSectionHeader(i)
		if err != nil {
			continue
		}
		name, _ := ef.ELF.GetSectionName(i)
		flags := header.GetFlags()
		sections = append(sections, Section{
			Name:   name,
			Offset: header.GetFileOffset(),
			Size:   header.GetSize(),
			Type:   uint32(header.GetType()),
			Flags:  parseFlags(flags),
			Index:  i,
		})
	}
	return sections
}

func parseSegments(ef *ELFFile) []Segment {
	count := ef.ELF.GetSegmentCount()
	segments := make([]Segment, 0, count)
	for i := uint16(0); i < count; i++ {
		phdr, err := ef.ELF.GetProgramHeader(i)
		if err != nil {
			continue
		}
		segments = append(segments, Segment{
			Offset:   phdr.GetFileOffset(),
			Size:     phdr.GetFileSize(),
			Type:     uint32(phdr.GetType()),
			Flags:    uint32(phdr.GetFlags()),
			Loadable: phdr.GetType() == elf_reader.ProgramHeaderType(1),
			Index:    i,
		})
	}
	return segments
}

func parseFlags(flags elf_reader.ELFSectionFlags) uint64 {
	var result uint64
	if flags.Executable() {
		result |= 0x4
	}
	if flags.Allocated() {
		result |= 0x2
	}
	if flags.Writable() {
		result |= 0x1
	}
	return result
}
