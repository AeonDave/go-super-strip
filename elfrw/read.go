package elfrw

import (
	"fmt"
	"io"
	"os"

	"github.com/yalue/elf_reader"
)

// DebugLogger is a function type for debug logging
type DebugLogger func(format string, args ...interface{})

// Global debug logger - can be set from main package
var debugLog DebugLogger = func(format string, args ...interface{}) {
	// Default: do nothing (no debug output)
}

// SetDebugLogger sets the debug logging function
func SetDebugLogger(logger DebugLogger) {
	debugLog = logger
}

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
	File        *os.File
	RawData     []byte
	ELF         elf_reader.ELFFile
	Is64Bit     bool
	FileName    string
	Sections    []Section
	Segments    []Segment
	nameOffsets map[string]uint32 // Cache for string table offsets during section insertion
}

func ReadELF(file *os.File) (*ELFFile, error) {
	debugLog("ReadELF - Starting to read file %s", file.Name())
	rawData, err := readFileData(file)
	if err != nil {
		return nil, err
	}
	debugLog("ReadELF - Read %d bytes", len(rawData))

	is64Bit := len(rawData) > 4 && rawData[4] == 2
	debugLog("ReadELF - About to call elf_reader.ParseELFFile, is64Bit=%v", is64Bit)
	elfFile, err := elf_reader.ParseELFFile(rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ELF file: %w", err)
	}
	debugLog("ReadELF - elf_reader.ParseELFFile completed successfully")

	ef := &ELFFile{
		File:     file,
		RawData:  rawData,
		ELF:      elfFile,
		Is64Bit:  is64Bit,
		FileName: file.Name(),
	}

	debugLog("ReadELF - About to call parseSections")
	ef.Sections = parseSections(ef)
	debugLog("ReadELF - parseSections completed, got %d sections", len(ef.Sections))

	debugLog("ReadELF - About to call parseSegments")
	ef.Segments = parseSegments(ef)
	debugLog("ReadELF - parseSegments completed, got %d segments", len(ef.Segments))

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
	debugLog("parseSections - Starting")
	// Check if the ELF file has section headers by reading e_shnum from raw data
	// For 64-bit ELF: e_shnum is at offset 60-62
	// For 32-bit ELF: e_shnum is at offset 48-50
	var shNumOffset int
	if ef.Is64Bit {
		shNumOffset = 60
	} else {
		shNumOffset = 48
	}
	debugLog("parseSections - shNumOffset=%d", shNumOffset)

	// Safety check: ensure we have enough data to read e_shnum
	if len(ef.RawData) < shNumOffset+2 {
		debugLog("parseSections - Not enough data for e_shnum, returning empty")
		return make([]Section, 0) // Return empty sections if header is too small
	}

	// Read e_shnum with correct endianness
	endian := ef.GetEndian()
	shNum := endian.Uint16(ef.RawData[shNumOffset : shNumOffset+2])
	debugLog("parseSections - Read e_shnum=%d", shNum)

	// If e_shnum is 0, there are no sections - return empty slice immediately
	if shNum == 0 {
		debugLog("parseSections - e_shnum is 0, returning empty sections")
		return make([]Section, 0)
	}

	debugLog("parseSections - about to call GetSectionCount(), e_shnum=%d", shNum)
	count := ef.ELF.GetSectionCount()
	debugLog("parseSections - GetSectionCount() returned %d", count)

	// Additional safety check: if library returns 0 count but e_shnum > 0, something's wrong
	if count == 0 && shNum > 0 {
		debugLog("parseSections - Warning: e_shnum=%d but GetSectionCount()=0, returning empty", shNum)
		return make([]Section, 0)
	}

	// If counts don't match, use the smaller value to be safe
	if count != shNum {
		debugLog("parseSections - Warning: e_shnum=%d != GetSectionCount()=%d, using minimum", shNum, count)
		if count > shNum {
			count = shNum
		}
	}
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
	debugLog("parseSections - Completed, returning %d sections", len(sections))
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

// IsELFFile checks if a file is a valid ELF file
func IsELFFile(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	// Read ELF header
	elfHeader := make([]byte, 16)
	if _, err := file.Read(elfHeader); err != nil {
		return false, nil // Not enough data, not an ELF file
	}

	// Check ELF signature (0x7f + "ELF")
	return elfHeader[0] == 0x7f && elfHeader[1] == 'E' && elfHeader[2] == 'L' && elfHeader[3] == 'F', nil
}
