package elfrw

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/yalue/elf_reader"
	"gosstrip/common"
	"io"
	"os"
	"strings"
)

func ReadELF(file *os.File) (*ELFFile, error) {
	ef, err := newELFFileFromDisk(file)
	if err != nil {
		return nil, err
	}
	if err := ef.parseAllELFComponents(); err != nil {
		return nil, err
	}
	return ef, nil
}

func (e *ELFFile) Close() error {
	if e.File != nil {
		return e.File.Close()
	}
	return nil
}

func IsELFFile(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	elfHeader := make([]byte, ELF_IDENT_SIZE)
	if _, err := file.Read(elfHeader); err != nil {
		return false, nil // Not enough data, not an ELF file
	}

	// Check ELF signature (0x7f + "ELF")
	return elfHeader[0] == ELF_MAG0 && elfHeader[1] == ELF_MAG1 && elfHeader[2] == ELF_MAG2 && elfHeader[3] == ELF_MAG3, nil
}

func newELFFileFromDisk(file *os.File) (*ELFFile, error) {
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	rawData, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file data: %w", err)
	}

	if err := validateELFHeader(rawData); err != nil {
		return nil, err
	}

	is64Bit := len(rawData) > 4 && rawData[4] == 2
	ef := &ELFFile{
		File:     file,
		FileName: file.Name(),
		RawData:  rawData,
		Is64Bit:  is64Bit,
		CommonFileInfo: common.CommonFileInfo{
			FileSize: fileInfo.Size(),
		},
		nameOffsets: make(map[string]uint32),
	}

	elfFile, err := elf_reader.ParseELFFile(rawData)
	if err != nil {
		fmt.Printf("⚠️ Parsing con elf_reader fallito per '%s': %v. Tentativo con la modalità di fallback.\n", ef.FileName, err)
		ef.usedFallbackMode = true
	} else {
		ef.ELF = elfFile
	}

	return ef, nil
}

func executeSafeParsing(component, fileName string, parseFunc func()) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("⚠️  Recovered from panic while parsing %s in '%s': %v\n", component, fileName, r)
		}
	}()
	parseFunc()
}

func validateELFHeader(data []byte) error {
	if len(data) < ELF_MAG_SIZE {
		return fmt.Errorf("file too small to be an ELF file")
	}
	if !(data[0] == ELF_MAG0 && data[1] == ELF_MAG1 && data[2] == ELF_MAG2 && data[3] == ELF_MAG3) {
		return fmt.Errorf("not an ELF file (invalid magic number)")
	}
	return nil
}

func parseFlags(flags elf_reader.ELFSectionFlags) uint64 {
	var result uint64
	if flags.Executable() {
		result |= SHF_EXECINSTR
	}
	if flags.Allocated() {
		result |= SHF_ALLOC
	}
	if flags.Writable() {
		result |= SHF_WRITE
	}
	return result
}

func (e *ELFFile) validateELF() error {
	if len(e.RawData) < ELF_MAG_SIZE {
		return fmt.Errorf("invalid ELF header")
	}
	if !(e.RawData[0] == ELF_MAG0 && e.RawData[1] == ELF_MAG1 &&
		e.RawData[2] == ELF_MAG2 && e.RawData[3] == ELF_MAG3) {
		return fmt.Errorf("invalid ELF header")
	}
	minHeaderSize := ELF64_EHDR_SIZE
	if len(e.RawData) < minHeaderSize {
		return fmt.Errorf("file too small to be a valid ELF: %d bytes", len(e.RawData))
	}
	var shOffset uint64
	var shCount, shEntSize uint16

	if e.Is64Bit {
		shOffset = e.readValue(ELF64_E_SHOFF, e.Is64Bit)
		shCount = e.readValue16(ELF64_E_SHNUM)
		shEntSize = e.readValue16(ELF64_E_SHENTSIZE)
	} else {
		shOffset = e.readValue(ELF32_E_SHOFF, e.Is64Bit)
		shCount = e.readValue16(ELF32_E_SHNUM)
		shEntSize = e.readValue16(ELF32_E_SHENTSIZE)
	}
	if shOffset == 0 && shCount == 0 {
		return nil // This is valid - no section headers
	}
	if shOffset >= uint64(len(e.RawData)) {
		return fmt.Errorf("section header offset (%d) out of bounds (%d)", shOffset, len(e.RawData))
	}
	totalSize := shOffset + uint64(shCount)*uint64(shEntSize)
	if totalSize > uint64(len(e.RawData)) {
		return fmt.Errorf("section headers exceed file size: %d > %d", totalSize, len(e.RawData))
	}
	return nil
}

func (e *ELFFile) readValue(offset int, is64bit bool) uint64 {
	if offset < 0 {
		return 0
	}

	endian := e.getEndian()
	if is64bit {
		if offset+8 > len(e.RawData) {
			return 0
		}
		if endian == binary.LittleEndian {
			return binary.LittleEndian.Uint64(e.RawData[offset : offset+8])
		}
		return binary.BigEndian.Uint64(e.RawData[offset : offset+8])
	}

	if offset+4 > len(e.RawData) {
		return 0
	}
	if endian == binary.LittleEndian {
		return uint64(binary.LittleEndian.Uint32(e.RawData[offset : offset+4]))
	}
	return uint64(binary.BigEndian.Uint32(e.RawData[offset : offset+4]))
}

func (e *ELFFile) readValue16(offset int) uint16 {
	if offset < 0 || offset+2 > len(e.RawData) {
		return 0
	}
	endian := e.getEndian()
	if endian == binary.LittleEndian {
		return binary.LittleEndian.Uint16(e.RawData[offset : offset+2])
	}
	return binary.BigEndian.Uint16(e.RawData[offset : offset+2])
}

func (e *ELFFile) getMachineType() string {
	if len(e.RawData) < 20 {
		return "Unknown"
	}
	endian := e.getEndian()
	machine := endian.Uint16(e.RawData[18:20])
	switch machine {
	case 0x3E:
		return "x86-64"
	case 0x03:
		return "i386"
	case 0xB7:
		return "AArch64"
	case 0x28:
		return "ARM"
	default:
		return fmt.Sprintf("Unknown (0x%x)", machine)
	}
}

func (e *ELFFile) checkForOverlay() {
	var maxEnd int64 = 0
	for _, section := range e.Sections {
		if section.Type != SHT_NOBITS {
			if end := section.Offset + section.Size; end > maxEnd {
				maxEnd = end
			}
		}
	}
	for _, segment := range e.Segments {
		if end := int64(segment.Offset + segment.FileSize); end > maxEnd {
			maxEnd = end
		}
	}

	if maxEnd > 0 && maxEnd < e.FileSize {
		e.HasOverlay = true
		e.OverlayOffset = maxEnd
		e.OverlaySize = e.FileSize - maxEnd
	}
}

func (e *ELFFile) checkIfDynamic() bool {
	for _, segment := range e.Segments {
		if segment.Type == PT_DYNAMIC {
			return true
		}
	}
	for _, section := range e.Sections {
		if section.Type == SHT_DYNAMIC {
			return true
		}
	}
	return false
}

func (e *ELFFile) checkHasInterpreter() bool {
	for _, segment := range e.Segments {
		if segment.Type == PT_INTERP {
			return true
		}
	}
	for _, section := range e.Sections {
		if strings.ToLower(section.Name) == ".interp" {
			return true
		}
	}
	return false
}

func (e *ELFFile) checkForPacking() {
	e.IsPacked = false
	for _, section := range e.Sections {
		name := strings.ToLower(section.Name)
		for _, suspicious := range common.SuspiciousSectionNames {
			if strings.Contains(name, suspicious) {
				e.IsPacked = true
				return
			}
		}
	}
	for _, section := range e.Sections {
		if section.Entropy > 7.5 && section.Size > 1024 {
			e.IsPacked = true
			return
		}
	}
}

func (e *ELFFile) parseAllELFComponents() error {
	if e.usedFallbackMode {
		fmt.Printf("⚠️  Using fallback parsing mode for ELF file '%s'\n", e.FileName)
		_ = e.parseBasicSectionsFromRaw()
	} else {
		executeSafeParsing("sections", e.FileName, func() { e.Sections = e.parseSections() })
		executeSafeParsing("segments", e.FileName, func() { e.Segments = e.parseSegments() })
		executeSafeParsing("dynamic entries", e.FileName, func() { e.DynamicEntries = e.parseDynamicEntries() })
	}
	e.isDynamic = e.checkIfDynamic()
	e.hasInterpreter = e.checkHasInterpreter()
	e.machineType = e.getMachineType()
	e.checkForPacking()
	e.checkForOverlay()
	if e.Sections == nil {
		e.Sections = make([]Section, 0)
	}
	if e.Segments == nil {
		e.Segments = make([]Segment, 0)
	}
	if e.Symbols == nil {
		e.Symbols = make([]Symbol, 0)
	}
	if e.DynamicEntries == nil {
		e.DynamicEntries = make([]DynamicEntry, 0)
	}

	return nil
}

func (e *ELFFile) parseSections() []Section {
	count := e.ELF.GetSectionCount()
	sections := make([]Section, 0, count)

	fmt.Printf("🔍 Parsing %d sections\n", count)

	for i := uint16(0); i < count; i++ {
		header, err := e.ELF.GetSectionHeader(i)
		if err != nil {
			fmt.Printf("⚠️  Failed to get section header %d: %v\n", i, err)
			continue
		}
		name, err := e.ELF.GetSectionName(i)
		if err != nil && i != SHT_NULL {
			fmt.Printf("⚠️  Failed to get section name %d: %v\n", i, err)
			name = fmt.Sprintf("section_%d", i)
		}
		if name == "" && i != SHT_NULL {
			fmt.Printf("⚠️  Empty section name for section %d\n", i)
			name = fmt.Sprintf("section_%d", i)
		}

		flags := header.GetFlags()

		section := Section{
			Name:      name,
			Offset:    int64(header.GetFileOffset()),
			Size:      int64(header.GetSize()),
			Address:   header.GetVirtualAddress(),
			Index:     int(i),
			Type:      uint32(header.GetType()),
			Flags:     parseFlags(flags),
			IsAlloc:   flags.Allocated(),
			Alignment: header.GetAlignment(),
			CommonSectionInfo: common.CommonSectionInfo{
				IsExecutable: flags.Executable(),
				IsReadable:   true,
				IsWritable:   flags.Writable(),
			},
		}
		if section.Size > 0 && section.Offset >= 0 && section.Offset+section.Size <= int64(len(e.RawData)) {
			content := e.RawData[section.Offset : section.Offset+section.Size]
			section.MD5Hash = fmt.Sprintf("%x", md5.Sum(content))
			section.SHA1Hash = fmt.Sprintf("%x", sha1.Sum(content))
			section.SHA256Hash = fmt.Sprintf("%x", sha256.Sum256(content))
			section.Entropy = common.CalculateEntropy(content)
		}
		sections = append(sections, section)
	}
	return sections
}

func (e *ELFFile) parseBasicSectionsFromRaw() error {
	var shOffset uint64
	var shNum, shEntSize uint16
	var shOffPos, shNumPos, shEntSizePos int
	var shstrndx uint16

	if e.Is64Bit {
		shOffPos = ELF64_E_SHOFF
		shNumPos = ELF64_E_SHNUM
		shEntSizePos = ELF64_E_SHENTSIZE
		shstrndxPos := ELF64_E_SHSTRNDX
		if len(e.RawData) < shNumPos+2 {
			return fmt.Errorf("file too small for 64-bit ELF header")
		}
		shOffset = e.getEndian().Uint64(e.RawData[shOffPos : shOffPos+8])
		shNum = e.getEndian().Uint16(e.RawData[shNumPos : shNumPos+2])
		shEntSize = e.getEndian().Uint16(e.RawData[shEntSizePos : shEntSizePos+2])
		shstrndx = e.getEndian().Uint16(e.RawData[shstrndxPos : shstrndxPos+2])
	} else {
		shOffPos = ELF32_E_SHOFF
		shNumPos = ELF32_E_SHNUM
		shEntSizePos = ELF32_E_SHENTSIZE
		shstrndxPos := ELF32_E_SHSTRNDX
		if len(e.RawData) < shNumPos+2 {
			return fmt.Errorf("file too small for 32-bit ELF header")
		}
		shOffset = uint64(e.getEndian().Uint32(e.RawData[shOffPos : shOffPos+4]))
		shNum = e.getEndian().Uint16(e.RawData[shNumPos : shNumPos+2])
		shEntSize = e.getEndian().Uint16(e.RawData[shEntSizePos : shEntSizePos+2])
		shstrndx = e.getEndian().Uint16(e.RawData[shstrndxPos : shstrndxPos+2])
	}

	if shNum == 0 || shEntSize == 0 {
		e.Sections = make([]Section, 0)
		return nil
	}

	var stringTableData []byte
	if shstrndx < shNum {
		stringHeaderBase := shOffset + uint64(shstrndx)*uint64(shEntSize)
		if stringHeaderBase+uint64(shEntSize) <= uint64(len(e.RawData)) {
			stringTableOffset, stringTableSize := e.parseSectionOffsetAndSize(stringHeaderBase)
			if stringTableOffset+stringTableSize <= uint64(len(e.RawData)) {
				stringTableData = e.RawData[stringTableOffset : stringTableOffset+stringTableSize]
				fmt.Printf("🔍 String table found: offset=0x%X, size=%d bytes\n", stringTableOffset, stringTableSize)
			} else {
				fmt.Printf("⚠️  String table bounds check failed: offset=0x%X, size=%d, fileSize=%d\n",
					stringTableOffset, stringTableSize, len(e.RawData))
			}
		} else {
			fmt.Printf("⚠️  String table header bounds check failed: headerBase=0x%X, entrySize=%d, fileSize=%d\n",
				stringHeaderBase, shEntSize, len(e.RawData))
		}
	} else {
		fmt.Printf("⚠️  Invalid string table index: shstrndx=%d, shNum=%d\n", shstrndx, shNum)
	}

	sections := make([]Section, 0, shNum)
	for i := uint16(0); i < shNum; i++ {
		base := shOffset + uint64(i)*uint64(shEntSize)
		if base+uint64(shEntSize) > uint64(len(e.RawData)) {
			break
		}
		section := e.parseSectionHeader(base, i, stringTableData)
		sections = append(sections, section)
	}
	e.Sections = sections
	return nil
}

func (e *ELFFile) parseSectionOffsetAndSize(base uint64) (uint64, uint64) {
	if e.Is64Bit {
		off := e.getEndian().Uint64(e.RawData[base+ELF64_S_OFFSET : base+ELF64_S_OFFSET+8])
		sz := e.getEndian().Uint64(e.RawData[base+ELF64_S_SIZE : base+ELF64_S_SIZE+8])
		return off, sz
	}
	off := uint64(e.getEndian().Uint32(e.RawData[base+ELF32_S_OFFSET : base+ELF32_S_OFFSET+4]))
	sz := uint64(e.getEndian().Uint32(e.RawData[base+ELF32_S_SIZE : base+ELF32_S_SIZE+4]))
	return off, sz
}

func (e *ELFFile) parseSectionHeader(base uint64, index uint16, stringTableData []byte) Section {
	nameOffset := uint64(e.getEndian().Uint32(e.RawData[base+ELF_SH_NAME : base+ELF_SH_NAME+4]))
	sectionType := e.getEndian().Uint32(e.RawData[base+ELF_SH_TYPE : base+ELF_SH_TYPE+4])

	var flags, address uint64
	if e.Is64Bit {
		flags = e.getEndian().Uint64(e.RawData[base+ELF64_SH_FLAGS : base+ELF64_SH_FLAGS+8])
		address = e.getEndian().Uint64(e.RawData[base+ELF64_SH_ADDR : base+ELF64_SH_ADDR+8])
	} else {
		flags = uint64(e.getEndian().Uint32(e.RawData[base+ELF32_SH_FLAGS : base+ELF32_SH_FLAGS+4]))
		address = uint64(e.getEndian().Uint32(e.RawData[base+ELF32_SH_ADDR : base+ELF32_SH_ADDR+4]))
	}
	offset, size := e.parseSectionOffsetAndSize(base)
	var link, info, alignment uint64
	if e.Is64Bit {
		link = uint64(e.getEndian().Uint32(e.RawData[base+ELF64_SH_LINK : base+ELF64_SH_LINK+4]))
		info = uint64(e.getEndian().Uint32(e.RawData[base+ELF64_SH_INFO : base+ELF64_SH_INFO+4]))
		alignment = e.getEndian().Uint64(e.RawData[base+ELF64_SH_ADDRALIGN : base+ELF64_SH_ADDRALIGN+8])
	} else {
		link = uint64(e.getEndian().Uint32(e.RawData[base+ELF32_SH_LINK : base+ELF32_SH_LINK+4]))
		info = uint64(e.getEndian().Uint32(e.RawData[base+ELF32_SH_INFO : base+ELF32_SH_INFO+4]))
		alignment = uint64(e.getEndian().Uint32(e.RawData[base+ELF32_SH_ADDRALIGN : base+ELF32_SH_ADDRALIGN+4]))
	}
	name := fmt.Sprintf("raw_section_%d", index)
	if stringTableData != nil && nameOffset < uint64(len(stringTableData)) {
		end := nameOffset
		for end < uint64(len(stringTableData)) && stringTableData[end] != 0 {
			end++
		}
		if end > nameOffset {
			name = string(stringTableData[nameOffset:end])
		}
	} else if stringTableData == nil {
		fmt.Printf("⚠️  No string table data available for section %d\n", index)
	} else if nameOffset >= uint64(len(stringTableData)) {
		fmt.Printf("⚠️  Name offset %d out of bounds for section %d (string table size: %d)\n",
			nameOffset, index, len(stringTableData))
	}
	section := Section{
		Name:      name,
		Offset:    int64(offset),
		Size:      int64(size),
		Address:   address,
		Index:     int(index),
		Type:      sectionType,
		Flags:     flags,
		IsAlloc:   (flags & SHF_ALLOC) != 0,
		Alignment: alignment,
		Link:      uint32(link),
		Info:      uint32(info),
		CommonSectionInfo: common.CommonSectionInfo{
			IsExecutable: (flags & SHF_EXECINSTR) != 0,
			IsReadable:   true,
			IsWritable:   (flags & SHF_WRITE) != 0,
		},
	}

	if section.Size > 0 && section.Type != SHT_NOBITS && section.Offset >= 0 && section.Offset+section.Size <= int64(len(e.RawData)) {
		content := e.RawData[section.Offset : section.Offset+section.Size]
		section.MD5Hash = fmt.Sprintf("%x", md5.Sum(content))
		section.SHA1Hash = fmt.Sprintf("%x", sha1.Sum(content))
		section.SHA256Hash = fmt.Sprintf("%x", sha256.Sum256(content))
		section.Entropy = common.CalculateEntropy(content)
	}

	return section
}

func (e *ELFFile) parseSegments() []Segment {
	count := e.ELF.GetSegmentCount()
	segments := make([]Segment, 0, count)

	for i := uint16(0); i < count; i++ {
		phdr, err := e.ELF.GetProgramHeader(i)
		if err != nil {
			continue
		}
		flags := phdr.GetFlags()
		segments = append(segments, Segment{
			Type:         uint32(phdr.GetType()),
			Flags:        uint32(flags),
			Offset:       phdr.GetFileOffset(),
			FileSize:     phdr.GetFileSize(),
			MemSize:      phdr.GetMemorySize(),
			IsExecutable: (flags & common.PERM_EXECUTE) != 0,
			IsReadable:   (flags & common.PERM_READ) != 0,
			IsWritable:   (flags & common.PERM_WRITE) != 0,
			Loadable:     phdr.GetType() == elf_reader.ProgramHeaderType(PT_LOAD),
			Index:        i,
		})
	}
	return segments
}

func (e *ELFFile) parseBasicSegmentsFromRaw() error {
	minHeaderSize := ELF64_EHDR_SIZE
	if len(e.RawData) < minHeaderSize {
		return fmt.Errorf("file too small")
	}
	e.Segments = []Segment{}
	return nil
}

func (e *ELFFile) parseDynamicEntries() []DynamicEntry {
	var entries []DynamicEntry
	dynIndex, found := e.findSectionByName(".dynamic")
	if !found {
		return entries
	}
	dynData, err := e.ELF.GetSectionContent(dynIndex)
	if err != nil {
		return entries
	}
	var entrySize int
	if e.Is64Bit {
		entrySize = ELF64_DYN_SIZE
	} else {
		entrySize = ELF32_DYN_SIZE
	}
	for offset := 0; offset < len(dynData); offset += entrySize {
		if offset+entrySize > len(dynData) {
			break
		}

		var tag int64
		var value uint64

		if e.Is64Bit {
			tag = int64(e.readUint64FromBytes(dynData[offset:]))
			value = e.readUint64FromBytes(dynData[offset+ELF64_DYN_VAL:])
		} else {
			tag = int64(e.readUint32FromBytes(dynData[offset:]))
			value = uint64(e.readUint32FromBytes(dynData[offset+ELF32_DYN_VAL:]))
		}
		if tag == 0 {
			break
		}

		entries = append(entries, DynamicEntry{
			Tag:   tag,
			Value: value,
		})
	}
	return entries
}
