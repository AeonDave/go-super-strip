package elfrw

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"io"
	"math"
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
	if e.ELF != nil {
		_ = e.ELF.Close()
	}
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

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to reset file cursor: %w", err)
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

	if elfFile, err := elf.NewFile(bytes.NewReader(rawData)); err == nil {
		ef.ELF = elfFile
	} else {
		ef.usedFallbackMode = true
	}

	return ef, nil
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

func parseFlags(flags elf.SectionFlag) uint64 {
	var result uint64
	if flags&elf.SHF_EXECINSTR != 0 {
		result |= SHF_EXECINSTR
	}
	if flags&elf.SHF_ALLOC != 0 {
		result |= SHF_ALLOC
	}
	if flags&elf.SHF_WRITE != 0 {
		result |= SHF_WRITE
	}
	if flags&elf.SHF_STRINGS != 0 {
		result |= SHF_STRINGS
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
	fileSize := e.FileSize
	if fileSize <= 0 {
		fileSize = int64(len(e.RawData))
	}
	clamp := func(value int64) int64 {
		switch {
		case value < 0:
			return 0
		case value > fileSize:
			return fileSize
		default:
			return value
		}
	}

	var maxEnd int64
	for _, section := range e.Sections {
		if section.Type == SHT_NOBITS {
			continue
		}
		end := section.Offset + section.Size
		end = clamp(end)
		if end > maxEnd {
			maxEnd = end
		}
	}
	for _, segment := range e.Segments {
		if segment.FileSize == 0 {
			continue
		}
		end := int64(segment.Offset + segment.FileSize)
		end = clamp(end)
		if end > maxEnd {
			maxEnd = end
		}
	}

	// Include the section header table itself to ensure it is treated as part of the base file.
	shoffPos, shnumPos, _ := e.getHeaderPositions()
	if shoff, err := e.getSectionHeaderOffset(shoffPos); err == nil {
		entrySize := uint64(0)
		if e.Is64Bit {
			entrySize = uint64(e.readUint16(ELF64_E_SHENTSIZE))
		} else {
			entrySize = uint64(e.readUint16(ELF32_E_SHENTSIZE))
		}
		count := uint64(e.readUint16(shnumPos))
		headerEnd := int64(shoff + entrySize*count)
		headerEnd = clamp(headerEnd)
		if headerEnd > maxEnd {
			maxEnd = headerEnd
		}
	}

	if shstrEnd := clamp(e.sectionStringTableEnd()); shstrEnd > maxEnd {
		maxEnd = shstrEnd
	}

	if maxEnd > 0 && maxEnd < fileSize {
		e.HasOverlay = true
		e.OverlayOffset = maxEnd
		e.OverlaySize = fileSize - maxEnd
	}
}

func (e *ELFFile) sectionStringTableEnd() int64 {
	var idx uint16
	if e.Is64Bit {
		idx = e.readValue16(ELF64_E_SHSTRNDX)
	} else {
		idx = e.readValue16(ELF32_E_SHSTRNDX)
	}
	if int(idx) >= len(e.Sections) {
		return 0
	}
	section := e.Sections[idx]
	if section.Type == SHT_NOBITS || section.Offset < 0 || section.Size <= 0 {
		return 0
	}
	return section.Offset + section.Size
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
	if e.Is64Bit {
		e.entryPoint = e.readValue(ELF64_E_ENTRY, true)
	} else {
		e.entryPoint = e.readValue(ELF32_E_ENTRY, false)
	}

	if e.usedFallbackMode {
		if err := e.parseBasicSectionsFromRaw(); err != nil {
			e.Sections = make([]Section, 0)
		}
		if err := e.parseBasicSegmentsFromRaw(); err != nil {
			e.Segments = make([]Segment, 0)
		}
	} else {
		sections, err := e.parseSectionsFromELF()
		if err != nil {
			return err
		}
		segments, err := e.parseSegmentsFromELF()
		if err != nil {
			return err
		}
		e.Sections = sections
		e.Segments = segments
	}

	e.DynamicEntries = e.parseDynamicEntries()
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
			}
		}
	}

	sections := make([]Section, 0, shNum)
	for i := uint16(0); i < shNum; i++ {
		base := shOffset + uint64(i)*uint64(shEntSize)
		if base+uint64(shEntSize) > uint64(len(e.RawData)) {
			break
		}
		section := e.parseSectionHeader(base, i, stringTableData)
		e.populateSectionMetadata(&section)
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
	endian := e.getEndian()
	nameOffset := uint64(endian.Uint32(e.RawData[base+ELF_SH_NAME : base+ELF_SH_NAME+4]))
	sectionType := endian.Uint32(e.RawData[base+ELF_SH_TYPE : base+ELF_SH_TYPE+4])

	var flags, address uint64
	if e.Is64Bit {
		flags = endian.Uint64(e.RawData[base+ELF64_SH_FLAGS : base+ELF64_SH_FLAGS+8])
		address = endian.Uint64(e.RawData[base+ELF64_SH_ADDR : base+ELF64_SH_ADDR+8])
	} else {
		flags = uint64(endian.Uint32(e.RawData[base+ELF32_SH_FLAGS : base+ELF32_SH_FLAGS+4]))
		address = uint64(endian.Uint32(e.RawData[base+ELF32_SH_ADDR : base+ELF32_SH_ADDR+4]))
	}
	offset, size := e.parseSectionOffsetAndSize(base)
	var link, info, alignment uint64
	if e.Is64Bit {
		link = uint64(endian.Uint32(e.RawData[base+ELF64_SH_LINK : base+ELF64_SH_LINK+4]))
		info = uint64(endian.Uint32(e.RawData[base+ELF64_SH_INFO : base+ELF64_SH_INFO+4]))
		alignment = endian.Uint64(e.RawData[base+ELF64_SH_ADDRALIGN : base+ELF64_SH_ADDRALIGN+8])
	} else {
		link = uint64(endian.Uint32(e.RawData[base+ELF32_SH_LINK : base+ELF32_SH_LINK+4]))
		info = uint64(endian.Uint32(e.RawData[base+ELF32_SH_INFO : base+ELF32_SH_INFO+4]))
		alignment = uint64(endian.Uint32(e.RawData[base+ELF32_SH_ADDRALIGN : base+ELF32_SH_ADDRALIGN+4]))
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
	}
	return Section{
		Name:      name,
		Offset:    int64(offset),
		Size:      int64(size),
		Address:   address,
		Index:     int(index),
		Type:      sectionType,
		Flags:     flags,
		Alignment: alignment,
		Link:      uint32(link),
		Info:      uint32(info),
	}
}

func (e *ELFFile) populateSectionMetadata(section *Section) {
	flags := section.Flags
	section.IsAlloc = (flags & SHF_ALLOC) != 0
	section.CommonSectionInfo.IsExecutable = (flags & SHF_EXECINSTR) != 0
	section.CommonSectionInfo.IsReadable = true
	section.CommonSectionInfo.IsWritable = (flags & SHF_WRITE) != 0

	if section.Size <= 0 || section.Type == SHT_NOBITS || section.Offset < 0 {
		return
	}

	start := section.Offset
	end := start + section.Size
	if end < start || end > int64(len(e.RawData)) {
		return
	}

	startIdx := int(start)
	endIdx := int(end)
	if startIdx < 0 || endIdx > len(e.RawData) {
		return
	}

	content := e.RawData[startIdx:endIdx]
	section.MD5Hash = fmt.Sprintf("%x", md5.Sum(content))
	section.SHA1Hash = fmt.Sprintf("%x", sha1.Sum(content))
	section.SHA256Hash = fmt.Sprintf("%x", sha256.Sum256(content))
	section.Entropy = common.CalculateEntropy(content)
}

func (e *ELFFile) parseSectionsFromELF() ([]Section, error) {
	if e.ELF == nil {
		return nil, fmt.Errorf("elf reader is not initialized")
	}

	sections := make([]Section, 0, len(e.ELF.Sections))
	for i, sec := range e.ELF.Sections {
		if sec == nil {
			continue
		}
		header := sec.SectionHeader
		name := sec.Name
		if name == "" && i != int(SHT_NULL) {
			name = fmt.Sprintf("section_%d", i)
		}

		flags := parseFlags(header.Flags)
		section := Section{
			Name:      name,
			Offset:    int64(header.Offset),
			Size:      int64(header.Size),
			Address:   header.Addr,
			Index:     i,
			Type:      uint32(header.Type),
			Flags:     flags,
			Alignment: header.Addralign,
			Link:      header.Link,
			Info:      header.Info,
		}
		e.populateSectionMetadata(&section)
		sections = append(sections, section)
	}
	return sections, nil
}

func (e *ELFFile) parseSegmentsFromELF() ([]Segment, error) {
	if e.ELF == nil {
		return nil, fmt.Errorf("elf reader is not initialized")
	}

	segments := make([]Segment, 0, len(e.ELF.Progs))
	for i, prog := range e.ELF.Progs {
		if prog == nil {
			continue
		}
		if i > int(math.MaxUint16) {
			return nil, fmt.Errorf("program header index exceeds uint16 range: %d", i)
		}
		flags := uint32(prog.Flags)
		segments = append(segments, Segment{
			Type:         uint32(prog.Type),
			Flags:        flags,
			Offset:       prog.Off,
			VirtualAddr:  prog.Vaddr,
			PhysicalAddr: prog.Paddr,
			FileSize:     prog.Filesz,
			MemSize:      prog.Memsz,
			Alignment:    prog.Align,
			IsExecutable: (flags & common.PERM_EXECUTE) != 0,
			IsReadable:   (flags & common.PERM_READ) != 0,
			IsWritable:   (flags & common.PERM_WRITE) != 0,
			Loadable:     prog.Type == elf.PT_LOAD,
			Index:        uint16(i),
		})
	}
	return segments, nil
}

func (e *ELFFile) parseBasicSegmentsFromRaw() error {
	minHeaderSize := ELF64_EHDR_SIZE
	if !e.Is64Bit {
		minHeaderSize = ELF32_EHDR_SIZE
	}
	if len(e.RawData) < minHeaderSize {
		return fmt.Errorf("file too small")
	}

	var phOffset uint64
	var phEntrySize uint16
	var phCount uint16

	if e.Is64Bit {
		phOffset = e.readValue(ELF64_E_PHOFF, true)
		phEntrySize = e.readValue16(ELF64_E_PHENTSIZE)
		phCount = e.readValue16(ELF64_E_PHNUM)
	} else {
		phOffset = e.readValue(ELF32_E_PHOFF, false)
		phEntrySize = e.readValue16(ELF32_E_PHENTSIZE)
		phCount = e.readValue16(ELF32_E_PHNUM)
	}

	if phOffset == 0 || phEntrySize == 0 || phCount == 0 {
		e.Segments = make([]Segment, 0)
		return nil
	}

	if phOffset >= uint64(len(e.RawData)) {
		return fmt.Errorf("program header offset out of range")
	}

	maxSize := phOffset + uint64(phEntrySize)*uint64(phCount)
	if maxSize > uint64(len(e.RawData)) {
		phCount = uint16((uint64(len(e.RawData)) - phOffset) / uint64(phEntrySize))
	}

	segments := make([]Segment, 0, phCount)
	endian := e.getEndian()

	for i := uint16(0); i < phCount; i++ {
		base := phOffset + uint64(i)*uint64(phEntrySize)
		if base+uint64(phEntrySize) > uint64(len(e.RawData)) {
			break
		}
		start := int(base)
		seg := Segment{Index: i}
		if e.Is64Bit {
			if phEntrySize < 56 {
				break
			}
			seg.Type = endian.Uint32(e.RawData[start : start+4])
			seg.Flags = endian.Uint32(e.RawData[start+4 : start+8])
			seg.Offset = endian.Uint64(e.RawData[start+8 : start+16])
			seg.VirtualAddr = endian.Uint64(e.RawData[start+16 : start+24])
			seg.PhysicalAddr = endian.Uint64(e.RawData[start+24 : start+32])
			seg.FileSize = endian.Uint64(e.RawData[start+32 : start+40])
			seg.MemSize = endian.Uint64(e.RawData[start+40 : start+48])
			seg.Alignment = endian.Uint64(e.RawData[start+48 : start+56])
		} else {
			if phEntrySize < 32 {
				break
			}
			seg.Type = endian.Uint32(e.RawData[start : start+4])
			seg.Offset = uint64(endian.Uint32(e.RawData[start+4 : start+8]))
			seg.VirtualAddr = uint64(endian.Uint32(e.RawData[start+8 : start+12]))
			seg.PhysicalAddr = uint64(endian.Uint32(e.RawData[start+12 : start+16]))
			seg.FileSize = uint64(endian.Uint32(e.RawData[start+16 : start+20]))
			seg.MemSize = uint64(endian.Uint32(e.RawData[start+20 : start+24]))
			seg.Flags = endian.Uint32(e.RawData[start+24 : start+28])
			seg.Alignment = uint64(endian.Uint32(e.RawData[start+28 : start+32]))
		}
		seg.IsExecutable = (seg.Flags & common.PERM_EXECUTE) != 0
		seg.IsReadable = (seg.Flags & common.PERM_READ) != 0
		seg.IsWritable = (seg.Flags & common.PERM_WRITE) != 0
		seg.Loadable = seg.Type == PT_LOAD
		segments = append(segments, seg)
	}

	e.Segments = segments
	return nil
}

func (e *ELFFile) parseDynamicEntries() []DynamicEntry {
	var entries []DynamicEntry
	dynIndex, found := e.findSectionByName(".dynamic")
	if !found {
		return entries
	}
	dynData, err := e.getSectionContent(dynIndex)
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

func (e *ELFFile) sectionCount() int {
	if e.ELF != nil {
		return len(e.ELF.Sections)
	}
	return len(e.Sections)
}

func (e *ELFFile) getSectionName(index uint16) (string, error) {
	if e.ELF != nil {
		if int(index) >= len(e.ELF.Sections) {
			return "", fmt.Errorf("invalid section index: %d", index)
		}
		section := e.ELF.Sections[index]
		if section == nil {
			return "", fmt.Errorf("section %d is nil", index)
		}
		return section.Name, nil
	}
	if int(index) >= len(e.Sections) {
		return "", fmt.Errorf("invalid section index: %d", index)
	}
	return e.Sections[index].Name, nil
}

func (e *ELFFile) getSectionContent(index uint16) ([]byte, error) {
	if e.ELF != nil {
		if int(index) >= len(e.ELF.Sections) {
			return nil, fmt.Errorf("invalid section index: %d", index)
		}
		section := e.ELF.Sections[index]
		if section == nil {
			return nil, fmt.Errorf("section %d is nil", index)
		}
		size := section.Size
		if size == 0 || section.Type == elf.SHT_NOBITS {
			return []byte{}, nil
		}
		offset := section.Offset
		end := offset + size
		if end < offset {
			return nil, fmt.Errorf("section %d size overflow", index)
		}
		if offset > uint64(len(e.RawData)) || end > uint64(len(e.RawData)) {
			return nil, fmt.Errorf("section %d content out of range", index)
		}
		if offset > uint64(math.MaxInt) || end > uint64(math.MaxInt) {
			return nil, fmt.Errorf("section %d content exceeds supported size", index)
		}
		start := int(offset)
		finish := int(end)
		data := make([]byte, finish-start)
		copy(data, e.RawData[start:finish])
		return data, nil
	}

	if int(index) >= len(e.Sections) {
		return nil, fmt.Errorf("invalid section index: %d", index)
	}
	section := e.Sections[index]
	if section.Size <= 0 || section.Type == SHT_NOBITS {
		return []byte{}, nil
	}
	if section.Offset < 0 {
		return nil, fmt.Errorf("section %d content out of range", index)
	}
	offset := uint64(section.Offset)
	size := uint64(section.Size)
	end := offset + size
	if end < offset || end > uint64(len(e.RawData)) {
		return nil, fmt.Errorf("section %d content out of range", index)
	}
	if offset > uint64(math.MaxInt) || end > uint64(math.MaxInt) {
		return nil, fmt.Errorf("section %d content exceeds supported size", index)
	}
	start := int(offset)
	finish := int(end)
	data := make([]byte, finish-start)
	copy(data, e.RawData[start:finish])
	return data, nil
}

func (e *ELFFile) getProgramHeader(index uint16) (*elf.Prog, error) {
	if e.ELF != nil {
		if int(index) >= len(e.ELF.Progs) {
			return nil, fmt.Errorf("invalid program header index: %d", index)
		}
		prog := e.ELF.Progs[index]
		if prog == nil {
			return nil, fmt.Errorf("program header %d is nil", index)
		}
		return prog, nil
	}
	if int(index) >= len(e.Segments) {
		return nil, fmt.Errorf("invalid program header index: %d", index)
	}
	seg := e.Segments[index]
	return &elf.Prog{ProgHeader: elf.ProgHeader{
		Type:   elf.ProgType(seg.Type),
		Flags:  elf.ProgFlag(seg.Flags),
		Off:    seg.Offset,
		Vaddr:  seg.VirtualAddr,
		Paddr:  seg.PhysicalAddr,
		Filesz: seg.FileSize,
		Memsz:  seg.MemSize,
		Align:  seg.Alignment,
	}}, nil
}
