package elfrw

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"gosstrip/common"
	"io"
	"os"
	"strings"

	"github.com/yalue/elf_reader"
)

// ReadELF reads and parses an ELF file
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

func isLikelyPackedELF(sections []Section) bool {
	if len(sections) == 0 {
		return false
	}
	var (
		highEntropyCount int
		total            int
		sumEntropy       float64
	)
	for _, s := range sections {
		if s.Size == 0 {
			continue
		}
		total++
		sumEntropy += s.Entropy
		if s.Entropy > 7.0 {
			highEntropyCount++
		}
	}
	if total == 0 {
		return false
	}
	avgEntropy := sumEntropy / float64(total)
	percentHigh := float64(highEntropyCount) / float64(total)

	return percentHigh > 0.5 || avgEntropy > 6.8
}

func newELFFileFromDisk(file *os.File) (*ELFFile, error) {
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	rawData, err := readFileData(file)
	if err != nil {
		return nil, err
	}

	if err := validateELFHeader(rawData); err != nil {
		return nil, err
	}

	// Parse basic file info
	is64Bit := len(rawData) > 4 && rawData[4] == 2

	// Parse ELF using elf_reader
	elfFile, err := elf_reader.ParseELFFile(rawData)
	if err != nil {
		// Similar to PE's handling of corrupted files
		var reason string
		var packed bool

		tempEF := &ELFFile{
			File:     file,
			FileName: file.Name(),
			RawData:  rawData,
		}
		_ = tempEF.parseBasicSectionsFromRaw()
		packed = isLikelyPackedELF(tempEF.Sections)

		if packed {
			reason = "File appears to be packed/compressed (high entropy)"
		} else if strings.Contains(err.Error(), "header") {
			reason = "Corrupted or modified ELF structure"
		} else {
			reason = "Non-standard ELF format"
		}

		fmt.Printf("⚠️  %s (%s)\n", reason, err.Error())

		ef := &ELFFile{
			File:        file,
			ELF:         nil,
			FileName:    file.Name(),
			RawData:     rawData,
			Is64Bit:     is64Bit,
			FileSize:    fileInfo.Size(),
			nameOffsets: make(map[string]uint32),
		}

		// Fallback parsing for corrupted or packed ELF files
		if err := parseWithFallback(ef); err != nil {
			return nil, fmt.Errorf("fallback parsing failed: %w", err)
		}

		return ef, nil
	}

	ef := &ELFFile{
		File:        file,
		ELF:         elfFile,
		FileName:    file.Name(),
		RawData:     rawData,
		Is64Bit:     is64Bit,
		FileSize:    fileInfo.Size(),
		nameOffsets: make(map[string]uint32),
	}

	return ef, nil
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

func (e *ELFFile) parseAllELFComponents() error {
	var errors []string

	// Handle case where ELF parsing failed
	if e.ELF == nil {
		return e.parseBasicSectionsFromRaw()
	}

	// Parse sections with detailed info
	if err := func() error {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("⚠️  Recovered from panic parsing sections: %v\n", r)
			}
		}()
		e.Sections = e.parseSections()
		return nil
	}(); err != nil {
		errors = append(errors, fmt.Sprintf("sections: %v", err))
		if e.Sections == nil {
			e.Sections = make([]Section, 0)
		}
	}

	// Parse segments
	if err := func() error {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("⚠️  Recovered from panic parsing segments: %v\n", r)
			}
		}()
		e.Segments = e.parseSegments()
		return nil
	}(); err != nil {
		errors = append(errors, fmt.Sprintf("segments: %v", err))
		if e.Segments == nil {
			e.Segments = make([]Segment, 0)
		}
	}

	// Parse symbols (simplified for now)
	e.Symbols = make([]Symbol, 0)

	// Parse dynamic entries
	e.DynamicEntries = e.parseDynamicEntries()

	// Set basic properties
	e.isDynamic = e.checkIfDynamic()
	e.hasInterpreter = e.checkHasInterpreter()
	e.machineType = e.getMachineType()

	// Check for overlays and packing
	e.checkForOverlay()
	e.checkForPacking()

	// Analyze file similar to PE
	// if err := e.analyzeFile(); err != nil { // TODO: implement analyzeFile method
	//	errors = append(errors, fmt.Sprintf("analysis: %v", err))
	// }

	if len(errors) > 0 && len(errors) >= 3 {
		return fmt.Errorf("too many parsing errors: %v", errors)
	}

	return nil
}

// IsExecutableOrShared checks if the ELF file is executable or a shared object
func (e *ELFFile) IsExecutableOrShared() bool {
	fileType := e.ELF.GetFileType()
	return fileType == elf_reader.ELFFileType(2) || fileType == elf_reader.ELFFileType(3)
}

// CalculateMemorySize calculates the memory size needed for the ELF file
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

// TruncateZeros removes trailing zeros from the file
func (e *ELFFile) TruncateZeros(size uint64) (uint64, error) {
	if size > uint64(len(e.RawData)) {
		return size, fmt.Errorf("specified size exceeds file size")
	}
	for size > 0 && e.RawData[size-1] == 0 {
		size--
	}
	return size, nil
}

func (e *ELFFile) parseSections() []Section {
	// Check if the ELF file has section headers by reading e_shnum from raw data
	var shNumOffset int
	if e.Is64Bit {
		shNumOffset = 60
	} else {
		shNumOffset = 48
	}

	// Safety check: ensure we have enough data to read e_shnum
	if len(e.RawData) < shNumOffset+2 {
		return make([]Section, 0)
	}

	// Read e_shnum with correct endianness
	endian := e.GetEndian()
	shNum := endian.Uint16(e.RawData[shNumOffset : shNumOffset+2])

	// If e_shnum is 0, there are no sections
	if shNum == 0 {
		return make([]Section, 0)
	}

	count := e.ELF.GetSectionCount()

	// Additional safety check
	if count == 0 && shNum > 0 {
		return make([]Section, 0)
	}

	// If counts don't match, use the smaller value
	if count != shNum {
		if count > shNum {
			count = shNum
		}
	}

	sections := make([]Section, 0, count)
	for i := uint16(0); i < count; i++ {
		header, err := e.ELF.GetSectionHeader(i)
		if err != nil {
			continue
		}
		name, _ := e.ELF.GetSectionName(i)
		flags := header.GetFlags()

		section := Section{
			Name:         name,
			Offset:       int64(header.GetFileOffset()),
			Size:         int64(header.GetSize()),
			Address:      header.GetVirtualAddress(),
			Index:        int(i),
			Type:         uint32(header.GetType()),
			Flags:        parseFlags(flags),
			IsExecutable: flags.Executable(),
			IsReadable:   true,
			IsWritable:   flags.Writable(),
			IsAlloc:      flags.Allocated(),
			Link:         0, // Simplified
			Info:         0, // Simplified
			Alignment:    header.GetAlignment(),
		}

		// Calculate hashes for the section content
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

func (e *ELFFile) parseSegments() []Segment {
	count := e.ELF.GetSegmentCount()
	segments := make([]Segment, 0, count)

	for i := uint16(0); i < count; i++ {
		phdr, err := e.ELF.GetProgramHeader(i)
		if err != nil {
			continue
		}

		flags := phdr.GetFlags()
		segment := Segment{
			Type:         uint32(phdr.GetType()),
			Flags:        uint32(flags),
			Offset:       phdr.GetFileOffset(),
			VirtualAddr:  phdr.GetVirtualAddress(),
			PhysicalAddr: phdr.GetPhysicalAddress(),
			FileSize:     phdr.GetFileSize(),
			MemSize:      phdr.GetMemorySize(),
			Alignment:    phdr.GetAlignment(),
			IsExecutable: (flags & PF_X) != 0,
			IsReadable:   (flags & PF_R) != 0,
			IsWritable:   (flags & PF_W) != 0,
			Loadable:     phdr.GetType() == elf_reader.ProgramHeaderType(1), // PT_LOAD
			Index:        i,
		}
		segments = append(segments, segment)
	}

	return segments
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

func (e *ELFFile) checkIfDynamic() bool {
	// Check if there's a dynamic segment
	for _, segment := range e.Segments {
		if segment.Type == PT_DYNAMIC {
			return true
		}
	}

	// Check if there's a dynamic section
	for _, section := range e.Sections {
		if section.Type == SHT_DYNAMIC {
			return true
		}
	}

	return false
}

func (e *ELFFile) checkHasInterpreter() bool {
	// Check for interpreter segment
	for _, segment := range e.Segments {
		if segment.Type == PT_INTERP {
			return true
		}
	}

	// Check for interpreter section
	for _, section := range e.Sections {
		if strings.ToLower(section.Name) == ".interp" {
			return true
		}
	}

	return false
}

func (e *ELFFile) getMachineType() string {
	// Since we can't access machine type directly from elf_reader,
	// we'll determine it from the raw data
	if len(e.RawData) < 20 {
		return "Unknown"
	}

	endian := e.GetEndian()
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
	// Calculate the end of the last section/segment
	maxEnd := uint64(0)

	for _, section := range e.Sections {
		if section.Type != SHT_NOBITS {
			end := uint64(section.Offset + section.Size)
			if end > maxEnd {
				maxEnd = end
			}
		}
	}

	for _, segment := range e.Segments {
		end := segment.Offset + segment.FileSize
		if end > maxEnd {
			maxEnd = end
		}
	}

	fileSize := uint64(len(e.RawData))
	if fileSize > maxEnd {
		e.HasOverlay = true
		e.OverlayOffset = int64(maxEnd)
		e.OverlaySize = int64(fileSize - maxEnd)
	}
}

func (e *ELFFile) checkForPacking() {
	// Simple heuristics to detect packing
	e.IsPacked = false

	// Check for suspicious section names
	for _, section := range e.Sections {
		name := strings.ToLower(section.Name)
		for _, suspicious := range common.SuspiciousSectionNames {
			if strings.Contains(name, suspicious) {
				e.IsPacked = true
				return
			}
		}
	}

	// Check for high entropy sections (possible compression/encryption)
	for _, section := range e.Sections {
		if section.Entropy > 7.5 && section.Size > 1024 {
			e.IsPacked = true
			return
		}
	}
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

func validateELFHeader(data []byte) error {
	if len(data) < 16 {
		return fmt.Errorf("file too small to be an ELF file")
	}

	// Check ELF magic number
	if data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return fmt.Errorf("not an ELF file")
	}

	return nil
}

// parseWithFallback handles parsing of corrupted or packed ELF files
func parseWithFallback(ef *ELFFile) error {
	fmt.Printf("⚠️  Using fallback parsing mode for ELF file\n")

	// Initialize basic structures
	ef.nameOffsets = make(map[string]uint32)
	ef.versionInfo = make(map[string]string)

	// Try to parse basic components with relaxed validation
	_ = ef.parseBasicSectionsFromRaw()
	_ = ef.parseBasicSegmentsFromRaw()

	// Check if file is likely packed
	// ef.IsPacked = isLikelyPackedELF(ef.Sections) // TODO: implement packing detection

	// Check for overlay
	lastSectionEnd := int64(0)
	for _, section := range ef.Sections {
		if sectionEnd := int64(section.Offset + section.Size); sectionEnd > lastSectionEnd {
			lastSectionEnd = sectionEnd
		}
	}

	if lastSectionEnd < ef.FileSize {
		ef.HasOverlay = true
		ef.OverlayOffset = lastSectionEnd
		ef.OverlaySize = ef.FileSize - lastSectionEnd
	}

	return nil
}

// parseBasicSectionsFromRaw attempts basic section parsing from raw data
func (e *ELFFile) parseBasicSectionsFromRaw() error {
	if len(e.RawData) < 64 {
		return fmt.Errorf("file too small")
	}

	// This is a simplified parser for the fallback mode
	// It tries to extract what it can from the raw data
	e.Sections = []Section{}

	return nil
}

// parseBasicSegmentsFromRaw attempts basic segment parsing from raw data
func (e *ELFFile) parseBasicSegmentsFromRaw() error {
	if len(e.RawData) < 64 {
		return fmt.Errorf("file too small")
	}

	// This is a simplified parser for the fallback mode
	e.Segments = []Segment{}

	return nil
}

// parseDynamicEntries reads and parses the .dynamic section
func (e *ELFFile) parseDynamicEntries() []DynamicEntry {
	var entries []DynamicEntry

	// Find the dynamic section
	dynIndex, found := e.findSectionByName(".dynamic")
	if !found {
		return entries
	}

	// Get the section content
	dynData, err := e.ELF.GetSectionContent(dynIndex)
	if err != nil {
		return entries
	}

	// Dynamic entry size depends on architecture
	var entrySize int
	if e.Is64Bit {
		entrySize = 16 // 64-bit: 8 bytes tag + 8 bytes value
	} else {
		entrySize = 8 // 32-bit: 4 bytes tag + 4 bytes value
	}

	// Parse each dynamic entry
	for offset := 0; offset < len(dynData); offset += entrySize {
		if offset+entrySize > len(dynData) {
			break
		}

		var tag int64
		var value uint64

		if e.Is64Bit {
			// 64-bit dynamic entry
			tag = int64(e.readUint64FromBytes(dynData[offset:]))
			value = e.readUint64FromBytes(dynData[offset+8:])
		} else {
			// 32-bit dynamic entry
			tag = int64(e.readUint32FromBytes(dynData[offset:]))
			value = uint64(e.readUint32FromBytes(dynData[offset+4:]))
		}

		// DT_NULL marks the end of dynamic section
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

func (e *ELFFile) Close() error {
	var errors []error

	if e.File != nil {
		if err := e.File.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close file: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("close errors: %v", errors)
	}

	return nil
}

// ExtractOverlay extracts overlay data from an ELF file if present
func (e *ELFFile) ExtractOverlay() ([]byte, error) {
	if !e.HasOverlay {
		return nil, fmt.Errorf("no overlay found in ELF file")
	}

	if e.OverlayOffset < 0 || e.OverlayOffset >= int64(len(e.RawData)) {
		return nil, fmt.Errorf("invalid overlay offset: %d", e.OverlayOffset)
	}

	overlayEnd := e.OverlayOffset + e.OverlaySize
	if overlayEnd > int64(len(e.RawData)) {
		overlayEnd = int64(len(e.RawData))
	}

	overlayData := make([]byte, overlayEnd-e.OverlayOffset)
	copy(overlayData, e.RawData[e.OverlayOffset:overlayEnd])

	return overlayData, nil
}
