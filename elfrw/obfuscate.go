package elfrw

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"strings"
)

// ELF header field positions
type elfOffsets struct {
	shOff      int // Section header table offset
	shEntSize  int // Section header entry size
	shNum      int // Number of section headers
	shStrNdx   int // Section header string table index
	phOff      int // Program header table offset
	phEntSize  int // Program header entry size
	entryPoint int // Entry point
	flags      int // Processor-specific flags
}

// getELFOffsets returns the correct field offsets based on architecture
func (e *ELFFile) getELFOffsets() elfOffsets {
	if e.Is64Bit {
		return elfOffsets{
			shOff:      40,
			shEntSize:  58,
			shNum:      60,
			shStrNdx:   62,
			phOff:      32,
			phEntSize:  54,
			entryPoint: 24,
			flags:      48,
		}
	}
	return elfOffsets{
		shOff:      32,
		shEntSize:  46,
		shNum:      48,
		shStrNdx:   50,
		phOff:      28,
		phEntSize:  42,
		entryPoint: 24,
		flags:      36,
	}
}

// readValue reads a value from the ELF file at the given offset
func (e *ELFFile) readValue(offset int, is64bit bool) uint64 {
	endian := e.GetEndian()
	if is64bit {
		if endian == binary.LittleEndian {
			return binary.LittleEndian.Uint64(e.RawData[offset : offset+8])
		}
		return binary.BigEndian.Uint64(e.RawData[offset : offset+8])
	}

	if endian == binary.LittleEndian {
		return uint64(binary.LittleEndian.Uint32(e.RawData[offset : offset+4]))
	}
	return uint64(binary.BigEndian.Uint32(e.RawData[offset : offset+4]))
}

// readValue16 reads a 16-bit value from the ELF file
func (e *ELFFile) readValue16(offset int) uint16 {
	endian := e.GetEndian()
	if endian == binary.LittleEndian {
		return binary.LittleEndian.Uint16(e.RawData[offset : offset+2])
	}
	return binary.BigEndian.Uint16(e.RawData[offset : offset+2])
}

// generateRandomName creates a random section name
func generateRandomName() (string, error) {
	randBytes := make([]byte, 7)
	if _, err := rand.Read(randBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	name := "."
	for _, b := range randBytes {
		name += string(rune('a' + (b % 26)))
	}

	if len(name) > 8 {
		name = name[:8]
	}
	return name, nil
}

// generateRandomOffset creates a page-aligned random offset
func generateRandomOffset() (uint64, error) {
	var randomBytes [8]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return 0, fmt.Errorf("failed to generate random offset: %w", err)
	}

	offset := (binary.LittleEndian.Uint64(randomBytes[:]) / 0x1000) * 0x1000
	if offset > 0x40000000 {
		offset = offset % 0x40000000
	}
	return offset, nil
}

// findSection finds a section by name
func (e *ELFFile) findSection(name string) *Section {
	for i := range e.Sections {
		if e.Sections[i].Name == name {
			return &e.Sections[i]
		}
	}
	return nil
}

// findSections finds multiple sections by names
func (e *ELFFile) findSections(names []string) map[string]*Section {
	result := make(map[string]*Section)
	for _, name := range names {
		result[name] = e.findSection(name)
	}
	return result
}

// validateELF checks if critical ELF values are reasonable
func (e *ELFFile) validateELF() error {
	if len(e.RawData) < 4 || string(e.RawData[0:4]) != "\x7FELF" {
		return fmt.Errorf("invalid ELF header")
	}

	if len(e.RawData) < 64 {
		return fmt.Errorf("file too small to be a valid ELF: %d bytes", len(e.RawData))
	}

	offsets := e.getELFOffsets()
	shOffset := e.readValue(offsets.shOff, e.Is64Bit)
	shCount := e.readValue16(offsets.shNum)

	// Handle the case where there are no section headers (valid for stripped binaries)
	if shOffset == 0 && shCount == 0 {
		return nil // This is valid - no section headers
	}

	if shOffset >= uint64(len(e.RawData)) {
		return fmt.Errorf("section header offset (%d) out of bounds (%d)", shOffset, len(e.RawData))
	}

	shEntSize := e.readValue16(offsets.shEntSize)

	totalSize := shOffset + uint64(shCount)*uint64(shEntSize)
	if totalSize > uint64(len(e.RawData)) {
		return fmt.Errorf("section headers exceed file size: %d > %d", totalSize, len(e.RawData))
	}

	return nil
}

// RandomizeSectionNames randomizes ELF section names
func (e *ELFFile) RandomizeSectionNames() *common.OperationResult {
	if err := e.validateELF(); err != nil {
		return common.NewSkipped(fmt.Sprintf("ELF validation failed: %v", err))
	}

	offsets := e.getELFOffsets()

	// Check if file has sections (UPX-packed files have e_shnum = 0)
	shCount := e.readValue16(offsets.shNum)
	if shCount == 0 || len(e.Sections) == 0 {
		return common.NewSkipped("no sections found to randomize")
	}

	shstrtabIndex := e.readValue16(offsets.shStrNdx)

	shstrtabContent, err := e.ELF.GetSectionContent(shstrtabIndex)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read string table: %v", err))
	}

	shstrtabHeader, err := e.ELF.GetSectionHeader(shstrtabIndex)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to read string table header: %v", err))
	}

	// Build new string table
	newShstrtab := []byte{0} // Start with null terminator
	nameOffsets := make(map[string]uint32)
	renamedSections := []string{}

	for i := range e.Sections {
		if e.Sections[i].Name == "" {
			continue
		}

		randomName, err := generateRandomName()
		if err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to generate random name: %v", err))
		}

		nameOffsets[e.Sections[i].Name] = uint32(len(newShstrtab))
		newShstrtab = append(newShstrtab, []byte(randomName)...)
		newShstrtab = append(newShstrtab, 0)

		renamedSections = append(renamedSections, fmt.Sprintf("%s→%s", e.Sections[i].Name, randomName))
		e.Sections[i].Name = randomName
	}

	if len(renamedSections) == 0 {
		return common.NewSkipped("no section names to randomize")
	}

	// Update string table in file
	shstrtabOffset := shstrtabHeader.GetFileOffset()
	copy(e.RawData[shstrtabOffset:shstrtabOffset+uint64(len(newShstrtab))], newShstrtab)

	// Zero remaining bytes if new table is smaller
	if len(newShstrtab) < len(shstrtabContent) {
		for i := len(newShstrtab); i < len(shstrtabContent); i++ {
			e.RawData[shstrtabOffset+uint64(i)] = 0
		}
	}

	// Update section header name offsets
	shOffset := e.readValue(offsets.shOff, e.Is64Bit)
	shEntSize := e.readValue16(offsets.shEntSize)

	for i := uint16(0); i < e.ELF.GetSectionCount(); i++ {
		oldName, err := e.ELF.GetSectionName(i)
		if err != nil {
			continue
		}

		shdrOffset := shOffset + uint64(i)*uint64(shEntSize)
		if shdrOffset >= uint64(len(e.RawData)) {
			continue
		}

		if newOffset, ok := nameOffsets[oldName]; ok {
			if err := WriteAtOffset(e.RawData, shdrOffset, e.GetEndian(), newOffset); err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to write name offset: %v", err))
			}
		}
	}

	message := fmt.Sprintf("renamed sections: %s", strings.Join(renamedSections, ", "))
	return common.NewApplied(message, len(renamedSections))
}

// ObfuscateBaseAddresses randomly modifies virtual base addresses
func (e *ELFFile) ObfuscateBaseAddresses(force bool) *common.OperationResult {
	if err := e.validateELF(); err != nil {
		return common.NewSkipped(fmt.Sprintf("ELF validation failed: %v", err))
	}

	// Base address obfuscation is risky for ELF files
	if !force {
		return common.NewSkipped("base address obfuscation skipped (risky operation, use -f to force)")
	}

	randomOffset, err := generateRandomOffset()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to generate random offset: %v", err))
	}

	offsets := e.getELFOffsets()
	phdrTableOffset := e.readValue(offsets.phOff, e.Is64Bit)
	phdrEntrySize := e.readValue16(offsets.phEntSize)

	modifiedSegments := []string{}

	// Update loadable segments
	for i, segment := range e.Segments {
		if !segment.Loadable {
			continue
		}

		if _, err := e.ELF.GetProgramHeader(segment.Index); err != nil {
			continue
		}

		phdrPos := phdrTableOffset + uint64(segment.Index)*uint64(phdrEntrySize)

		// Update virtual address
		vaddrPos := phdrPos + getVAddrOffset(e.Is64Bit)
		originalVaddr := e.readValue(int(vaddrPos), e.Is64Bit)
		newVaddr := originalVaddr + randomOffset

		if err := e.writeValue(vaddrPos, newVaddr, e.Is64Bit); err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to update virtual address: %v", err))
		}

		// Update physical address
		paddrPos := phdrPos + getPAddrOffset(e.Is64Bit)
		if err := e.writeValue(paddrPos, newVaddr, e.Is64Bit); err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to update physical address: %v", err))
		}

		e.Segments[i].Offset = segment.Offset
		modifiedSegments = append(modifiedSegments, fmt.Sprintf("segment%d(0x%x→0x%x)", i, originalVaddr, newVaddr))
	}

	// Update entry point
	originalEntryPoint := e.readValue(offsets.entryPoint, e.Is64Bit)
	if originalEntryPoint != 0 {
		newEntryPoint := originalEntryPoint + randomOffset
		if err := e.writeValue(uint64(offsets.entryPoint), newEntryPoint, e.Is64Bit); err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to update entry point: %v", err))
		}
		modifiedSegments = append(modifiedSegments, fmt.Sprintf("entry(0x%x→0x%x)", originalEntryPoint, newEntryPoint))
	}

	if len(modifiedSegments) == 0 {
		return common.NewSkipped("no loadable segments or entry point found")
	}

	message := fmt.Sprintf("randomized base addresses: %s", strings.Join(modifiedSegments, ", "))
	return common.NewApplied(message, len(modifiedSegments))
}

// Helper functions for program header offsets
func getVAddrOffset(is64bit bool) uint64 {
	if is64bit {
		return 16
	}
	return 8
}

func getPAddrOffset(is64bit bool) uint64 {
	if is64bit {
		return 24
	}
	return 12
}

// writeValue writes a value to the ELF file
func (e *ELFFile) writeValue(offset, value uint64, is64bit bool) error {
	if is64bit {
		return WriteAtOffset(e.RawData, offset, e.GetEndian(), value)
	}
	return WriteAtOffset(e.RawData, offset, e.GetEndian(), uint32(value))
}

// ObfuscateSectionPadding randomizes padding between sections
func (e *ELFFile) ObfuscateSectionPadding() *common.OperationResult {
	paddingCount := 0

	for i := 0; i < len(e.Sections)-1; i++ {
		end := e.Sections[i].Offset + e.Sections[i].Size
		next := e.Sections[i+1].Offset

		if end < next && next-end < 0x10000 && end > 0 {
			paddingSize := int(next - end)
			randomPadding := make([]byte, paddingSize)
			if _, err := rand.Read(randomPadding); err == nil {
				copy(e.RawData[end:next], randomPadding)
				paddingCount++
			}
		}
	}

	if paddingCount == 0 {
		return common.NewSkipped("no section padding found to obfuscate")
	}

	return common.NewApplied(fmt.Sprintf("obfuscated padding between %d section pairs", paddingCount), paddingCount)
}

// ObfuscateReservedHeaderFields randomizes reserved fields in ELF header
func (e *ELFFile) ObfuscateReservedHeaderFields() *common.OperationResult {
	modifiedFields := []string{}

	// Randomize e_ident[9:16] (padding)
	randBytes := make([]byte, 7)
	if _, err := rand.Read(randBytes); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to generate random header bytes: %v", err))
	}
	copy(e.RawData[9:16], randBytes)
	modifiedFields = append(modifiedFields, "header padding")

	// Randomize e_flags
	offsets := e.getELFOffsets()
	if offsets.flags+4 <= len(e.RawData) {
		randFlags := make([]byte, 4)
		if _, err := rand.Read(randFlags); err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to generate random flags: %v", err))
		}
		copy(e.RawData[offsets.flags:offsets.flags+4], randFlags)
		modifiedFields = append(modifiedFields, "processor flags")
	}

	if len(modifiedFields) == 0 {
		return common.NewSkipped("no header fields available for obfuscation")
	}

	message := fmt.Sprintf("obfuscated reserved header fields: %s", strings.Join(modifiedFields, ", "))
	return common.NewApplied(message, len(modifiedFields))
}

// ObfuscateSecondaryTimestamps randomizes timestamps in note/debug sections
func (e *ELFFile) ObfuscateSecondaryTimestamps() *common.OperationResult {
	timestampSections := []string{".note", ".note.gnu.build-id", ".comment"}
	sections := e.findSections(timestampSections)

	obfuscatedSections := []string{}
	for name, section := range sections {
		if section == nil {
			continue
		}

		if err := e.obfuscateTimestampsInSection(section); err != nil {
			continue // Skip sections that fail
		}
		obfuscatedSections = append(obfuscatedSections, name)
	}

	if len(obfuscatedSections) == 0 {
		return common.NewSkipped("no timestamp sections found")
	}

	message := fmt.Sprintf("obfuscated timestamps in sections: %s", strings.Join(obfuscatedSections, ", "))
	return common.NewApplied(message, len(obfuscatedSections))
}

// obfuscateTimestampsInSection randomizes timestamps in a section
func (e *ELFFile) obfuscateTimestampsInSection(section *Section) error {
	data, err := e.ReadBytes(section.Offset, int(section.Size))
	if err != nil || len(data) < 4 {
		return nil
	}

	for i := 0; i+4 <= len(data); i += 4 {
		randBytes := make([]byte, 4)
		if _, err := rand.Read(randBytes); err != nil {
			return fmt.Errorf("failed to generate random timestamp: %w", err)
		}
		copy(data[i:i+4], randBytes)
	}

	copy(e.RawData[section.Offset:section.Offset+uint64(len(data))], data)
	return nil
}

// ObfuscateAll applies all obfuscation techniques
func (e *ELFFile) ObfuscateAll(force bool) *common.OperationResult {
	if err := e.validateELF(); err != nil {
		return common.NewSkipped(fmt.Sprintf("ELF validation failed: %v", err))
	}

	// Check if this is a Go binary BEFORE any obfuscation
	isGoBinary := e.isGoBinary()

	obfuscationSteps := []struct {
		name string
		fn   func() *common.OperationResult
	}{
		{"RenameSectionNames", e.RandomizeSectionNames},
		{"ObfuscateBaseAddresses", func() *common.OperationResult {
			if isGoBinary && !force {
				return common.NewSkipped("skipping base address randomization for Go binary (would break runtime, use -f to force)")
			}
			return e.ObfuscateBaseAddresses(force)
		}},
		{"ObfuscateReservedHeaderFields", e.ObfuscateReservedHeaderFields},
		{"ObfuscateSecondaryTimestamps", e.ObfuscateSecondaryTimestamps},
		{"ObfuscateSectionPadding", e.ObfuscateSectionPadding},
	}

	appliedOperations := []string{}
	totalCount := 0

	for _, step := range obfuscationSteps {
		result := step.fn()
		if result.Applied {
			appliedOperations = append(appliedOperations, result.Message)
			totalCount += result.Count
		}
	}

	if len(appliedOperations) == 0 {
		return common.NewSkipped("no obfuscation operations could be applied")
	}

	message := fmt.Sprintf("applied obfuscation: %s", strings.Join(appliedOperations, "; "))
	return common.NewApplied(message, totalCount)
}
