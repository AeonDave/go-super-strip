package perw

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
)

const (
	dosHeaderSize        = 0x40
	peSignatureSize      = 4
	coffHeaderSize       = 20
	sectionHeaderSize    = 40
	sectionNameSize      = 8
	maxPaddingSize       = 0x10000
	pageSize             = 0x10000
	randomOffsetMultiple = 0x10000
	importDescriptorSize = 20 // Size of IMAGE_IMPORT_DESCRIPTOR
	thunkDataSize32      = 4  // Size of IMAGE_THUNK_DATA32
	thunkDataSize64      = 8  // Size of IMAGE_THUNK_DATA64
)

// PE directory table offsets (relative to optional header start)
var directoryOffsets = struct {
	debug, loadConfig, tls, baseReloc, importTable map[bool]int64
}{
	debug:       map[bool]int64{true: 128, false: 112},
	loadConfig:  map[bool]int64{true: 152, false: 136},
	tls:         map[bool]int64{true: 144, false: 128},
	baseReloc:   map[bool]int64{true: 168, false: 152}, // Base Relocation Table is at index 5 in Data Directory
	importTable: map[bool]int64{true: 104, false: 88},  // Import Table is at index 1 in Data Directory
}

// PE header field offsets
var headerOffsets = struct {
	imageBase, loaderFlags map[bool]int64
}{
	imageBase:   map[bool]int64{true: 24, false: 28},
	loaderFlags: map[bool]int64{true: 108, false: 92},
}

// PEOffsets holds commonly used PE file offsets
type PEOffsets struct {
	ELfanew          int64
	OptionalHeader   int64
	FirstSectionHdr  int64
	NumberOfSections int
	OptionalHdrSize  int
}

// calculateOffsets computes all necessary PE file offsets in one pass
func (p *PEFile) calculateOffsets() (*PEOffsets, error) {
	if len(p.RawData) < dosHeaderSize {
		return nil, fmt.Errorf("file too small for DOS header")
	}

	offsets := &PEOffsets{
		ELfanew: int64(binary.LittleEndian.Uint32(p.RawData[0x3C:0x40])),
	}

	coffHeaderOffset := offsets.ELfanew + peSignatureSize
	offsets.OptionalHeader = coffHeaderOffset + coffHeaderSize

	// Validate we can read COFF header fields
	if int(coffHeaderOffset+coffHeaderSize) > len(p.RawData) {
		return nil, fmt.Errorf("file too small for COFF header")
	}

	offsets.NumberOfSections = int(binary.LittleEndian.Uint16(p.RawData[coffHeaderOffset+2 : coffHeaderOffset+4]))
	offsets.OptionalHdrSize = int(binary.LittleEndian.Uint16(p.RawData[coffHeaderOffset+16 : coffHeaderOffset+18]))
	offsets.FirstSectionHdr = offsets.OptionalHeader + int64(offsets.OptionalHdrSize)

	return offsets, nil
}

// validateOffset checks if an offset and size are within file bounds
func (p *PEFile) validateOffset(offset int64, size int) error {
	if int(offset+int64(size)) > len(p.RawData) {
		return fmt.Errorf("offset %d + size %d exceeds file size %d", offset, size, len(p.RawData))
	}
	return nil
}

// generateRandomBytes creates a byte slice of specified size filled with random data
func generateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate %d random bytes: %w", size, err)
	}
	return bytes, nil
}

// hasBaseRelocations checks if the PE file has base relocation table
func (p *PEFile) hasBaseRelocations() bool {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return false
	}

	// Base relocation table is at directory entry index 5
	baseRelocOffset := offsets.OptionalHeader + directoryOffsets.baseReloc[p.Is64Bit]

	if err := p.validateOffset(baseRelocOffset, 8); err != nil {
		return false
	}

	rva := binary.LittleEndian.Uint32(p.RawData[baseRelocOffset:])
	size := binary.LittleEndian.Uint32(p.RawData[baseRelocOffset+4:])

	// Both RVA and Size must be non-zero for valid base relocations
	return rva != 0 && size != 0
}

// ObfuscateBaseAddresses modifies base virtual addresses with a conservative approach
func (p *PEFile) ObfuscateBaseAddresses() error {
	// CRITICAL: Check for base relocations before modifying ImageBase
	if !p.hasBaseRelocations() {
		// Executable has no base relocations - cannot safely change ImageBase
		// This would cause the executable to crash if Windows tries to relocate it
		return nil // Silently skip modification to preserve functionality
	}

	offsets, err := p.calculateOffsets()
	if err != nil {
		return err
	}

	imageBaseOffset := offsets.OptionalHeader + headerOffsets.imageBase[p.Is64Bit]
	wordSize := map[bool]int{true: 8, false: 4}[p.Is64Bit]

	if err := p.validateOffset(imageBaseOffset, wordSize); err != nil {
		return fmt.Errorf("ImageBase offset validation failed: %w", err)
	}

	// Conservative approach: only modify the least significant byte
	// while preserving alignment and valid address ranges
	if p.Is64Bit {
		current := binary.LittleEndian.Uint64(p.RawData[imageBaseOffset:])

		// For 64-bit, ensure we stay in valid user-mode range (< 0x7FF00000000)
		// and maintain 64KB alignment (Windows requirement)
		if current >= 0x7FF00000000 {
			return nil // Don't modify system range addresses
		}

		// Generate a small, aligned offset (multiple of 64KB)
		randBytes, err := generateRandomBytes(2)
		if err != nil {
			return fmt.Errorf("failed to generate random offset: %w", err)
		}

		offset := uint64(randBytes[0]) * 0x10000 // 64KB aligned offset
		newBase := (current & 0xFFFFFFFF0000) + offset

		// Ensure we don't exceed safe ranges
		if newBase < current+0x1000000 && newBase >= 0x10000 {
			return WriteAtOffset(p.RawData, imageBaseOffset, newBase)
		}
	} else {
		current := binary.LittleEndian.Uint32(p.RawData[imageBaseOffset:])

		// For 32-bit, ensure we stay below 2GB and maintain 64KB alignment
		if current >= 0x80000000 {
			return nil // Don't modify high addresses
		}

		randBytes, err := generateRandomBytes(1)
		if err != nil {
			return fmt.Errorf("failed to generate random offset: %w", err)
		}

		offset := uint32(randBytes[0]) * 0x10000 // 64KB aligned
		newBase := (current & 0xFFFF0000) + offset

		if newBase < current+0x10000000 && newBase >= 0x10000 {
			return WriteAtOffset(p.RawData, imageBaseOffset, newBase)
		}
	}

	return nil // Safe fallback: do nothing if conditions aren't met
}

// obfuscateDirectory clears a specific directory entry (generic helper)
func (p *PEFile) obfuscateDirectory(relativeOffset int64) error {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return err
	}

	dirOffset := offsets.OptionalHeader + relativeOffset
	if err := p.validateOffset(dirOffset, 8); err != nil {
		return fmt.Errorf("directory offset validation failed: %w", err)
	}

	// Clear both RVA and Size (8 bytes total)
	if err := WriteAtOffset(p.RawData, dirOffset, uint32(0)); err != nil {
		return err
	}
	return WriteAtOffset(p.RawData, dirOffset+4, uint32(0))
}

// ObfuscateDebugDirectory clears the debug directory
func (p *PEFile) ObfuscateDebugDirectory() error {
	return p.obfuscateDirectory(directoryOffsets.debug[p.Is64Bit])
}

// ObfuscateLoadConfig selectively obfuscates non-critical load configuration fields
func (p *PEFile) ObfuscateLoadConfig() error {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return err
	}

	// Get the load config directory entry
	dirOffset := offsets.OptionalHeader + directoryOffsets.loadConfig[p.Is64Bit]
	if err := p.validateOffset(dirOffset, 8); err != nil {
		return fmt.Errorf("load config directory offset validation failed: %w", err)
	}

	// Read current RVA and Size
	rva := binary.LittleEndian.Uint32(p.RawData[dirOffset:])
	size := binary.LittleEndian.Uint32(p.RawData[dirOffset+4:])

	// If there's no load config, nothing to obfuscate
	if rva == 0 || size == 0 {
		return nil
	}

	// Find the physical offset of the load config structure
	loadConfigPhysical, err := p.rvaToPhysical(uint64(rva))
	if err != nil {
		return fmt.Errorf("failed to convert load config RVA to physical: %w", err)
	}

	// Validate we can access the load config structure
	minSize := uint32(64) // Minimum size for a load config structure
	if size < minSize {
		return nil // Too small, skip
	}

	if err := p.validateOffset(int64(loadConfigPhysical), int(minSize)); err != nil {
		return nil // Can't access safely, skip
	}

	// Obfuscate only non-critical fields that don't affect execution:
	// 1. TimeDateStamp (offset 4, 4 bytes)
	// 2. MajorVersion (offset 8, 2 bytes)
	// 3. MinorVersion (offset 10, 2 bytes)
	// 4. Reserved fields that are actually unused

	// Obfuscate TimeDateStamp
	if size >= 8 {
		randBytes, err := generateRandomBytes(4)
		if err == nil {
			copy(p.RawData[loadConfigPhysical+4:loadConfigPhysical+8], randBytes)
		}
	}

	// Obfuscate Version fields (but keep them reasonable)
	if size >= 12 {
		randBytes, err := generateRandomBytes(4)
		if err == nil {
			// Keep versions in reasonable range (1-255)
			p.RawData[loadConfigPhysical+8] = randBytes[0]%255 + 1  // Major
			p.RawData[loadConfigPhysical+9] = 0                     // Reserved
			p.RawData[loadConfigPhysical+10] = randBytes[1]%255 + 1 // Minor
			p.RawData[loadConfigPhysical+11] = 0                    // Reserved
		}
	}

	return nil
}

// Helper function to convert RVA to physical offset
func (p *PEFile) rvaToPhysical(rva uint64) (uint64, error) {
	for _, section := range p.Sections {
		if rva >= uint64(section.VirtualAddress) &&
			rva < uint64(section.VirtualAddress+section.VirtualSize) {
			offset := rva - uint64(section.VirtualAddress)
			return uint64(section.Offset) + offset, nil
		}
	}
	return 0, fmt.Errorf("RVA %x not found in any section", rva)
}

// ObfuscateTLSDirectory clears the TLS directory
func (p *PEFile) ObfuscateTLSDirectory() error {
	return p.obfuscateDirectory(directoryOffsets.tls[p.Is64Bit])
}

// ObfuscateSection finds and returns a section by name
func (p *PEFile) ObfuscateSection(name string) (*Section, error) {
	for i := range p.Sections {
		if p.Sections[i].Name == name {
			return &p.Sections[i], nil
		}
	}
	return nil, nil
}

// ObfuscateSectionPadding randomizes unused bytes between PE sections
func (p *PEFile) ObfuscateSectionPadding() error {
	for i := 0; i < len(p.Sections)-1; i++ {
		current := &p.Sections[i]
		next := &p.Sections[i+1]

		end := current.Offset + current.Size
		start := next.Offset

		// Validate padding area
		if end >= start || start-end >= maxPaddingSize || end <= 0 {
			continue
		}

		paddingSize := int(start - end)
		randomPadding, err := generateRandomBytes(paddingSize)
		if err != nil {
			return fmt.Errorf("failed to generate padding for section %d: %w", i, err)
		}

		copy(p.RawData[end:start], randomPadding)
	}
	return nil
}

// ObfuscateReservedHeaderFields randomizes reserved/zero fields in PE headers
func (p *PEFile) ObfuscateReservedHeaderFields() error {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return err
	}

	// Randomize DOS header reserved fields (0x1C-0x3B)
	dosReservedStart, dosReservedSize := int64(0x1C), 0x3C-0x1C
	randDOSBytes, err := generateRandomBytes(dosReservedSize)
	if err != nil {
		return fmt.Errorf("failed to generate DOS reserved field bytes: %w", err)
	}
	copy(p.RawData[dosReservedStart:dosReservedStart+int64(dosReservedSize)], randDOSBytes)

	// Randomize LoaderFlags field in optional header
	loaderFlagsOffset := offsets.OptionalHeader + headerOffsets.loaderFlags[p.Is64Bit]
	if err := p.validateOffset(loaderFlagsOffset, 4); err != nil {
		return fmt.Errorf("LoaderFlags offset validation failed: %w", err)
	}

	randLoaderFlags, err := generateRandomBytes(4)
	if err != nil {
		return fmt.Errorf("failed to generate LoaderFlags bytes: %w", err)
	}
	copy(p.RawData[loaderFlagsOffset:loaderFlagsOffset+4], randLoaderFlags)

	return nil
}

// ObfuscateSecondaryTimestamps randomizes timestamp patterns in resource sections
func (p *PEFile) ObfuscateSecondaryTimestamps() error {
	timestampPattern := regexp.MustCompile(`19\d{2}|20\d{2}`)
	targetSections := map[string]bool{".rsrc": true, ".data": true, ".rdata": true}

	for _, section := range p.Sections {
		if !targetSections[section.Name] {
			continue
		}

		data, err := p.ReadBytes(section.Offset, int(section.Size))
		if err != nil || len(data) < 4 {
			continue
		}

		indices := timestampPattern.FindAllIndex(data, -1)
		for _, idx := range indices {
			matchLen := idx[1] - idx[0]
			randDigits, err := generateRandomBytes(matchLen)
			if err != nil {
				return fmt.Errorf("failed to generate timestamp digits for %s: %w", section.Name, err)
			}

			// Convert to digit characters
			for k := range randDigits {
				randDigits[k] = (randDigits[k] % 10) + '0'
			}
			copy(data[idx[0]:idx[1]], randDigits)
		}

		copy(p.RawData[section.Offset:section.Offset+int64(len(data))], data)
	}
	return nil
}

// RandomizeSectionNames changes section names to random strings
func (p *PEFile) RandomizeSectionNames() error {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return err
	}

	for i := 0; i < offsets.NumberOfSections; i++ {
		sectionHeaderOffset := offsets.FirstSectionHdr + int64(i*sectionHeaderSize)
		sectionNameOffset := sectionHeaderOffset

		if err := p.validateOffset(sectionNameOffset, sectionNameSize); err != nil {
			return fmt.Errorf("section name offset validation failed for section %d: %w", i, err)
		}

		// Generate random 7-character name with leading dot
		randBytes, err := generateRandomBytes(7)
		if err != nil {
			return fmt.Errorf("failed to generate random name for section %d: %w", i, err)
		}

		randomName := "."
		for _, b := range randBytes {
			randomName += string(rune('a' + (b % 26)))
		}

		// PE section names are 8 bytes, null-padded
		newNameBytes := make([]byte, sectionNameSize)
		copy(newNameBytes, randomName)
		copy(p.RawData[sectionNameOffset:sectionNameOffset+sectionNameSize], newNameBytes)

		// Update internal structure
		if i < len(p.Sections) {
			p.Sections[i].Name = strings.TrimRight(string(newNameBytes), "\x00")
		}
	}
	return nil
}

// ObfuscateAll applies all obfuscation techniques with improved error context
func (p *PEFile) ObfuscateAll() error {
	operations := []struct {
		name string
		fn   func() error
	}{
		{"randomize section names", p.RandomizeSectionNames},
		{"obfuscate base addresses", p.ObfuscateBaseAddresses}, // RE-ENABLED: Fixed with conservative approach
		{"obfuscate debug directory", p.ObfuscateDebugDirectory},
		{"obfuscate load config", p.ObfuscateLoadConfig}, // RE-ENABLED: Fixed with selective approach
		{"obfuscate TLS directory", p.ObfuscateTLSDirectory},
		{"obfuscate section padding", p.ObfuscateSectionPadding},
		{"obfuscate reserved header fields", p.ObfuscateReservedHeaderFields},
		{"obfuscate secondary timestamps", p.ObfuscateSecondaryTimestamps},
		{"obfuscate import table", p.ObfuscateImportTable},
	}

	for _, op := range operations {
		if err := op.fn(); err != nil {
			return fmt.Errorf("failed to %s: %w", op.name, err)
		}
	}
	return nil
}

// ImportDescriptor represents an IMAGE_IMPORT_DESCRIPTOR
type ImportDescriptor struct {
	OriginalFirstThunk uint32 // RVA to original unbound IAT
	TimeDateStamp      uint32 // 0 if not bound, -1 if bound
	ForwarderChain     uint32 // -1 if no forwarders
	Name               uint32 // RVA of imported DLL name
	FirstThunk         uint32 // RVA to IAT (bound import table)
}

// ObfuscateImportTable applies various obfuscation techniques to the import table
func (p *PEFile) ObfuscateImportTable() error {
	// Get import table directory entry
	offsets, err := p.calculateOffsets()
	if err != nil {
		return err
	}

	importDirOffset := offsets.OptionalHeader + directoryOffsets.importTable[p.Is64Bit]
	if err := p.validateOffset(importDirOffset, 8); err != nil {
		return nil // No import table or can't access safely
	}

	// Read import table RVA and size
	importRVA := binary.LittleEndian.Uint32(p.RawData[importDirOffset:])
	importSize := binary.LittleEndian.Uint32(p.RawData[importDirOffset+4:])

	if importRVA == 0 || importSize == 0 {
		return nil // No import table to obfuscate
	}

	// Convert RVA to physical offset
	importPhysical, err := p.rvaToPhysical(uint64(importRVA))
	if err != nil {
		return fmt.Errorf("failed to convert import table RVA to physical: %w", err)
	}

	// Apply obfuscation techniques
	if err := p.shuffleImportDescriptors(importPhysical, importSize); err != nil {
		return fmt.Errorf("failed to shuffle import descriptors: %w", err)
	}

	if err := p.addFakeImportEntries(importPhysical, importSize); err != nil {
		return fmt.Errorf("failed to add fake import entries: %w", err)
	}

	if err := p.obfuscateImportNames(importPhysical, importSize); err != nil {
		return fmt.Errorf("failed to obfuscate import names: %w", err)
	}

	return nil
}

// shuffleImportDescriptors randomizes the order of import descriptors
func (p *PEFile) shuffleImportDescriptors(importPhysical uint64, importSize uint32) error {
	// Calculate number of descriptors (excluding null terminator)
	numDescriptors := (importSize / importDescriptorSize) - 1
	if numDescriptors <= 1 {
		return nil // Nothing to shuffle
	}

	// Read all descriptors
	descriptors := make([]ImportDescriptor, numDescriptors)
	for i := uint32(0); i < numDescriptors; i++ {
		offset := importPhysical + uint64(i*importDescriptorSize)
		if err := p.validateOffset(int64(offset), importDescriptorSize); err != nil {
			return err
		}

		descriptors[i] = ImportDescriptor{
			OriginalFirstThunk: binary.LittleEndian.Uint32(p.RawData[offset:]),
			TimeDateStamp:      binary.LittleEndian.Uint32(p.RawData[offset+4:]),
			ForwarderChain:     binary.LittleEndian.Uint32(p.RawData[offset+8:]),
			Name:               binary.LittleEndian.Uint32(p.RawData[offset+12:]),
			FirstThunk:         binary.LittleEndian.Uint32(p.RawData[offset+16:]),
		}
	}

	// Shuffle using Fisher-Yates algorithm
	for i := len(descriptors) - 1; i > 0; i-- {
		randBytes, err := generateRandomBytes(1)
		if err != nil {
			return err
		}
		j := int(randBytes[0]) % (i + 1)
		descriptors[i], descriptors[j] = descriptors[j], descriptors[i]
	}

	// Write shuffled descriptors back
	for i, desc := range descriptors {
		offset := importPhysical + uint64(i*importDescriptorSize)
		binary.LittleEndian.PutUint32(p.RawData[offset:], desc.OriginalFirstThunk)
		binary.LittleEndian.PutUint32(p.RawData[offset+4:], desc.TimeDateStamp)
		binary.LittleEndian.PutUint32(p.RawData[offset+8:], desc.ForwarderChain)
		binary.LittleEndian.PutUint32(p.RawData[offset+12:], desc.Name)
		binary.LittleEndian.PutUint32(p.RawData[offset+16:], desc.FirstThunk)
	}

	return nil
}

// addFakeImportEntries adds dummy import descriptors to confuse analysis tools
func (p *PEFile) addFakeImportEntries(importPhysical uint64, importSize uint32) error {
	// For safety, we'll just modify timestamps rather than adding new entries
	// Adding new entries would require relocating the entire import table

	numDescriptors := (importSize / importDescriptorSize) - 1
	if numDescriptors == 0 {
		return nil
	}

	// Randomize timestamps in existing descriptors
	for i := uint32(0); i < numDescriptors; i++ {
		offset := importPhysical + uint64(i*importDescriptorSize) + 4 // TimeDateStamp offset
		if err := p.validateOffset(int64(offset), 4); err != nil {
			continue
		}

		// Generate random timestamp (avoiding 0 and -1 which have special meaning)
		randBytes, err := generateRandomBytes(4)
		if err != nil {
			continue
		}

		timestamp := binary.LittleEndian.Uint32(randBytes)
		if timestamp == 0 || timestamp == 0xFFFFFFFF {
			timestamp = 0x12345678 // Safe fallback
		}

		binary.LittleEndian.PutUint32(p.RawData[offset:], timestamp)
	}

	return nil
}

// obfuscateImportNames applies obfuscation to import table strings (conservative approach)
func (p *PEFile) obfuscateImportNames(importPhysical uint64, importSize uint32) error {
	// This is a conservative implementation that only modifies non-critical metadata
	// We avoid changing actual DLL names or function names to prevent breaking functionality

	numDescriptors := (importSize / importDescriptorSize) - 1
	if numDescriptors == 0 {
		return nil
	}

	// Only modify ForwarderChain field (usually unused)
	for i := uint32(0); i < numDescriptors; i++ {
		offset := importPhysical + uint64(i*importDescriptorSize) + 8 // ForwarderChain offset
		if err := p.validateOffset(int64(offset), 4); err != nil {
			continue
		}

		// Read current value
		current := binary.LittleEndian.Uint32(p.RawData[offset:])

		// If it's already -1 (unused), randomize it
		if current == 0xFFFFFFFF {
			randBytes, err := generateRandomBytes(4)
			if err != nil {
				continue
			}

			// Ensure we don't accidentally create a valid forwarder chain
			randomValue := binary.LittleEndian.Uint32(randBytes)
			if randomValue != 0xFFFFFFFF {
				randomValue |= 0x80000000 // Set high bit to indicate it's not a real forwarder
			}

			binary.LittleEndian.PutUint32(p.RawData[offset:], randomValue)
		}
	}

	return nil
}

// ObfuscateImportNames provides more aggressive import name obfuscation by randomizing function names
// This is more aggressive than the conservative obfuscateImportNames used in ObfuscateImportTable
func (p *PEFile) ObfuscateImportNames() error {
	// Get import table directory entry
	offsets, err := p.calculateOffsets()
	if err != nil {
		return err
	}

	importDirOffset := offsets.OptionalHeader + directoryOffsets.importTable[p.Is64Bit]
	if err := p.validateOffset(importDirOffset, 8); err != nil {
		return nil // No import table or can't access safely
	}

	// Read import table RVA and size
	importRVA := binary.LittleEndian.Uint32(p.RawData[importDirOffset:])
	importSize := binary.LittleEndian.Uint32(p.RawData[importDirOffset+4:])

	if importRVA == 0 || importSize == 0 {
		return nil // No import table to obfuscate
	}

	// Convert RVA to physical offset
	importPhysical, err := p.rvaToPhysical(uint64(importRVA))
	if err != nil {
		return fmt.Errorf("failed to convert import table RVA to physical: %w", err)
	}

	return p.obfuscateImportNamesAggressive(importPhysical, importSize)
}

// obfuscateImportNamesAggressive applies more aggressive import name obfuscation
func (p *PEFile) obfuscateImportNamesAggressive(importPhysical uint64, importSize uint32) error {
	numDescriptors := (importSize / importDescriptorSize) - 1
	if numDescriptors == 0 {
		return nil
	}

	// Process each import descriptor
	for i := uint32(0); i < numDescriptors; i++ {
		descOffset := importPhysical + uint64(i*importDescriptorSize)
		if err := p.validateOffset(int64(descOffset), importDescriptorSize); err != nil {
			continue
		}

		// Get the OriginalFirstThunk (Import Name Table) RVA
		originalFirstThunk := binary.LittleEndian.Uint32(p.RawData[descOffset:])
		if originalFirstThunk == 0 {
			continue // No import name table
		}

		// Convert RVA to physical offset
		intPhysical, err := p.rvaToPhysical(uint64(originalFirstThunk))
		if err != nil {
			continue // Can't access import name table
		}

		// Process the Import Name Table
		if err := p.obfuscateImportNameTable(intPhysical); err != nil {
			// Don't fail the entire operation if one table fails
			continue
		}
	}

	return nil
}

// obfuscateImportNameTable obfuscates function names in an Import Name Table
func (p *PEFile) obfuscateImportNameTable(intPhysical uint64) error {
	ptrSize := map[bool]int{true: 8, false: 4}[p.Is64Bit]

	for offset := intPhysical; ; offset += uint64(ptrSize) {
		if err := p.validateOffset(int64(offset), ptrSize); err != nil {
			break
		}

		// Read the thunk value
		var thunkValue uint64
		if p.Is64Bit {
			thunkValue = binary.LittleEndian.Uint64(p.RawData[offset:])
		} else {
			thunkValue = uint64(binary.LittleEndian.Uint32(p.RawData[offset:]))
		}

		// Check for end of table
		if thunkValue == 0 {
			break
		}

		// Check if it's an ordinal import (high bit set)
		if (p.Is64Bit && (thunkValue&0x8000000000000000) != 0) ||
			(!p.Is64Bit && (thunkValue&0x80000000) != 0) {
			continue // Skip ordinal imports
		}

		// It's a name import - get the hint/name table entry
		hintNameRVA := thunkValue
		hintNamePhysical, err := p.rvaToPhysical(hintNameRVA)
		if err != nil {
			continue
		}

		// Obfuscate the function name (skip the 2-byte hint)
		if err := p.obfuscateFunctionName(hintNamePhysical + 2); err != nil {
			continue
		}
	}

	return nil
}

// obfuscateFunctionName randomizes a null-terminated function name
func (p *PEFile) obfuscateFunctionName(namePhysical uint64) error {
	if err := p.validateOffset(int64(namePhysical), 1); err != nil {
		return err
	}

	// Find the length of the original name
	nameLen := 0
	for i := namePhysical; int(i) < len(p.RawData); i++ {
		if p.RawData[i] == 0 {
			break
		}
		nameLen++
	}

	if nameLen == 0 || nameLen > 255 {
		return nil // Invalid name length
	}

	// Generate a random name of the same length
	randomName, err := p.generateRandomFunctionName(nameLen)
	if err != nil {
		return err
	}

	// Replace the function name (preserve null terminator)
	copy(p.RawData[namePhysical:namePhysical+uint64(nameLen)], randomName)

	return nil
}

// generateRandomFunctionName creates a random function name of specified length
func (p *PEFile) generateRandomFunctionName(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("invalid length: %d", length)
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
	result := make([]byte, length)

	// First character should be a letter or underscore
	randBytes, err := generateRandomBytes(length)
	if err != nil {
		return nil, err
	}

	// First character from letters/underscore only
	firstCharset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
	result[0] = firstCharset[randBytes[0]%byte(len(firstCharset))]

	// Remaining characters can be any valid identifier character
	for i := 1; i < length; i++ {
		result[i] = charset[randBytes[i]%byte(len(charset))]
	}

	return result, nil
}
