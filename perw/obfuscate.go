package perw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"regexp"
	"strings"
)

const (
	dosHeaderSize        = 0x40
	sectionHeaderSize    = 40
	sectionNameSize      = 8
	maxPaddingSize       = 0x10000
	importDescriptorSize = 20 // Size of IMAGE_IMPORT_DESCRIPTOR
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
func (p *PEFile) ObfuscateBaseAddresses() *common.OperationResult {
	// CRITICAL: Check for base relocations before modifying ImageBase
	if !p.hasBaseRelocations() {
		return common.NewSkipped("no base relocations found (would break executable)")
	}

	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}

	imageBaseOffset := offsets.OptionalHeader + headerOffsets.imageBase[p.Is64Bit]
	wordSize := map[bool]int{true: 8, false: 4}[p.Is64Bit]

	if err := p.validateOffset(imageBaseOffset, wordSize); err != nil {
		return common.NewSkipped(fmt.Sprintf("ImageBase offset validation failed: %v", err))
	}

	// Conservative approach: only modify the least significant byte
	// while preserving alignment and valid address ranges
	if p.Is64Bit {
		current := binary.LittleEndian.Uint64(p.RawData[imageBaseOffset:])

		// For 64-bit, ensure we stay in valid user-mode range (< 0x7FF00000000)
		// and maintain 64KB alignment (Windows requirement)
		if current >= 0x7FF00000000 {
			return common.NewSkipped("address in system range, unsafe to modify")
		}

		// Generate a small, aligned offset (multiple of 64KB)
		randBytes, err := common.GenerateRandomBytes(2)
		if err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to generate random offset: %v", err))
		}

		offset := uint64(randBytes[0]) * 0x10000 // 64KB aligned offset
		newBase := (current & 0xFFFFFFFF0000) + offset

		// Ensure we don't exceed safe ranges
		if newBase < current+0x1000000 && newBase >= 0x10000 {
			if err := WriteAtOffset(p.RawData, imageBaseOffset, newBase); err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to write new base address: %v", err))
			}
			return common.NewApplied(fmt.Sprintf("changed ImageBase from 0x%X to 0x%X", current, newBase), 1)
		}
	} else {
		current := binary.LittleEndian.Uint32(p.RawData[imageBaseOffset:])

		// For 32-bit, ensure we stay below 2GB and maintain 64KB alignment
		if current >= 0x80000000 {
			return common.NewSkipped("address too high for 32-bit, unsafe to modify")
		}

		randBytes, err := common.GenerateRandomBytes(1)
		if err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to generate random offset: %v", err))
		}

		offset := uint32(randBytes[0]) * 0x10000 // 64KB aligned
		newBase := (current & 0xFFFF0000) + offset

		if newBase < current+0x10000000 && newBase >= 0x10000 {
			if err := WriteAtOffset(p.RawData, imageBaseOffset, newBase); err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to write new base address: %v", err))
			}
			return common.NewApplied(fmt.Sprintf("changed ImageBase from 0x%X to 0x%X", current, newBase), 1)
		}
	}
	return common.NewSkipped("conditions not met for safe modification")
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
func (p *PEFile) ObfuscateLoadConfig() *common.OperationResult {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}

	// Get the load config directory entry
	dirOffset := offsets.OptionalHeader + directoryOffsets.loadConfig[p.Is64Bit]
	if err := p.validateOffset(dirOffset, 8); err != nil {
		return common.NewSkipped(fmt.Sprintf("load config directory offset validation failed: %v", err))
	}

	// Read current RVA and Size
	rva := binary.LittleEndian.Uint32(p.RawData[dirOffset:])
	size := binary.LittleEndian.Uint32(p.RawData[dirOffset+4:])

	// If there's no load config, nothing to obfuscate
	if rva == 0 || size == 0 {
		return common.NewSkipped("no load configuration directory found")
	}

	// Find the physical offset of the load config structure
	loadConfigPhysical, err := p.rvaToPhysical(uint64(rva))
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to convert load config RVA to physical: %v", err))
	}

	// Validate we can access the load config structure
	minSize := uint32(64) // Minimum size for a load config structure
	if size < minSize {
		return common.NewSkipped("load configuration structure too small")
	}

	if err := p.validateOffset(int64(loadConfigPhysical), int(minSize)); err != nil {
		return common.NewSkipped("load configuration structure not accessible")
	}

	modifications := 0

	// Obfuscate only non-critical fields that don't affect execution:
	// 1. TimeDateStamp (offset 4, 4 bytes)
	// 2. MajorVersion (offset 8, 2 bytes)
	// 3. MinorVersion (offset 10, 2 bytes)
	// 4. Reserved fields that are actually unused

	// Obfuscate TimeDateStamp
	if size >= 8 {
		randBytes, err := common.GenerateRandomBytes(4)
		if err == nil {
			copy(p.RawData[loadConfigPhysical+4:loadConfigPhysical+8], randBytes)
			modifications++
		}
	}

	// Obfuscate Version fields (but keep them reasonable)
	if size >= 12 {
		randBytes, err := common.GenerateRandomBytes(4)
		if err == nil {
			// Keep versions in reasonable range (1-255)
			p.RawData[loadConfigPhysical+8] = randBytes[0]%255 + 1  // Major
			p.RawData[loadConfigPhysical+9] = 0                     // Reserved
			p.RawData[loadConfigPhysical+10] = randBytes[1]%255 + 1 // Minor
			p.RawData[loadConfigPhysical+11] = 0                    // Reserved
			modifications++
		}
	}

	if modifications > 0 {
		return common.NewApplied(fmt.Sprintf("obfuscated %d load configuration fields", modifications), modifications)
	}
	return common.NewSkipped("no load configuration fields could be obfuscated")
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
		randomPadding, err := common.GenerateRandomBytes(paddingSize)
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
	randDOSBytes, err := common.GenerateRandomBytes(dosReservedSize)
	if err != nil {
		return fmt.Errorf("failed to generate DOS reserved field bytes: %w", err)
	}
	copy(p.RawData[dosReservedStart:dosReservedStart+int64(dosReservedSize)], randDOSBytes)

	// Randomize LoaderFlags field in optional header
	loaderFlagsOffset := offsets.OptionalHeader + headerOffsets.loaderFlags[p.Is64Bit]
	if err := p.validateOffset(loaderFlagsOffset, 4); err != nil {
		return fmt.Errorf("LoaderFlags offset validation failed: %w", err)
	}

	randLoaderFlags, err := common.GenerateRandomBytes(4)
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
			randDigits, err := common.GenerateRandomBytes(matchLen)
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
func (p *PEFile) RandomizeSectionNames() *common.OperationResult {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}

	if offsets.NumberOfSections == 0 {
		return common.NewSkipped("no sections found")
	}

	var renamedSections []string
	for i := 0; i < offsets.NumberOfSections; i++ {
		sectionHeaderOffset := offsets.FirstSectionHdr + int64(i*sectionHeaderSize)
		sectionNameOffset := sectionHeaderOffset

		if err := p.validateOffset(sectionNameOffset, sectionNameSize); err != nil {
			return common.NewSkipped(fmt.Sprintf("section name offset validation failed for section %d: %v", i, err))
		}

		// Get original name
		originalName := ""
		if i < len(p.Sections) {
			originalName = p.Sections[i].Name
		}

		// Generate random 7-character name with leading dot
		randBytes, err := common.GenerateRandomBytes(7)
		if err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to generate random name for section %d: %v", i, err))
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

		if originalName != "" {
			renamedSections = append(renamedSections, fmt.Sprintf("%s→%s", originalName, randomName))
		} else {
			renamedSections = append(renamedSections, randomName)
		}
	}

	message := fmt.Sprintf("renamed sections: %s", strings.Join(renamedSections, ", "))
	return common.NewApplied(message, len(renamedSections))
}

// ObfuscateAll applies all obfuscation techniques with improved error context
func (p *PEFile) ObfuscateAll() *common.OperationResult {
	operations := []struct {
		name string
		fn   func() *common.OperationResult
	}{
		{"randomize section names", p.RandomizeSectionNames},
		{"obfuscate base addresses", p.ObfuscateBaseAddresses},
		{"obfuscate load config", p.ObfuscateLoadConfig},
		{"obfuscate import table", p.ObfuscateImportTable},
		{"obfuscate rich header", p.ObfuscateRichHeader},
		{"obfuscate resource directory", p.ObfuscateResourceDirectory},
		{"obfuscate export table", p.ObfuscateExportTable},
	}

	totalApplied := 0
	appliedOperations := []string{}
	skippedOperations := []string{}

	for _, op := range operations {
		result := op.fn()
		if result.Applied {
			totalApplied += result.Count
			appliedOperations = append(appliedOperations, op.name)
		} else {
			skippedOperations = append(skippedOperations, fmt.Sprintf("%s (%s)", op.name, result.Message))
		}
	}

	if totalApplied > 0 {
		message := fmt.Sprintf("applied %d techniques: %s", len(appliedOperations), strings.Join(appliedOperations, ", "))
		if len(skippedOperations) > 0 {
			message += fmt.Sprintf("; skipped: %s", strings.Join(skippedOperations, ", "))
		}
		return common.NewApplied(message, totalApplied)
	}

	return common.NewSkipped(fmt.Sprintf("all techniques skipped: %s", strings.Join(skippedOperations, ", ")))
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
func (p *PEFile) ObfuscateImportTable() *common.OperationResult {
	// Get import table directory entry
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}

	importDirOffset := offsets.OptionalHeader + directoryOffsets.importTable[p.Is64Bit]
	if err := p.validateOffset(importDirOffset, 8); err != nil {
		return common.NewSkipped("import table directory not accessible")
	}

	// Read import table RVA and size
	importRVA := binary.LittleEndian.Uint32(p.RawData[importDirOffset:])
	importSize := binary.LittleEndian.Uint32(p.RawData[importDirOffset+4:])

	if importRVA == 0 || importSize == 0 {
		return common.NewSkipped("no import table found")
	}

	// Convert RVA to physical offset
	importPhysical, err := p.rvaToPhysical(uint64(importRVA))
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to convert import RVA to physical: %v", err))
	}

	modifications := 0

	// Apply obfuscation techniques
	if err := p.shuffleImportDescriptors(importPhysical, importSize); err == nil {
		modifications++
	}

	if err := p.addFakeImportEntries(importPhysical, importSize); err == nil {
		modifications++
	}

	if err := p.obfuscateImportNames(importPhysical, importSize); err == nil {
		modifications++
	}

	if modifications > 0 {
		return common.NewApplied(fmt.Sprintf("applied %d import table obfuscation techniques", modifications), modifications)
	}
	return common.NewSkipped("no import table obfuscation could be applied")
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
		randBytes, err := common.GenerateRandomBytes(1)
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
		randBytes, err := common.GenerateRandomBytes(4)
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
			randBytes, err := common.GenerateRandomBytes(4)
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
func (p *PEFile) ObfuscateImportNames() *common.OperationResult {
	// Get import table directory entry
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}

	importDirOffset := offsets.OptionalHeader + directoryOffsets.importTable[p.Is64Bit]
	if err := p.validateOffset(importDirOffset, 8); err != nil {
		return common.NewSkipped("import table directory not accessible")
	}

	// Read import table RVA and size
	importRVA := binary.LittleEndian.Uint32(p.RawData[importDirOffset:])
	importSize := binary.LittleEndian.Uint32(p.RawData[importDirOffset+4:])

	if importRVA == 0 || importSize == 0 {
		return common.NewSkipped("no import table found")
	}

	// Convert RVA to physical offset
	importPhysical, err := p.rvaToPhysical(uint64(importRVA))
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to convert import RVA to physical: %v", err))
	}

	if err := p.obfuscateImportNamesAggressive(importPhysical, importSize); err != nil {
		return common.NewSkipped(fmt.Sprintf("import name obfuscation failed: %v", err))
	}
	return common.NewApplied("obfuscated import function names", 1)
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
	randBytes, err := common.GenerateRandomBytes(length)
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

// ObfuscateRichHeader removes or modifies the Rich Header (hidden Microsoft compilation metadata)
func (p *PEFile) ObfuscateRichHeader() *common.OperationResult {
	// Rich Header is located between DOS header and PE header
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}

	// Search for Rich Header signature "Rich" (0x68636952)
	richSignature := []byte{0x52, 0x69, 0x63, 0x68} // "Rich" in little endian

	// Search in the area between DOS header end and PE header start
	searchStart := int64(dosHeaderSize)
	searchEnd := offsets.ELfanew

	if searchEnd <= searchStart {
		return common.NewSkipped("no space for Rich Header")
	}

	for i := searchStart; i < searchEnd-3; i++ {
		if err := p.validateOffset(i, 4); err != nil {
			continue
		}

		if bytes.Equal(p.RawData[i:i+4], richSignature) {
			// Found Rich Header, now find the start (DanS signature)
			dansSignature := []byte{0x44, 0x61, 0x6E, 0x53} // "DanS"

			// Search backwards for DanS
			for j := i - 4; j >= searchStart; j -= 4 {
				if err := p.validateOffset(j, 4); err != nil {
					continue
				}

				if bytes.Equal(p.RawData[j:j+4], dansSignature) {
					// Found complete Rich Header from j to i+8 (including checksum)
					headerSize := int(i + 8 - j)
					if err := p.validateOffset(j, headerSize); err != nil {
						return common.NewSkipped("Rich Header not accessible")
					}

					// Option 1: Zero out the entire Rich Header
					for k := 0; k < headerSize; k++ {
						p.RawData[j+int64(k)] = 0x00
					}

					return common.NewApplied(fmt.Sprintf("removed Rich Header (%d bytes)", headerSize), 1)
				}
			}
		}
	}

	return common.NewSkipped("no Rich Header found")
}

// ObfuscateResourceDirectory modifies resource section metadata
func (p *PEFile) ObfuscateResourceDirectory() *common.OperationResult {
	// Find resource section (.rsrc)
	section := p.findSectionByName(".rsrc")
	if section == nil {
		return common.NewSkipped("no resource section found")
	}

	if section.Size == 0 {
		return common.NewSkipped("empty resource section")
	}

	// Resource directory starts at the beginning of .rsrc section
	resourceStart := section.Offset

	if err := p.validateOffset(resourceStart, 16); err != nil {
		return common.NewSkipped("resource directory not accessible")
	}

	modifications := 0

	// Resource directory header (IMAGE_RESOURCE_DIRECTORY)
	// Offset 0: Characteristics (4 bytes) - usually 0
	// Offset 4: TimeDateStamp (4 bytes) - we can randomize this
	// Offset 8: MajorVersion (2 bytes) - we can randomize this
	// Offset 10: MinorVersion (2 bytes) - we can randomize this
	// Offset 12: NumberOfNameEntries (2 bytes) - don't touch
	// Offset 14: NumberOfIdEntries (2 bytes) - don't touch

	// Randomize timestamp
	randBytes, err := common.GenerateRandomBytes(4)
	if err == nil {
		copy(p.RawData[resourceStart+4:resourceStart+8], randBytes)
		modifications++
	}

	// Randomize version numbers (keep them reasonable)
	randBytes, err = common.GenerateRandomBytes(4)
	if err == nil {
		majorVer := uint16(randBytes[0] % 16)  // 0-15
		minorVer := uint16(randBytes[1] % 100) // 0-99
		binary.LittleEndian.PutUint16(p.RawData[resourceStart+8:], majorVer)
		binary.LittleEndian.PutUint16(p.RawData[resourceStart+10:], minorVer)
		modifications++
	}

	if modifications > 0 {
		return common.NewApplied(fmt.Sprintf("obfuscated %d resource directory fields", modifications), modifications)
	}
	return common.NewSkipped("no resource directory fields could be obfuscated")
}

// ObfuscateExportTable modifies export table metadata (for DLLs mainly)
func (p *PEFile) ObfuscateExportTable() *common.OperationResult {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}

	// Export table is at directory entry index 0
	exportDirOffset := offsets.OptionalHeader + 96 // Export table is always at offset 96 for both 32/64-bit
	if p.Is64Bit {
		exportDirOffset = offsets.OptionalHeader + 112
	}

	if err := p.validateOffset(exportDirOffset, 8); err != nil {
		return common.NewSkipped("export table directory not accessible")
	}

	// Read export table RVA and size
	exportRVA := binary.LittleEndian.Uint32(p.RawData[exportDirOffset:])
	exportSize := binary.LittleEndian.Uint32(p.RawData[exportDirOffset+4:])

	if exportRVA == 0 || exportSize == 0 {
		return common.NewSkipped("no export table found")
	}

	// Convert RVA to physical offset
	exportPhysical, err := p.rvaToPhysical(uint64(exportRVA))
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to convert export RVA to physical: %v", err))
	}

	if err := p.validateOffset(int64(exportPhysical), 40); err != nil {
		return common.NewSkipped("export directory not accessible")
	}

	modifications := 0

	// IMAGE_EXPORT_DIRECTORY structure:
	// Offset 4: TimeDateStamp - randomize this
	// Offset 8: MajorVersion - randomize
	// Offset 10: MinorVersion - randomize

	// Randomize timestamp
	randBytes, err := common.GenerateRandomBytes(4)
	if err == nil {
		copy(p.RawData[exportPhysical+4:exportPhysical+8], randBytes)
		modifications++
	}

	// Randomize version
	randBytes, err = common.GenerateRandomBytes(4)
	if err == nil {
		majorVer := uint16(randBytes[0] % 16)
		minorVer := uint16(randBytes[1] % 100)
		binary.LittleEndian.PutUint16(p.RawData[exportPhysical+8:], majorVer)
		binary.LittleEndian.PutUint16(p.RawData[exportPhysical+10:], minorVer)
		modifications++
	}

	if modifications > 0 {
		return common.NewApplied(fmt.Sprintf("obfuscated %d export table fields", modifications), modifications)
	}
	return common.NewSkipped("no export table fields could be obfuscated")
}
