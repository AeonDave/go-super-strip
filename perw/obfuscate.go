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
	dosHeaderSize     = 0x40
	sectionHeaderSize = 40
	sectionNameSize   = 8
	maxPaddingSize    = 0x10000
)

// PE directory table offsets (relative to optional header start)
var directoryOffsets = struct {
	debug, loadConfig, tls, baseReloc, importTable map[bool]int64
}{
	debug:       map[bool]int64{true: 128, false: 112},
	loadConfig:  map[bool]int64{true: 152, false: 136},
	tls:         map[bool]int64{true: 144, false: 128},
	baseReloc:   map[bool]int64{true: 168, false: 152},
	importTable: map[bool]int64{true: 104, false: 88},
}

// PE header field offsets
var headerOffsets = struct {
	imageBase, loaderFlags map[bool]int64
}{
	imageBase:   map[bool]int64{true: 24, false: 28},
	loaderFlags: map[bool]int64{true: 108, false: 92},
}

// ImportDescriptor represents an IMAGE_IMPORT_DESCRIPTOR
type ImportDescriptor struct {
	OriginalFirstThunk uint32 // RVA to original unbound IAT
	TimeDateStamp      uint32 // 0 if not bound, -1 if bound
	ForwarderChain     uint32 // -1 if no forwarders
	Name               uint32 // RVA of imported DLL name
	FirstThunk         uint32 // RVA to IAT (bound import table)
}

// True se il file ha la relocation table
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

// Offusca l'ImageBase in modo molto sicuro
func (p *PEFile) ObfuscateBaseAddresses() *common.OperationResult {
	// CRITICAL: Check for base relocations before modifying ImageBase
	if !p.hasBaseRelocations() {
		return common.NewSkipped("no base relocations found (changing ImageBase would break executable)")
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

	// Approccio ultra-conservativo: solo piccole modifiche allineate
	if p.Is64Bit {
		current := binary.LittleEndian.Uint64(p.RawData[imageBaseOffset:])

		// Controlli di sicurezza molto stringenti per 64-bit
		if current >= 0x7FF00000000 || current < 0x140000000 {
			return common.NewSkipped("address outside safe modification range")
		}

		// Modifica solo gli ultimi 16 bit, mantenendo allineamento 64KB
		randBytes, err := common.GenerateRandomBytes(1)
		if err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to generate random offset: %v", err))
		}

		// Offset molto piccolo, multiplo di 64KB (solo 0-15 * 64KB = max 960KB)
		offset := uint64(randBytes[0]&0x0F) * 0x10000
		newBase := (current & 0xFFFFFFFFFFF00000) + offset

		// Verifica finale di sicurezza - differenza massima di 1MB
		if newBase >= current-0x100000 && newBase <= current+0x100000 && newBase >= 0x10000 {
			if err := WriteAtOffset(p.RawData, imageBaseOffset, newBase); err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to write new base address: %v", err))
			}
			return common.NewApplied(fmt.Sprintf("changed ImageBase from 0x%X to 0x%X", current, newBase), 1)
		}
	} else {
		current := binary.LittleEndian.Uint32(p.RawData[imageBaseOffset:])

		// Controlli di sicurezza molto stringenti per 32-bit
		if current >= 0x80000000 || current < 0x400000 {
			return common.NewSkipped("address outside safe modification range")
		}

		randBytes, err := common.GenerateRandomBytes(1)
		if err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to generate random offset: %v", err))
		}

		// Offset piccolo per 32-bit (solo 0-15 * 64KB)
		offset := uint32(randBytes[0]&0x0F) * 0x10000
		newBase := (current & 0xFFF00000) + offset

		// Verifica finale - differenza massima di 16MB
		if newBase >= current-0x1000000 && newBase <= current+0x1000000 && newBase >= 0x10000 {
			if err := WriteAtOffset(p.RawData, imageBaseOffset, newBase); err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to write new base address: %v", err))
			}
			return common.NewApplied(fmt.Sprintf("changed ImageBase from 0x%X to 0x%X", current, newBase), 1)
		}
	}
	return common.NewSkipped("conditions not met for safe modification")
}

// Pulisce una directory entry specifica
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

// Pulisce la debug directory
func (p *PEFile) ObfuscateDebugDirectory() error {
	return p.obfuscateDirectory(directoryOffsets.debug[p.Is64Bit])
}

// Offusca campi non critici della load config
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

	// Obfuscate non-critical fields that don't affect execution:
	// 1. TimeDateStamp (offset 4, 4 bytes) - randomize
	// 2. MajorVersion (offset 8, 2 bytes) - randomize
	// 3. MinorVersion (offset 10, 2 bytes) - randomize
	// These fields are safe to modify without breaking functionality

	// Randomize TimeDateStamp
	if size >= 8 {
		randBytes, err := common.GenerateRandomBytes(4)
		if err == nil {
			binary.LittleEndian.PutUint32(p.RawData[loadConfigPhysical+4:], binary.LittleEndian.Uint32(randBytes))
			modifications++
		}
	}

	// Randomize Version fields
	if size >= 12 {
		randBytes, err := common.GenerateRandomBytes(4)
		if err == nil {
			// MajorVersion (2 bytes at offset 8)
			binary.LittleEndian.PutUint16(p.RawData[loadConfigPhysical+8:], binary.LittleEndian.Uint16(randBytes[0:2]))
			// MinorVersion (2 bytes at offset 10)
			binary.LittleEndian.PutUint16(p.RawData[loadConfigPhysical+10:], binary.LittleEndian.Uint16(randBytes[2:4]))
			modifications++
		}
	}

	if modifications > 0 {
		return common.NewApplied(fmt.Sprintf("obfuscated %d load configuration fields", modifications), modifications)
	}
	return common.NewSkipped("no load configuration fields could be obfuscated")
}

// Converte RVA in offset fisico
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

// Pulisce la TLS directory
func (p *PEFile) ObfuscateTLSDirectory() error {
	return p.obfuscateDirectory(directoryOffsets.tls[p.Is64Bit])
}

// Randomizza i padding tra le sezioni
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

// Randomizza campi riservati negli header PE
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

// Randomizza pattern di timestamp nelle sezioni risorse
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

// Randomizza i nomi delle sezioni con nomi realistici
func (p *PEFile) RandomizeSectionNames() *common.OperationResult {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}

	if offsets.NumberOfSections == 0 {
		return common.NewSkipped("no sections found")
	}

	// Nomi di sezione realistici per evitare sospetti
	realisticNames := []string{
		".text", ".data", ".rdata", ".pdata", ".rsrc", ".reloc",
		".idata", ".edata", ".tls", ".debug", ".bss", ".const",
		".code", ".init", ".fini", ".rodata", ".ctors", ".dtors",
	}

	var renamedSections []string
	usedNames := make(map[string]bool)

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

		// Scegli un nome realistico non ancora usato
		var newName string
		for attempts := 0; attempts < 10; attempts++ {
			randBytes, err := common.GenerateRandomBytes(1)
			if err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to generate random name for section %d: %v", i, err))
			}

			candidateName := realisticNames[randBytes[0]%byte(len(realisticNames))]
			if !usedNames[candidateName] {
				newName = candidateName
				usedNames[candidateName] = true
				break
			}
		}

		// Se non troviamo un nome unico, genera uno casuale
		if newName == "" {
			randBytes, err := common.GenerateRandomBytes(6)
			if err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to generate random name for section %d: %v", i, err))
			}

			newName = "."
			for _, b := range randBytes {
				newName += string(rune('a' + (b % 26)))
			}
		}

		// PE section names are 8 bytes, null-padded
		newNameBytes := make([]byte, sectionNameSize)
		copy(newNameBytes, newName)
		copy(p.RawData[sectionNameOffset:sectionNameOffset+sectionNameSize], newNameBytes)

		// Update internal structure
		if i < len(p.Sections) {
			p.Sections[i].Name = strings.TrimRight(string(newNameBytes), "\x00")
		}

		if originalName != "" {
			renamedSections = append(renamedSections, fmt.Sprintf("%s→%s", originalName, newName))
		} else {
			renamedSections = append(renamedSections, newName)
		}
	}

	message := fmt.Sprintf("renamed sections: %s", strings.Join(renamedSections, ", "))
	return common.NewApplied(message, len(renamedSections))
}

// Applica tecniche di offuscamento sicure (senza -f)
func (p *PEFile) ObfuscateSafe() *common.OperationResult {
	safeOperations := []struct {
		name string
		fn   func() *common.OperationResult
	}{
		{"randomize section names", p.RandomizeSectionNames},
		{"obfuscate load config metadata", p.ObfuscateLoadConfig},
		{"randomize padding", func() *common.OperationResult { return p.obfuscatePaddingSafe() }},
		{"obfuscate timestamps", func() *common.OperationResult { return p.obfuscateTimestampsSafe() }},
		{"obfuscate resource directory", p.ObfuscateResourceDirectory},
		{"obfuscate Rich Header", func() *common.OperationResult { return p.ObfuscateRichHeader() }},
		{"obfuscate runtime strings", p.ObfuscateRuntimeStrings},
	}

	return p.executeObfuscationOperations(safeOperations, "safe")
}

// Applica tecniche di offuscamento rischiose (con -f)
func (p *PEFile) ObfuscateRisky() *common.OperationResult {
	riskyOperations := []struct {
		name string
		fn   func() *common.OperationResult
	}{
		{"obfuscate base addresses", p.ObfuscateBaseAddresses},
		{"clear debug directories", func() *common.OperationResult { return p.clearDebugDirectories() }},
		{"obfuscate TLS directory", func() *common.OperationResult { return p.obfuscateTLSDirectorySafe() }},
	}

	return p.executeObfuscationOperations(riskyOperations, "risky")
}

// Applica tutte le tecniche di offuscamento
func (p *PEFile) ObfuscateAll(force bool) *common.OperationResult {
	// Prima applica le tecniche sicure
	safeResult := p.ObfuscateSafe()

	if !force {
		return safeResult
	}

	// Poi applica quelle rischiose se force è abilitato
	riskyResult := p.ObfuscateRisky()

	// Combina i risultati
	totalApplied := 0
	var allApplied []string
	var allSkipped []string

	if safeResult.Applied {
		totalApplied += safeResult.Count
		allApplied = append(allApplied, "safe techniques")
	} else {
		allSkipped = append(allSkipped, fmt.Sprintf("safe techniques (%s)", safeResult.Message))
	}

	if riskyResult.Applied {
		totalApplied += riskyResult.Count
		allApplied = append(allApplied, "risky techniques")
	} else {
		allSkipped = append(allSkipped, fmt.Sprintf("risky techniques (%s)", riskyResult.Message))
	}

	if totalApplied > 0 {
		message := fmt.Sprintf("applied %s", strings.Join(allApplied, " and "))
		if len(allSkipped) > 0 {
			message += fmt.Sprintf("; skipped: %s", strings.Join(allSkipped, ", "))
		}
		return common.NewApplied(message, totalApplied)
	}

	return common.NewSkipped(fmt.Sprintf("all techniques skipped: %s", strings.Join(allSkipped, ", ")))
}

// Rimossa - troppo rischiosa per l'integrità dell'eseguibile
// L'obfuscation della import table può facilmente rompere la funzionalità
// func (p *PEFile) ObfuscateImportTable(force bool) *common.OperationResult {
// Import table modification is risky - can break functionality

// Get import table directory entry

// Read import table RVA and size

// Convert RVA to physical offset

// Apply obfuscation techniques
// }

// Mischia l'ordine dei descrittori di import
// Mischia l'ordine dei descrittori di import
// RIMOSSE - TROPPO RISCHIOSE

// Modifica timestamp nei descrittori di import
// RIMOSSE - TROPPO RISCHIOSE

// Offusca metadati non critici nella import table
// RIMOSSE - TROPPO RISCHIOSE

// Offusca in modo aggressivo i nomi delle funzioni importate
// This is more aggressive than the conservative obfuscateImportNames used in ObfuscateImportTable
// RIMOSSE - TROPPO RISCHIOSE

// Offusca in modo aggressivo la import name table
// RIMOSSE - TROPPO RISCHIOSE

// Offusca i nomi funzione nella import name table
// RIMOSSE - TROPPO RISCHIOSE

// Randomizza un nome funzione null-terminated
// RIMOSSE - TROPPO RISCHIOSE

// Genera un nome funzione random di lunghezza specificata
// RIMOSSE - TROPPO RISCHIOSE

// Rimuove o modifica la Rich Header
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

// Offusca metadati della resource section
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

// Offusca metadati della export table
// RIMOSSE - TROPPO RISCHIOSE

// Offusca stringhe comuni di runtime/debug
func (p *PEFile) ObfuscateRuntimeStrings() *common.OperationResult {
	// Common strings that can be safely obfuscated without breaking functionality
	stringReplacements := map[string]string{
		"runtime.":      "system_.",
		"gopau":         "xypau",
		"debugCal":      "traceCal",
		"__getmainargs": "__getargs",
		"fprintf":       "foutput",
		"printf":        "output",
		"gccmain.c":     "mainfile.c",
		"mingw_helpers": "sys_helpers",
		"libgcc2.c":     "libsys2.c",
	}

	modifications := 0

	for _, section := range p.Sections {
		// Focus on data sections
		if !strings.Contains(strings.ToLower(section.Name), "data") &&
			!strings.Contains(strings.ToLower(section.Name), "rdata") {
			continue
		}

		data, err := p.ReadBytes(section.Offset, int(section.Size))
		if err != nil || len(data) < 5 {
			continue
		}

		for original, replacement := range stringReplacements {
			originalBytes := []byte(original)
			replacementBytes := []byte(replacement)

			// Only replace if lengths match (safer)
			if len(originalBytes) == len(replacementBytes) {
				if bytes.Contains(data, originalBytes) {
					data = bytes.ReplaceAll(data, originalBytes, replacementBytes)
					modifications++
				}
			}
		}

		if modifications > 0 {
			copy(p.RawData[section.Offset:section.Offset+int64(len(data))], data)
		}
	}

	if modifications > 0 {
		return common.NewApplied(fmt.Sprintf("obfuscated %d runtime strings", modifications), modifications)
	}
	return common.NewSkipped("no runtime strings found")
}

// Helper function to find a section by name
func (p *PEFile) findSectionByName(name string) *Section {
	for i := range p.Sections {
		if strings.EqualFold(p.Sections[i].Name, name) {
			return &p.Sections[i]
		}
	}
	return nil
}

// Helper per eseguire operazioni di obfuscation
func (p *PEFile) executeObfuscationOperations(operations []struct {
	name string
	fn   func() *common.OperationResult
}, operationType string) *common.OperationResult {
	totalApplied := 0
	var appliedOperations []string
	var skippedOperations []string

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
		message := fmt.Sprintf("applied %d %s techniques: %s", len(appliedOperations), operationType, strings.Join(appliedOperations, ", "))
		if len(skippedOperations) > 0 {
			message += fmt.Sprintf("; skipped: %s", strings.Join(skippedOperations, ", "))
		}
		return common.NewApplied(message, totalApplied)
	}

	return common.NewSkipped(fmt.Sprintf("all %s techniques skipped: %s", operationType, strings.Join(skippedOperations, ", ")))
}

// Versione sicura dell'obfuscation del padding
func (p *PEFile) obfuscatePaddingSafe() *common.OperationResult {
	if err := p.ObfuscateSectionPadding(); err != nil {
		return common.NewSkipped(fmt.Sprintf("padding obfuscation failed: %v", err))
	}
	return common.NewApplied("randomized section padding", 1)
}

// Versione sicura dell'obfuscation dei timestamp
func (p *PEFile) obfuscateTimestampsSafe() *common.OperationResult {
	modifications := 0

	// Obfusca timestamp nelle sezioni di risorsa (sicuro)
	if err := p.ObfuscateSecondaryTimestamps(); err == nil {
		modifications++
	}

	// Obfusca campi riservati negli header (sicuro)
	if err := p.ObfuscateReservedHeaderFields(); err == nil {
		modifications++
	}

	if modifications > 0 {
		return common.NewApplied(fmt.Sprintf("obfuscated %d timestamp areas", modifications), modifications)
	}
	return common.NewSkipped("no timestamps could be obfuscated")
}

// Pulisce le directory di debug in modo sicuro
func (p *PEFile) clearDebugDirectories() *common.OperationResult {
	modifications := 0

	// Pulisci debug directory
	if err := p.ObfuscateDebugDirectory(); err == nil {
		modifications++
	}

	if modifications > 0 {
		return common.NewApplied("cleared debug directories", modifications)
	}
	return common.NewSkipped("no debug directories found")
}

// Versione sicura dell'obfuscation TLS
func (p *PEFile) obfuscateTLSDirectorySafe() *common.OperationResult {
	if err := p.ObfuscateTLSDirectory(); err != nil {
		return common.NewSkipped(fmt.Sprintf("TLS directory obfuscation failed: %v", err))
	}
	return common.NewApplied("cleared TLS directory", 1)
}
