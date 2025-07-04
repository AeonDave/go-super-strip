package perw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"strings"
)

const (
	maxPaddingSize = 0x10000
)

var directoryOffsets = struct {
	debug, loadConfig, tls, baseReloc, importTable map[bool]int64
}{
	debug:       map[bool]int64{true: PE64_DATA_DIRECTORIES + 6*8, false: PE32_DATA_DIRECTORIES + 6*8},
	loadConfig:  map[bool]int64{true: PE64_DATA_DIRECTORIES + 10*8, false: PE32_DATA_DIRECTORIES + 10*8},
	tls:         map[bool]int64{true: PE64_DATA_DIRECTORIES + 9*8, false: PE32_DATA_DIRECTORIES + 9*8},
	baseReloc:   map[bool]int64{true: PE64_DATA_DIRECTORIES + 5*8, false: PE32_DATA_DIRECTORIES + 5*8},
	importTable: map[bool]int64{true: PE64_DATA_DIRECTORIES + 1*8, false: PE32_DATA_DIRECTORIES + 1*8},
}

// PE header field offsets
var headerOffsets = struct {
	imageBase, loaderFlags map[bool]int64
}{
	imageBase:   map[bool]int64{true: PE64_IMAGE_BASE, false: PE32_IMAGE_BASE},
	loaderFlags: map[bool]int64{true: PE64_DATA_DIRECTORIES - 4, false: PE32_DATA_DIRECTORIES - 4},
}

func (p *PEFile) ObfuscateAll(force bool) *common.OperationResult {
	originalSize := uint64(len(p.RawData))
	var operations []string
	totalCount := 0

	if result := p.ObfuscateSectionNames(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	if result := p.ObfuscateSectionPadding(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	if result := p.ObfuscateRuntimeStrings(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	//if force {
	//	if result := p.ObfuscateBaseAddresses(); result != nil && result.Applied {
	//		message := fmt.Sprintf("⚠️  %s (risky)", result.Message)
	//		operations = append(operations, message)
	//		totalCount += result.Count
	//	}
	//}

	if len(operations) == 0 {
		return common.NewSkipped("no obfuscation operations applied")
	}

	message := fmt.Sprintf("PE obfuscation completed: %d bytes processed\n%s",
		originalSize, p.formatObfuscationOperations(operations))

	result := common.NewApplied(message, totalCount)

	// Save the file with the changes
	if result.Applied {
		if saveErr := p.Save(true, int64(len(p.RawData))); saveErr != nil {
			fmt.Printf("⚠️ Warning: Failed to save with headers: %v\n", saveErr)
			if saveErr = p.Save(false, int64(len(p.RawData))); saveErr != nil {
				fmt.Printf("⚠️ Warning: Failed to save without headers: %v\n", saveErr)
				return common.NewSkipped("Obfuscation succeeded but failed to save file")
			}
		}
	}

	return result
}

func (p *PEFile) ObfuscateSectionNames() *common.OperationResult {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}

	if offsets.NumberOfSections == 0 {
		return common.NewSkipped("no sections found")
	}

	realisticNames := []string{
		".text", ".data", ".rdata", ".pdata", ".rsrc", ".reloc",
		".idata", ".edata", ".tls", ".debug", ".bss", ".const",
		".code", ".init", ".fini", ".rodata", ".ctors", ".dtors",
		".xdata", ".sdata", ".udata", ".vdata", ".zdata", ".ndata",
		".cinit", ".dinit", ".mdata", ".tdata", ".edata2", ".rdata2",
		".bdata", ".idata2", ".pdata2", ".sinit", ".fdata", ".gdata",
		".hdata", ".idata3", ".reloc2", ".rsrc2", ".debug2", ".tls2",
	}

	var renamedSections []string
	usedNames := make(map[string]bool)

	for i := 0; i < offsets.NumberOfSections; i++ {
		sectionHeaderOffset := offsets.FirstSectionHdr + int64(i*PE_SECTION_HEADER_SIZE)
		sectionNameOffset := sectionHeaderOffset

		if err := p.validateOffset(sectionNameOffset, PE_SECTION_NAME_SIZE); err != nil {
			return common.NewSkipped(fmt.Sprintf("section name offset validation failed for section %d: %v", i, err))
		}

		// Get original name
		originalName := ""
		if i < len(p.Sections) {
			originalName = p.Sections[i].Name
		}

		// Choose a realistic name not already used
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

		if newName == "" {
			randBytes, err := common.GenerateRandomBytes(5)
			if err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to generate random name for section %d: %v", i, err))
			}
			for j := range randBytes {
				randBytes[j] = 'a' + (randBytes[j] % 26)
			}
			newName = "." + string(randBytes[:4+int(randBytes[4]%4)])
		}

		newNameBytes := make([]byte, PE_SECTION_NAME_SIZE)
		copy(newNameBytes, newName)
		copy(p.RawData[sectionNameOffset:sectionNameOffset+PE_SECTION_NAME_SIZE], newNameBytes)

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

	message := fmt.Sprintf("renamed %d sections: %s", len(renamedSections), strings.Join(renamedSections, ", "))
	return common.NewApplied(message, len(renamedSections))
}

func (p *PEFile) ObfuscateSectionPadding() *common.OperationResult {
	paddingCount := 0
	for i := 0; i < len(p.Sections)-1; i++ {
		current := &p.Sections[i]
		next := &p.Sections[i+1]
		end := current.Offset + current.Size
		start := next.Offset
		if end >= start || start-end >= maxPaddingSize || end <= 0 {
			continue
		}
		paddingSize := int(start - end)
		randomPadding, err := common.GenerateRandomBytes(paddingSize)
		if err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to generate padding for section %d: %v", i, err))
		}
		copy(p.RawData[end:start], randomPadding)
		paddingCount++
	}
	if paddingCount == 0 {
		return common.NewSkipped("no section padding areas found")
	}
	return common.NewApplied(fmt.Sprintf("randomized padding in %d section gaps", paddingCount), paddingCount)
}

func (p *PEFile) ObfuscateRuntimeStrings() *common.OperationResult {
	stringReplacements := map[string]string{
		"fprintf":   "foutput",   // 7 byte -> 7 byte
		"printf":    "output",    // 6 byte -> 6 byte
		"libgcc2.c": "libsys2.c", // 9 byte -> 9 byte
		"WinMain":   "AppMain",   // 7 byte -> 7 byte
	}

	modifications := 0
	var modifiedSections []string

	for _, section := range p.Sections {
		if !strings.Contains(strings.ToLower(section.Name), "data") &&
			!strings.Contains(strings.ToLower(section.Name), "rdata") {
			continue
		}

		data, err := p.ReadBytes(section.Offset, int(section.Size))
		if err != nil || len(data) < 3 { // min len for \x00s\x00
			continue
		}

		sectionModified := false
		for original, replacement := range stringReplacements {
			originalBytes := []byte(original)
			replacementBytes := []byte(replacement)

			if len(originalBytes) != len(replacementBytes) {
				continue
			}

			searchPattern := append(append([]byte{0}, originalBytes...), 0)
			replacementPattern := append(append([]byte{0}, replacementBytes...), 0)

			if bytes.Contains(data, searchPattern) {
				tempData := bytes.ReplaceAll(data, searchPattern, replacementPattern)
				if !bytes.Equal(data, tempData) {
					data = tempData
					modifications++
					sectionModified = true
				}
			}
		}

		if sectionModified {
			copy(p.RawData[section.Offset:section.Offset+int64(len(data))], data)
			modifiedSections = append(modifiedSections, section.Name)
		}
	}

	if modifications == 0 {
		return common.NewSkipped("nessuna stringa di runtime mirata trovata per l'offuscamento")
	}

	message := fmt.Sprintf("offuscati %d tipi di stringhe nelle sezioni: %s", modifications, strings.Join(modifiedSections, ", "))
	return common.NewApplied(message, modifications)
}

func (p *PEFile) ObfuscateBaseAddresses() *common.OperationResult {
	if !p.hasBaseRelocations() {
		return common.NewSkipped("no base relocations found (changing ImageBase would break executable)")
	}

	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}

	is64 := p.Is64Bit
	imageBaseOffset := offsets.OptionalHeader + headerOffsets.imageBase[is64]
	wordSize := 8
	if !is64 {
		wordSize = 4
	}

	if err := p.validateOffset(imageBaseOffset, wordSize); err != nil {
		return common.NewSkipped(fmt.Sprintf("ImageBase offset validation failed: %v", err))
	}

	var (
		current, minx, maxx, mask, diffLimit, align uint64
	)
	if is64 {
		current = binary.LittleEndian.Uint64(p.RawData[imageBaseOffset:])
		minx, maxx = 0x140000000, 0x7FF00000000
		mask, diffLimit, align = 0xFFFFFFFFFFF00000, 0x100000, 0x10000
	} else {
		current = uint64(binary.LittleEndian.Uint32(p.RawData[imageBaseOffset:]))
		minx, maxx = 0x400000, 0x80000000
		mask, diffLimit, align = 0xFFF00000, 0x1000000, 0x10000
	}

	if current < minx || current >= maxx {
		return common.NewSkipped("address outside safe modification range")
	}

	randBytes, err := common.GenerateRandomBytes(1)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to generate random offset: %v", err))
	}
	offset := uint64(randBytes[0]&0x0F) * align
	newBase := (current & mask) + offset

	if newBase >= current-diffLimit && newBase <= current+diffLimit && newBase >= align {
		if err := WriteAtOffset(p.RawData, imageBaseOffset, newBase); err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to write new base address: %v", err))
		}
		return common.NewApplied(fmt.Sprintf("changed ImageBase from 0x%X to 0x%X", current, newBase), 1)
	}
	return common.NewSkipped("conditions not met for safe ImageBase modification")
}

func (p *PEFile) hasBaseRelocations() bool {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return false
	}
	baseRelocOffset := offsets.OptionalHeader + directoryOffsets.baseReloc[p.Is64Bit]
	if err := p.validateOffset(baseRelocOffset, 8); err != nil {
		return false
	}
	rva := binary.LittleEndian.Uint32(p.RawData[baseRelocOffset:])
	size := binary.LittleEndian.Uint32(p.RawData[baseRelocOffset+4:])
	return rva != 0 && size != 0
}

func (p *PEFile) findSectionByName(name string) *Section {
	for i := range p.Sections {
		if strings.EqualFold(p.Sections[i].Name, name) {
			return &p.Sections[i]
		}
	}
	return nil
}

func (p *PEFile) formatObfuscationOperations(operations []string) string {
	if len(operations) == 0 {
		return "No operations performed"
	}

	var result strings.Builder
	grouped := map[string][]string{
		"section": {},
		"string":  {},
		"other":   {},
	}

	for _, op := range operations {
		switch {
		case strings.Contains(op, "renamed") && strings.Contains(op, "sections"):
			grouped["section"] = append(grouped["section"], op)
		case strings.Contains(op, "obfuscated") && strings.Contains(op, "strings"):
			grouped["string"] = append(grouped["string"], op)
		default:
			grouped["other"] = append(grouped["other"], op)
		}
	}

	if len(grouped["section"]) > 0 {
		result.WriteString("📦 SECTION OBFUSCATION:\n")
		for _, op := range grouped["section"] {
			prefix := "   ✓ "
			if strings.HasPrefix(op, "⚠️") {
				prefix = "   "
			}
			result.WriteString(prefix + op + "\n")
		}
	}

	if len(grouped["string"]) > 0 {
		result.WriteString("🔤 STRING OBFUSCATION:\n")
		for _, op := range grouped["string"] {
			prefix := "   ✓ "
			if strings.HasPrefix(op, "⚠️") {
				prefix = "   "
			}
			result.WriteString(prefix + op + "\n")
		}
	}

	if len(grouped["other"]) > 0 {
		result.WriteString("🛠️  OTHER OBFUSCATION:\n")
		for _, op := range grouped["other"] {
			prefix := "   ✓ "
			if strings.HasPrefix(op, "⚠️") {
				prefix = "   "
			}
			result.WriteString(prefix + op + "\n")
		}
	}

	return strings.TrimSuffix(result.String(), "\n")
}
