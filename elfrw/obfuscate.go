package elfrw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"strings"
)

func generateRandomOffset() (uint64, error) {
	randomBytes, err := common.GenerateRandomBytes(8)
	if err != nil {
		return 0, fmt.Errorf("failed to generate random offset: %w", err)
	}

	offset := (binary.LittleEndian.Uint64(randomBytes) / 0x1000) * 0x1000
	if offset > 0x40000000 {
		offset = offset % 0x40000000
	}
	return offset, nil
}

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

func (e *ELFFile) ObfuscateAll(force bool) *common.OperationResult {
	originalSize := uint64(len(e.RawData))
	var operations []string
	totalCount := 0

	if err := e.validateELF(); err != nil {
		return common.NewSkipped(fmt.Sprintf("ELF validation failed: %v", err))
	}

	if result := e.obfuscateSectionNames(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	if result := e.obfuscateSectionPadding(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	if result := e.obfuscateRuntimeStrings(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	if result := e.obfuscateReservedHeaderFields(); result != nil && result.Applied {
		operations = append(operations, result.Message)
		totalCount += result.Count
	}

	//if force {
	//	if result := e.obfuscateBaseAddresses(); result != nil && result.Applied {
	//		message := fmt.Sprintf("⚠️ %s (risky)", result.Message)
	//		operations = append(operations, message)
	//		totalCount += result.Count
	//	}
	//}

	if len(operations) == 0 {
		return common.NewSkipped("no obfuscation operations applied")
	}

	message := fmt.Sprintf("ELF obfuscation completed: %d bytes processed\n%s",
		originalSize, e.formatObfuscationOperations(operations))

	result := common.NewApplied(message, totalCount)

	// Save the file with the changes
	if result.Applied {
		if saveErr := e.Save(true, int64(len(e.RawData))); saveErr != nil {
			fmt.Printf("⚠️ Warning: Failed to save with headers: %v\n", saveErr)
			if saveErr = e.Save(false, int64(len(e.RawData))); saveErr != nil {
				fmt.Printf("⚠️ Warning: Failed to save without headers: %v\n", saveErr)
				return common.NewSkipped("Obfuscation succeeded but failed to save file")
			}
		}
	}

	return result
}

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

func (e *ELFFile) obfuscateSectionNames() *common.OperationResult {
	if err := e.validateELF(); err != nil {
		return common.NewSkipped(fmt.Sprintf("ELF validation failed: %v", err))
	}

	offsets := e.getELFOffsets()

	// Check if file has sections (UPX-packed files have e_shnum = 0)
	shCount := e.readValue16(offsets.shNum)
	if shCount == 0 || len(e.Sections) == 0 {
		return common.NewSkipped("no sections found to obfuscate")
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

	realisticNames := []string{
		".text", ".data", ".rodata", ".bss", ".shstrtab", ".symtab",
		".strtab", ".rela.text", ".rela.data", ".rela.rodata", ".rela.eh_frame",
		".init", ".fini", ".eh_frame", ".note.ABI-tag", ".note.gnu.build-id",
		".gnu.hash", ".dynsym", ".dynstr", ".gnu.version", ".gnu.version_r",
		".rela.dyn", ".rela.plt", ".init_array", ".fini_array", ".dynamic",
		".got", ".got.plt", ".plt", ".interp", ".comment", ".debug_info",
		".debug_abbrev", ".debug_line", ".debug_str", ".debug_loc", ".debug_ranges",
		".tbss", ".tdata", ".ctors", ".dtors", ".preinit_array", ".gnu_debuglink",
		".gnu.version_d", ".gnu.prelink_undo", ".gnu.conflict", ".gnu.liblist",
		".gnu.attributes", ".gnu.lto_legacy", ".gnu.lto_legacy1", ".gnu.lto_legacy2",
		".SUNW_sort", ".SUNW_signature", ".SUNW_cap", ".SUNW_move", ".SUNW_syminfo",
		".SUNW_ldynsym", ".SUNW_dynsymsort", ".SUNW_dyntlssort", ".SUNW_dynstr",
		".SUNW_bss", ".SUNW_COM", ".SUNW_versym", ".SUNW_verdef", ".SUNW_verneed",
		".debug_frame", ".debug_pubnames", ".debug_pubtypes", ".debug_aranges",
		".debug_macinfo", ".debug_line_str", ".debug_addr", ".debug_cu_index",
		".debug_tu_index", ".debug_sup", ".debug_types", ".debug_macro",
	}

	// Build new string table
	newShstrtab := []byte{0} // Start with null terminator
	nameOffsets := make(map[string]uint32)
	renamedSections := []string{}
	usedNames := make(map[string]bool)

	for i := range e.Sections {
		if e.Sections[i].Name == "" {
			continue
		}

		var newName string
		for attempts := 0; attempts < 10; attempts++ {
			randBytes, err := common.GenerateRandomBytes(1)
			if err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to generate random index for section %d: %v", i, err))
			}

			candidateName := realisticNames[randBytes[0]%byte(len(realisticNames))]
			if !usedNames[candidateName] {
				newName = candidateName
				usedNames[candidateName] = true
				break
			}
		}

		// If all realistic names are used, create a fallback name
		if newName == "" {
			randBytes, err := common.GenerateRandomBytes(5)
			if err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to generate fallback name for section %d: %v", i, err))
			}
			for j := range randBytes {
				randBytes[j] = 'a' + (randBytes[j] % 26)
			}
			newName = "." + string(randBytes[:4+int(randBytes[4]%4)])
		}

		nameOffsets[e.Sections[i].Name] = uint32(len(newShstrtab))
		newShstrtab = append(newShstrtab, []byte(newName)...)
		newShstrtab = append(newShstrtab, 0)

		renamedSections = append(renamedSections, fmt.Sprintf("%s→%s", e.Sections[i].Name, newName))
		e.Sections[i].Name = newName
	}

	if len(renamedSections) == 0 {
		return common.NewSkipped("no section names to obfuscate")
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
			if err := WriteAtOffset(e.RawData, int64(shdrOffset), newOffset, e.getEndian()); err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to write name offset: %v", err))
			}
		}
	}

	message := fmt.Sprintf("renamed %d sections: %s", len(renamedSections), strings.Join(renamedSections, ", "))
	return common.NewApplied(message, len(renamedSections))
}

func (e *ELFFile) obfuscateBaseAddresses() *common.OperationResult {
	if err := e.validateELF(); err != nil {
		return common.NewSkipped(fmt.Sprintf("ELF validation failed: %v", err))
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

func (e *ELFFile) obfuscateSectionPadding() *common.OperationResult {
	paddingCount := 0

	for i := 0; i < len(e.Sections)-1; i++ {
		end := e.Sections[i].Offset + e.Sections[i].Size
		next := e.Sections[i+1].Offset

		if end < next && next-end < 0x10000 && end > 0 {
			paddingSize := int(next - end)
			randomPadding, err := common.GenerateRandomBytes(paddingSize)
			if err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to generate padding for section %d: %v", i, err))
			}
			copy(e.RawData[end:next], randomPadding)
			paddingCount++
		}
	}

	if paddingCount == 0 {
		return common.NewSkipped("no section padding found to obfuscate")
	}

	return common.NewApplied(fmt.Sprintf("randomized padding in %d section gaps", paddingCount), paddingCount)
}

func (e *ELFFile) obfuscateReservedHeaderFields() *common.OperationResult {
	var modifiedFields []string

	// Randomize e_ident[9:16] (padding)
	randBytes, err := common.GenerateRandomBytes(7)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to generate random header bytes: %v", err))
	}
	copy(e.RawData[9:16], randBytes)
	modifiedFields = append(modifiedFields, "header padding")

	// Randomize e_flags
	offsets := e.getELFOffsets()
	if offsets.flags+4 <= len(e.RawData) {
		randFlags, err := common.GenerateRandomBytes(4)
		if err != nil {
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

func (e *ELFFile) obfuscateRuntimeStrings() *common.OperationResult {
	stringReplacements := map[string]string{
		"fprintf":   "foutput",   // 7 byte -> 7 byte
		"printf":    "output",    // 6 byte -> 6 byte
		"libgcc.so": "libsys.so", // 9 byte -> 9 byte
		"main":      "entry",     // 4 byte -> 5 byte (padding with null)
		"__libc_":   "__std_",    // 7 byte -> 6 byte (padding with null)
	}

	modifications := 0
	var modifiedSections []string

	for _, section := range e.Sections {
		// Focus on data sections
		if !strings.Contains(strings.ToLower(section.Name), "data") &&
			!strings.Contains(strings.ToLower(section.Name), "rodata") &&
			!strings.Contains(strings.ToLower(section.Name), ".str") {
			continue
		}

		sectionData, err := e.ELF.GetSectionContent(uint16(section.Index))
		if err != nil || len(sectionData) < 3 {
			continue
		}

		sectionModified := false
		for original, replacement := range stringReplacements {
			originalBytes := []byte(original)
			replacementBytes := []byte(replacement)

			// Ensure replacement is same length or padded
			if len(replacementBytes) < len(originalBytes) {
				replacementBytes = append(replacementBytes, make([]byte, len(originalBytes)-len(replacementBytes))...)
			} else if len(replacementBytes) > len(originalBytes) {
				continue // Skip if replacement is longer
			}

			// Look for null-terminated strings
			searchPattern := append(append([]byte{0}, originalBytes...), 0)
			replacementPattern := append(append([]byte{0}, replacementBytes...), 0)

			if bytes.Contains(sectionData, searchPattern) {
				tempData := bytes.ReplaceAll(sectionData, searchPattern, replacementPattern)
				if !bytes.Equal(sectionData, tempData) {
					sectionData = tempData
					modifications++
					sectionModified = true
				}
			}

			// Also look for plain strings
			if bytes.Contains(sectionData, originalBytes) {
				tempData := bytes.ReplaceAll(sectionData, originalBytes, replacementBytes)
				if !bytes.Equal(sectionData, tempData) {
					sectionData = tempData
					modifications++
					sectionModified = true
				}
			}
		}

		if sectionModified {
			sectionOffset := section.Offset
			copy(e.RawData[sectionOffset:sectionOffset+int64(len(sectionData))], sectionData)
			modifiedSections = append(modifiedSections, section.Name)
		}
	}

	if modifications == 0 {
		return common.NewSkipped("no runtime strings found for obfuscation")
	}

	message := fmt.Sprintf("obfuscated %d string patterns in sections: %s", modifications, strings.Join(modifiedSections, ", "))
	return common.NewApplied(message, modifications)
}

func (e *ELFFile) formatObfuscationOperations(operations []string) string {
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
		case strings.Contains(op, "obfuscated") && strings.Contains(op, "string"):
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
