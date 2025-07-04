package elfrw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"sort"
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
	totalCount := 0

	// Create result object
	result := common.NewApplied(fmt.Sprintf("%d bytes processed", originalSize), 0)

	if err := e.validateELF(); err != nil {
		return common.NewSkipped(fmt.Sprintf("ELF validation failed: %v", err))
	}

	if sectionResult := e.obfuscateSectionNames(); sectionResult != nil && sectionResult.Applied {
		// Add all details from the section result
		for _, detail := range sectionResult.Details {
			result.AddDetail(detail.Message, detail.Count, detail.IsRisky)
		}
		totalCount += sectionResult.Count
	}

	if paddingResult := e.obfuscateSectionPadding(); paddingResult != nil && paddingResult.Applied {
		result.AddDetail(paddingResult.Message, paddingResult.Count, false)
		totalCount += paddingResult.Count
	}

	if stringsResult := e.obfuscateRuntimeStrings(); stringsResult != nil && stringsResult.Applied {
		result.AddDetail(stringsResult.Message, stringsResult.Count, false)
		totalCount += stringsResult.Count
	}

	if headerResult := e.obfuscateReservedHeaderFields(); headerResult != nil && headerResult.Applied {
		result.AddDetail(headerResult.Message, headerResult.Count, false)
		totalCount += headerResult.Count
	}

	//if force {
	//	if baseResult := e.obfuscateBaseAddresses(); baseResult != nil && baseResult.Applied {
	//		result.AddDetail(baseResult.Message, baseResult.Count, true)
	//		totalCount += baseResult.Count
	//	}
	//}

	if totalCount == 0 {
		return common.NewSkipped("no obfuscation operations applied")
	}

	// Update the count and message
	result.Count = totalCount
	result.Message = fmt.Sprintf("%d operations applied", totalCount)

	// Save the file with the changes
	if saveErr := e.Save(true, int64(len(e.RawData))); saveErr != nil {
		result.AddDetail(fmt.Sprintf("Failed to save with headers: %v", saveErr), 0, true)
		if saveErr = e.Save(false, int64(len(e.RawData))); saveErr != nil {
			result.AddDetail(fmt.Sprintf("Failed to save without headers: %v", saveErr), 0, true)
			return common.NewSkipped("Obfuscation succeeded but failed to save file")
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

	if len(e.Sections) == 0 {
		return common.NewSkipped("no sections found to obfuscate")
	}

	realisticNames := []string{
		".text", ".data", ".rodata", ".bss", ".tls", ".shstrtab", ".symtab",
		".strtab", ".rela.text", ".rela.data", ".rela.rodata", ".rela.eh_frame",
		".init", ".fini", ".eh_frame", ".note.ABI-tag", ".note.gnu.build-id",
		".gnu.hash", ".dynsym", ".dynstr", ".gnu.version", ".gnu.version_r",
		".rela.dyn", ".rela.plt", ".init_array", ".fini_array", ".dynamic",
		".got", ".got.plt", ".plt", ".interp", ".comment", ".debug_info",
		".debug_abbrev", ".debug_line", ".debug_str", ".debug_loc", ".debug_ranges",
		".tbss", ".tdata", ".ctors", ".dtors", ".preinit_array", ".gnu_debuglink",
		".gnu.version_d", ".gnu.prelink_undo", ".gnu.conflict", ".gnu.liblist",
		".gnu.attributes", ".SUNW_signature", ".debug_frame", ".debug_pubnames",
		".debug_pubtypes", ".debug_cu_index", ".debug_types",
	}

	var renamedSectionsLog []string
	usedNames := make(map[string]bool)

	for i := range e.Sections {
		if e.Sections[i].Index == SHT_NULL {
			continue
		}
		oldName := e.Sections[i].Name
		if oldName == "" {
			continue
		}
		var newName string
		for attempts := 0; attempts < len(realisticNames); attempts++ {
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
		if newName == "" {
			randBytes, err := common.GenerateRandomBytes(5)
			if err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to generate fallback name for section %d: %v", i, err))
			}
			for j := range randBytes {
				randBytes[j] = 'a' + (randBytes[j] % 26)
			}
			newName = "." + string(randBytes)
		}
		e.Sections[i].Name = newName
		renamedSectionsLog = append(renamedSectionsLog, fmt.Sprintf("%s→%s", oldName, newName))
	}

	if len(renamedSectionsLog) == 0 {
		return common.NewSkipped("no section names were changed")
	}
	if err := e.rebuildSectionHeaderTable(); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to rebuild section header table after renaming: %v", err))
	}
	e.clearNameOffsetCache()
	result := common.NewApplied(fmt.Sprintf("renamed %d sections", len(renamedSectionsLog)), len(renamedSectionsLog))
	result.SetCategory("SECTIONS")
	for _, renamed := range renamedSectionsLog {
		result.AddDetail(fmt.Sprintf("renamed section: %s", renamed), 1, false)
	}
	return result
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

	var modifiedSegments []string

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
	result := common.NewApplied(message, len(modifiedSegments))
	result.SetCategory("OTHER")
	return result
}

func (e *ELFFile) obfuscateSectionPadding() *common.OperationResult {
	paddingCount := 0

	// Sort sections by file offset to ensure correct gap identification
	sections := make([]Section, len(e.Sections))
	copy(sections, e.Sections)
	sort.Slice(sections, func(i, j int) bool { return sections[i].Offset < sections[j].Offset })

	for i := 0; i < len(sections)-1; i++ {
		endOffset := sections[i].Offset + sections[i].Size
		nextOffset := sections[i+1].Offset

		if endOffset < nextOffset && nextOffset-endOffset < 0x10000 && endOffset > 0 {
			// Skip gaps that overlap loadable segments
			skip := false
			for _, seg := range e.Segments {
				if seg.Loadable {
					segStart := int64(seg.Offset)
					segEnd := segStart + int64(seg.FileSize)
					if endOffset < segEnd && nextOffset > segStart {
						skip = true
						break
					}
				}
			}
			if skip {
				continue
			}

			paddingSize := int(nextOffset - endOffset)
			randomPadding, err := common.GenerateRandomBytes(paddingSize)
			if err != nil {
				return common.NewSkipped(fmt.Sprintf("failed to generate padding for section %d: %v", i, err))
			}
			// use int indices to slice RawData correctly
			startIdx := int(endOffset)
			endIdx := int(nextOffset)
			copy(e.RawData[startIdx:endIdx], randomPadding)
			paddingCount++
		}
	}

	if paddingCount == 0 {
		return common.NewSkipped("no section padding found to obfuscate")
	}

	result := common.NewApplied(fmt.Sprintf("randomized padding in %d section gaps", paddingCount), paddingCount)
	result.SetCategory("SECTIONS")
	return result
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
	result := common.NewApplied(message, len(modifiedFields))
	result.SetCategory("OTHER")
	return result
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
	result := common.NewApplied(message, modifications)
	result.SetCategory("PATTERNS")
	return result
}

// This function has been replaced by common.FormatOperationResult
