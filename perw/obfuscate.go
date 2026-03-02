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
	pipeline := common.NewPipeline()
	result := &common.OperationResult{
		Message: "PE obfuscation",
		Details: []common.OperationDetail{},
	}

	pipeline.AddStep("section names", func() (*common.OperationResult, error) {
		return p.ObfuscateSectionNames(), nil
	})
	pipeline.AddStep("section padding", func() (*common.OperationResult, error) {
		return p.ObfuscateSectionPadding(), nil
	})
	pipeline.AddStep("runtime strings", func() (*common.OperationResult, error) {
		return p.ObfuscateRuntimeStrings(), nil
	})
	pipeline.AddStep("header metadata", func() (*common.OperationResult, error) {
		return p.ObfuscateHeaderMetadata(force), nil
	})
	pipeline.AddStep("imports", func() (*common.OperationResult, error) {
		return p.ObfuscateImportTable(force), nil
	})
	pipeline.AddStep("executable padding", func() (*common.OperationResult, error) {
		return p.ObfuscateExecutablePadding(force), nil
	})
	// InjectDebugDirectoryNoise removed: injecting fake CodeView RSDS records with
	// random GUIDs and fabricated PDB paths creates detectable anomalies. AV/EDR
	// engines check RSDS GUID consistency and flag synthetic debug entries.
	// Debug directory stripping (in strip.go) is sufficient.

	if err := pipeline.Execute(result); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to obfuscate PE: %v", err))
	}
	if !result.Applied {
		return common.NewSkipped("no obfuscation operations applied")
	}

	result.Message = fmt.Sprintf("PE obfuscation completed: %d bytes processed", originalSize)
	if err := p.Save(true, int64(len(p.RawData))); err != nil {
		result.AddDetail(fmt.Sprintf("failed to save with headers: %v", err), 0, true)
		if err = p.Save(false, int64(len(p.RawData))); err != nil {
			result.AddDetail(fmt.Sprintf("failed to save without headers: %v", err), 0, true)
			return common.NewSkipped("obfuscation succeeded but failed to save file")
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

	// Wipe section names to NULL bytes (Astral-PE approach).
	// This removes identifiable section names without introducing synthetic names
	// that could be fingerprinted by AV/EDR heuristics. NULL-named sections are
	// valid per the PE specification and are produced by several legitimate tools.
	var wipedSections []string

	for i := 0; i < offsets.NumberOfSections; i++ {
		sectionHeaderOffset := offsets.FirstSectionHdr + int64(i*PE_SECTION_HEADER_SIZE)
		sectionNameOffset := sectionHeaderOffset

		if err := p.validateOffset(sectionNameOffset, PE_SECTION_NAME_SIZE); err != nil {
			return common.NewSkipped(fmt.Sprintf("section name offset validation failed for section %d: %v", i, err))
		}

		originalName := ""
		if i < len(p.Sections) {
			originalName = p.Sections[i].Name
		}

		// Zero the section name field
		for b := int64(0); b < PE_SECTION_NAME_SIZE; b++ {
			p.RawData[sectionNameOffset+b] = 0
		}

		// Update internal structure
		if i < len(p.Sections) {
			p.Sections[i].Name = ""
		}

		if originalName != "" {
			wipedSections = append(wipedSections, fmt.Sprintf("%s→(null)", originalName))
		}
	}

	if len(wipedSections) == 0 {
		return common.NewSkipped("no section names to wipe")
	}
	message := fmt.Sprintf("wiped %d section names: %s", len(wipedSections), strings.Join(wipedSections, ", "))
	return common.NewApplied(message, len(wipedSections))
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
	// Zero-fill identifiable runtime strings instead of replacing them with fixed
	// substitutions (e.g. fprintf→foutput). Fixed replacements create a unique
	// fingerprint for this tool that AV vendors can signature. Zeroing is safer
	// and what standard strippers do.
	targetStrings := []string{
		"fprintf", "printf", "libgcc2.c", "WinMain",
	}

	modifications := 0
	var modifiedSections []string

	for _, section := range p.Sections {
		if !strings.Contains(strings.ToLower(section.Name), "data") &&
			!strings.Contains(strings.ToLower(section.Name), "rdata") {
			continue
		}

		data, err := p.ReadBytes(section.Offset, int(section.Size))
		if err != nil || len(data) < 3 {
			continue
		}

		sectionModified := false
		for _, target := range targetStrings {
			targetBytes := []byte(target)
			zeroBytes := make([]byte, len(targetBytes))

			// Search for null-terminated occurrences: \x00target\x00
			searchPattern := append(append([]byte{0}, targetBytes...), 0)
			replacementPattern := append(append([]byte{0}, zeroBytes...), 0)

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
		return common.NewSkipped("no runtime strings found for obfuscation")
	}

	message := fmt.Sprintf("zeroed %d runtime string patterns in sections: %s", modifications, strings.Join(modifiedSections, ", "))
	return common.NewApplied(message, modifications)
}

func (p *PEFile) ObfuscateHeaderMetadata(force bool) *common.OperationResult {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}
	coffHeaderOffset := offsets.ELfanew + PE_SIGNATURE_SIZE
	timeStampOffset := coffHeaderOffset + PE_TIMESTAMP_OFFSET
	if err := p.validateOffset(timeStampOffset, 4); err != nil {
		return common.NewSkipped("TimeDateStamp field not accessible")
	}
	// Zero the timestamp instead of randomizing. Zeroed timestamps are common in
	// deterministic/release builds and don't trigger ML-based anomaly detectors
	// that flag unrealistic random values. Astral-PE uses the same approach.
	_ = WriteAtOffset(p.RawData, timeStampOffset, uint32(0))

	linkerMajor := offsets.OptionalHeader + 2
	linkerMinor := offsets.OptionalHeader + 3
	if err := p.validateOffset(linkerMajor, 2); err != nil {
		return common.NewSkipped("linker version fields not accessible")
	}
	// Zero linker version instead of randomizing. Random values like 237.42 don't
	// correspond to any real toolchain and create statistical anomalies in ML
	// classifiers trained on legitimate PE field distributions.
	_ = WriteAtOffset(p.RawData, linkerMajor, byte(0))
	_ = WriteAtOffset(p.RawData, linkerMinor, byte(0))

	var messages []string
	messages = append(messages, "zeroed PE timestamp")
	messages = append(messages, "zeroed linker version")

	is64 := p.Is64Bit
	if force {
		subsystemOffset := offsets.OptionalHeader
		dllCharOffset := offsets.OptionalHeader
		if is64 {
			subsystemOffset += PE64_SUBSYSTEM
			dllCharOffset += PE64_DLL_CHARACTERISTICS
		} else {
			subsystemOffset += PE32_SUBSYSTEM
			dllCharOffset += PE32_DLL_CHARACTERISTICS
		}
		if err := p.validateOffset(subsystemOffset, 2); err == nil {
			subVals := []uint16{IMAGE_SUBSYSTEM_WINDOWS_GUI, IMAGE_SUBSYSTEM_WINDOWS_CUI}
			randByte, _ := common.GenerateRandomBytes(1)
			newSubsystem := subVals[randByte[0]%byte(len(subVals))]
			_ = WriteAtOffset(p.RawData, subsystemOffset, newSubsystem)
			messages = append(messages, fmt.Sprintf("forged subsystem value 0x%X", newSubsystem))
		}
		if err := p.validateOffset(dllCharOffset, 2); err == nil {
			current := binary.LittleEndian.Uint16(p.RawData[dllCharOffset : dllCharOffset+2])
			mask := uint16(IMAGE_DLL_CHARACTERISTICS_NX_COMPAT | IMAGE_DLL_CHARACTERISTICS_NO_SEH)
			randBytes, _ := common.GenerateRandomBytes(2)
			randomBits := mask & binary.LittleEndian.Uint16(randBytes)
			updated := (current &^ mask) | randomBits
			_ = WriteAtOffset(p.RawData, dllCharOffset, updated)
			messages = append(messages, "mutated DLL characteristics flags")
		}
	}

	if len(messages) == 0 {
		return common.NewSkipped("no header metadata obfuscation applied")
	}
	msg := "obfuscated PE header metadata:\n"
	for _, m := range messages {
		msg += "   • " + m + "\n"
	}
	return common.NewApplied(strings.TrimSuffix(msg, "\n"), len(messages))
}

func (p *PEFile) ObfuscateImportTable(force bool) *common.OperationResult {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}
	importDirOffset := offsets.OptionalHeader + directoryOffsets.importTable[p.Is64Bit]
	if err := p.validateOffset(importDirOffset, 8); err != nil {
		return common.NewSkipped("import directory not accessible")
	}
	importRVA := binary.LittleEndian.Uint32(p.RawData[importDirOffset:])
	if importRVA == 0 {
		return common.NewSkipped("no import directory present")
	}
	importPhys, err := p.rvaToPhysical(uint64(importRVA))
	if err != nil || int(importPhys) >= len(p.RawData) {
		return common.NewSkipped("failed to map import directory RVA")
	}
	const descriptorSize = 20
	cursor := int(importPhys)
	var descriptors [][]byte
	for cursor+descriptorSize <= len(p.RawData) {
		descriptor := append([]byte(nil), p.RawData[cursor:cursor+descriptorSize]...)
		if bytes.Equal(descriptor, make([]byte, descriptorSize)) {
			break
		}
		descriptors = append(descriptors, descriptor)
		cursor += descriptorSize
	}
	if len(descriptors) <= 1 {
		return common.NewSkipped("not enough import descriptors to obfuscate")
	}

	shuffled := make([][]byte, len(descriptors))
	copy(shuffled, descriptors)
	permBytes, _ := common.GenerateRandomBytes(len(descriptors))
	for i := range shuffled {
		j := int(permBytes[i]) % len(shuffled)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	writeCursor := int(importPhys)
	for _, desc := range shuffled {
		copy(p.RawData[writeCursor:writeCursor+descriptorSize], desc)
		writeCursor += descriptorSize
	}
	// zero terminator entry
	if writeCursor+descriptorSize <= len(p.RawData) {
		for i := 0; i < descriptorSize; i++ {
			p.RawData[writeCursor+i] = 0
		}
	}

	changedThunks := 0
	if force {
		entrySize := 4
		if p.Is64Bit {
			entrySize = 8
		}
		for _, desc := range shuffled {
			if p.shuffleThunkArray(binary.LittleEndian.Uint32(desc[0:4]), entrySize) {
				changedThunks++
			}
			if p.shuffleThunkArray(binary.LittleEndian.Uint32(desc[16:20]), entrySize) {
				changedThunks++
			}
		}
	}

	message := fmt.Sprintf("shuffled %d import descriptors", len(shuffled))
	if changedThunks > 0 {
		message += fmt.Sprintf("; randomized %d thunk groups", changedThunks)
	}
	return common.NewApplied(message, len(shuffled)+changedThunks)
}

func (p *PEFile) shuffleThunkArray(rva uint32, entrySize int) bool {
	if rva == 0 {
		return false
	}
	phys, err := p.rvaToPhysical(uint64(rva))
	if err != nil {
		return false
	}
	start := int(phys)
	var entries []int
	for start+entrySize <= len(p.RawData) {
		chunk := p.RawData[start : start+entrySize]
		if bytes.Equal(chunk, make([]byte, entrySize)) {
			break
		}
		entries = append(entries, start)
		start += entrySize
	}
	if len(entries) <= 1 {
		return false
	}
	idxBytes, _ := common.GenerateRandomBytes(2)
	i := int(idxBytes[0]) % len(entries)
	j := int(idxBytes[1]) % len(entries)
	if i == j {
		j = (j + 1) % len(entries)
	}
	temp := append([]byte(nil), p.RawData[entries[i]:entries[i]+entrySize]...)
	copy(p.RawData[entries[i]:entries[i]+entrySize], p.RawData[entries[j]:entries[j]+entrySize])
	copy(p.RawData[entries[j]:entries[j]+entrySize], temp)
	return true
}

// InjectDebugDirectoryNoise is deprecated and now always returns a skip result.
// Injecting fake CodeView RSDS records with random GUIDs and fabricated PDB paths
// creates detectable anomalies that AV/EDR engines flag. Debug directory stripping
// (via StripAll) is the preferred approach.
func (p *PEFile) InjectDebugDirectoryNoise() *common.OperationResult {
	return common.NewSkipped("debug directory noise injection disabled (creates detectable anomalies)")
}

func (p *PEFile) ObfuscateExecutablePadding(force bool) *common.OperationResult {
	if p.IsPacked && !force {
		return common.NewSkipped("packed binary detected; skipping executable padding obfuscation")
	}
	if len(p.Sections) == 0 {
		return common.NewSkipped("no sections to obfuscate")
	}
	language, _ := p.detectLanguageAndCompiler()
	allowRunScramble := force || !strings.EqualFold(language, "Go")
	nopPatterns := [][]byte{
		{0x90},
		{0x66, 0x90},
		{0x0F, 0x1F, 0x00},
		{0x2E, 0x90},
	}
	if force {
		nopPatterns = append(nopPatterns,
			[]byte{0x0F, 0x1F, 0x40, 0x00},
			[]byte{0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00},
			[]byte{0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00},
			[]byte{0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
		)
	}
	totalTail := 0
	totalRuns := 0
	for _, section := range p.Sections {
		if section.Flags&IMAGE_SCN_MEM_EXECUTE == 0 || section.Size <= 0 {
			continue
		}

		if section.VirtualSize > 0 && int64(section.VirtualSize) < section.Size {
			start := section.Offset + int64(section.VirtualSize)
			end := section.Offset + section.Size
			if start >= 0 && start < int64(len(p.RawData)) {
				if end > int64(len(p.RawData)) {
					end = int64(len(p.RawData))
				}
				if end > start {
					if err := p.fillRegion(start, int(end-start), RandomFill); err != nil {
						return common.NewSkipped(fmt.Sprintf("failed to randomize executable tail padding: %v", err))
					}
					totalTail++
				}
			}
		}

		if !allowRunScramble {
			continue
		}
		loadedSize := section.Size
		if section.VirtualSize > 0 && int64(section.VirtualSize) < loadedSize {
			loadedSize = int64(section.VirtualSize)
		}
		if loadedSize <= 0 {
			continue
		}
		data, err := p.ReadBytes(section.Offset, int(loadedSize))
		if err != nil || len(data) == 0 {
			continue
		}
		changed := false
		runStart := -1
		for i, b := range data {
			if b == 0 {
				if runStart == -1 {
					runStart = i
				}
				continue
			}
			if runStart != -1 && i-runStart >= 8 {
				if p.fillPaddingRun(data[runStart:i], nopPatterns, force) {
					changed = true
					totalRuns++
				}
			}
			runStart = -1
		}
		if runStart != -1 && len(data)-runStart >= 8 {
			if p.fillPaddingRun(data[runStart:], nopPatterns, force) {
				changed = true
				totalRuns++
			}
		}
		if changed {
			copy(p.RawData[section.Offset:section.Offset+int64(len(data))], data)
		}
	}
	if totalTail == 0 && totalRuns == 0 {
		return common.NewSkipped("no executable padding found for obfuscation")
	}
	var messages []string
	if totalTail > 0 {
		messages = append(messages, fmt.Sprintf("randomized tail padding in %d executable sections", totalTail))
	}
	if totalRuns > 0 {
		mode := "default"
		if force {
			mode = "force"
		}
		messages = append(messages, fmt.Sprintf("scrambled %d executable padding runs (%s)", totalRuns, mode))
	}
	return common.NewApplied(strings.Join(messages, "; "), totalTail+totalRuns)
}

func (p *PEFile) fillPaddingRun(run []byte, patterns [][]byte, force bool) bool {
	if len(run) == 0 {
		return false
	}
	changed := false
	pos := 0
	for pos < len(run) {
		pat := patterns[int(run[pos])%len(patterns)]
		for i := 0; i < len(pat) && pos+i < len(run); i++ {
			if run[pos+i] != pat[i] {
				run[pos+i] = pat[i]
				changed = true
			}
		}
		pos += len(pat)
	}
	return changed
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
