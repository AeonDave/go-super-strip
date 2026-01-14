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
		return ELF64_P_VADDR // p_vaddr offset in 64-bit program header
	}
	return ELF32_P_VADDR // p_vaddr offset in 32-bit program header
}

func getPAddrOffset(is64bit bool) uint64 {
	if is64bit {
		return ELF64_P_PADDR // p_paddr offset in 64-bit program header
	}
	return ELF32_P_PADDR // p_paddr offset in 32-bit program header
}

func generateSyntheticSectionName(used map[string]bool) (string, error) {
	const maxAttempts = 64
	for attempts := 0; attempts < maxAttempts; attempts++ {
		bytes, err := common.GenerateRandomBytes(3)
		if err != nil {
			return "", err
		}
		name := fmt.Sprintf(".sec%02x%02x%02x", bytes[0], bytes[1], bytes[2])
		if !used[name] {
			used[name] = true
			return name, nil
		}
	}
	return "", fmt.Errorf("unable to generate unique section name")
}

func (e *ELFFile) ObfuscateAll(force bool, preserveLoadOrder bool) *common.OperationResult {
	if err := e.validateELF(); err != nil {
		return common.NewSkipped(fmt.Sprintf("ELF validation failed: %v", err))
	}
	originalSize := uint64(len(e.RawData))
	pipeline := common.NewPipeline()
	result := &common.OperationResult{
		Message: "ELF obfuscation",
		Details: []common.OperationDetail{},
	}

	pipeline.AddStep("section names", func() (*common.OperationResult, error) {
		return e.obfuscateSectionNames(), nil
	})
	pipeline.AddStep("section padding", func() (*common.OperationResult, error) {
		return e.obfuscateSectionPadding(), nil
	})
	pipeline.AddStep("runtime strings", func() (*common.OperationResult, error) {
		return e.obfuscateRuntimeStrings(), nil
	})
	pipeline.AddStep("header fields", func() (*common.OperationResult, error) {
		return e.obfuscateReservedHeaderFields(), nil
	})
	pipeline.AddStep("program headers", func() (*common.OperationResult, error) {
		return e.obfuscateProgramHeaders(force, originalSize, preserveLoadOrder), nil
	})
	pipeline.AddStep("dynamic symbols", func() (*common.OperationResult, error) {
		return e.obfuscateDynamicSymbols(force), nil
	})
	if force {
		pipeline.AddStep("section string scramble", func() (*common.OperationResult, error) {
			return e.scrambleSectionStringTableForce(), nil
		})
		pipeline.AddStep("section string wipe", func() (*common.OperationResult, error) {
			return e.wipeSectionStringTableBeforeSave(), nil
		})
	}

	if err := pipeline.Execute(result); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to obfuscate ELF: %v", err))
	}
	if !result.Applied {
		return common.NewSkipped("no obfuscation operations applied")
	}

	result.Message = fmt.Sprintf("ELF obfuscation completed: %d bytes processed", originalSize)
	if saveErr := e.Save(true, int64(len(e.RawData))); saveErr != nil {
		result.AddDetail(fmt.Sprintf("failed to save with headers: %v", saveErr), 0, true)
		if saveErr = e.Save(false, int64(len(e.RawData))); saveErr != nil {
			result.AddDetail(fmt.Sprintf("failed to save without headers: %v", saveErr), 0, true)
			return common.NewSkipped("obfuscation succeeded but failed to save file")
		}
	}
	return result
}

func (e *ELFFile) obfuscateSectionNames() *common.OperationResult {
	if err := e.validateELF(); err != nil {
		return common.NewSkipped(fmt.Sprintf("ELF validation failed: %v", err))
	}

	if len(e.Sections) == 0 {
		return common.NewSkipped("no sections found to obfuscate")
	}

	var renamedSectionsLog []string
	usedNames := make(map[string]bool)

	for i := range e.Sections {
		if e.Sections[i].Index == SHT_NULL {
			continue
		}
		if e.Sections[i].Name == ".shstrtab" {
			continue
		}
		oldName := e.Sections[i].Name
		if oldName == "" {
			continue
		}
		newName, err := generateSyntheticSectionName(usedNames)
		if err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to generate section alias for %s: %v", oldName, err))
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

	// Randomize e_ident[9:16] (padding) — safe to alter.
	randBytes, err := common.GenerateRandomBytes(7)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to generate random header bytes: %v", err))
	}
	copy(e.RawData[9:16], randBytes)
	modifiedFields = append(modifiedFields, "header padding")

	// Normalize e_flags to 0 (do not randomize). Randomizing processor flags can break loaders.
	var flagsOffset int
	if e.Is64Bit {
		flagsOffset = ELF64_E_FLAGS
	} else {
		flagsOffset = ELF32_E_FLAGS
	}
	if flagsOffset+4 <= len(e.RawData) {
		zeros := []byte{0, 0, 0, 0}
		copy(e.RawData[flagsOffset:flagsOffset+4], zeros)
		modifiedFields = append(modifiedFields, "processor flags (zeroed)")
	}

	if len(modifiedFields) == 0 {
		return common.NewSkipped("no header fields available for obfuscation")
	}
	message := fmt.Sprintf("obfuscated reserved header fields: %s", strings.Join(modifiedFields, ", "))
	result := common.NewApplied(message, len(modifiedFields))
	result.SetCategory("OTHER")
	return result
}

type programHeaderMeta struct {
	offset    uint64
	entrySize uint16
	count     uint16
}

func (e *ELFFile) fetchProgramHeaderMeta() (*programHeaderMeta, error) {
	meta := &programHeaderMeta{}
	if e.Is64Bit {
		meta.offset = e.readUint64(ELF64_E_PHOFF)
		meta.entrySize = e.readUint16(ELF64_E_PHENTSIZE)
		meta.count = e.readUint16(ELF64_E_PHNUM)
	} else {
		meta.offset = uint64(e.readUint32(ELF32_E_PHOFF))
		meta.entrySize = e.readUint16(ELF32_E_PHENTSIZE)
		meta.count = e.readUint16(ELF32_E_PHNUM)
	}
	if meta.offset == 0 || meta.entrySize == 0 || meta.count == 0 {
		return nil, fmt.Errorf("program header table missing or empty")
	}
	totalSize := uint64(meta.entrySize) * uint64(meta.count)
	if meta.offset+totalSize > uint64(len(e.RawData)) {
		maxEntries := (uint64(len(e.RawData)) - meta.offset) / uint64(meta.entrySize)
		meta.count = uint16(maxEntries)
		if meta.count == 0 {
			return nil, fmt.Errorf("program header table outside file bounds")
		}
	}
	return meta, nil
}

const maxForceGrowthRatio = 1.15

func (e *ELFFile) obfuscateProgramHeaders(force bool, originalSize uint64, preserveLoadOrder bool) *common.OperationResult {
	meta, err := e.fetchProgramHeaderMeta()
	if err != nil || len(e.Segments) == 0 {
		return common.NewSkipped("no program headers available for obfuscation")
	}
	if !force && !preserveLoadOrder && (e.IsPacked || e.usedFallbackMode || len(e.Sections) == 0) {
		preserveLoadOrder = true
	}
	segmentCount := len(e.Segments)
	phCount := int(meta.count)
	if phCount > segmentCount {
		phCount = segmentCount
	}
	if phCount == 0 {
		return common.NewSkipped("no parsed segments available")
	}
	entrySize := int(meta.entrySize)
	entries := make([][]byte, phCount)
	for i := 0; i < phCount; i++ {
		start := meta.offset + uint64(i)*uint64(entrySize)
		end := start + uint64(entrySize)
		entryBytes := make([]byte, entrySize)
		copy(entryBytes, e.RawData[start:end])
		entries[i] = entryBytes
	}

	result := common.NewApplied("modified program headers", 0)
	result.SetCategory("OTHER")
	changesApplied := 0

	if e.rotateSegmentType(entries, PT_NOTE) {
		noteCount := e.countSegmentsOfType(PT_NOTE, phCount)
		if noteCount > 0 {
			result.AddDetail(fmt.Sprintf("rotated %d PT_NOTE entries", noteCount), noteCount, false)
			changesApplied += noteCount
		}
	}
	if !preserveLoadOrder {
		if e.reverseSegmentType(entries, PT_LOAD) {
			loadCount := e.countSegmentsOfType(PT_LOAD, phCount)
			if loadCount > 0 {
				result.AddDetail(fmt.Sprintf("reordered %d PT_LOAD entries", loadCount), loadCount, false)
				changesApplied += loadCount
			}
		}

		if alignCount, alignErr := e.randomizeLoadAlignments(entries); alignErr == nil && alignCount > 0 {
			result.AddDetail(fmt.Sprintf("randomized alignment on %d load segments", alignCount), alignCount, false)
			changesApplied += alignCount
		}
	}

	if paddrCount, paddrErr := e.randomizePhysicalAddresses(entries); paddrErr == nil && paddrCount > 0 {
		result.AddDetail(fmt.Sprintf("randomized physical addresses on %d metadata segments", paddrCount), paddrCount, false)
		changesApplied += paddrCount
	}

	if force {
		if moveCount := e.relocateMetadataSegments(entries, originalSize); moveCount > 0 {
			result.AddDetail(fmt.Sprintf("relocated %d metadata segments", moveCount), moveCount, true)
			changesApplied += moveCount
		}
	}

	if changesApplied == 0 {
		return common.NewSkipped("program headers already obfuscated")
	}

	for i := 0; i < phCount; i++ {
		start := meta.offset + uint64(i)*uint64(entrySize)
		copy(e.RawData[start:start+uint64(entrySize)], entries[i])
		e.Segments[i].Index = uint16(i)
	}
	result.Count = changesApplied
	return result
}

func (e *ELFFile) rotateSegmentType(entries [][]byte, segmentType uint32) bool {
	var indices []int
	for idx, seg := range e.Segments {
		if idx >= len(entries) {
			break
		}
		if seg.Type == segmentType {
			indices = append(indices, idx)
		}
	}
	if len(indices) < 2 {
		return false
	}
	tempSegments := make([]Segment, len(indices))
	tempEntries := make([][]byte, len(indices))
	for i, idx := range indices {
		tempSegments[i] = e.Segments[idx]
		tempEntries[i] = entries[idx]
	}
	for i, idx := range indices {
		next := (i + 1) % len(indices)
		e.Segments[idx] = tempSegments[next]
		e.Segments[idx].Index = uint16(idx)
		entries[idx] = tempEntries[next]
	}
	return true
}

func (e *ELFFile) reverseSegmentType(entries [][]byte, segmentType uint32) bool {
	var indices []int
	for idx, seg := range e.Segments {
		if idx >= len(entries) {
			break
		}
		if seg.Type == segmentType {
			indices = append(indices, idx)
		}
	}
	if len(indices) < 2 {
		return false
	}
	tempSegments := make([]Segment, len(indices))
	tempEntries := make([][]byte, len(indices))
	for i, idx := range indices {
		tempSegments[i] = e.Segments[idx]
		tempEntries[i] = entries[idx]
	}
	for i, idx := range indices {
		reverseIdx := len(indices) - 1 - i
		e.Segments[idx] = tempSegments[reverseIdx]
		e.Segments[idx].Index = uint16(idx)
		entries[idx] = tempEntries[reverseIdx]
	}
	return true
}

func (e *ELFFile) countSegmentsOfType(segmentType uint32, limit int) int {
	count := 0
	for idx := 0; idx < limit && idx < len(e.Segments); idx++ {
		if e.Segments[idx].Type == segmentType {
			count++
		}
	}
	return count
}

func (e *ELFFile) randomizeLoadAlignments(entries [][]byte) (int, error) {
	changed := 0
	alignCandidates := []uint64{0x1000, 0x1800, 0x2000, 0x3000, 0x4000}
	for idx, seg := range e.Segments {
		if idx >= len(entries) {
			break
		}
		if seg.Type != PT_LOAD || seg.Alignment == 0 {
			continue
		}
		randBytes, err := common.GenerateRandomBytes(2)
		if err != nil {
			return changed, err
		}
		nextAlign := alignCandidates[int(binary.LittleEndian.Uint16(randBytes))%len(alignCandidates)]
		if nextAlign == seg.Alignment {
			continue
		}
		e.Segments[idx].Alignment = nextAlign
		if e.Is64Bit {
			e.getEndian().PutUint64(entries[idx][ELF64_P_ALIGN:ELF64_P_ALIGN+8], nextAlign)
		} else {
			e.getEndian().PutUint32(entries[idx][ELF32_P_ALIGN:ELF32_P_ALIGN+4], uint32(nextAlign))
		}
		changed++
	}
	return changed, nil
}

func (e *ELFFile) randomizePhysicalAddresses(entries [][]byte) (int, error) {
	changed := 0
	for idx, seg := range e.Segments {
		if idx >= len(entries) {
			break
		}
		if seg.Type == PT_LOAD {
			continue
		}
		randomAddr, err := generateRandomOffset()
		if err != nil {
			return changed, err
		}
		if randomAddr == 0 {
			randomAddr = 0x1000
		}
		e.Segments[idx].PhysicalAddr = randomAddr
		if e.Is64Bit {
			e.getEndian().PutUint64(entries[idx][ELF64_P_PADDR:ELF64_P_PADDR+8], randomAddr)
		} else {
			e.getEndian().PutUint32(entries[idx][ELF32_P_PADDR:ELF32_P_PADDR+4], uint32(randomAddr))
		}
		changed++
	}
	return changed, nil
}

func (e *ELFFile) relocateMetadataSegments(entries [][]byte, originalSize uint64) int {
	moved := 0
	sectionsTouched := false
	growthLimit := int64(float64(originalSize) * maxForceGrowthRatio)
	if growthLimit < int64(len(e.RawData)) {
		growthLimit = int64(len(e.RawData))
	}
	for idx, seg := range e.Segments {
		if idx >= len(entries) {
			break
		}
		if seg.Type != PT_NOTE && seg.Type != PT_GNU_EH_FRAME {
			continue
		}
		if seg.FileSize == 0 || int64(seg.Offset) < 0 || int64(seg.Offset)+int64(seg.FileSize) > int64(len(e.RawData)) {
			continue
		}
		newOffset := e.appendSegmentDataCopy(int64(seg.Offset), int64(seg.FileSize), growthLimit)
		if newOffset == -1 {
			continue
		}
		e.updateSectionsForRelocatedRange(int64(seg.Offset), int64(seg.FileSize), newOffset)
		sectionsTouched = true
		if e.Is64Bit {
			e.getEndian().PutUint64(entries[idx][ELF64_P_OFFSET:ELF64_P_OFFSET+8], uint64(newOffset))
		} else {
			e.getEndian().PutUint32(entries[idx][ELF32_P_OFFSET:ELF32_P_OFFSET+4], uint32(newOffset))
		}
		e.Segments[idx].Offset = uint64(newOffset)
		moved++
	}
	if sectionsTouched {
		_ = e.updateSectionHeaders()
	}
	return moved
}

func (e *ELFFile) appendSegmentDataCopy(oldOffset int64, size int64, maxSize int64) int64 {
	if size <= 0 {
		return -1
	}
	if oldOffset < 0 || oldOffset+size > int64(len(e.RawData)) {
		return -1
	}
	segmentBytes := make([]byte, size)
	copy(segmentBytes, e.RawData[oldOffset:oldOffset+size])

	align := int64(0x1000)
	newOffset := common.AlignUp64(int64(len(e.RawData)), align)
	if maxSize > 0 && newOffset+size > maxSize {
		return -1
	}
	padding := newOffset - int64(len(e.RawData))
	if padding > 0 {
		e.RawData = append(e.RawData, make([]byte, padding)...)
	}
	e.RawData = append(e.RawData, segmentBytes...)

	randomFill, err := common.GenerateRandomBytes(int(size))
	if err == nil {
		copy(e.RawData[oldOffset:oldOffset+size], randomFill)
	}
	return newOffset
}

func (e *ELFFile) updateSectionsForRelocatedRange(oldOffset, size, newOffset int64) {
	for idx := range e.Sections {
		section := &e.Sections[idx]
		if section.Offset >= oldOffset && section.Offset < oldOffset+size {
			delta := section.Offset - oldOffset
			section.Offset = newOffset + delta
		}
	}
}

func (e *ELFFile) scrambleSectionStringTableForce() *common.OperationResult {
	index, found := e.findSectionByName(".shstrtab")
	if !found {
		return common.NewSkipped("no .shstrtab present to scrub")
	}
	section := e.Sections[index]
	if section.Size <= 1 || section.Offset <= 0 || int(section.Offset)+int(section.Size) > len(e.RawData) {
		return common.NewSkipped(".shstrtab too small to scrub")
	}
	start := section.Offset
	end := start + section.Size
	slice := e.RawData[start:end]
	randomBytes, err := common.GenerateRandomBytes(len(slice) - 1)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to generate random bytes for shstrtab: %v", err))
	}
	for i := 1; i < len(slice); i++ {
		if slice[i] == 0 {
			continue
		}
		slice[i] = randomBytes[i-1]
		if slice[i] == 0 {
			slice[i] = 'a'
		}
	}
	return common.NewApplied("scrubbed .shstrtab contents (force mode)", 1)
}

func (e *ELFFile) wipeSectionStringTableBeforeSave() *common.OperationResult {
	index, found := e.findSectionByName(".shstrtab")
	if !found {
		return common.NewSkipped("no .shstrtab available for wipe")
	}
	section := e.Sections[index]
	if section.Offset < 0 || section.Size <= 1 {
		return common.NewSkipped(".shstrtab too small to wipe")
	}
	start := int(section.Offset)
	end := start + int(section.Size)
	if end > len(e.RawData) {
		return common.NewSkipped(".shstrtab exceeds file bounds")
	}
	for i := start + 1; i < end; i++ {
		e.RawData[i] = 0
	}
	return common.NewApplied("wiped .shstrtab before save", 1)
}

func (e *ELFFile) collectDynsymUsage(dynsymIndex uint16) map[int]bool {
	used := make(map[int]bool)
	for idx := range e.Sections {
		section := &e.Sections[idx]
		if (section.Type != SHT_RELA && section.Type != SHT_REL) || uint16(section.Link) != dynsymIndex {
			continue
		}
		data, err := e.getSectionContent(uint16(idx))
		if err != nil || len(data) == 0 {
			continue
		}
		entrySize := e.relocationEntrySize(section.Type)
		if entrySize == 0 {
			continue
		}
		for offset := 0; offset+entrySize <= len(data); offset += entrySize {
			info := e.readRelocationInfo(section.Type, data[offset:], entrySize)
			used[int(info.symIndex)] = true
		}
	}
	return used
}

type relocationInfo struct {
	symIndex uint32
	typ      uint32
}

func (e *ELFFile) rewriteDynsymRelocations(dynsymIndex uint16, indexMap map[int]int) int {
	updated := 0
	for secIdx := range e.Sections {
		section := &e.Sections[secIdx]
		if (section.Type != SHT_RELA && section.Type != SHT_REL) || uint16(section.Link) != dynsymIndex {
			continue
		}
		data, err := e.getSectionContent(uint16(secIdx))
		if err != nil || len(data) == 0 {
			continue
		}
		entrySize := e.relocationEntrySize(section.Type)
		if entrySize == 0 || section.Offset < 0 {
			continue
		}
		sectionStart := section.Offset
		for offset := 0; offset+entrySize <= len(data); offset += entrySize {
			info := e.readRelocationInfo(section.Type, data[offset:], entrySize)
			newIdx, ok := indexMap[int(info.symIndex)]
			if !ok {
				continue
			}
			if newIdx == int(info.symIndex) {
				continue
			}
			e.writeRelocationInfo(section.Type, sectionStart+int64(offset), entrySize, relocationInfo{
				symIndex: uint32(newIdx),
				typ:      info.typ,
			})
			updated++
		}
	}
	return updated
}

func (e *ELFFile) relocationEntrySize(sectionType uint32) int {
	switch sectionType {
	case SHT_RELA:
		if e.Is64Bit {
			return 24
		}
		return 12
	case SHT_REL:
		if e.Is64Bit {
			return 16
		}
		return 8
	default:
		return 0
	}
}

func (e *ELFFile) readRelocationInfo(sectionType uint32, data []byte, entrySize int) relocationInfo {
	if e.Is64Bit {
		infoOffset := 8
		info := binary.LittleEndian.Uint64(data[infoOffset : infoOffset+8])
		return relocationInfo{
			symIndex: uint32(info >> 32),
			typ:      uint32(info & 0xffffffff),
		}
	}
	// 32-bit
	infoOffset := 4
	info := binary.LittleEndian.Uint32(data[infoOffset : infoOffset+4])
	return relocationInfo{
		symIndex: info >> 8,
		typ:      info & 0xff,
	}
}

func (e *ELFFile) writeRelocationInfo(sectionType uint32, absoluteOffset int64, entrySize int, info relocationInfo) {
	if e.Is64Bit {
		pos := absoluteOffset + 8
		newInfo := (uint64(info.symIndex) << 32) | uint64(info.typ)
		_ = e.writeAtOffset(int(pos), newInfo)
		return
	}
	pos := absoluteOffset + 4
	newInfo := (info.symIndex << 8) | (info.typ & 0xff)
	_ = e.writeAtOffset(int(pos), uint32(newInfo))
}

func (e *ELFFile) shuffleDynsymEntries(entries []dynsymEntry) (int, map[int]int) {
	if len(entries) <= 2 {
		return 0, map[int]int{}
	}
	swapCount := 0
	shuffleRange := entries[1:]
	for i := len(shuffleRange) - 1; i > 0; i-- {
		randBytes, err := common.GenerateRandomBytes(2)
		if err != nil {
			continue
		}
		j := int(binary.LittleEndian.Uint16(randBytes)) % (i + 1)
		if i == j {
			continue
		}
		shuffleRange[i], shuffleRange[j] = shuffleRange[j], shuffleRange[i]
		swapCount++
	}
	// rebuild
	for i := 1; i < len(entries); i++ {
		entries[i] = shuffleRange[i-1]
	}
	indexMap := make(map[int]int, len(entries))
	for newIdx, entry := range entries {
		indexMap[entry.originalIndex] = newIdx
	}
	return swapCount, indexMap
}

func (e *ELFFile) injectFakeLocalSymbols(entries []dynsymEntry, dynstr *Section, used map[int]bool) int {
	candidates := make([]int, 0)
	for idx := range entries {
		if idx == 0 {
			continue
		}
		entry := entries[idx]
		if used[entry.originalIndex] {
			continue
		}
		binding, _ := e.getSymbolBindingType(entry.data)
		if binding == STB_LOCAL {
			candidates = append(candidates, idx)
		}
	}
	if len(candidates) == 0 {
		return 0
	}
	maxFake := 3
	if len(candidates) < maxFake {
		maxFake = len(candidates)
	}
	added := 0
	for i := 0; i < maxFake; i++ {
		idx := candidates[i]
		entry := entries[idx]
		if !e.rewriteSymbolAsPadding(entry.data, dynstr) {
			continue
		}
		added++
	}
	return added
}

func (e *ELFFile) getSymbolBindingType(data []byte) (uint8, uint8) {
	if e.Is64Bit {
		info := data[4]
		return info >> 4, info & 0x0f
	}
	info := data[12]
	return info >> 4, info & 0x0f
}

func (e *ELFFile) setSymbolBindingType(data []byte, binding, typ uint8) {
	info := (binding << 4) | (typ & 0x0f)
	if e.Is64Bit {
		data[4] = info
		return
	}
	data[12] = info
}

func (e *ELFFile) setSymbolValue(data []byte, value uint64) {
	if e.Is64Bit {
		binary.LittleEndian.PutUint64(data[8:16], value)
		return
	}
	binary.LittleEndian.PutUint32(data[4:8], uint32(value))
}

func (e *ELFFile) setSymbolSize(data []byte, size uint64) {
	if e.Is64Bit {
		binary.LittleEndian.PutUint64(data[16:24], size)
		return
	}
	binary.LittleEndian.PutUint32(data[8:12], uint32(size))
}

func (e *ELFFile) setSymbolSectionIndex(data []byte, index uint16) {
	if e.Is64Bit {
		binary.LittleEndian.PutUint16(data[6:8], index)
		return
	}
	binary.LittleEndian.PutUint16(data[14:16], index)
}

func (e *ELFFile) getSymbolNameOffset(data []byte) uint32 {
	return binary.LittleEndian.Uint32(data[0:4])
}

func (e *ELFFile) rewriteSymbolAsPadding(data []byte, dynstr *Section) bool {
	addr, ok := e.samplePaddingVirtualAddress()
	if !ok {
		return false
	}
	nameOffset := e.getSymbolNameOffset(data)
	if !e.randomizeDynstrName(dynstr, nameOffset) {
		return false
	}
	e.setSymbolBindingType(data, STB_LOCAL, STT_NOTYPE)
	e.setSymbolValue(data, addr)
	e.setSymbolSize(data, 0)
	e.setSymbolSectionIndex(data, 0)
	return true
}

func (e *ELFFile) reorderVersionTable(section *Section, original []byte, entries []dynsymEntry) {
	if section == nil || section.Offset < 0 {
		return
	}
	entryCount := len(entries)
	if entryCount == 0 || len(original) < entryCount*2 {
		return
	}
	reordered := make([]byte, len(original))
	for newIdx, entry := range entries {
		srcStart := entry.originalIndex * 2
		dstStart := newIdx * 2
		if srcStart+2 > len(original) || dstStart+2 > len(reordered) {
			continue
		}
		copy(reordered[dstStart:dstStart+2], original[srcStart:srcStart+2])
	}
	start := section.Offset
	end := start + int64(len(reordered))
	if end > int64(len(e.RawData)) {
		return
	}
	copy(e.RawData[start:end], reordered)
}

func (e *ELFFile) randomizeDynstrName(dynstr *Section, nameOffset uint32) bool {
	start := dynstr.Offset + int64(nameOffset)
	if start < 0 || start >= int64(len(e.RawData)) {
		return false
	}
	end := start
	for end < dynstr.Offset+dynstr.Size {
		if e.RawData[end] == 0 {
			break
		}
		end++
	}
	if end <= start {
		return false
	}
	length := int(end - start)
	randBytes, err := common.GenerateRandomBytes(length)
	if err != nil {
		return false
	}
	startIdx := int(start)
	for i := 0; i < length; i++ {
		ch := randBytes[i]%26 + 'a'
		e.RawData[startIdx+i] = ch
	}
	return true
}

func (e *ELFFile) samplePaddingVirtualAddress() (uint64, bool) {
	type padRange struct {
		fileOffset int64
		length     int64
		segment    *Segment
	}
	sections := make([]Section, 0, len(e.Sections))
	for _, sec := range e.Sections {
		if sec.Offset <= 0 || sec.Size <= 0 {
			continue
		}
		sections = append(sections, sec)
	}
	sort.Slice(sections, func(i, j int) bool { return sections[i].Offset < sections[j].Offset })
	var pads []padRange
	for i := 0; i < len(sections)-1; i++ {
		currentEnd := sections[i].Offset + sections[i].Size
		nextStart := sections[i+1].Offset
		if nextStart <= currentEnd+0x20 {
			continue
		}
		seg := e.segmentForOffset(currentEnd)
		if seg == nil {
			continue
		}
		pads = append(pads, padRange{
			fileOffset: currentEnd,
			length:     nextStart - currentEnd,
			segment:    seg,
		})
	}
	if len(pads) == 0 {
		return 0, false
	}
	randIdxBytes, err := common.GenerateRandomBytes(1)
	if err != nil {
		return 0, false
	}
	pad := pads[int(randIdxBytes[0])%len(pads)]
	randWithin, err := common.GenerateRandomBytes(2)
	if err != nil {
		return 0, false
	}
	offset := int64(binary.LittleEndian.Uint16(randWithin)) % pad.length
	fileOffset := pad.fileOffset + offset
	if fileOffset < int64(pad.segment.Offset) {
		fileOffset = int64(pad.segment.Offset)
	}
	virtual := pad.segment.VirtualAddr + uint64(fileOffset-int64(pad.segment.Offset))
	return virtual, true
}

func (e *ELFFile) segmentForOffset(offset int64) *Segment {
	for idx := range e.Segments {
		seg := &e.Segments[idx]
		if !seg.Loadable {
			continue
		}
		segStart := int64(seg.Offset)
		segEnd := segStart + int64(seg.FileSize)
		if offset >= segStart && offset < segEnd {
			return seg
		}
	}
	return nil
}

func (e *ELFFile) scrambleDynstrForce(entries []dynsymEntry, dynstrIdx uint16, essential map[int]bool) *common.OperationResult {
	dynstr := &e.Sections[dynstrIdx]
	if dynstr.Size <= 1 {
		return common.NewSkipped(".dynstr too small for scrambling")
	}
	encrypted := 0
	for idx := range entries {
		if idx == 0 || essential[idx] {
			continue
		}
		entry := entries[idx]
		binding, _ := e.getSymbolBindingType(entry.data)
		if binding != STB_LOCAL {
			continue
		}
		nameOffset := e.getSymbolNameOffset(entry.data)
		if e.xorDynstrString(dynstr, nameOffset) {
			encrypted++
		}
	}
	if encrypted == 0 {
		return common.NewSkipped("no eligible dynstr entries to scramble")
	}

	result := common.NewApplied(fmt.Sprintf("XOR-obfuscated %d dynstr entries", encrypted), encrypted)
	result.SetCategory("SYMBOLS")
	return result
}

func (e *ELFFile) xorDynstrString(dynstr *Section, nameOffset uint32) bool {
	start := dynstr.Offset + int64(nameOffset)
	if start < dynstr.Offset || start >= dynstr.Offset+dynstr.Size {
		return false
	}
	end := start
	for end < dynstr.Offset+dynstr.Size {
		if e.RawData[end] == 0 {
			break
		}
		end++
	}
	if end <= start {
		return false
	}
	length := int(end - start)
	if length == 0 {
		return false
	}
	randomBytes, err := common.GenerateRandomBytes(length)
	if err != nil {
		return false
	}
	startIdx := int(start)
	for i := 0; i < length; i++ {
		e.RawData[startIdx+i] ^= randomBytes[i]
	}
	return true
}

type dynsymEntry struct {
	originalIndex int
	data          []byte
}

func (e *ELFFile) obfuscateDynamicSymbols(force bool) *common.OperationResult {
	dynsymIdx, found := e.findSectionIndexByType(SHT_DYNSYM)
	if !found {
		return common.NewSkipped("no .dynsym section present")
	}
	dynstrIdx, found := e.dynamicStringTableIndex()
	if !found {
		return common.NewSkipped("no .dynstr section present")
	}
	dynsym := e.Sections[dynsymIdx]
	dynstr := &e.Sections[dynstrIdx]
	if dynsym.Size == 0 || dynstr.Size == 0 {
		return common.NewSkipped(".dynsym or .dynstr empty")
	}
	entrySize := e.symbolEntrySize()
	if entrySize == 0 || dynsym.Size%entrySize != 0 {
		return common.NewSkipped("invalid .dynsym layout")
	}

	entryCount := int(dynsym.Size / entrySize)
	if entryCount <= 1 {
		return common.NewSkipped("not enough dynamic symbols to shuffle")
	}

	entries := make([]dynsymEntry, entryCount)
	base := dynsym.Offset
	for i := 0; i < entryCount; i++ {
		start := base + int64(i)*entrySize
		end := start + entrySize
		if end > int64(len(e.RawData)) {
			return common.NewSkipped("dynsym out of range")
		}
		data := make([]byte, entrySize)
		copy(data, e.RawData[start:end])
		entries[i] = dynsymEntry{
			originalIndex: i,
			data:          data,
		}
	}

	usedIndices := e.collectDynsymUsage(uint16(dynsymIdx))
	shuffleCount, indexMap := e.shuffleDynsymEntries(entries)
	if shuffleCount == 0 {
		return common.NewSkipped("dynsym entries already randomized")
	}

	// Inject fake locals using entries that are unused by relocations.
	fakeLocalCount := e.injectFakeLocalSymbols(entries, dynstr, usedIndices)

	// Persist symbol table back to file.
	for i := 0; i < entryCount; i++ {
		start := base + int64(i)*entrySize
		copy(e.RawData[start:start+entrySize], entries[i].data)
	}

	// Rewrite relocation references with the new ordering.
	relocationUpdates := e.rewriteDynsymRelocations(uint16(dynsymIdx), indexMap)

	if versionIdx, ok := e.findSectionIndexByType(SHT_GNU_VERSYM); ok {
		if data, err := e.getSectionContent(uint16(versionIdx)); err == nil && len(data) >= entryCount*2 {
			e.reorderVersionTable(&e.Sections[versionIdx], data, entries)
		}
	}

	result := common.NewApplied("updated dynamic symbols", 0)
	result.SetCategory("SYMBOLS")
	result.AddDetail(fmt.Sprintf("shuffled %d dynamic symbols", shuffleCount), shuffleCount, false)
	if fakeLocalCount > 0 {
		result.AddDetail(fmt.Sprintf("injected %d fake local symbols", fakeLocalCount), fakeLocalCount, false)
	}
	if relocationUpdates > 0 {
		result.AddDetail(fmt.Sprintf("patched %d relocation entries", relocationUpdates), relocationUpdates, false)
	}

	result.Count = shuffleCount + fakeLocalCount + relocationUpdates

	if force {
		essentialNew := make(map[int]bool)
		for oldIdx := range usedIndices {
			if newIdx, ok := indexMap[oldIdx]; ok {
				essentialNew[newIdx] = true
			}
		}
		if dynstrResult := e.scrambleDynstrForce(entries, dynstrIdx, essentialNew); dynstrResult != nil && dynstrResult.Applied {
			for _, detail := range dynstrResult.Details {
				result.AddDetail(detail.Message, detail.Count, detail.IsRisky)
			}
			result.Count += dynstrResult.Count
		}
	}

	return result
}

func (e *ELFFile) symbolEntrySize() int64 {
	if e.Is64Bit {
		return ELF64_SYM_SIZE
	}
	return ELF32_SYM_SIZE
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
		lowName := strings.ToLower(section.Name)
		// Never touch dynamic or static string tables used by the linker/loader
		if lowName == ".dynstr" || lowName == ".strtab" {
			continue
		}
		if !strings.Contains(lowName, "data") &&
			!strings.Contains(lowName, "rodata") &&
			!strings.Contains(lowName, ".str") {
			continue
		}

		sectionData, err := e.getSectionContent(uint16(section.Index))
		if err != nil || len(sectionData) < 3 {
			continue
		}

		sectionModified := false
		for original, replacement := range stringReplacements {
			originalBytes := []byte(original)
			replacementBytes := []byte(replacement)
			if len(replacementBytes) < len(originalBytes) {
				replacementBytes = append(replacementBytes, make([]byte, len(originalBytes)-len(replacementBytes))...)
			} else if len(replacementBytes) > len(originalBytes) {
				continue
			}
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
