package elfrw

import (
	"fmt"
	"gosstrip/common"
	"sort"
	"strings"
)

func (e *ELFFile) Compact(force bool) *common.OperationResult {
	if len(e.Sections) == 0 {
		return common.NewSkipped("no sections to process")
	}
	originalSize := int64(len(e.RawData))
	removables := e.identifyCompactableSections(force)
	if len(removables) == 0 {
		return common.NewSkipped("no compactable sections found")
	}
	sort.Sort(sort.Reverse(sort.IntSlice(removables)))
	removedNames := e.getRemovedSectionNames(removables)
	var totalRemoved int64

	skip := func(format string, a ...interface{}) *common.OperationResult {
		return common.NewSkipped(fmt.Sprintf(format, a...))
	}
	for _, idx := range removables {
		if err := e.removeSection(idx, &totalRemoved); err != nil {
			fmt.Printf(
				"⚠️  Warning: Failed to remove section %d (%s): %v\n",
				idx, e.Sections[idx].Name, err,
			)
		}
	}
	e.updateSections(removables)
	trim := func() int64 {
		maxEnd := 0
		for _, seg := range e.Segments {
			end := int(seg.Offset + seg.FileSize)
			if end > maxEnd {
				maxEnd = end
			}
		}
		if len(e.RawData) <= maxEnd {
			return 0
		}
		removed := int64(len(e.RawData) - maxEnd)
		e.RawData = e.RawData[:maxEnd]
		return removed
	}
	totalRemoved += trim()
	if err := e.rebuildSectionHeaderTable(); err != nil {
		return skip("failed to rebuild section header table: %v", err)
	}
	if err := e.updateELFHeaderSectionCount(); err != nil {
		return skip("failed to update ELF header section count: %v", err)
	}

	newSize := int64(len(e.RawData))
	percent := float64(totalRemoved) / float64(originalSize) * 100
	msg := fmt.Sprintf(
		"removed %d sections: %s (%d -> %d bytes, %d bytes removed, %.1f%% reduction)",
		len(removables), strings.Join(removedNames, ", "),
		originalSize, newSize, totalRemoved, percent,
	)
	return common.NewApplied(msg, len(removables))
}

func (e *ELFFile) getRemovedSectionNames(removable []int) []string {
	names := make([]string, 0, len(removable))
	for _, idx := range removable {
		if idx >= 0 && idx < len(e.Sections) {
			names = append(names, e.Sections[idx].Name)
		}
	}
	return names
}

func (e *ELFFile) updateSections(removable []int) {
	removableSet := make(map[int]bool)
	for _, idx := range removable {
		removableSet[idx] = true
	}

	newSections := make([]Section, 0, len(e.Sections)-len(removable))
	for i, section := range e.Sections {
		if !removableSet[i] {
			section.Index = len(newSections)
			newSections = append(newSections, section)
		}
	}
	e.Sections = newSections
}

func (e *ELFFile) identifyCompactableSections(force bool) []int {
	critical := e.identifyCriticalSections()
	var removable []int

	for i, section := range e.Sections {
		if _, ok := critical[i]; ok && section.Size > 0 {
			continue
		}
		if section.Name == ".shstrtab" ||
			section.Name == ".strtab" ||
			section.Name == ".dynstr" ||
			section.Type == SHT_NOBITS {
			continue
		}

		if e.isCorruptedSection(section) ||
			e.isEmptySection(section) ||
			(force && e.isNullOrZeroSection(section)) ||
			e.isAlreadyStrippedSection(section) {
			removable = append(removable, i)
		}
	}

	return removable
}

func (e *ELFFile) isEmptySection(section Section) bool {
	return section.Size == 0
}

func (e *ELFFile) isAlreadyStrippedSection(section Section) bool {
	return e.isEmptySection(section) && section.Offset == 0
}

func (e *ELFFile) removeSection(sectionIdx int, totalRemovedSize *int64) error {
	if sectionIdx < 0 || sectionIdx >= len(e.Sections) {
		return fmt.Errorf("invalid section index: %d", sectionIdx)
	}

	section := e.Sections[sectionIdx]
	if section.Offset <= 0 || section.Size <= 0 {
		return nil
	}

	fileAlignment := e.getFileAlignment()
	start := int(section.Offset)
	end := start + int(common.AlignUp64(section.Size, fileAlignment))
	if start > len(e.RawData) {
		return fmt.Errorf("section offset beyond file size: %d > %d", start, len(e.RawData))
	}
	if end > len(e.RawData) {
		end = len(e.RawData)
	}
	if end <= start {
		return nil
	}

	removedSize := int64(end - start)
	e.RawData = append(e.RawData[:start], e.RawData[end:]...)
	*totalRemovedSize += removedSize

	for i, sec := range e.Sections {
		if i != sectionIdx && sec.Offset > section.Offset {
			sec.Offset -= removedSize
		}
	}

	e.updateProgramHeaderOffsets(section.Offset, removedSize)
	_ = e.updateSectionHeaderTableOffset(section.Offset, removedSize)

	return nil
}

func (e *ELFFile) updateProgramHeaderOffsets(removedOffset int64, removedSize int64) {
	offset := uint64(removedOffset)
	size := uint64(removedSize)

	for _, segment := range e.Segments {
		if segment.Offset > offset {
			segment.Offset -= size
		}
	}
}

func (e *ELFFile) updateELFHeaderSectionCount() error {
	pos := elf32E_shnum_offset
	if e.Is64Bit {
		pos = elf64E_shnum_offset
	}

	return e.writeAtOffset(pos, uint16(len(e.Sections)))
}

func (e *ELFFile) isCorruptedSection(section Section) bool {
	dataLen := int64(len(e.RawData))

	if section.Offset < 0 || section.Size < 0 ||
		(section.Offset > 0 && section.Offset > dataLen) ||
		(section.Offset > 0 && section.Size > 0 && section.Offset+section.Size > dataLen) {
		return true
	}

	return false
}

func (e *ELFFile) isNullOrZeroSection(section Section) bool {
	if section.Offset <= 0 || section.Size <= 0 || section.Size > 65536 {
		return false
	}

	start := int(section.Offset)
	end := start + int(section.Size)
	if end > len(e.RawData) {
		end = len(e.RawData)
	}

	for i := start; i < end; i++ {
		if e.RawData[i] != 0 {
			return false
		}
	}
	return true
}

func (e *ELFFile) identifyCriticalSections() map[int]struct{} {
	criticalSectionNames := map[string]struct{}{
		".text": {}, ".data": {}, ".rodata": {}, ".bss": {}, ".init": {}, ".fini": {},
		".plt": {}, ".got": {}, ".got.plt": {}, ".dynamic": {}, ".dynsym": {}, ".dynstr": {},
		".hash": {}, ".gnu.hash": {}, ".interp": {}, ".ctors": {}, ".dtors": {}, ".init_array": {},
		".fini_array": {}, ".eh_frame": {}, ".eh_frame_hdr": {}, ".gcc_except_table": {},
		".gopclntab": {}, ".typelink": {}, ".itablink": {}, ".tdata": {}, ".tbss": {},
	}

	critical := make(map[int]struct{})
	for i, sec := range e.Sections {
		name := strings.ToLower(strings.Trim(sec.Name, "\x00"))
		if _, exists := criticalSectionNames[name]; exists {
			critical[i] = struct{}{}
		}
	}

	return critical
}

func (e *ELFFile) updateSectionHeaderTableOffset(removedOffset int64, removedSize int64) error {
	shoffPos, _, _ := e.getHeaderPositions()
	if shoffPos < 0 {
		return nil
	}

	currentOffset, err := e.getSectionHeaderOffset(shoffPos)
	if err != nil || currentOffset == 0 {
		return nil
	}

	if int64(currentOffset) > removedOffset {
		newOffset := int64(currentOffset) - removedSize
		if newOffset < 0 {
			newOffset = 0
		}

		if e.Is64Bit {
			e.GetEndian().PutUint64(e.RawData[shoffPos:shoffPos+8], uint64(newOffset))
		} else {
			e.GetEndian().PutUint32(e.RawData[shoffPos:shoffPos+4], uint32(newOffset))
		}
		fmt.Printf("🔧 Updated section header table offset: 0x%X -> 0x%X\n", currentOffset, newOffset)
	}

	return nil
}

func (e *ELFFile) rebuildSectionHeaderTable() error {
	if len(e.Sections) == 0 {
		shoffPos, shnumPos, _ := e.getHeaderPositions()
		if shoffPos > 0 || shnumPos > 0 {
			endian := e.GetEndian()
			if e.Is64Bit {
				if shoffPos > 0 {
					endian.PutUint64(e.RawData[shoffPos:shoffPos+8], 0)
				}
				if shnumPos > 0 {
					endian.PutUint16(e.RawData[shnumPos:shnumPos+2], 0)
				}
			} else {
				if shoffPos > 0 {
					endian.PutUint32(e.RawData[shoffPos:shoffPos+4], 0)
				}
				if shnumPos > 0 {
					endian.PutUint16(e.RawData[shnumPos:shnumPos+2], 0)
				}
			}
		}
		return nil
	}

	shstrtabData := []byte{0}
	nameOffsets := make(map[int]uint32)
	for i, section := range e.Sections {
		if section.Name != "" {
			nameOffsets[i] = uint32(len(shstrtabData))
			shstrtabData = append(shstrtabData, []byte(section.Name)...)
			shstrtabData = append(shstrtabData, 0)
		} else {
			nameOffsets[i] = 0
		}
	}

	shstrtabIndex := -1
	for i, section := range e.Sections {
		if section.Name == ".shstrtab" {
			shstrtabIndex = i
			break
		}
	}
	if shstrtabIndex == -1 {
		shstrtabIndex = len(e.Sections)
		e.Sections = append(e.Sections, Section{
			Name: ".shstrtab",
			Type: SHT_STRTAB,
			Size: int64(len(shstrtabData)),
		})
		if err := e.updateELFHeaderSectionCount(); err != nil {
			return fmt.Errorf("failed to update section count: %w", err)
		}
	}

	shstrtabSection := &e.Sections[shstrtabIndex]
	shstrtabSection.Size = int64(len(shstrtabData))
	shstrtabSection.Alignment = 1

	entrySize := int64(40)
	if e.Is64Bit {
		entrySize = 64
	}
	totalHeaderTableSize := int64(len(e.Sections)) * entrySize

	maxOffset := int64(0)
	for i, sec := range e.Sections {
		if i != shstrtabIndex && sec.Type != SHT_NOBITS {
			end := sec.Offset + sec.Size
			if end > maxOffset {
				maxOffset = end
			}
		}
	}

	alignment := e.getFileAlignment()
	shstrtabSection.Offset = (maxOffset + alignment - 1) &^ (alignment - 1)
	newSHTOffset := (shstrtabSection.Offset + shstrtabSection.Size + alignment - 1) &^ (alignment - 1)

	headerTableData := make([]byte, totalHeaderTableSize)
	pos := 0
	endian := e.GetEndian()
	for i, section := range e.Sections {
		nameOffset := nameOffsets[i]
		entsize := uint64(0)
		if i == shstrtabIndex {
			section = *shstrtabSection
		}

		if e.Is64Bit {
			endian.PutUint32(headerTableData[pos:], nameOffset)
			endian.PutUint32(headerTableData[pos+4:], section.Type)
			endian.PutUint64(headerTableData[pos+8:], section.Flags)
			endian.PutUint64(headerTableData[pos+16:], section.Address)
			endian.PutUint64(headerTableData[pos+24:], uint64(section.Offset))
			endian.PutUint64(headerTableData[pos+32:], uint64(section.Size))
			endian.PutUint32(headerTableData[pos+40:], section.Link)
			endian.PutUint32(headerTableData[pos+44:], section.Info)
			endian.PutUint64(headerTableData[pos+48:], section.Alignment)
			endian.PutUint64(headerTableData[pos+56:], entsize)
			pos += 64
		} else {
			endian.PutUint32(headerTableData[pos:], nameOffset)
			endian.PutUint32(headerTableData[pos+4:], section.Type)
			endian.PutUint32(headerTableData[pos+8:], uint32(section.Flags))
			endian.PutUint32(headerTableData[pos+12:], uint32(section.Address))
			endian.PutUint32(headerTableData[pos+16:], uint32(section.Offset))
			endian.PutUint32(headerTableData[pos+20:], uint32(section.Size))
			endian.PutUint32(headerTableData[pos+24:], section.Link)
			endian.PutUint32(headerTableData[pos+28:], section.Info)
			endian.PutUint32(headerTableData[pos+32:], uint32(section.Alignment))
			endian.PutUint32(headerTableData[pos+36:], uint32(entsize))
			pos += 40
		}
	}

	e.RawData = e.RawData[:maxOffset]
	e.RawData = append(e.RawData, make([]byte, shstrtabSection.Offset-int64(len(e.RawData)))...)
	e.RawData = append(e.RawData, shstrtabData...)
	e.RawData = append(e.RawData, make([]byte, newSHTOffset-int64(len(e.RawData)))...)
	e.RawData = append(e.RawData, headerTableData...)

	shoffPos, _, _ := e.getHeaderPositions()
	if shoffPos >= 0 {
		if e.Is64Bit {
			endian.PutUint64(e.RawData[shoffPos:shoffPos+8], uint64(newSHTOffset))
		} else {
			endian.PutUint32(e.RawData[shoffPos:shoffPos+4], uint32(newSHTOffset))
		}
		fmt.Printf("🔧 Rebuilt section header table at offset 0x%X (size: %d bytes)\n", newSHTOffset, totalHeaderTableSize)
	}

	return nil
}
