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
	removable := e.identifyCompactableSections(force)
	if len(removable) == 0 {
		return common.NewSkipped("no compactable sections found")
	}

	sort.Sort(sort.Reverse(sort.IntSlice(removable)))
	removedNames := e.getRemovedSectionNames(removable)

	shstrIndex := e.findSectionIndex(".shstrtab")
	totalRemoved := int64(0)

	// 1) Rimuove i blocchi dati delle sezioni
	for _, idx := range removable {
		if err := e.removeCompactSection(idx, &totalRemoved); err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to remove section %d: %v", idx, err))
		}
	}

	// 2) Aggiorna le tabelle interne
	e.updateSections(removable)
	if err := e.UpdateSectionHeaders(); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to update section headers: %v", err))
	}
	if err := e.updateELFHeaderSectionCount(); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to update ELF header section count: %v", err))
	}
	if shstrIndex >= 0 {
		newIdx := e.calculateNewShstrtabIndex(removable, shstrIndex)
		if err := e.updateELFHeaderShstrtabIndex(uint16(newIdx)); err != nil {
			return common.NewSkipped(fmt.Sprintf("failed to update ELF header shstrtab index: %v", err))
		}
	}

	// 3) Trancia l’overlay oltre l’ultimo segmento
	maxEnd := 0
	for _, seg := range e.Segments {
		end := int(seg.Offset + seg.FileSize)
		if end > maxEnd {
			maxEnd = end
		}
	}
	if len(e.RawData) > maxEnd {
		removedOverlay := int64(len(e.RawData) - maxEnd)
		e.RawData = e.RawData[:maxEnd]
		totalRemoved += removedOverlay
	}

	newSize := int64(len(e.RawData))
	percent := float64(totalRemoved) / float64(originalSize) * 100
	msg := fmt.Sprintf(
		"removed %d sections: %s (%d -> %d bytes, %d bytes removed, %.1f%% reduction)",
		len(removable), strings.Join(removedNames, ", "),
		originalSize, newSize, totalRemoved, percent,
	)
	return common.NewApplied(msg, len(removable))
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

func (e *ELFFile) findSectionIndex(name string) int {
	for i, section := range e.Sections {
		if section.Name == name {
			return i
		}
	}
	return -1
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

func (e *ELFFile) calculateNewShstrtabIndex(removable []int, shstrtabIndex int) int {
	newIndex := shstrtabIndex
	for _, idx := range removable {
		if idx < shstrtabIndex {
			newIndex--
		}
	}
	return newIndex
}

func (e *ELFFile) identifyCompactableSections(force bool) []int {
	critical := e.identifyCriticalSections()
	var removable []int

	for i, section := range e.Sections {
		if _, ok := critical[i]; ok && section.Size > 0 {
			continue
		}
		if section.Name == ".shstrtab" || section.Type == 8 {
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
	if section.Type == 8 {
		return section.Size == 0
	}
	return section.Size == 0
}

func (e *ELFFile) isAlreadyStrippedSection(section Section) bool {
	return section.Size == 0 && section.Offset == 0
}

func (e *ELFFile) removeCompactSection(sectionIdx int, totalRemovedSize *int64) error {
	if sectionIdx < 0 || sectionIdx >= len(e.Sections) {
		return fmt.Errorf("invalid section index: %d", sectionIdx)
	}

	section := e.Sections[sectionIdx]
	if section.Offset <= 0 || section.Size <= 0 {
		return nil
	}

	fileAlignment := e.getFileAlignment()
	alignedSize := common.AlignUp64(section.Size, fileAlignment)
	start, end := int(section.Offset), int(section.Offset+alignedSize)
	if end > len(e.RawData) {
		end = len(e.RawData)
	}

	if end > start {
		e.RawData = append(e.RawData[:start], e.RawData[end:]...)
		removedSize := int64(end - start)
		*totalRemovedSize += removedSize

		for i := range e.Sections {
			if i != sectionIdx && e.Sections[i].Offset > section.Offset {
				e.Sections[i].Offset -= removedSize
			}
		}
		e.updateProgramHeaderOffsets(section.Offset, removedSize)
	}

	return nil
}

func (e *ELFFile) updateProgramHeaderOffsets(removedOffset int64, removedSize int64) {
	for i := range e.Segments {
		if e.Segments[i].Offset > uint64(removedOffset) {
			e.Segments[i].Offset -= uint64(removedSize)
		}
	}
}

func (e *ELFFile) updateELFHeaderSectionCount() error {
	sectionCount := uint16(len(e.Sections))

	var pos int
	if e.Is64Bit {
		pos = elf64E_shnum_offset
	} else {
		pos = elf32E_shnum_offset
	}

	return e.writeAtOffset(pos, sectionCount)
}

func (e *ELFFile) updateELFHeaderShstrtabIndex(shstrtabIndex uint16) error {
	var pos int
	if e.Is64Bit {
		pos = elf64E_shstrndx_offset
	} else {
		pos = elf32E_shstrndx_offset
	}

	return e.writeAtOffset(pos, shstrtabIndex)
}

func (e *ELFFile) isCorruptedSection(section Section) bool {
	if section.Offset < 0 || section.Size < 0 {
		return true
	}
	if section.Offset > 0 && section.Offset > int64(len(e.RawData)) {
		return true
	}
	if section.Offset > 0 && section.Size > 0 {
		end := section.Offset + section.Size
		if end > int64(len(e.RawData)) {
			return true
		}
	}

	return false
}

func (e *ELFFile) isNullOrZeroSection(section Section) bool {
	if section.Offset <= 0 || section.Size <= 0 {
		return false
	}
	if section.Size > 65536 {
		return false
	}

	start := int(section.Offset)
	end := min(start+int(section.Size), len(e.RawData))
	for i := start; i < end; i++ {
		if e.RawData[i] != 0 {
			return false
		}
	}
	return true
}

func (e *ELFFile) getFileAlignment() int64 {
	if e.Is64Bit {
		return 8
	}
	return 4
}

func (e *ELFFile) identifyCriticalSections() map[int]struct{} {
	criticalSectionNames := []string{
		// Essential ELF sections
		".text", ".data", ".rodata", ".bss", ".init", ".fini",
		".plt", ".got", ".got.plt", ".dynamic", ".dynsym", ".dynstr",
		".hash", ".gnu.hash", ".interp",
		// Constructor/destructor sections
		".ctors", ".dtors", ".init_array", ".fini_array",
		// Exception handling (often critical)
		".eh_frame", ".eh_frame_hdr", ".gcc_except_table",
		// Go-specific critical sections
		".gopclntab", ".typelink", ".itablink",
		// TLS sections
		".tdata", ".tbss",
	}

	critical := make(map[int]struct{})
	for i, sec := range e.Sections {
		name := strings.ToLower(strings.Trim(sec.Name, "\x00"))
		for _, crit := range criticalSectionNames {
			if name == strings.ToLower(crit) {
				critical[i] = struct{}{}
				break
			}
		}
	}

	return critical
}
