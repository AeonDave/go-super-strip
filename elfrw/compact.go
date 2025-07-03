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
	totalRemoved := int64(0)

	// Rimuove le sezioni dal file e aggiorna gli offset
	for _, idx := range removable {
		if err := e.removeCompactSection(idx, &totalRemoved); err != nil {
			// Non è un errore fatale, continuiamo
			fmt.Printf("⚠️  Warning: Failed to remove section %d (%s): %v\n", idx, e.Sections[idx].Name, err)
		}
	}

	// Aggiorna la lista delle sezioni in memoria
	e.updateSections(removable)

	// Tronca l'overlay se presente
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

	// Ricostruisce la tabella delle sezioni e la .shstrtab
	if err := e.rebuildSectionHeaderTable(); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to rebuild section header table: %v", err))
	}

	// Aggiorna il conteggio delle sezioni nell'header ELF
	if err := e.updateELFHeaderSectionCount(); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to update ELF header section count: %v", err))
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

	// Sezione senza dati nel file, nulla da rimuovere
	if section.Offset <= 0 || section.Size <= 0 {
		return nil
	}

	fileAlignment := e.getFileAlignment()
	alignedSize := common.AlignUp64(section.Size, fileAlignment)
	start, end := int(section.Offset), int(section.Offset+alignedSize)

	// Controllo dei limiti del file
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

	for i := range e.Sections {
		if i == sectionIdx {
			continue
		}
		if e.Sections[i].Offset > section.Offset {
			e.Sections[i].Offset -= removedSize
		}
	}

	// Aggiornamento program header e section header table
	e.updateProgramHeaderOffsets(section.Offset, removedSize)
	_ = e.updateSectionHeaderTableOffset(section.Offset, removedSize)

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

func (e *ELFFile) updateSectionHeaderTableOffset(removedOffset int64, removedSize int64) error {
	shoffPos, _, _ := e.getHeaderPositions()

	if shoffPos < 0 {
		return nil
	}

	// Get current section header table offset
	currentOffset, err := e.getSectionHeaderOffset(shoffPos)
	if err != nil || currentOffset == 0 {
		return nil
	}

	// If section header table is after the removed section, update its offset
	if int64(currentOffset) > removedOffset {
		newOffset := int64(currentOffset) - removedSize
		if newOffset < 0 {
			newOffset = 0
		}

		// Write the new offset back to the ELF header
		if e.Is64Bit {
			if shoffPos+8 <= len(e.RawData) {
				e.GetEndian().PutUint64(e.RawData[shoffPos:shoffPos+8], uint64(newOffset))
				fmt.Printf("🔧 Updated section header table offset: 0x%X -> 0x%X\n", currentOffset, newOffset)
			}
		} else {
			if shoffPos+4 <= len(e.RawData) {
				e.GetEndian().PutUint32(e.RawData[shoffPos:shoffPos+4], uint32(newOffset))
				fmt.Printf("🔧 Updated section header table offset: 0x%X -> 0x%X\n", currentOffset, newOffset)
			}
		}
	}

	return nil
}

func (e *ELFFile) rebuildSectionHeaderTable() error {
	if len(e.Sections) == 0 {
		// Se non ci sono sezioni, azzera l'offset e il numero di sezioni nell'header
		shoffPos, shnumPos, _ := e.getHeaderPositions()
		if shoffPos > 0 {
			if e.Is64Bit {
				e.GetEndian().PutUint64(e.RawData[shoffPos:shoffPos+8], 0)
			} else {
				e.GetEndian().PutUint32(e.RawData[shoffPos:shoffPos+4], 0)
			}
		}
		if shnumPos > 0 {
			if e.Is64Bit {
				e.GetEndian().PutUint16(e.RawData[shnumPos:shnumPos+2], 0)
			} else {
				e.GetEndian().PutUint16(e.RawData[shnumPos:shnumPos+2], 0)
			}
		}
		return nil
	}

	// 1. Ricostruisci la section header string table (.shstrtab)
	shstrtabData := []byte{0} // Inizia con un byte nullo
	nameOffsets := make(map[int]uint32)
	for i, section := range e.Sections {
		if section.Name == "" {
			nameOffsets[i] = 0
			continue
		}
		nameOffsets[i] = uint32(len(shstrtabData))
		shstrtabData = append(shstrtabData, []byte(section.Name)...)
		shstrtabData = append(shstrtabData, 0) // Termina con un byte nullo
	}

	// Trova o crea la sezione .shstrtab
	shstrtabIndex := -1
	for i, section := range e.Sections {
		if section.Name == ".shstrtab" {
			shstrtabIndex = i
			break
		}
	}
	if shstrtabIndex == -1 {
		// Se non esiste, la aggiungiamo (questo caso è improbabile per file validi)
		shstrtabIndex = len(e.Sections)
		e.Sections = append(e.Sections, Section{
			Name: ".shstrtab",
			Type: SHT_STRTAB,
			Size: int64(len(shstrtabData)),
		})
		// Aggiorna il conteggio delle sezioni nell'header
		if err := e.updateELFHeaderSectionCount(); err != nil {
			return fmt.Errorf("failed to update section count for new shstrtab: %w", err)
		}
	}

	// Aggiorna la sezione .shstrtab
	shstrtabSection := &e.Sections[shstrtabIndex]
	shstrtabSection.Size = int64(len(shstrtabData))
	shstrtabSection.Type = SHT_STRTAB
	shstrtabSection.Flags = 0
	shstrtabSection.Address = 0
	shstrtabSection.Link = 0
	shstrtabSection.Info = 0
	shstrtabSection.Alignment = 1

	// Aggiorna l'indice della shstrtab nell'header ELF
	if err := e.updateELFHeaderShstrtabIndex(uint16(shstrtabIndex)); err != nil {
		return fmt.Errorf("failed to update shstrtab index: %w", err)
	}

	// Calcola la dimensione di ogni entry della tabella delle sezioni
	entrySize := int64(40) // Dimensione per ELF32
	if e.Is64Bit {
		entrySize = 64 // Dimensione per ELF64
	}
	totalHeaderTableSize := int64(len(e.Sections)) * entrySize

	// Trova la fine corrente dei dati delle sezioni (allineata)
	// Escludiamo la vecchia tabella delle sezioni e la vecchia shstrtab
	maxOffset := int64(0)
	for i, sec := range e.Sections {
		if i != shstrtabIndex && sec.Type != SHT_NOBITS {
			endOffset := sec.Offset + sec.Size
			if endOffset > maxOffset {
				maxOffset = endOffset
			}
		}
	}

	alignment := e.getFileAlignment()
	// Allinea l'offset per la nuova .shstrtab
	shstrtabSection.Offset = (maxOffset + alignment - 1) &^ (alignment - 1)

	// Allinea l'offset per la nuova tabella delle intestazioni di sezione
	newSHTOffset := (shstrtabSection.Offset + shstrtabSection.Size + alignment - 1) &^ (alignment - 1)

	// Prepara i dati della tabella delle intestazioni
	headerTableData := make([]byte, totalHeaderTableSize)
	pos := 0
	for i, section := range e.Sections {
		nameOffset := nameOffsets[i]
		entsize := uint64(0)

		// Per la sezione .shstrtab, assicurati che i campi siano corretti
		if i == shstrtabIndex {
			section = *shstrtabSection
		}

		if e.Is64Bit {
			e.GetEndian().PutUint32(headerTableData[pos:], nameOffset)
			e.GetEndian().PutUint32(headerTableData[pos+4:], section.Type)
			e.GetEndian().PutUint64(headerTableData[pos+8:], section.Flags)
			e.GetEndian().PutUint64(headerTableData[pos+16:], section.Address)
			e.GetEndian().PutUint64(headerTableData[pos+24:], uint64(section.Offset))
			e.GetEndian().PutUint64(headerTableData[pos+32:], uint64(section.Size))
			e.GetEndian().PutUint32(headerTableData[pos+40:], section.Link)
			e.GetEndian().PutUint32(headerTableData[pos+44:], section.Info)
			e.GetEndian().PutUint64(headerTableData[pos+48:], section.Alignment)
			e.GetEndian().PutUint64(headerTableData[pos+56:], entsize)
			pos += 64
		} else {
			e.GetEndian().PutUint32(headerTableData[pos:], nameOffset)
			e.GetEndian().PutUint32(headerTableData[pos+4:], section.Type)
			e.GetEndian().PutUint32(headerTableData[pos+8:], uint32(section.Flags))
			e.GetEndian().PutUint32(headerTableData[pos+12:], uint32(section.Address))
			e.GetEndian().PutUint32(headerTableData[pos+16:], uint32(section.Offset))
			e.GetEndian().PutUint32(headerTableData[pos+20:], uint32(section.Size))
			e.GetEndian().PutUint32(headerTableData[pos+24:], section.Link)
			e.GetEndian().PutUint32(headerTableData[pos+28:], section.Info)
			e.GetEndian().PutUint32(headerTableData[pos+32:], uint32(section.Alignment))
			e.GetEndian().PutUint32(headerTableData[pos+36:], uint32(entsize))
			pos += 40
		}
	}

	// Rimuovi la vecchia tabella delle intestazioni e la vecchia shstrtab
	// e tronca il file alla fine dei dati delle sezioni.
	e.RawData = e.RawData[:maxOffset]

	// Aggiungi padding per l'allineamento della .shstrtab
	paddingSize := shstrtabSection.Offset - int64(len(e.RawData))
	if paddingSize > 0 {
		e.RawData = append(e.RawData, make([]byte, paddingSize)...)
	}

	// Aggiungi la nuova .shstrtab
	e.RawData = append(e.RawData, shstrtabData...)

	// Aggiungi padding per l'allineamento della SHT
	paddingSize = newSHTOffset - int64(len(e.RawData))
	if paddingSize > 0 {
		e.RawData = append(e.RawData, make([]byte, paddingSize)...)
	}

	// Aggiungi la nuova tabella delle intestazioni
	e.RawData = append(e.RawData, headerTableData...)

	// Aggiorna l'offset della tabella nell'header ELF
	shoffPos, _, _ := e.getHeaderPositions()
	if shoffPos >= 0 {
		if e.Is64Bit {
			e.GetEndian().PutUint64(e.RawData[shoffPos:shoffPos+8], uint64(newSHTOffset))
		} else {
			e.GetEndian().PutUint32(e.RawData[shoffPos:shoffPos+4], uint32(newSHTOffset))
		}
		fmt.Printf("🔧 Rebuilt section header table at offset 0x%X (size: %d bytes)\n", newSHTOffset, totalHeaderTableSize)
	}

	return nil
}
