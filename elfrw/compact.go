package elfrw

import (
	"bytes"
	"fmt"
	"gosstrip/common"
	"sort"
	"strings"
)

const (
	// Maximum section size to check for null/zero content (64KB)
	MAX_NULL_CHECK_SIZE = 65536
)

func (e *ELFFile) Compact(force bool, fillRandom bool) *common.OperationResult {
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

	// Create result object
	result := common.NewApplied("ELF Compaction", len(removable))
	result.SetCategory("SECTIONS")

	// Track warnings
	var warnings []string

	for _, idx := range removable {
		if err := e.removeCompactSection(idx, &totalRemoved, fillRandom); err != nil {
			warning := fmt.Sprintf("Failed to remove section %d (%s): %v", idx, e.Sections[idx].Name, err)
			warnings = append(warnings, warning)
		}
	}
	e.updateSections(removable)
	e.trimZeroTailBeyond(e.logicalFileEnd())

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

	if err := e.rebuildSectionHeaderTable(); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to rebuild section header table: %v", err))
	}

	if err := e.updateELFHeaderSectionCount(uint16(len(e.Sections))); err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to update ELF header section count: %v", err))
	}

	// Keep Section Header Table even under force to maintain runtime compatibility.

	newSize := int64(len(e.RawData))
	// Report actual on-disk reduction to avoid misleading percentages
	removedBytes := originalSize - newSize
	if removedBytes < 0 {
		removedBytes = 0
	}
	percent := 0.0
	if originalSize > 0 {
		percent = float64(removedBytes) / float64(originalSize) * 100.0
	}

	// Add details to result
	for _, name := range removedNames {
		result.AddDetail(fmt.Sprintf("removed section: %s", name), 1, false)
	}
	result.AddDetail(fmt.Sprintf("size reduced: %d -> %d bytes (%d bytes removed, %.1f%% reduction)",
		originalSize, newSize, removedBytes, percent), 1, false)

	// Add any warnings
	for _, warning := range warnings {
		result.AddDetail(warning, 0, true)
	}
	for _, warning := range e.validatePostCompact() {
		result.AddDetail(warning, 0, true)
	}

	// Update the main message
	result.Message = fmt.Sprintf("removed %d sections", len(removable))

	return result
}

func (e *ELFFile) getRemovedSectionNames(removable []int) []string {
	names := make([]string, 0, len(removable))
	for _, idx := range removable {
		if idx >= 0 && idx < len(e.Sections) {
			name := strings.TrimSpace(e.Sections[idx].Name)
			if name == "" {
				name = fmt.Sprintf("section_%d@0x%X", idx, e.Sections[idx].Offset)
			}
			names = append(names, name)
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
	critical := e.identifyCriticalSections(force)
	var removable []int
	sectionRules := getSectionStripRule()
	isSharedObject := e.IsSharedObject()

	for i, section := range e.Sections {
		if i == 0 {
			continue
		}
		if _, ok := critical[i]; ok && section.Size > 0 {
			continue
		}
		if section.Name == ".shstrtab" ||
			section.Name == ".strtab" ||
			section.Name == ".dynstr" ||
			section.Type == SHT_NOBITS {
			continue
		}

		if section.Stripped ||
			e.isCorruptedSection(section) ||
			e.isEmptySection(section) ||
			(force && e.isNullOrZeroSection(section)) ||
			e.isAlreadyStrippedSection(section) ||
			e.matchesZeroFilledStripRule(section, sectionRules, isSharedObject, force) {
			removable = append(removable, i)
		}
	}

	return removable
}

func (e *ELFFile) isEmptySection(section Section) bool {
	return section.Size == 0
}

func (e *ELFFile) isAlreadyStrippedSection(section Section) bool {
	if section.Stripped {
		return true
	}
	return e.isEmptySection(section) && section.Offset == 0
}

func (e *ELFFile) isZeroFilledSection(section Section) bool {
	if section.Offset < 0 || section.Size <= 0 {
		return false
	}
	end := section.Offset + section.Size
	if end > int64(len(e.RawData)) {
		return false
	}
	for _, b := range e.RawData[section.Offset:end] {
		if b != 0 {
			return false
		}
	}
	return true
}

func (e *ELFFile) matchesZeroFilledStripRule(section Section, rules map[SectionType]SectionStripRule, isSharedObject bool, force bool) bool {
	if !e.isZeroFilledSection(section) {
		return false
	}
	for _, rule := range rules {
		if rule.IsRisky && !force {
			continue
		}
		if (isSharedObject && !rule.StripForSO) || (!isSharedObject && !rule.StripForBIN) {
			continue
		}
		if common.MatchesPattern(section.Name, rule.ExactNames, rule.PrefixNames) {
			return true
		}
	}
	return false
}

func (e *ELFFile) removeCompactSection(sectionIdx int, totalRemovedSize *int64, fillRandom bool) error {
	if sectionIdx < 0 || sectionIdx >= len(e.Sections) {
		return fmt.Errorf("invalid section index: %d", sectionIdx)
	}

	section := e.Sections[sectionIdx]

	if section.Offset <= 0 || section.Size <= 0 {
		return nil
	}

	fillSize := section.Size
	if uint64(section.Offset)+uint64(fillSize) > uint64(len(e.RawData)) {
		fillSize = int64(uint64(len(e.RawData)) - uint64(section.Offset))
		if fillSize < 0 {
			fillSize = 0
		}
	}
	if err := e.fillRegion(uint64(section.Offset), int(fillSize), fillRandom); err != nil {
		return fmt.Errorf("failed to fill section %s: %w", section.Name, err)
	}
	canChop := int64(section.Offset) >= e.maxLoadSegmentEnd()
	fileAlignment := e.getFileAlignment()
	alignedSize := common.AlignUp64(section.Size, fileAlignment)
	start, end := int(section.Offset), int(section.Offset+alignedSize)
	if start > len(e.RawData) {
		return fmt.Errorf("section offset beyond file size: %d > %d", start, len(e.RawData))
	}
	if end > len(e.RawData) {
		end = len(e.RawData)
	}
	if end <= start {
		canChop = false
	}
	if canChop {
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
		section.Offset = 0
	} else {
		// leave bytes in place to preserve PT_LOAD offsets
	}

	name := strings.ToLower(strings.Trim(section.Name, "\x00"))
	switch name {
	case ".interp":
		e.hasInterpreter = false
	case ".dynamic":
		e.isDynamic = false
	}
	e.Sections[sectionIdx].Stripped = true
	e.Sections[sectionIdx].Size = 0

	return nil
}

func (e *ELFFile) updateProgramHeaderOffsets(removedOffset int64, removedSize int64) {
	for i := range e.Segments {
		if e.Segments[i].Offset > uint64(removedOffset) {
			e.Segments[i].Offset -= uint64(removedSize)
		}
	}
}

func (e *ELFFile) updateELFHeaderSectionCount(sectionCount uint16) error {
	var pos int
	if e.Is64Bit {
		pos = ELF64_E_SHNUM
	} else {
		pos = ELF32_E_SHNUM
	}

	return e.writeAtOffset(pos, sectionCount)
}

func (e *ELFFile) updateELFHeaderShstrtabIndex(shstrtabIndex uint16) error {
	var pos int
	if e.Is64Bit {
		pos = ELF64_E_SHSTRNDX
	} else {
		pos = ELF32_E_SHSTRNDX
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
	if section.Size > MAX_NULL_CHECK_SIZE {
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

func (e *ELFFile) identifyCriticalSections(force bool) map[int]struct{} {
	alwaysCritical := []string{
		".text", ".data", ".rodata", ".bss",
		".init", ".fini",
		".tdata", ".tbss",
	}
	loaderCritical := []string{
		".interp", ".dynamic", ".dynsym", ".dynstr",
		".gnu.hash", ".hash",
		".got", ".got.plt", ".plt", ".plt.got",
		".rel.plt", ".rela.plt", ".rel.dyn", ".rela.dyn",
		".init_array", ".fini_array", ".ctors", ".dtors",
		".eh_frame", ".eh_frame_hdr", ".gcc_except_table",
	}
	optional := []string{
		".comment", ".note.gnu.property",
	}

	critical := make(map[int]struct{})
	for i, sec := range e.Sections {
		name := strings.ToLower(strings.Trim(sec.Name, "\x00"))
		if sec.ExecutionCritical {
			critical[i] = struct{}{}
			continue
		}
		for _, req := range alwaysCritical {
			if name == req {
				critical[i] = struct{}{}
				goto next
			}
		}
		for _, req := range loaderCritical {
			if name == req {
				critical[i] = struct{}{}
				goto next
			}
		}
		if strings.Contains(name, "go.") || strings.Contains(name, "runtime") || name == ".gosymtab" || name == ".gopclntab" {
			critical[i] = struct{}{}
			goto next
		}
		if !force {
			for _, opt := range optional {
				if name == opt {
					critical[i] = struct{}{}
					goto next
				}
			}
		}
	next:
	}

	return critical
}

func (e *ELFFile) maxLoadSegmentEnd() int64 {
	var maxEnd int64
	for _, seg := range e.Segments {
		if seg.Type != PT_LOAD && !seg.Loadable {
			continue
		}
		end := int64(seg.Offset + seg.FileSize)
		if end > maxEnd {
			maxEnd = end
		}
	}
	return maxEnd
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
				e.getEndian().PutUint64(e.RawData[shoffPos:shoffPos+8], uint64(newOffset))
				fmt.Printf("🔧 Updated section header table offset: 0x%X -> 0x%X\n", currentOffset, newOffset)
			}
		} else {
			if shoffPos+4 <= len(e.RawData) {
				e.getEndian().PutUint32(e.RawData[shoffPos:shoffPos+4], uint32(newOffset))
				fmt.Printf("🔧 Updated section header table offset: 0x%X -> 0x%X\n", currentOffset, newOffset)
			}
		}
	}

	return nil
}

func (e *ELFFile) validatePostCompact() []string {
	var warnings []string
	entry := e.entryPoint
	valid := false
	for _, seg := range e.Segments {
		if !seg.Loadable {
			continue
		}
		start := seg.VirtualAddr
		end := seg.VirtualAddr + seg.MemSize
		if entry >= start && entry < end {
			valid = true
			break
		}
	}
	if !valid {
		warnings = append(warnings, fmt.Sprintf("entry point 0x%X no longer resides in a PT_LOAD segment", entry))
	}
	if e.isDynamic && !e.hasInterpreter {
		warnings = append(warnings, "interpreter removed from dynamically-linked ELF; loader may fail")
	}
	return warnings
}

func (e *ELFFile) entrySize() int64 {
	if e.Is64Bit {
		return ELF64_SHDR_SIZE
	}
	return ELF32_SHDR_SIZE
}

func (e *ELFFile) setShoff(offset uint64) {
	pos, _, _ := e.getHeaderPositions()
	if pos < 0 {
		return
	}
	if e.Is64Bit {
		e.getEndian().PutUint64(e.RawData[pos:pos+8], offset)
	} else {
		e.getEndian().PutUint32(e.RawData[pos:pos+4], uint32(offset))
	}
}

func (e *ELFFile) setShnum(count uint16) {
	_, pos, _ := e.getHeaderPositions()
	if pos < 0 {
		return
	}
	e.getEndian().PutUint16(e.RawData[pos:pos+2], count)
}

func (e *ELFFile) buildShstrtab() ([]byte, map[int]uint32) {
	var buf bytes.Buffer
	buf.WriteByte(0) // La tabella inizia sempre con un byte nullo.

	nameOffsets := make(map[int]uint32)
	for i, section := range e.Sections {
		if section.Name == "" {
			nameOffsets[i] = 0
			continue
		}
		nameOffsets[i] = uint32(buf.Len())
		buf.WriteString(section.Name)
		buf.WriteByte(0) // Terminatore NUL
	}
	return buf.Bytes(), nameOffsets
}

func (e *ELFFile) findOrCreateShstrtabSection() (int, error) {
	for i, section := range e.Sections {
		if section.Name == ".shstrtab" {
			return i, nil
		}
	}

	// Se non esiste, la aggiungiamo.
	shstrtabIndex := len(e.Sections)
	e.Sections = append(e.Sections, Section{
		Name:      ".shstrtab",
		Type:      SHT_STRTAB,
		Alignment: 1,
	})

	// Aggiorniamo il conteggio delle sezioni nell'header.
	if err := e.updateELFHeaderSectionCount(uint16(len(e.Sections))); err != nil {
		return -1, fmt.Errorf("failed to update section count for new shstrtab: %w", err)
	}
	return shstrtabIndex, nil
}

func (e *ELFFile) calculateLayout(shstrtabIndex int) (maxDataOffset, newSHTOffset int64) {
	// Trova la fine dei dati delle sezioni esistenti (escludendo la SHT stessa).
	for i, sec := range e.Sections {
		if i != shstrtabIndex && sec.Type != SHT_NOBITS {
			if endOffset := sec.Offset + sec.Size; endOffset > maxDataOffset {
				maxDataOffset = endOffset
			}
		}
	}

	alignment := e.getFileAlignment()
	shstrtabSection := &e.Sections[shstrtabIndex]

	// Allinea l'offset per la nuova .shstrtab.
	shstrtabSection.Offset = (maxDataOffset + alignment - 1) &^ (alignment - 1)

	// Allinea l'offset per la nuova tabella delle intestazioni di sezione.
	newSHTOffset = (shstrtabSection.Offset + shstrtabSection.Size + alignment - 1) &^ (alignment - 1)
	return maxDataOffset, newSHTOffset
}

func (e *ELFFile) serializeHeaders(nameOffsets map[int]uint32, shstrtabIndex int) []byte {
	entrySize := e.entrySize()
	totalSize := int64(len(e.Sections)) * entrySize
	headerTableData := make([]byte, totalSize)

	for i, section := range e.Sections {
		// Se la sezione è .shstrtab, usiamo la sua versione aggiornata in memoria.
		if i == shstrtabIndex {
			section = e.Sections[shstrtabIndex]
		}

		offset := int64(i) * entrySize
		data := headerTableData[offset : offset+entrySize]
		nameOffset := nameOffsets[i]

		// Il campo sh_entsize è significativo solo per tabelle che contengono entry di dimensione fissa,
		// come la tabella dei simboli. Per le altre, è 0.
		entsize := uint64(0)
		if section.Type == SHT_SYMTAB || section.Type == SHT_DYNSYM || section.Type == SHT_RELA || section.Type == SHT_REL {
			// Qui si potrebbe impostare la dimensione corretta, ma 0 è generalmente sicuro se non si gestiscono simboli in dettaglio.
		}

		if e.Is64Bit {
			e.getEndian().PutUint32(data[0:], nameOffset)
			e.getEndian().PutUint32(data[4:], section.Type)
			e.getEndian().PutUint64(data[8:], section.Flags)
			e.getEndian().PutUint64(data[16:], section.Address)
			e.getEndian().PutUint64(data[24:], uint64(section.Offset))
			e.getEndian().PutUint64(data[32:], uint64(section.Size))
			e.getEndian().PutUint32(data[40:], section.Link)
			e.getEndian().PutUint32(data[44:], section.Info)
			e.getEndian().PutUint64(data[48:], section.Alignment)
			e.getEndian().PutUint64(data[56:], entsize)
		} else {
			e.getEndian().PutUint32(data[0:], nameOffset)
			e.getEndian().PutUint32(data[4:], section.Type)
			e.getEndian().PutUint32(data[8:], uint32(section.Flags))
			e.getEndian().PutUint32(data[12:], uint32(section.Address))
			e.getEndian().PutUint32(data[16:], uint32(section.Offset))
			e.getEndian().PutUint32(data[20:], uint32(section.Size))
			e.getEndian().PutUint32(data[24:], section.Link)
			e.getEndian().PutUint32(data[28:], section.Info)
			e.getEndian().PutUint32(data[32:], uint32(section.Alignment))
			e.getEndian().PutUint32(data[36:], uint32(entsize))
		}
	}
	return headerTableData
}

func (e *ELFFile) rebuildSectionHeaderTable() error {
	// Caso base: nessuna sezione. Azzera i campi relativi nell'header.
	if len(e.Sections) == 0 {
		e.setShoff(0)
		e.setShnum(0)
		return nil
	}

	// 1. Costruisci la nuova .shstrtab e ottieni la mappa degli offset dei nomi.
	shstrtabData, nameOffsets := e.buildShstrtab()

	// 2. Trova o crea la sezione .shstrtab e aggiorna l'header ELF di conseguenza.
	shstrtabIndex, err := e.findOrCreateShstrtabSection()
	if err != nil {
		return err
	}
	if err := e.updateELFHeaderShstrtabIndex(uint16(shstrtabIndex)); err != nil {
		return fmt.Errorf("failed to update shstrtab index: %w", err)
	}

	// 3. Aggiorna i metadati della sezione .shstrtab in memoria.
	shstrtabSection := &e.Sections[shstrtabIndex]
	shstrtabSection.Type = SHT_STRTAB
	shstrtabSection.Size = int64(len(shstrtabData))
	shstrtabSection.Flags, shstrtabSection.Address, shstrtabSection.Link, shstrtabSection.Info = 0, 0, 0, 0
	shstrtabSection.Alignment = 1

	// 4. Calcola il nuovo layout del file, determinando gli offset per i nuovi dati.
	maxDataOffset, newSHTOffset := e.calculateLayout(shstrtabIndex)

	// 5. Serializza le nuove intestazioni di sezione in un buffer di byte.
	headerTableData := e.serializeHeaders(nameOffsets, shstrtabIndex)

	// 6. Ricostruisci il buffer RawData del file.
	// Tronca il file per rimuovere la vecchia SHT e la vecchia .shstrtab.
	newData := e.RawData[:maxDataOffset]

	// Funzione di supporto per aggiungere padding e dati in modo pulito.
	appendWithPadding := func(buf []byte, data []byte, targetOffset int64) []byte {
		if paddingSize := targetOffset - int64(len(buf)); paddingSize > 0 {
			buf = append(buf, make([]byte, paddingSize)...)
		}
		return append(buf, data...)
	}

	// Aggiungi la nuova .shstrtab con il padding necessario.
	newData = appendWithPadding(newData, shstrtabData, shstrtabSection.Offset)
	// Aggiungi la nuova tabella delle intestazioni di sezione con il padding necessario.
	e.RawData = appendWithPadding(newData, headerTableData, newSHTOffset)

	// 7. Aggiorna l'offset finale della SHT nell'header ELF.
	e.setShoff(uint64(newSHTOffset))
	fmt.Printf("🔧 Rebuilt section header table at offset 0x%X (size: %d bytes)\n", newSHTOffset, len(headerTableData))

	return nil
}
