package perw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"strings"
	"time"
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
	if force {
		pipeline.AddStep("debug directory", func() (*common.OperationResult, error) {
			return p.InjectDebugDirectoryNoise(), nil
		})
	}

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

		originalName := ""
		if i < len(p.Sections) {
			originalName = p.Sections[i].Name
		}

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
	tsBytes, err := common.GenerateRandomBytes(4)
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to generate timestamp: %v", err))
	}
	tsValue := binary.LittleEndian.Uint32(tsBytes)
	_ = WriteAtOffset(p.RawData, timeStampOffset, tsValue)

	linkerMajor := offsets.OptionalHeader + 2
	linkerMinor := offsets.OptionalHeader + 3
	if err := p.validateOffset(linkerMajor, 2); err != nil {
		return common.NewSkipped("linker version fields not accessible")
	}
	linkBytes, _ := common.GenerateRandomBytes(2)
	_ = WriteAtOffset(p.RawData, linkerMajor, linkBytes[0])
	_ = WriteAtOffset(p.RawData, linkerMinor, linkBytes[1])

	var messages []string
	messages = append(messages, fmt.Sprintf("randomized PE timestamp to 0x%X", tsValue))
	messages = append(messages, fmt.Sprintf("set linker version to %d.%d", linkBytes[0], linkBytes[1]))

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

func (p *PEFile) InjectDebugDirectoryNoise() *common.OperationResult {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return common.NewSkipped(fmt.Sprintf("failed to calculate offsets: %v", err))
	}
	debugDirOffset := offsets.OptionalHeader + directoryOffsets.debug[p.Is64Bit]
	if err := p.validateOffset(debugDirOffset, 8); err != nil {
		return common.NewSkipped("debug directory not accessible")
	}
	dirRVA := binary.LittleEndian.Uint32(p.RawData[debugDirOffset:])
	dirSize := binary.LittleEndian.Uint32(p.RawData[debugDirOffset+4:])
	const entrySize = 28
	if dirRVA == 0 || dirSize < entrySize {
		return common.NewSkipped("debug directory absent")
	}
	var existing [][]byte
	if phys, err := p.rvaToPhysical(uint64(dirRVA)); err == nil {
		maxBytes := int(dirSize / entrySize * entrySize)
		if int(phys)+maxBytes <= len(p.RawData) {
			for i := 0; i < maxBytes; i += entrySize {
				entry := append([]byte(nil), p.RawData[int(phys)+i:int(phys)+i+entrySize]...)
				existing = append(existing, entry)
			}
		}
	}

	cvRecord := p.buildCodeViewRecord()
	recordOffset := uint32(len(p.RawData))
	p.RawData = append(p.RawData, cvRecord...)
	for len(p.RawData)%4 != 0 {
		p.RawData = append(p.RawData, 0)
	}

	recordRVA, err := p.physicalToRVA(recordOffset)
	if err != nil {
		return common.NewSkipped("debug directory unavailable (cannot map CodeView RVA)")
	}

	desc := make([]byte, entrySize)
	timeStamp := uint32(time.Now().Unix())
	binary.LittleEndian.PutUint32(desc[4:], timeStamp)
	binary.LittleEndian.PutUint16(desc[8:], 0)
	binary.LittleEndian.PutUint16(desc[10:], 0)
	binary.LittleEndian.PutUint32(desc[12:], IMAGE_DEBUG_TYPE_CODEVIEW)
	binary.LittleEndian.PutUint32(desc[16:], uint32(len(cvRecord)))
	binary.LittleEndian.PutUint32(desc[20:], recordRVA)
	binary.LittleEndian.PutUint32(desc[24:], recordOffset)

	newEntries := append(existing, desc)
	dirBlock := make([]byte, len(newEntries)*entrySize)
	for i, e := range newEntries {
		copy(dirBlock[i*entrySize:(i+1)*entrySize], e)
	}
	dirOffset := uint32(len(p.RawData))
	p.RawData = append(p.RawData, dirBlock...)

	dirRVA, err = p.physicalToRVA(dirOffset)
	if err != nil {
		return common.NewSkipped("debug directory unavailable (cannot map RVA)")
	}
	binary.LittleEndian.PutUint32(p.RawData[debugDirOffset:], dirRVA)
	binary.LittleEndian.PutUint32(p.RawData[debugDirOffset+4:], uint32(len(dirBlock)))

	return common.NewApplied("injected fake CodeView debug directory entry", 1)
}

func (p *PEFile) buildCodeViewRecord() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{'R', 'S', 'D', 'S'})
	guidBytes, _ := common.GenerateRandomBytes(16)
	buf.Write(guidBytes)
	ageBytes, _ := common.GenerateRandomBytes(4)
	buf.Write(ageBytes)
	buf.WriteString(fmt.Sprintf("C:\\builds\\%s\\fake_%s.pdb", randomAscii(6), randomAscii(8)))
	buf.WriteByte(0)
	for buf.Len()%4 != 0 {
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

func randomAscii(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	randomBytes, _ := common.GenerateRandomBytes(n)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = alphabet[int(randomBytes[i])%len(alphabet)]
	}
	return string(out)
}

func (p *PEFile) ObfuscateExecutablePadding(force bool) *common.OperationResult {
	if len(p.Sections) == 0 {
		return common.NewSkipped("no sections to obfuscate")
	}
	nopPatterns := [][]byte{
		{0x90},
		{0x66, 0x90},
		{0x0F, 0x1F, 0x00},
		{0x2E, 0x90},
	}
	totalRuns := 0
	for _, section := range p.Sections {
		if section.Flags&IMAGE_SCN_MEM_EXECUTE == 0 || section.Size <= 0 {
			continue
		}
		data, err := p.ReadBytes(section.Offset, int(section.Size))
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
	if totalRuns == 0 {
		return common.NewSkipped("no executable padding found for obfuscation")
	}
	mode := "default"
	if force {
		mode = "force"
	}
	return common.NewApplied(fmt.Sprintf("scrambled %d executable padding runs (%s)", totalRuns, mode), totalRuns)
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
	if force && len(run) >= 6 {
		step := 8
		if step > len(run)-2 {
			step = len(run) - 2
		}
		for off := 0; off+2 < len(run); off += step {
			jumpSize := byte(2)
			if len(run)-off-2 > 5 {
				randByte, _ := common.GenerateRandomBytes(1)
				jumpSize = 2 + randByte[0]%4
			}
			run[off] = 0xEB
			run[off+1] = jumpSize
			for fill := off + 2; fill < off+int(jumpSize); fill++ {
				if fill >= len(run) {
					break
				}
				if run[fill] != 0x90 {
					run[fill] = 0x90
					changed = true
				}
			}
			changed = true
		}
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
