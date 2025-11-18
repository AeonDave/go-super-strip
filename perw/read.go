package perw

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

const importDirectoryIndex = 1

func ReadPE(file *os.File) (*PEFile, error) {
	pf, err := newPEFileFromDisk(file)
	if err != nil {
		return nil, err
	}
	if err := pf.parseAllPEComponents(); err != nil {
		return nil, err
	}
	return pf, nil
}

func (p *PEFile) Close() error {
	if p.File != nil {
		return p.File.Close()
	}
	return nil
}

func newPEFileFromDisk(file *os.File) (*PEFile, error) {
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}
	rawData, err := readFileData(file)
	if err != nil {
		return nil, err
	}
	if err := validateDOSHeader(rawData); err != nil {
		return nil, err
	}
	peLibFile, err := pe.NewFile(bytes.NewReader(rawData))
	if err != nil {
		// If the PE parser fails, try a targeted self-heal for COFF symbol table issues
		if strings.Contains(err.Error(), "string table") {
			// Attempt to zero the COFF PointerToSymbolTable and NumberOfSymbols to avoid invalid string table parsing
			if len(rawData) >= PE_DOS_HEADER_SIZE {
				peHeaderOffset := int64(binary.LittleEndian.Uint32(rawData[PE_ELFANEW_OFFSET : PE_ELFANEW_OFFSET+4]))
				coffHeaderOffset := peHeaderOffset + PE_SIGNATURE_SIZE
				if peHeaderOffset >= 0 && coffHeaderOffset+16 <= int64(len(rawData)) {
					ptrSym := binary.LittleEndian.Uint32(rawData[coffHeaderOffset+8 : coffHeaderOffset+12])
					nSym := binary.LittleEndian.Uint32(rawData[coffHeaderOffset+12 : coffHeaderOffset+16])
					if ptrSym != 0 || nSym != 0 {
						_ = WriteAtOffset(rawData, coffHeaderOffset+8, uint32(0))
						_ = WriteAtOffset(rawData, coffHeaderOffset+12, uint32(0))
						// Retry parsing after sanitizing the COFF symbol table fields
						if peRetry, retryErr := pe.NewFile(bytes.NewReader(rawData)); retryErr == nil {
							peLibFile = peRetry
							err = nil
						}
					}
				}
			}
		}

		if err != nil { // still failing after optional retry
			var reason string
			var packed bool

			tempPF := &PEFile{
				File:     file,
				FileName: file.Name(),
				RawData:  rawData,
			}
			_ = tempPF.parseBasicSectionsFromRaw()
			packed = isLikelyPacked(tempPF.Sections)
			if packed {
				reason = "File appears to be packed/compressed (high entropy)"
			} else if strings.Contains(err.Error(), "string table") {
				reason = "COFF symbol table inconsistent (string table)"
			} else {
				reason = "Non-standard PE format"
			}

			// Print detailed warning only in verbose mode to avoid noisy output during strip operations
			if os.Getenv("GOSSTRIP_VERBOSE") == "1" {
				fmt.Printf("⚠️  %s (%s)\n", reason, err.Error())
			}

			pf := &PEFile{
				File:     file,
				PE:       nil,
				FileName: file.Name(),
				RawData:  rawData,
				Is64Bit:  false,
				CommonFileInfo: common.CommonFileInfo{
					FileSize: fileInfo.Size(),
				},
			}

			if len(rawData) > PE_DOS_HEADER_SIZE {
				dosHeaderOffset := int(rawData[PE_ELFANEW_OFFSET]) | int(rawData[PE_ELFANEW_OFFSET+1])<<8 | int(rawData[PE_ELFANEW_OFFSET+2])<<16 | int(rawData[PE_ELFANEW_OFFSET+3])<<24
				if dosHeaderOffset > 0 && dosHeaderOffset+PE_FILE_HEADER_SIZE+4 < len(rawData) {
					magic := rawData[dosHeaderOffset+PE_FILE_HEADER_SIZE+4 : dosHeaderOffset+PE_FILE_HEADER_SIZE+6]
					if len(magic) >= 2 {
						magicValue := uint16(magic[0]) | uint16(magic[1])<<8
						pf.Is64Bit = magicValue == PE64_MAGIC
					}
				}
			}

			return pf, nil
		}
	}

	pf := &PEFile{
		File:     file,
		PE:       peLibFile,
		FileName: file.Name(),
		RawData:  rawData,
		Is64Bit:  peLibFile.FileHeader.Machine == pe.IMAGE_FILE_MACHINE_AMD64,
		CommonFileInfo: common.CommonFileInfo{
			FileSize: fileInfo.Size(),
		},
	}
	return pf, nil
}

func IsPEFile(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	dosHeader := make([]byte, PE_DOS_HEADER_SIZE)
	if _, err := file.Read(dosHeader); err != nil {
		return false, nil
	}

	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		return false, nil
	}

	peOffset := binary.LittleEndian.Uint32(dosHeader[PE_ELFANEW_OFFSET : PE_ELFANEW_OFFSET+4])

	if _, err := file.Seek(int64(peOffset), 0); err != nil {
		return false, nil
	}

	peSignature := make([]byte, 4)
	if _, err := file.Read(peSignature); err != nil {
		return false, nil
	}

	return string(peSignature) == "PE\x00\x00", nil
}

func readFileData(file *os.File) ([]byte, error) {
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	data := make([]byte, fileInfo.Size())
	_, err = file.ReadAt(data, 0)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func validateDOSHeader(data []byte) error {
	if len(data) < PE_DOS_HEADER_SIZE {
		return fmt.Errorf("file too small to be a valid PE file")
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return fmt.Errorf("invalid DOS header signature")
	}
	return nil
}

func (p *PEFile) parseAllPEComponents() error {
	var errors []string

	if err := p.parseHeaders(); err != nil {
		errors = append(errors, fmt.Sprintf("headers: %v", err))
	}

	if err := p.parseSections(); err != nil {
		errors = append(errors, fmt.Sprintf("sections: %v", err))

		if p.Sections == nil {
			p.Sections = make([]Section, 0)
		}
	}

	if err := p.parseDirectories(); err != nil {
		errors = append(errors, fmt.Sprintf("directories: %v", err))
	}

	if err := p.parseImports(); err != nil {
		errors = append(errors, fmt.Sprintf("imports: %v", err))

		if p.Imports == nil {
			p.Imports = make([]ImportInfo, 0)
		}
	}

	if err := p.parseExports(); err != nil {
		errors = append(errors, fmt.Sprintf("exports: %v", err))

		if p.Exports == nil {
			p.Exports = make([]ExportInfo, 0)
		}
	}

	if err := p.analyzeFile(); err != nil {
		errors = append(errors, fmt.Sprintf("analysis: %v", err))
	}

	if len(errors) > 0 && len(errors) >= 4 {
		return fmt.Errorf("too many parsing errors: %v", errors)
	}

	return nil
}

func (p *PEFile) parseSections() error {
	p.Sections = make([]Section, 0)

	if p.PE == nil {

		return p.parseBasicSectionsFromRaw()
	}

	if p.PE.Sections == nil {
		return p.parseBasicSectionsFromRaw()
	}

	for i, s := range p.PE.Sections {
		if s == nil {
			continue
		}

		func() {

			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("⚠️  Recovered from panic parsing section %d: %v\n", i, r)
				}
			}()

			section := p.parseSectionBase(i, s)
			p.fillSectionHashesAndEntropy(&section)
			p.Sections = append(p.Sections, section)
		}()
	}

	return nil
}

func (p *PEFile) parseSectionBase(i int, s *pe.Section) Section {
	return Section{
		Name:           strings.TrimRight(s.Name, "\x00"),
		Offset:         int64(s.Offset),
		Size:           int64(s.Size),
		VirtualAddress: s.VirtualAddress,
		VirtualSize:    s.VirtualSize,
		Index:          i,
		Flags:          s.Characteristics,
		RVA:            s.VirtualAddress,
		FileOffset:     s.Offset,
		CommonSectionInfo: common.CommonSectionInfo{
			IsExecutable: (s.Characteristics & pe.IMAGE_SCN_MEM_EXECUTE) != 0,
			IsReadable:   (s.Characteristics & pe.IMAGE_SCN_MEM_READ) != 0,
			IsWritable:   (s.Characteristics & pe.IMAGE_SCN_MEM_WRITE) != 0,
		},
	}
}

func (p *PEFile) fillSectionHashesAndEntropy(section *Section) {
	if section.Size > 0 && section.Offset+section.Size <= int64(len(p.RawData)) {
		sectionData := p.RawData[section.Offset : section.Offset+section.Size]
		md5Hash := md5.Sum(sectionData)
		sha1Hash := sha1.Sum(sectionData)
		sha256Hash := sha256.Sum256(sectionData)
		section.MD5Hash = fmt.Sprintf("%x", md5Hash)
		section.SHA1Hash = fmt.Sprintf("%x", sha1Hash)
		section.SHA256Hash = fmt.Sprintf("%x", sha256Hash)
		section.Entropy = common.CalculateEntropy(sectionData)
	} else {

		section.MD5Hash = "N/A (no raw data)"
		section.SHA1Hash = "N/A (no raw data)"
		section.SHA256Hash = "N/A (no raw data)"
		section.Entropy = 0.0
	}
}

func (p *PEFile) parseImports() error {
	if p.PE == nil {
		return fmt.Errorf("PE not initialized")
	}
	if !p.hasUsableImportDirectory() {
		p.Imports = nil
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			p.Imports = nil
		}
	}()

	syms, err := p.PE.ImportedSymbols()
	if err != nil {
		return err
	}

	importsMap := map[string]*ImportInfo{}
	for _, s := range syms {
		parts := strings.SplitN(s, ":", 2)
		if len(parts) != 2 {
			continue // Skip malformed symbols
		}

		// Determine which part is the library and which is the function
		// Check if first part looks like a DLL name
		var dll, fn string
		if strings.HasSuffix(strings.ToLower(parts[0]), ".dll") ||
			strings.HasSuffix(strings.ToLower(parts[0]), ".sys") ||
			strings.HasSuffix(strings.ToLower(parts[0]), ".ocx") {
			// Format: library:function
			dll = strings.ToLower(parts[0])
			fn = parts[1]
		} else if strings.HasSuffix(strings.ToLower(parts[1]), ".dll") ||
			strings.HasSuffix(strings.ToLower(parts[1]), ".sys") ||
			strings.HasSuffix(strings.ToLower(parts[1]), ".ocx") {
			// Format: function:library (old format)
			fn = parts[0]
			dll = strings.ToLower(parts[1])
		} else {
			// Fallback: assume first part is function, second is library
			fn = parts[0]
			dll = strings.ToLower(parts[1])
		}

		if _, ok := importsMap[dll]; !ok {
			importsMap[dll] = &ImportInfo{
				LibraryName: dll,
				DLL:         dll,
				Functions:   make([]string, 0),
			}
		}
		if fn != "" {
			importsMap[dll].Functions = append(importsMap[dll].Functions, fn)
		}
	}

	p.Imports = make([]ImportInfo, 0, len(importsMap))
	for _, info := range importsMap {
		if len(info.Functions) > 0 {
			p.Imports = append(p.Imports, *info)
		}
	}
	return nil
}

func (p *PEFile) hasUsableImportDirectory() bool {
	rva, size, ok := p.readDataDirectoryEntry(importDirectoryIndex)
	if !ok || rva == 0 || size == 0 {
		return false
	}
	startPhys, err := p.rvaToPhysical(uint64(rva))
	if err != nil {
		return false
	}
	end := rva
	if size > 0 {
		if size-1 > math.MaxUint32-rva {
			end = math.MaxUint32
		} else {
			end = rva + size - 1
		}
		if _, err := p.rvaToPhysical(uint64(end)); err != nil {
			return false
		}
	}
	descriptorSize := uint64(20)
	if uint64(len(p.RawData)) < startPhys+descriptorSize {
		return false
	}
	allZero := true
	for _, b := range p.RawData[startPhys : startPhys+descriptorSize] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}
	return true
}

func (p *PEFile) readDataDirectoryEntry(index int) (uint32, uint32, bool) {
	offsets, err := p.calculateOffsets()
	if err != nil {
		return 0, 0, false
	}
	var base int64
	if p.Is64Bit {
		base = offsets.OptionalHeader + PE64_DATA_DIRECTORIES
	} else {
		base = offsets.OptionalHeader + PE32_DATA_DIRECTORIES
	}
	entryOffset := base + int64(index*IMAGE_SIZEOF_DATA_DIRECTORY)
	if entryOffset < 0 || entryOffset+IMAGE_SIZEOF_DATA_DIRECTORY > int64(len(p.RawData)) {
		return 0, 0, false
	}
	rva := binary.LittleEndian.Uint32(p.RawData[entryOffset:])
	size := binary.LittleEndian.Uint32(p.RawData[entryOffset+4:])
	return rva, size, true
}

func (p *PEFile) parseHeaders() error {

	if p.PE == nil {
		return p.parseBasicHeadersFromRaw()
	}

	if p.PE.OptionalHeader == nil {
		fmt.Printf("⚠️  Optional header unavailable, using defaults\n")
		return nil
	}

	switch oh := p.PE.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		p.imageBase = uint64(oh.ImageBase)
		p.entryPoint = oh.AddressOfEntryPoint
		p.sizeOfImage = oh.SizeOfImage
		p.sizeOfHeaders = oh.SizeOfHeaders
		p.checksum = oh.CheckSum
		p.subsystem = oh.Subsystem
		p.dllCharacteristics = oh.DllCharacteristics
	case *pe.OptionalHeader64:
		p.imageBase = oh.ImageBase
		p.entryPoint = oh.AddressOfEntryPoint
		p.sizeOfImage = oh.SizeOfImage
		p.sizeOfHeaders = oh.SizeOfHeaders
		p.checksum = oh.CheckSum
		p.subsystem = oh.Subsystem
		p.dllCharacteristics = oh.DllCharacteristics
	default:
		return fmt.Errorf("unsupported optional header type")
	}

	p.extractMachineType()
	p.extractTimeDateStamp()

	p.extractVersionInfo()

	return nil
}

func (p *PEFile) parseDirectories() error {
	p.directories = make([]DirectoryEntry, 0, PE_DATA_DIRECTORY_COUNT)

	if p.PE == nil || p.PE.OptionalHeader == nil {
		return nil
	}

	switch oh := p.PE.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		for i := 0; i < len(oh.DataDirectory); i++ {
			dd := oh.DataDirectory[i]
			p.directories = append(p.directories, DirectoryEntry{Type: uint16(i), RVA: dd.VirtualAddress, Size: dd.Size})
		}
	case *pe.OptionalHeader64:
		for i := 0; i < len(oh.DataDirectory); i++ {
			dd := oh.DataDirectory[i]
			p.directories = append(p.directories, DirectoryEntry{Type: uint16(i), RVA: dd.VirtualAddress, Size: dd.Size})
		}
	default:
		// Unsupported optional header type; leave directories empty
	}
	return nil
}

func (p *PEFile) parseExports() error {
	p.Exports = make([]ExportInfo, 0)

	// Locate Export Directory entry
	var expDir *DirectoryEntry
	for i := range p.directories {
		d := &p.directories[i]
		if d.Type == IMAGE_DIRECTORY_ENTRY_EXPORT {
			expDir = d
			break
		}
	}
	if expDir == nil || expDir.RVA == 0 || expDir.Size < 40 {
		return nil
	}

	// Convert export directory RVA to physical offset
	off, err := p.rvaToPhysical(uint64(expDir.RVA))
	if err != nil {
		return nil // Graceful fallback
	}
	if int(off)+40 > len(p.RawData) {
		return nil
	}

	data := p.RawData
	// Parse IMAGE_EXPORT_DIRECTORY (40 bytes)
	// DWORD Characteristics
	// DWORD TimeDateStamp
	// WORD  MajorVersion
	// WORD  MinorVersion
	// DWORD Name
	// DWORD Base
	// DWORD NumberOfFunctions
	// DWORD NumberOfNames
	// DWORD AddressOfFunctions
	// DWORD AddressOfNames
	// DWORD AddressOfNameOrdinals

	base := binary.LittleEndian.Uint32(data[off+16 : off+20])
	numFunctions := binary.LittleEndian.Uint32(data[off+20 : off+24])
	numNames := binary.LittleEndian.Uint32(data[off+24 : off+28])
	addrFuncsRVA := binary.LittleEndian.Uint32(data[off+28 : off+32])
	addrNamesRVA := binary.LittleEndian.Uint32(data[off+32 : off+36])
	addrOrdinalsRVA := binary.LittleEndian.Uint32(data[off+36 : off+40])

	if numNames == 0 || addrNamesRVA == 0 || addrOrdinalsRVA == 0 || addrFuncsRVA == 0 {
		return nil
	}

	namesOff, err := p.rvaToPhysical(uint64(addrNamesRVA))
	if err != nil {
		return nil
	}
	ordsOff, err := p.rvaToPhysical(uint64(addrOrdinalsRVA))
	if err != nil {
		return nil
	}
	funcsOff, err := p.rvaToPhysical(uint64(addrFuncsRVA))
	if err != nil {
		return nil
	}

	// Helper to read ASCII null-terminated string at physical offset
	readCString := func(start uint64) (string, bool) {
		if int(start) >= len(data) {
			return "", false
		}
		end := int(start)
		for end < len(data) && data[end] != 0 {
			end++
		}
		return string(data[int(start):end]), true
	}

	maxNames := int(numNames)
	// Cap iteration to avoid pathological sizes
	if maxNames > 10000 {
		maxNames = 10000
	}

	for i := 0; i < maxNames; i++ {
		entryOff := int(namesOff) + i*4
		ordOff := int(ordsOff) + i*2
		if entryOff+4 > len(data) || ordOff+2 > len(data) {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(data[entryOff : entryOff+4])
		namePhys, err := p.rvaToPhysical(uint64(nameRVA))
		if err != nil {
			continue
		}
		name, ok := readCString(namePhys)
		if !ok || name == "" {
			continue
		}
		ordinalIndex := uint32(binary.LittleEndian.Uint16(data[ordOff : ordOff+2]))
		if ordinalIndex >= numFunctions {
			// Out of range, skip
			continue
		}
		funcRva := binary.LittleEndian.Uint32(data[int(funcsOff)+int(ordinalIndex)*4 : int(funcsOff)+int(ordinalIndex)*4+4])
		p.Exports = append(p.Exports, ExportInfo{
			Name:    name,
			Ordinal: uint16(base + ordinalIndex),
			RVA:     funcRva,
		})
	}

	// Sort exports by name for stable output
	if len(p.Exports) > 1 {
		sort.Slice(p.Exports, func(i, j int) bool { return p.Exports[i].Name < p.Exports[j].Name })
	}
	return nil
}

func (p *PEFile) analyzeFile() error {
	calculatedSize, err := p.CalculatePhysicalFileSize()
	if err != nil {
		return err
	}

	if uint64(p.FileSize) > calculatedSize {
		p.HasOverlay = true
		p.OverlayOffset = int64(calculatedSize)
		p.OverlaySize = p.FileSize - int64(calculatedSize)
	}

	return nil
}

func (p *PEFile) ReadBytes(offset int64, size int) ([]byte, error) {
	if offset < 0 || size < 0 {
		return nil, fmt.Errorf("offset (%d) or size (%d) cannot be negative", offset, size)
	}
	if size == 0 {
		return []byte{}, nil
	}
	if offset+int64(size) > int64(len(p.RawData)) {
		return nil, fmt.Errorf("read beyond file limits: offset %d, size %d, file len %d",
			offset, size, len(p.RawData))
	}

	return p.RawData[offset : offset+int64(size)], nil
}

func (p *PEFile) extractMachineType() {
	switch p.PE.FileHeader.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		p.Machine = "i386"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		p.Machine = "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM:
		p.Machine = "arm"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		p.Machine = "arm64"
	default:
		p.Machine = fmt.Sprintf("Unknown (0x%X)", p.PE.FileHeader.Machine)
	}
}

func (p *PEFile) extractTimeDateStamp() {
	if p.PE.FileHeader.TimeDateStamp != 0 {
		timestamp := int64(p.PE.FileHeader.TimeDateStamp)
		t := time.Unix(timestamp, 0)
		p.TimeDateStamp = t.Format("2006-01-02 15:04:05 UTC")
	} else {
		p.TimeDateStamp = "Not set"
	}
}

func (p *PEFile) extractVersionInfo() {
	p.VersionInfo = make(map[string]string)

	if p.PE != nil && len(p.PE.Sections) > 0 {
		for _, s := range p.PE.Sections {
			if s.Name == ".rsrc" {
				data, err := s.Data()
				if err != nil || len(data) == 0 {
					break
				}
				sig := []byte("VS_VERSION_INFO")
				idx := bytes.Index(data, sig)
				if idx >= 0 {
					block := data[idx:]
					fields := []string{"FileVersion", "ProductVersion", "CompanyName", "FileDescription", "InternalName", "OriginalFilename", "ProductName", "LegalCopyright"}
					for _, field := range fields {
						fieldUtf16 := utf16le(field)
						fidx := bytes.Index(block, fieldUtf16)
						if fidx >= 0 {
							valStart := fidx + len(fieldUtf16) + 2
							val := readUtf16String(block[valStart:])
							if val != "" {
								p.VersionInfo[field] = val
							}
						}
					}

					if len(p.VersionInfo) > 0 {
						return
					}
				}
			}
		}
	}
	p.VersionInfo["FileVersion"] = "Unknown"
	p.VersionInfo["ProductVersion"] = "Unknown"
	p.VersionInfo["CompanyName"] = "Unknown"
	p.VersionInfo["FileDescription"] = "Unknown"

}

func (p *PEFile) ExtractOverlay() ([]byte, error) {
	if !p.HasOverlay {
		return nil, fmt.Errorf("no overlay found in PE file")
	}

	if p.OverlayOffset < 0 || p.OverlayOffset >= int64(len(p.RawData)) {
		return nil, fmt.Errorf("invalid overlay offset: %d", p.OverlayOffset)
	}

	overlayEnd := p.OverlayOffset + p.OverlaySize
	if overlayEnd > int64(len(p.RawData)) {
		overlayEnd = int64(len(p.RawData))
	}

	overlayData := make([]byte, overlayEnd-p.OverlayOffset)
	copy(overlayData, p.RawData[p.OverlayOffset:overlayEnd])

	return overlayData, nil
}
