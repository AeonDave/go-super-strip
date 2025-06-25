package perw

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	veloxpe "github.com/Velocidex/go-pe"
)

// Section represents a PE section with additional metadata
type Section struct {
	Name            string
	VirtualAddress  uint32
	RVA             uint32 // Alias for VirtualAddress (for compatibility)
	VirtualSize     uint32
	FileOffset      uint32
	Offset          uint32 // Alias for FileOffset (for compatibility)
	Size            uint32
	Characteristics uint32
	Flags           uint32
	Index           int // Section index in the PE file
	Data            []byte
	Hash            string
	MD5Hash         string
	SHA1Hash        string
	SHA256Hash      string
	Entropy         float64
	IsExecutable    bool
	IsReadable      bool
	IsWritable      bool
}

// DirectoryEntry represents a PE directory entry
type DirectoryEntry struct {
	Name    string
	Address uint32
	Size    uint32
}

// ImportInfo represents import information
type ImportInfo struct {
	DLL         string
	LibraryName string // Alias for DLL (for compatibility)
	Functions   []string
	Address     uint32
}

// ExportInfo represents export information
type ExportInfo struct {
	Name      string
	Address   uint32
	RVA       uint32 // Alias for Address (for compatibility)
	Ordinal   uint16
	Forwarded bool
}

// PEFile represents a PE file with comprehensive metadata
type PEFile struct {
	File     *os.File
	VeloxPE  *veloxpe.PEFile
	StdPE    *pe.File // Fallback using standard library
	FileName string
	RawData  []byte
	FileSize int64
	Is64Bit  bool

	// PE Headers info
	Machine       string
	TimeDateStamp string
	GUIDAge       string
	PDB           string

	// Sections
	Sections []Section

	// Import/Export tables
	Imports []ImportInfo
	Exports []ExportInfo

	// Version Information
	VersionInfo map[string]string

	// Analysis fields
	IsPacked      bool
	HasOverlay    bool
	OverlayOffset int64
	OverlaySize   int64
}

// ReadPE creates a comprehensive PEFile structure using both libraries
func ReadPE(file *os.File) (*PEFile, error) {
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
	// Try to parse with veloxpe first
	veloxPE, err := veloxpe.NewPEFile(bytes.NewReader(rawData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse PE file with go-pe: %w", err)
	}

	// Try to parse with standard library as fallback (may fail for packed files)
	stdPE, err := pe.NewFile(bytes.NewReader(rawData))
	if err != nil {
		// If debug/pe fails (e.g., packed files), use only veloxpe
		pf := &PEFile{
			File:          file,
			VeloxPE:       veloxPE,
			StdPE:         nil, // No standard PE parser available
			FileName:      file.Name(),
			RawData:       rawData,
			FileSize:      fileInfo.Size(),
			Machine:       veloxPE.Machine,
			TimeDateStamp: veloxPE.TimeDateStamp,
			GUIDAge:       veloxPE.GUIDAge,
			PDB:           veloxPE.PDB,
			VersionInfo:   veloxPE.VersionInformation,
		}

		// Determine architecture using veloxpe
		pf.Is64Bit = strings.Contains(strings.ToLower(veloxPE.Machine), "64") ||
			strings.Contains(strings.ToLower(veloxPE.Machine), "amd64") ||
			strings.Contains(strings.ToLower(veloxPE.Machine), "x64")

		// Parse sections using only veloxpe
		err = parseSectionsFromVeloxOnly(pf)
		if err != nil {
			return nil, fmt.Errorf("failed to parse sections with veloxpe: %w", err)
		}

		// Parse imports and exports
		pf.parseImportsFromVelox()
		pf.parseExportsFromVelox()

		// Analyze file structure
		if err := pf.analyzeFile(); err != nil {
			return nil, fmt.Errorf("failed to analyze file: %w", err)
		}

		return pf, nil
	}

	pf := &PEFile{
		File:          file,
		VeloxPE:       veloxPE,
		StdPE:         stdPE,
		FileName:      file.Name(),
		RawData:       rawData,
		FileSize:      fileInfo.Size(),
		Machine:       veloxPE.Machine,
		TimeDateStamp: veloxPE.TimeDateStamp,
		GUIDAge:       veloxPE.GUIDAge,
		PDB:           veloxPE.PDB,
		VersionInfo:   veloxPE.VersionInformation,
	}

	// Determine architecture
	if stdPE.Machine == pe.IMAGE_FILE_MACHINE_AMD64 || stdPE.Machine == pe.IMAGE_FILE_MACHINE_IA64 {
		pf.Is64Bit = true
	} else {
		pf.Is64Bit = false
	}

	// Parse sections using hybrid approach
	err = parseSectionsHybrid(pf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse sections: %w", err)
	}

	// Parse imports and exports
	pf.parseImportsFromVelox()
	pf.parseExportsFromVelox()

	// Analyze file structure
	if err := pf.analyzeFile(); err != nil {
		return nil, fmt.Errorf("failed to analyze file: %w", err)
	}

	return pf, nil
}

// readFileData reads the entire file into memory
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

// validateDOSHeader validates the DOS header
func validateDOSHeader(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("file too small to have DOS header")
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return fmt.Errorf("invalid DOS header signature")
	}
	return nil
}

// parseSectionsHybrid parses sections using both libraries for best results
func parseSectionsHybrid(pf *PEFile) error {
	stdSections := pf.StdPE.Sections
	veloxSections := pf.VeloxPE.Sections

	if len(stdSections) == 0 {
		return fmt.Errorf("no sections found in PE file")
	}

	// Create a map for quick lookup of velox section info
	veloxSectionMap := make(map[string]*veloxpe.Section)
	for _, section := range veloxSections {
		if section.FileOffset > 0 {
			veloxSectionMap[section.Name] = section
		}
	}

	// Filter out sections with offset=0 (virtual sections)
	validSections := make([]*pe.Section, 0, len(stdSections))
	for _, section := range stdSections {
		if section.Offset > 0 {
			validSections = append(validSections, section)
		}
	}

	if len(validSections) == 0 {
		return fmt.Errorf("no valid sections with Offset > 0 found")
	}

	pf.Sections = make([]Section, len(validSections))
	for i, stdSection := range validSections {
		// Use debug/pe for accurate section names
		sectionName := strings.TrimRight(string(stdSection.Name[:]), "\x00")

		// Create section structure with debug/pe data
		section := Section{
			Name:            sectionName,
			VirtualAddress:  stdSection.VirtualAddress,
			RVA:             stdSection.VirtualAddress, // Alias for VirtualAddress
			VirtualSize:     stdSection.VirtualSize,
			FileOffset:      stdSection.Offset,
			Offset:          stdSection.Offset, // Alias for compatibility
			Characteristics: stdSection.Characteristics,
			Flags:           stdSection.Characteristics,
			Index:           i,
		}

		// Calculate section size
		if i < len(validSections)-1 {
			// Not the last section - calculate size as difference to next section
			section.Size = validSections[i+1].Offset - section.FileOffset
		} else {
			// Last section - calculate size as difference to file end
			section.Size = uint32(pf.FileSize) - section.FileOffset
		}

		// Parse characteristics flags
		section.IsExecutable = (section.Characteristics & 0x20000000) != 0 // IMAGE_SCN_MEM_EXECUTE
		section.IsReadable = (section.Characteristics & 0x40000000) != 0   // IMAGE_SCN_MEM_READ
		section.IsWritable = (section.Characteristics & 0x80000000) != 0   // IMAGE_SCN_MEM_WRITE

		// Extract section data
		if section.Size > 0 && section.FileOffset+section.Size <= uint32(len(pf.RawData)) {
			section.Data = pf.RawData[section.FileOffset : section.FileOffset+section.Size]
		} else {
			section.Data = []byte{}
		}

		// Calculate hashes and entropy
		if len(section.Data) > 0 {
			// MD5
			md5Hash := md5.Sum(section.Data)
			section.MD5Hash = fmt.Sprintf("%x", md5Hash)

			// SHA1
			sha1Hash := sha1.Sum(section.Data)
			section.SHA1Hash = fmt.Sprintf("%x", sha1Hash)

			// SHA256
			sha256Hash := sha256.Sum256(section.Data)
			section.SHA256Hash = fmt.Sprintf("%x", sha256Hash)

			// Use SHA256 as primary hash
			section.Hash = section.SHA256Hash

			// Calculate entropy
			section.Entropy = CalculateEntropy(section.Data)
		}

		pf.Sections[i] = section
	}

	return nil
}

// parseSectionsFromVeloxOnly parses sections using only go-pe (for packed files)
func parseSectionsFromVeloxOnly(pf *PEFile) error {
	sections := pf.VeloxPE.Sections

	if len(sections) == 0 {
		return fmt.Errorf("no sections found in PE file")
	}

	// Filter out sections with FileOffset=0 (virtual sections)
	validSections := make([]*veloxpe.Section, 0, len(sections))
	for _, section := range sections {
		if section.FileOffset > 0 {
			validSections = append(validSections, section)
		}
	}

	if len(validSections) == 0 {
		return fmt.Errorf("no valid sections with FileOffset > 0 found")
	}

	pf.Sections = make([]Section, len(validSections))
	for i, veloxSection := range validSections {
		// Use go-pe section name directly (may contain /4, /19, etc. for packed files)
		sectionName := veloxSection.Name

		// Create section structure with go-pe data
		section := Section{
			Name:           sectionName,
			VirtualAddress: uint32(veloxSection.VMA),
			RVA:            uint32(veloxSection.VMA), // Alias for VirtualAddress
			VirtualSize:    uint32(veloxSection.Size),
			FileOffset:     uint32(veloxSection.FileOffset),
			Offset:         uint32(veloxSection.FileOffset), // Alias for compatibility
			Index:          i,
		}

		// Calculate section size using the workaround (offset difference)
		if i < len(validSections)-1 {
			// Not the last section - calculate size as difference to next section
			section.Size = uint32(validSections[i+1].FileOffset) - section.FileOffset
		} else {
			// Last section - calculate size as difference to file end
			section.Size = uint32(pf.FileSize) - section.FileOffset
		}

		// Parse permissions from string to characteristics flags (go-pe specific)
		section.Characteristics = parsePermissionsToCharacteristics(veloxSection.Perm)
		section.Flags = section.Characteristics
		section.IsExecutable = (section.Characteristics & 0x20000000) != 0 // IMAGE_SCN_MEM_EXECUTE
		section.IsReadable = (section.Characteristics & 0x40000000) != 0   // IMAGE_SCN_MEM_READ
		section.IsWritable = (section.Characteristics & 0x80000000) != 0   // IMAGE_SCN_MEM_WRITE

		// Extract section data
		if section.Size > 0 && section.FileOffset+section.Size <= uint32(len(pf.RawData)) {
			section.Data = pf.RawData[section.FileOffset : section.FileOffset+section.Size]
		} else {
			section.Data = []byte{}
		}

		// Calculate hashes and entropy
		if len(section.Data) > 0 {
			// MD5
			md5Hash := md5.Sum(section.Data)
			section.MD5Hash = fmt.Sprintf("%x", md5Hash)

			// SHA1
			sha1Hash := sha1.Sum(section.Data)
			section.SHA1Hash = fmt.Sprintf("%x", sha1Hash)

			// SHA256
			sha256Hash := sha256.Sum256(section.Data)
			section.SHA256Hash = fmt.Sprintf("%x", sha256Hash)

			// Use SHA256 as primary hash
			section.Hash = section.SHA256Hash

			// Calculate entropy
			section.Entropy = CalculateEntropy(section.Data)
		}

		pf.Sections[i] = section
	}

	return nil
}

// parsePermissionsToCharacteristics converts go-pe permission string to PE characteristics
func parsePermissionsToCharacteristics(perm string) uint32 {
	var characteristics uint32

	// Parse the permission string (e.g., "r-x", "rw-", "r--")
	for _, char := range perm {
		switch char {
		case 'r':
			characteristics |= 0x40000000 // IMAGE_SCN_MEM_READ
		case 'w':
			characteristics |= 0x80000000 // IMAGE_SCN_MEM_WRITE
		case 'x':
			characteristics |= 0x20000000 // IMAGE_SCN_MEM_EXECUTE
		}
	}

	return characteristics
}

// Close closes the file and cleans up resources
func (p *PEFile) Close() error {
	if p.File != nil {
		err := p.File.Close()
		if p.StdPE != nil {
			if closeErr := p.StdPE.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
		}
		return err
	}
	return nil
}

// parseImportsFromVelox parses import information from go-pe and debug/pe
func (p *PEFile) parseImportsFromVelox() {
	// Try to parse imports using debug/pe first for better function resolution
	if p.StdPE != nil {
		p.parseImportsFromStdPE()
		if len(p.Imports) > 0 {
			return
		}
	}

	// Fallback: Extract imports from suspicious strings as a last resort
	p.parseImportsFromStrings()
}

// parseImportsFromStrings extracts DLL names and function names from strings in the file
func (p *PEFile) parseImportsFromStrings() {
	dllMap := make(map[string][]string)

	// Extract strings from the file
	fileStrings := p.extractStrings()

	for _, str := range fileStrings {
		// Look for DLL names
		if strings.HasSuffix(strings.ToLower(str), ".dll") && len(str) < 50 {
			dllName := strings.ToUpper(str)
			if dllMap[dllName] == nil {
				dllMap[dllName] = make([]string, 0)
			}
		}

		// Look for function patterns (common Windows API functions)
		if p.isLikelyFunctionName(str) {
			// Try to match with known DLLs
			dll := p.guessDllForFunction(str)
			if dll != "" {
				if dllMap[dll] == nil {
					dllMap[dll] = make([]string, 0)
				}
				dllMap[dll] = append(dllMap[dll], str)
			}
		}
	}

	// Convert map to ImportInfo structs
	for dllName, functions := range dllMap {
		importInfo := ImportInfo{
			DLL:         dllName,
			LibraryName: dllName,
			Functions:   functions,
			Address:     0,
		}
		p.Imports = append(p.Imports, importInfo)
	}
}

// extractStrings extracts ASCII strings from the PE file
func (p *PEFile) extractStrings() []string {
	var result []string
	var current []byte
	minLen := 4

	for _, b := range p.RawData {
		if b >= 32 && b < 127 { // Printable ASCII
			current = append(current, b)
		} else {
			if len(current) >= minLen {
				result = append(result, string(current))
			}
			current = nil
		}
	}

	// Check last string
	if len(current) >= minLen {
		result = append(result, string(current))
	}

	return result
}

// isLikelyFunctionName checks if a string looks like a Windows API function
func (p *PEFile) isLikelyFunctionName(str string) bool {
	if len(str) < 4 || len(str) > 50 {
		return false
	}

	// Common Windows API function patterns
	commonPrefixes := []string{
		"Create", "Get", "Set", "Open", "Close", "Read", "Write", "Load", "Free",
		"Find", "Query", "Register", "Unregister", "Initialize", "Cleanup",
		"Process", "Thread", "File", "Memory", "Handle", "Event", "Mutex",
		"Virtual", "Heap", "Local", "Global", "Wait", "Signal", "Sleep",
		"Format", "Convert", "Copy", "Move", "Delete", "Exit", "Terminate",
	}

	for _, prefix := range commonPrefixes {
		if strings.HasPrefix(str, prefix) {
			return true
		}
	}

	// Common suffixes
	commonSuffixes := []string{"A", "W", "Ex", "32", "64"}
	for _, suffix := range commonSuffixes {
		if strings.HasSuffix(str, suffix) && len(str) > len(suffix)+3 {
			return true
		}
	}

	return false
}

// guessDllForFunction tries to guess which DLL a function belongs to
func (p *PEFile) guessDllForFunction(funcName string) string {
	// Common function to DLL mappings
	kernelFunctions := []string{
		"CreateFile", "ReadFile", "WriteFile", "GetLastError", "CloseHandle",
		"VirtualAlloc", "VirtualFree", "VirtualProtect", "VirtualQuery",
		"LoadLibrary", "GetProcAddress", "FreeLibrary", "GetModuleHandle",
		"CreateThread", "ExitThread", "SuspendThread", "ResumeThread",
		"WaitForSingleObject", "WaitForMultipleObjects", "CreateEvent",
		"SetEvent", "ResetEvent", "CreateMutex", "ReleaseMutex", "Sleep",
		"GetSystemInfo", "GetTickCount", "QueryPerformanceCounter",
		"MultiByteToWideChar", "WideCharToMultiByte", "GetCommandLine",
		"GetEnvironmentVariable", "SetEnvironmentVariable", "ExitProcess",
	}

	userFunctions := []string{
		"MessageBox", "GetWindowText", "SetWindowText", "ShowWindow",
		"UpdateWindow", "GetDC", "ReleaseDC", "InvalidateRect",
		"CreateWindow", "DestroyWindow", "DefWindowProc", "RegisterClass",
		"GetMessage", "PeekMessage", "TranslateMessage", "DispatchMessage",
	}

	gdi32Functions := []string{
		"CreateDC", "DeleteDC", "SelectObject", "DeleteObject",
		"CreatePen", "CreateBrush", "CreateFont", "TextOut",
		"DrawText", "Rectangle", "Ellipse", "MoveTo", "LineTo",
	}

	for _, kFunc := range kernelFunctions {
		if strings.Contains(strings.ToUpper(funcName), strings.ToUpper(kFunc)) {
			return "KERNEL32.DLL"
		}
	}

	for _, uFunc := range userFunctions {
		if strings.Contains(strings.ToUpper(funcName), strings.ToUpper(uFunc)) {
			return "USER32.DLL"
		}
	}

	for _, gFunc := range gdi32Functions {
		if strings.Contains(strings.ToUpper(funcName), strings.ToUpper(gFunc)) {
			return "GDI32.DLL"
		}
	}

	// Common C runtime functions -> MSVCRT.DLL
	crtFunctions := []string{
		"printf", "scanf", "malloc", "free", "strlen", "strcpy", "strcmp",
		"memcpy", "memset", "fopen", "fclose", "fread", "fwrite", "exit",
	}

	for _, cFunc := range crtFunctions {
		if strings.Contains(strings.ToLower(funcName), cFunc) {
			return "MSVCRT.DLL"
		}
	}

	return ""
}

// parseImportsFromStdPE parses imports using debug/pe for detailed function information
func (p *PEFile) parseImportsFromStdPE() {
	// Try using ImportedSymbols first
	imports, err := p.StdPE.ImportedSymbols()
	if err == nil && len(imports) > 0 {
		p.parseImportsFromSymbols(imports)
		return
	}

	// Fallback: Parse imports manually from Import Directory
	p.parseImportsManually()
}

// parseImportsFromSymbols processes imported symbols from debug/pe
func (p *PEFile) parseImportsFromSymbols(imports []string) {
	// Group imports by DLL
	dllMap := make(map[string][]string)
	for _, imp := range imports {
		if strings.Contains(imp, "!") {
			parts := strings.SplitN(imp, "!", 2)
			if len(parts) == 2 {
				dllName := strings.ToUpper(parts[0])
				funcName := parts[1]

				if dllMap[dllName] == nil {
					dllMap[dllName] = make([]string, 0)
				}
				dllMap[dllName] = append(dllMap[dllName], funcName)
			}
		}
	}

	// Convert map to ImportInfo structs
	for dllName, functions := range dllMap {
		importInfo := ImportInfo{
			DLL:         dllName,
			LibraryName: dllName,
			Functions:   functions,
			Address:     0,
		}
		p.Imports = append(p.Imports, importInfo)
	}
}

// parseImportsManually manually parses the import table
func (p *PEFile) parseImportsManually() {
	// Get Import Directory from Data Directories
	var importDirRVA, importDirSize uint32

	switch oh := p.StdPE.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 1 {
			importDirRVA = oh.DataDirectory[1].VirtualAddress // IMAGE_DIRECTORY_ENTRY_IMPORT = 1
			importDirSize = oh.DataDirectory[1].Size
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 1 {
			importDirRVA = oh.DataDirectory[1].VirtualAddress
			importDirSize = oh.DataDirectory[1].Size
		}
	}

	if importDirRVA == 0 || importDirSize == 0 {
		return
	}

	// Convert RVA to file offset
	importDirOffset := p.rvaToFileOffset(importDirRVA)
	if importDirOffset == 0 {
		return
	}

	// Parse import descriptors
	for offset := importDirOffset; offset < importDirOffset+importDirSize; offset += 20 {
		if offset+20 > uint32(len(p.RawData)) {
			break
		}

		// Read Import Descriptor (20 bytes)
		importLookupTableRVA := binary.LittleEndian.Uint32(p.RawData[offset : offset+4])
		nameRVA := binary.LittleEndian.Uint32(p.RawData[offset+12 : offset+16])

		// Check for end of table
		if nameRVA == 0 {
			break
		}

		// Get DLL name
		nameOffset := p.rvaToFileOffset(nameRVA)
		if nameOffset == 0 {
			continue
		}

		dllName := p.readNullTerminatedString(nameOffset)
		if dllName == "" {
			continue
		}

		// Parse function names from Import Lookup Table
		var functions []string
		if importLookupTableRVA != 0 {
			lookupOffset := p.rvaToFileOffset(importLookupTableRVA)
			if lookupOffset != 0 {
				functions = p.parseImportLookupTable(lookupOffset)
			}
		}

		importInfo := ImportInfo{
			DLL:         strings.ToUpper(dllName),
			LibraryName: strings.ToUpper(dllName),
			Functions:   functions,
			Address:     0,
		}
		p.Imports = append(p.Imports, importInfo)
	}
}

// rvaToFileOffset converts RVA to file offset
func (p *PEFile) rvaToFileOffset(rva uint32) uint32 {
	for _, section := range p.Sections {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			return section.FileOffset + (rva - section.VirtualAddress)
		}
	}
	return 0
}

// readNullTerminatedString reads a null-terminated string from the given offset
func (p *PEFile) readNullTerminatedString(offset uint32) string {
	if offset >= uint32(len(p.RawData)) {
		return ""
	}

	var result []byte
	for i := offset; i < uint32(len(p.RawData)); i++ {
		if p.RawData[i] == 0 {
			break
		}
		result = append(result, p.RawData[i])
	}
	return string(result)
}

// parseImportLookupTable parses function names from Import Lookup Table
func (p *PEFile) parseImportLookupTable(offset uint32) []string {
	var functions []string
	entrySize := uint32(4) // 32-bit
	if p.Is64Bit {
		entrySize = 8 // 64-bit
	}

	for i := uint32(0); i < 1000; i++ { // Limit to prevent infinite loop
		entryOffset := offset + i*entrySize
		if entryOffset+entrySize > uint32(len(p.RawData)) {
			break
		}

		var entry uint64
		if p.Is64Bit {
			entry = binary.LittleEndian.Uint64(p.RawData[entryOffset : entryOffset+8])
		} else {
			entry = uint64(binary.LittleEndian.Uint32(p.RawData[entryOffset : entryOffset+4]))
		}

		// Check for end of table
		if entry == 0 {
			break
		}

		// Check if import by ordinal
		var ordinalFlag uint64 = 0x80000000
		if p.Is64Bit {
			ordinalFlag = 0x8000000000000000
		}

		if (entry & ordinalFlag) != 0 {
			// Import by ordinal
			ordinal := entry & 0xFFFF
			functions = append(functions, fmt.Sprintf("Ordinal_%d", ordinal))
		} else {
			// Import by name
			nameRVA := uint32(entry & 0x7FFFFFFF)
			nameOffset := p.rvaToFileOffset(nameRVA)
			if nameOffset != 0 && nameOffset+2 < uint32(len(p.RawData)) {
				// Skip hint (2 bytes) and read name
				funcName := p.readNullTerminatedString(nameOffset + 2)
				if funcName != "" {
					functions = append(functions, funcName)
				}
			}
		}
	}

	return functions
}

// parseExportsFromVelox parses export information from go-pe
func (p *PEFile) parseExportsFromVelox() {
	// TODO: Implement export parsing using go-pe
	// For now, create empty exports with RVA set to Address
	p.Exports = []ExportInfo{}
}

// analyzeFile performs comprehensive analysis of the PE file
func (p *PEFile) analyzeFile() error {
	// Basic validation
	if len(p.Sections) == 0 {
		return fmt.Errorf("no sections found")
	}

	// Additional analysis can be added here
	return nil
}

// ReadBytes reads bytes from the PE file at the specified offset and length
func (p *PEFile) ReadBytes(offset uint32, length int) ([]byte, error) {
	if int64(offset)+int64(length) > p.FileSize {
		return nil, fmt.Errorf("read out of bounds: offset %d + length %d > file size %d", offset, length, p.FileSize)
	}

	if int(offset)+length > len(p.RawData) {
		return nil, fmt.Errorf("read out of bounds: offset %d + length %d > raw data size %d", offset, length, len(p.RawData))
	}

	return p.RawData[offset : offset+uint32(length)], nil
}

// CalculatePhysicalFileSize calculates expected file size based on PE headers
func (p *PEFile) CalculatePhysicalFileSize() error {
	// This is a simplified version - the go-pe library should handle most of this
	return nil
}
