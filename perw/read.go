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
)

// Section represents a section in the PE file
type Section struct {
	Name           string
	Offset         int64
	Size           int64
	VirtualAddress uint32
	VirtualSize    uint32
	Index          int
	Flags          uint32
	RVA            uint32
	Entropy        float64 // Calculated entropy for analysis
	MD5Hash        string
	SHA1Hash       string
	SHA256Hash     string
}

// DirectoryEntry represents a directory entry in the PE file
type DirectoryEntry struct {
	Type uint16
	RVA  uint32
	Size uint32
}

// ImportInfo holds information about imported functions and libraries
type ImportInfo struct {
	LibraryName string
	Functions   []string
	IatRva      uint32
}

// ExportInfo holds information about exported functions
type ExportInfo struct {
	Name      string
	Ordinal   uint16
	RVA       uint32
	Forwarder string
}

// PEFile represents the PE file structure
type PEFile struct {
	File     *os.File
	PE       *pe.File
	Is64Bit  bool
	FileName string
	Sections []Section
	RawData  []byte

	// PE Header information
	ImageBase          uint64
	EntryPoint         uint32
	SizeOfImage        uint32
	SizeOfHeaders      uint32
	Checksum           uint32
	Subsystem          uint16
	DllCharacteristics uint16

	// Directory entries
	Directories []DirectoryEntry

	// Import/Export tables
	Imports []ImportInfo
	Exports []ExportInfo

	// File analysis
	FileSize      int64
	IsPacked      bool
	HasOverlay    bool
	OverlayOffset int64
	OverlaySize   int64

	// Security
	SignatureOffset int64
	SignatureSize   int64
}

// ReadPE creates a comprehensive PEFile structure with full analysis
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

	peLibFile, err := pe.NewFile(bytes.NewReader(rawData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse PE file: %w", err)
	}

	pf := &PEFile{
		File:     file,
		PE:       peLibFile,
		FileName: file.Name(),
		RawData:  rawData,
		Is64Bit:  isPE64Bit(peLibFile),
		FileSize: fileInfo.Size(),
	}

	// Parse all PE components
	if err := pf.parseHeaders(); err != nil {
		return nil, fmt.Errorf("failed to parse headers: %w", err)
	}

	if err := pf.parseSections(); err != nil {
		return nil, fmt.Errorf("failed to parse sections: %w", err)
	}

	if err := pf.parseDirectories(); err != nil {
		return nil, fmt.Errorf("failed to parse directories: %w", err)
	}

	if err := pf.parseImports(); err != nil {
		return nil, fmt.Errorf("failed to parse imports: %w", err)
	}

	if err := pf.parseExports(); err != nil {
		return nil, fmt.Errorf("failed to parse exports: %w", err)
	}

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

// isPE64Bit determines if the PE file is 64-bit
func isPE64Bit(peFile *pe.File) bool {
	return peFile.FileHeader.Machine == pe.IMAGE_FILE_MACHINE_AMD64
}

// validateDOSHeader validates the DOS header
func validateDOSHeader(data []byte) error {
	if len(data) < 64 {
		return fmt.Errorf("file too small to be a valid PE file")
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return fmt.Errorf("invalid DOS header signature")
	}
	return nil
}

// parseHeaders extracts comprehensive header information
func (p *PEFile) parseHeaders() error {
	switch oh := p.PE.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		p.ImageBase = uint64(oh.ImageBase)
		p.EntryPoint = oh.AddressOfEntryPoint
		p.SizeOfImage = oh.SizeOfImage
		p.SizeOfHeaders = oh.SizeOfHeaders
		p.Checksum = oh.CheckSum
		p.Subsystem = oh.Subsystem
		p.DllCharacteristics = oh.DllCharacteristics
	case *pe.OptionalHeader64:
		p.ImageBase = oh.ImageBase
		p.EntryPoint = oh.AddressOfEntryPoint
		p.SizeOfImage = oh.SizeOfImage
		p.SizeOfHeaders = oh.SizeOfHeaders
		p.Checksum = oh.CheckSum
		p.Subsystem = oh.Subsystem
		p.DllCharacteristics = oh.DllCharacteristics
	default:
		return fmt.Errorf("unsupported optional header type")
	}
	return nil
}

// parseSections creates detailed section information with hashes and entropy
func (p *PEFile) parseSections() error {
	p.Sections = make([]Section, 0, len(p.PE.Sections))

	for i, s := range p.PE.Sections {
		section := Section{
			Name:           strings.TrimRight(s.Name, "\x00"),
			Offset:         int64(s.Offset),
			Size:           int64(s.Size),
			VirtualAddress: s.VirtualAddress,
			VirtualSize:    s.VirtualSize,
			Index:          i,
			Flags:          s.Characteristics,
			RVA:            s.VirtualAddress,
		}

		// Calculate hashes and entropy for non-empty sections
		if section.Size > 0 && section.Offset+section.Size <= int64(len(p.RawData)) {
			sectionData := p.RawData[section.Offset : section.Offset+section.Size]

			// Calculate hashes
			md5Hash := md5.Sum(sectionData)
			sha1Hash := sha1.Sum(sectionData)
			sha256Hash := sha256.Sum256(sectionData)

			section.MD5Hash = fmt.Sprintf("%x", md5Hash)
			section.SHA1Hash = fmt.Sprintf("%x", sha1Hash)
			section.SHA256Hash = fmt.Sprintf("%x", sha256Hash)

			// Calculate entropy
			section.Entropy = calculateEntropy(sectionData)
		}

		p.Sections = append(p.Sections, section)
	}

	return nil
}

// parseDirectories extracts directory table information
func (p *PEFile) parseDirectories() error {
	// Implementation depends on manually parsing the directory table
	// This is a simplified version - full implementation would parse each directory
	p.Directories = make([]DirectoryEntry, 0)
	// Note: Full directory parsing not needed for current functionality
	return nil
}

// parseImports extracts detailed import information
func (p *PEFile) parseImports() error {
	imports, err := p.PE.ImportedSymbols()
	if err != nil {
		return err
	}

	libMap := make(map[string][]string)
	for _, imp := range imports {
		parts := strings.SplitN(imp, ":", 2)
		if len(parts) == 2 {
			lib := strings.ToLower(parts[0])
			function := parts[1]
			libMap[lib] = append(libMap[lib], function)
		}
	}

	p.Imports = make([]ImportInfo, 0, len(libMap))
	for lib, functions := range libMap {
		p.Imports = append(p.Imports, ImportInfo{
			LibraryName: lib,
			Functions:   functions,
		})
	}

	return nil
}

// parseExports extracts export table information
func (p *PEFile) parseExports() error {
	// This would require manual parsing of the export directory
	// The standard library doesn't provide direct access to exports
	p.Exports = make([]ExportInfo, 0)
	// Note: Export parsing not needed for current functionality
	return nil
}

// analyzeFile performs basic file analysis (detailed analysis in analyze.go)
func (p *PEFile) analyzeFile() error {
	// Check for overlay
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

// ReadBytes Enhanced with better error handling
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

// Close properly closes all resources
func (p *PEFile) Close() error {
	var errors []error

	if p.PE != nil {
		if err := p.PE.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close PE: %w", err))
		}
	}

	if p.File != nil {
		if err := p.File.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close file: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("close errors: %v", errors)
	}

	return nil
}

// reParseImportsFromRawData re-parses imports from the potentially modified RawData
// This is needed for accurate analysis after import obfuscation
func (p *PEFile) reParseImportsFromRawData() error {
	// Get import table directory entry
	offsets, err := p.calculateOffsets()
	if err != nil {
		return err
	}

	importDirOffset := offsets.OptionalHeader + directoryOffsets.importTable[p.Is64Bit]
	if err := p.validateOffset(importDirOffset, 8); err != nil {
		// No import table, clear imports
		p.Imports = make([]ImportInfo, 0)
		return nil
	}

	// Read import table RVA and size
	importRVA := binary.LittleEndian.Uint32(p.RawData[importDirOffset:])
	importSize := binary.LittleEndian.Uint32(p.RawData[importDirOffset+4:])

	if importRVA == 0 || importSize == 0 {
		p.Imports = make([]ImportInfo, 0)
		return nil
	}

	// Convert RVA to physical offset
	importPhysical, err := p.rvaToPhysical(uint64(importRVA))
	if err != nil {
		p.Imports = make([]ImportInfo, 0)
		return nil
	}

	// Parse import descriptors
	libMap := make(map[string][]string)
	numDescriptors := (importSize / importDescriptorSize) - 1

	for i := uint32(0); i < numDescriptors; i++ {
		descOffset := importPhysical + uint64(i*importDescriptorSize)
		if err := p.validateOffset(int64(descOffset), importDescriptorSize); err != nil {
			continue
		}

		// Get library name RVA
		nameRVA := binary.LittleEndian.Uint32(p.RawData[descOffset+12:])
		if nameRVA == 0 {
			continue
		}

		namePhysical, err := p.rvaToPhysical(uint64(nameRVA))
		if err != nil {
			continue
		}

		// Extract library name
		libNameBytes := make([]byte, 0, 256)
		for j := namePhysical; int(j) < len(p.RawData) && p.RawData[j] != 0; j++ {
			libNameBytes = append(libNameBytes, p.RawData[j])
		}
		libName := strings.ToLower(string(libNameBytes))

		// Get the OriginalFirstThunk (Import Name Table) RVA
		originalFirstThunk := binary.LittleEndian.Uint32(p.RawData[descOffset:])
		if originalFirstThunk == 0 {
			continue
		}

		intPhysical, err := p.rvaToPhysical(uint64(originalFirstThunk))
		if err != nil {
			continue
		}

		// Parse function names from Import Name Table
		functions := p.parseFunctionNamesFromINT(intPhysical)
		if len(functions) > 0 {
			libMap[libName] = functions
		}
	}

	// Convert to ImportInfo slice
	p.Imports = make([]ImportInfo, 0, len(libMap))
	for lib, functions := range libMap {
		p.Imports = append(p.Imports, ImportInfo{
			LibraryName: lib,
			Functions:   functions,
		})
	}

	return nil
}

// parseFunctionNamesFromINT extracts function names from Import Name Table
func (p *PEFile) parseFunctionNamesFromINT(intPhysical uint64) []string {
	ptrSize := map[bool]int{true: 8, false: 4}[p.Is64Bit]
	functions := make([]string, 0)

	for offset := intPhysical; ; offset += uint64(ptrSize) {
		if err := p.validateOffset(int64(offset), ptrSize); err != nil {
			break
		}

		// Read the thunk value
		var thunkValue uint64
		if p.Is64Bit {
			thunkValue = binary.LittleEndian.Uint64(p.RawData[offset:])
		} else {
			thunkValue = uint64(binary.LittleEndian.Uint32(p.RawData[offset:]))
		}

		// Check for end of table
		if thunkValue == 0 {
			break
		}

		// Check if it's an ordinal import (high bit set)
		if (p.Is64Bit && (thunkValue&0x8000000000000000) != 0) ||
			(!p.Is64Bit && (thunkValue&0x80000000) != 0) {
			ordinal := thunkValue & 0xFFFF
			functions = append(functions, fmt.Sprintf("Ordinal_%d", ordinal))
			continue
		}

		// It's a name import - get the hint/name table entry
		hintNameRVA := thunkValue
		hintNamePhysical, err := p.rvaToPhysical(hintNameRVA)
		if err != nil {
			continue
		}

		// Skip 2-byte hint and extract function name
		namePhysical := hintNamePhysical + 2
		if err := p.validateOffset(int64(namePhysical), 1); err != nil {
			continue
		}

		// Extract function name
		funcNameBytes := make([]byte, 0, 256)
		for j := namePhysical; int(j) < len(p.RawData) && p.RawData[j] != 0; j++ {
			funcNameBytes = append(funcNameBytes, p.RawData[j])
		}

		if len(funcNameBytes) > 0 {
			functions = append(functions, string(funcNameBytes))
		}
	}

	return functions
}

// IsPEFile checks if a file is a valid PE file
func IsPEFile(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	// Read DOS header
	dosHeader := make([]byte, 64)
	if _, err := file.Read(dosHeader); err != nil {
		return false, nil // Not enough data, not a PE file
	}

	// Check DOS signature (MZ)
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		return false, nil
	}

	// Get PE header offset
	peOffset := binary.LittleEndian.Uint32(dosHeader[60:64])

	// Seek to PE header
	if _, err := file.Seek(int64(peOffset), 0); err != nil {
		return false, nil
	}

	// Read PE signature
	peSignature := make([]byte, 4)
	if _, err := file.Read(peSignature); err != nil {
		return false, nil
	}

	// Check PE signature
	return string(peSignature) == "PE\x00\x00", nil
}
