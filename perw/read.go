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
	"time"
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

	// Additional fields for enhanced analysis
	FileOffset   uint32
	IsExecutable bool
	IsReadable   bool
	IsWritable   bool
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
	DLL         string // Alias for LibraryName for compatibility
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
	imageBase          uint64
	entryPoint         uint32
	sizeOfImage        uint32
	sizeOfHeaders      uint32
	checksum           uint32
	subsystem          uint16
	dllCharacteristics uint16
	Machine            string
	TimeDateStamp      string

	// Directory entries
	directories []DirectoryEntry

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
	signatureSize   int64

	// Debug information
	PDBPath string
	guidAge string

	// Version information
	versionInfo map[string]string
}

// ParseMode represents the parsing mode used
type ParseMode int

// ParseResult contains the result of PE parsing
type ParseResult struct {
	Mode     ParseMode
	Success  bool
	Reason   string
	Warnings []string
}

// ReadPE creates a comprehensive PEFile structure with full analysis
// ReadPE: crea una struttura PEFile completa e analizza tutte le componenti
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

// newPEFileFromDisk: step 1 - read file, validate, create PEFile struct base (with error tolerance)
// newPEFileFromDisk: step 1 - lettura file, validazione, creazione base PEFile (con tolleranza errori)
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
	// Try to parse with Go's standard PE library
	peLibFile, err := pe.NewFile(bytes.NewReader(rawData))
	if err != nil {
		// Determine the reason for parsing failure
		var reason string
		if isUPXSignaturePresent(rawData) {
			reason = "File appears to be packed/compressed"
		} else if strings.Contains(err.Error(), "string table") {
			reason = "Corrupted or modified PE structure"
		} else {
			reason = "Non-standard PE format"
		}

		// Single consolidated message
		fmt.Printf("⚠️  %s (%s)\n", reason, err.Error())

		pf := &PEFile{
			File:     file,
			PE:       nil, // Will be nil, but we can still analyze raw data
			FileName: file.Name(),
			RawData:  rawData,
			Is64Bit:  false, // We'll try to detect this manually if needed
			FileSize: fileInfo.Size(),
		}

		// Try to manually detect if it's 64-bit from raw data
		if len(rawData) > 64 {
			// Simple heuristic - check PE header magic
			dosHeaderOffset := int(rawData[60]) | int(rawData[61])<<8 | int(rawData[62])<<16 | int(rawData[63])<<24
			if dosHeaderOffset > 0 && dosHeaderOffset+24 < len(rawData) {
				magic := rawData[dosHeaderOffset+24 : dosHeaderOffset+26]
				if len(magic) >= 2 {
					magicValue := uint16(magic[0]) | uint16(magic[1])<<8
					pf.Is64Bit = (magicValue == 0x20b) // PE32+ magic
				}
			}
		}

		return pf, nil
	}

	pf := &PEFile{
		File:     file,
		PE:       peLibFile,
		FileName: file.Name(),
		RawData:  rawData,
		Is64Bit:  isPE64Bit(peLibFile),
		FileSize: fileInfo.Size(),
	}
	return pf, nil
}

// parseAllPEComponents: step 2 - parse all PE structures atomically (with error tolerance)
// parseAllPEComponents: step 2 - parsing atomico di tutte le strutture PE (con tolleranza errori)
func (p *PEFile) parseAllPEComponents() error {
	var errors []string

	// Try to parse each component, collecting errors but not failing immediately
	if err := p.parseHeaders(); err != nil {
		errors = append(errors, fmt.Sprintf("headers: %v", err))
	}

	if err := p.parseSectionsAtomic(); err != nil {
		errors = append(errors, fmt.Sprintf("sections: %v", err))
		// Initialize empty sections if parsing failed
		if p.Sections == nil {
			p.Sections = make([]Section, 0)
		}
	}

	if err := p.parseDirectories(); err != nil {
		errors = append(errors, fmt.Sprintf("directories: %v", err))
	}

	if err := p.parseImportsAtomic(); err != nil {
		errors = append(errors, fmt.Sprintf("imports: %v", err))
		// Initialize empty imports if parsing failed
		if p.Imports == nil {
			p.Imports = make([]ImportInfo, 0)
		}
	}

	if err := p.parseExports(); err != nil {
		errors = append(errors, fmt.Sprintf("exports: %v", err))
		// Initialize empty exports if parsing failed
		if p.Exports == nil {
			p.Exports = make([]ExportInfo, 0)
		}
	}

	if err := p.analyzeFile(); err != nil {
		errors = append(errors, fmt.Sprintf("analysis: %v", err))
	}

	// Store parsing errors for later reference but don't spam console
	if len(errors) > 0 && len(errors) >= 4 {
		return fmt.Errorf("too many parsing errors: %v", errors)
	}

	return nil
}

// parseSectionsAtomic: parse sections, hash, entropy (atomica con tolleranza errori)
func (p *PEFile) parseSectionsAtomic() error {
	p.Sections = make([]Section, 0)

	// Check if PE sections are available
	if p.PE == nil {
		// Fallback to raw parsing (already reported above)
		return p.parseBasicSectionsFromRaw()
	}

	if p.PE.Sections == nil {
		return p.parseBasicSectionsFromRaw()
	}

	// Try to parse each section individually
	for i, s := range p.PE.Sections {
		if s == nil {
			continue // Skip nil sections
		}

		func() {
			// Use defer recover to catch any panics during section parsing
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

// parseSectionBase: crea Section base da pe.Section
// parseSectionBase: crea Section base da pe.Section
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
		IsExecutable:   (s.Characteristics & pe.IMAGE_SCN_MEM_EXECUTE) != 0,
		IsReadable:     (s.Characteristics & pe.IMAGE_SCN_MEM_READ) != 0,
		IsWritable:     (s.Characteristics & pe.IMAGE_SCN_MEM_WRITE) != 0,
	}
}

// fillSectionHashesAndEntropy: calcola hash e entropia per una Section
// fillSectionHashesAndEntropy: calcola hash e entropia per una Section
func (p *PEFile) fillSectionHashesAndEntropy(section *Section) {
	if section.Size > 0 && section.Offset+section.Size <= int64(len(p.RawData)) {
		sectionData := p.RawData[section.Offset : section.Offset+section.Size]
		md5Hash := md5.Sum(sectionData)
		sha1Hash := sha1.Sum(sectionData)
		sha256Hash := sha256.Sum256(sectionData)
		section.MD5Hash = fmt.Sprintf("%x", md5Hash)
		section.SHA1Hash = fmt.Sprintf("%x", sha1Hash)
		section.SHA256Hash = fmt.Sprintf("%x", sha256Hash)
		section.Entropy = CalculateEntropy(sectionData)
	} else {
		// Virtual-only section or invalid section data
		section.MD5Hash = "N/A (no raw data)"
		section.SHA1Hash = "N/A (no raw data)"
		section.SHA256Hash = "N/A (no raw data)"
		section.Entropy = 0.0
	}
}

// parseImportsAtomic: parsing import table atomico (con tolleranza errori)
// parseImportsAtomic: parsing atomico della tabella import (con tolleranza errori)
func (p *PEFile) parseImportsAtomic() error {
	// Initialize empty imports
	p.Imports = make([]ImportInfo, 0)

	// If PE parsing failed, we can't extract imports
	if p.PE == nil {
		// No imports available (already reported in main message)
		return nil
	}

	symbols, err := p.PE.ImportedSymbols()
	if err != nil {
		return nil
	}
	if len(symbols) == 0 {
		return nil
	}
	libMapping := make(map[string][]string)
	for _, symbol := range symbols {
		if strings.Contains(symbol, ":") {
			parts := strings.SplitN(symbol, ":", 2)
			if len(parts) == 2 {
				function := parts[0]
				library := strings.ToLower(parts[1])
				libMapping[library] = append(libMapping[library], function)
			}
		}
	}
	p.Imports = make([]ImportInfo, 0, len(libMapping))
	for lib, functions := range libMapping {
		if len(functions) > 0 {
			p.Imports = append(p.Imports, ImportInfo{
				LibraryName: lib,
				DLL:         lib,
				Functions:   functions,
			})
		}
	}
	return nil
}

// readFileData reads the entire file into memory
// readFileData legge l'intero file in memoria
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
// isPE64Bit: true se PE 64 bit
func isPE64Bit(peFile *pe.File) bool {
	return peFile.FileHeader.Machine == pe.IMAGE_FILE_MACHINE_AMD64
}

// validateDOSHeader validates the DOS header
// validateDOSHeader: controlla la validità del DOS header
func validateDOSHeader(data []byte) error {
	if len(data) < 64 {
		return fmt.Errorf("file too small to be a valid PE file")
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return fmt.Errorf("invalid DOS header signature")
	}
	return nil
}

// parseHeaders extracts comprehensive header information (with error tolerance)
// parseHeaders: estrae header principali e info aggiuntive (con tolleranza errori)
func (p *PEFile) parseHeaders() error {
	// If PE parsing failed, try to extract basic info from raw data
	if p.PE == nil {
		return p.parseBasicHeadersFromRaw()
	}

	// If OptionalHeader is not available, skip header parsing
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

	// Extract additional header information
	p.extractMachineType()
	p.extractTimeDateStamp()
	p.extractDebugInfo()
	p.extractVersionInfo()

	return nil
}

// parseDirectories extracts directory table information
// parseDirectories: parsing semplificato delle directory (placeholder, non usato)
func (p *PEFile) parseDirectories() error {
	// Implementation depends on manually parsing the directory table
	// This is a simplified version - full implementation would parse each directory
	p.directories = make([]DirectoryEntry, 0)
	// Note: Full directory parsing not needed for current functionality
	return nil
}

// parseExports extracts export table information
// parseExports: parsing export (placeholder, non usato)
func (p *PEFile) parseExports() error {
	// This would require manual parsing of the export directory
	// The standard library doesn't provide direct access to exports
	p.Exports = make([]ExportInfo, 0)
	// Note: Export parsing not needed for current functionality
	return nil
}

// analyzeFile performs basic file analysis (detailed analysis in analyze.go)
// analyzeFile: analisi base del file (overlay, packed, ecc)
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
// ReadBytes: lettura sicura di byte dal buffer RawData
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
// Close: chiude tutte le risorse associate al PEFile
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

// IsPEFile checks if a file is a valid PE file
// IsPEFile: true se il file è un PE valido
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

// Accessor methods for PE file information
// Accessor: getter per info header PE
func (p *PEFile) ImageBase() uint64 {
	return p.imageBase
}

func (p *PEFile) EntryPoint() uint32 {
	return p.entryPoint
}

func (p *PEFile) SizeOfImage() uint32 {
	return p.sizeOfImage
}

func (p *PEFile) SizeOfHeaders() uint32 {
	return p.sizeOfHeaders
}

func (p *PEFile) Checksum() uint32 {
	return p.checksum
}

func (p *PEFile) Subsystem() uint16 {
	return p.subsystem
}

func (p *PEFile) DllCharacteristics() uint16 {
	return p.dllCharacteristics
}

func (p *PEFile) Directories() []DirectoryEntry {
	return p.directories
}

func (p *PEFile) SignatureSize() int64 {
	return p.signatureSize
}

func (p *PEFile) PDB() string {
	return p.PDBPath
}

func (p *PEFile) GUIDAge() string {
	return p.guidAge
}

func (p *PEFile) VersionInfo() map[string]string {
	if p.versionInfo == nil {
		p.versionInfo = make(map[string]string)
	}
	return p.versionInfo
}

// extractMachineType extracts machine type string from PE header
// extractMachineType: estrae tipo macchina dal PE header
func (p *PEFile) extractMachineType() {
	if p.PE.FileHeader.Machine == pe.IMAGE_FILE_MACHINE_I386 {
		p.Machine = "i386"
	} else if p.PE.FileHeader.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
		p.Machine = "amd64"
	} else if p.PE.FileHeader.Machine == pe.IMAGE_FILE_MACHINE_ARM {
		p.Machine = "arm"
	} else if p.PE.FileHeader.Machine == pe.IMAGE_FILE_MACHINE_ARM64 {
		p.Machine = "arm64"
	} else {
		p.Machine = fmt.Sprintf("Unknown (0x%X)", p.PE.FileHeader.Machine)
	}
}

// extractTimeDateStamp extracts compilation timestamp
// extractTimeDateStamp: estrae timestamp di compilazione
func (p *PEFile) extractTimeDateStamp() {
	if p.PE.FileHeader.TimeDateStamp != 0 {
		timestamp := int64(p.PE.FileHeader.TimeDateStamp)
		t := time.Unix(timestamp, 0)
		p.TimeDateStamp = t.Format("2006-01-02 15:04:05 UTC")
	} else {
		p.TimeDateStamp = "Not set"
	}
}

// extractDebugInfo extracts debug information like PDB path
// extractDebugInfo: placeholder per info debug (PDB)
func (p *PEFile) extractDebugInfo() {
	// This is a simplified version - full implementation would parse debug directory
	p.PDBPath = ""
	p.guidAge = ""

	// Look for debug directory entries and extract PDB info
	// This requires parsing the debug directory which is complex
	// For now, set placeholder values
}

// extractVersionInfo extracts version information from resources
// extractVersionInfo: placeholder per info versione
func (p *PEFile) extractVersionInfo() {
	p.versionInfo = make(map[string]string)

	// Try to parse version info from resources
	if p.PE != nil && len(p.PE.Sections) > 0 {
		for _, s := range p.PE.Sections {
			if s.Name == ".rsrc" {
				data, err := s.Data()
				if err != nil || len(data) == 0 {
					break
				}
				// Search for VS_VERSION_INFO signature
				sig := []byte("VS_VERSION_INFO")
				idx := bytes.Index(data, sig)
				if idx >= 0 {
					// Try to extract version strings from the block
					block := data[idx:]
					// Look for common fields as UTF-16LE null-terminated strings
					fields := []string{"FileVersion", "ProductVersion", "CompanyName", "FileDescription", "InternalName", "OriginalFilename", "ProductName", "LegalCopyright"}
					for _, field := range fields {
						// Search for field name as UTF-16LE
						fieldUtf16 := utf16le(field)
						fidx := bytes.Index(block, fieldUtf16)
						if fidx >= 0 {
							// Value is after field name, skip null terminator (2 bytes)
							valStart := fidx + len(fieldUtf16) + 2
							// Read until next double null (end of string)
							val := readUtf16String(block[valStart:])
							if val != "" {
								p.versionInfo[field] = val
							}
						}
					}
					// If at least one field found, return
					if len(p.versionInfo) > 0 {
						return
					}
				}
			}
		}
	}
	// Fallback: placeholder entries
	p.versionInfo["FileVersion"] = "Unknown"
	p.versionInfo["ProductVersion"] = "Unknown"
	p.versionInfo["CompanyName"] = "Unknown"
	p.versionInfo["FileDescription"] = "Unknown"

}

// Helper: encode Go string as UTF-16LE []byte
func utf16le(s string) []byte {
	u := make([]byte, len(s)*2)
	for i, r := range s {
		u[i*2] = byte(r)
		u[i*2+1] = 0
	}
	return u
}

// Helper: read null-terminated UTF-16LE string from []byte
func readUtf16String(b []byte) string {
	var runes []rune
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(b[i]) | (rune(b[i+1]) << 8)
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}

// sanitizeSectionName cleans and validates section names from raw PE data
// Handles corrupted/stripped files with enhanced validation
func (p *PEFile) sanitizeSectionName(nameBytes []byte) string {
	// Remove null bytes and trim
	name := strings.TrimRight(string(nameBytes), "\x00")

	// Check if the name contains only printable ASCII characters
	isValid := true
	for _, r := range name {
		if r < 32 || r > 126 {
			isValid = false
			break
		}
	}

	// If name is invalid or empty, generate a placeholder
	if !isValid || len(name) == 0 {
		return fmt.Sprintf("<stripped_%d>", len(p.Sections))
	}

	// Check for suspicious patterns that indicate corrupted/stripped data
	if strings.HasPrefix(name, "/") && len(name) <= 3 {
		// This looks like corrupted COFF string table reference (e.g., /4, /19, /32)
		return fmt.Sprintf("<coff_ref_%s>", strings.TrimPrefix(name, "/"))
	}

	// Check for other corruption patterns
	if len(name) == 1 && (name[0] < 'A' || name[0] > 'z') {
		return fmt.Sprintf("<corrupted_%02x>", name[0])
	}

	// Check for patterns that suggest the file was already processed
	nonPrintableCount := 0
	for _, b := range nameBytes {
		if b != 0 && (b < 32 || b > 126) {
			nonPrintableCount++
		}
	}

	// If more than half the bytes are non-printable, it's likely corrupted
	if nonPrintableCount > len(nameBytes)/2 {
		return fmt.Sprintf("<mangled_%d>", len(p.Sections))
	}

	return name
}

// parseBasicSectionsFromRaw attempts to extract basic section information from raw PE data
// parseBasicSectionsFromRaw: estrae informazioni base delle sezioni dai dati raw PE
func (p *PEFile) parseBasicSectionsFromRaw() error {
	// This is a simplified parser for when pe.NewFile() fails
	// We'll try to extract minimal section information for analysis

	if len(p.RawData) < 64 {
		return fmt.Errorf("file too small to be a valid PE")
	}

	// Get PE header offset from DOS header
	peOffset := int(p.RawData[60]) | int(p.RawData[61])<<8 | int(p.RawData[62])<<16 | int(p.RawData[63])<<24

	if peOffset+24 >= len(p.RawData) {
		return fmt.Errorf("invalid PE header offset")
	}

	// Check PE signature
	if string(p.RawData[peOffset:peOffset+4]) != "PE\x00\x00" {
		return fmt.Errorf("invalid PE signature")
	}

	// Get number of sections from COFF header
	numSections := int(p.RawData[peOffset+6]) | int(p.RawData[peOffset+7])<<8

	// Get optional header size
	optHeaderSize := int(p.RawData[peOffset+20]) | int(p.RawData[peOffset+21])<<8

	// Section headers start after PE header + COFF header + optional header
	sectionHeadersOffset := peOffset + 24 + optHeaderSize

	if sectionHeadersOffset+numSections*40 > len(p.RawData) {
		return fmt.Errorf("section headers extend beyond file")
	}

	// Parse each section header (40 bytes each) - quiet mode
	validSections := 0
	for i := 0; i < numSections; i++ {
		offset := sectionHeadersOffset + i*40
		if offset+40 > len(p.RawData) {
			fmt.Printf("⚠️  Section %d header extends beyond file, stopping\n", i)
			break
		}

		// Extract section name (first 8 bytes)
		nameBytes := p.RawData[offset : offset+8]
		name := p.sanitizeSectionName(nameBytes)

		// Extract virtual size (bytes 8-12)
		virtualSize := uint32(p.RawData[offset+8]) | uint32(p.RawData[offset+9])<<8 |
			uint32(p.RawData[offset+10])<<16 | uint32(p.RawData[offset+11])<<24

		// Extract virtual address (bytes 12-16)
		virtualAddress := uint32(p.RawData[offset+12]) | uint32(p.RawData[offset+13])<<8 |
			uint32(p.RawData[offset+14])<<16 | uint32(p.RawData[offset+15])<<24

		// Extract size of raw data (bytes 16-20)
		sizeOfRawData := int64(p.RawData[offset+16]) | int64(p.RawData[offset+17])<<8 |
			int64(p.RawData[offset+18])<<16 | int64(p.RawData[offset+19])<<24

		// Extract pointer to raw data (bytes 20-24)
		pointerToRawData := int64(p.RawData[offset+20]) | int64(p.RawData[offset+21])<<8 |
			int64(p.RawData[offset+22])<<16 | int64(p.RawData[offset+23])<<24

		// Extract characteristics (bytes 36-40)
		characteristics := uint32(p.RawData[offset+36]) | uint32(p.RawData[offset+37])<<8 |
			uint32(p.RawData[offset+38])<<16 | uint32(p.RawData[offset+39])<<24

		// Validate section data for stripped files
		if p.isValidSectionData(virtualAddress, virtualSize, pointerToRawData, sizeOfRawData) {
			// Create section struct
			section := Section{
				Name:           name,
				VirtualAddress: virtualAddress,
				VirtualSize:    virtualSize,
				Size:           sizeOfRawData,
				Offset:         pointerToRawData,
				FileOffset:     uint32(pointerToRawData),
				Flags:          characteristics,
				Index:          validSections,
				IsExecutable:   (characteristics & 0x20000000) != 0, // IMAGE_SCN_MEM_EXECUTE
				IsReadable:     (characteristics & 0x40000000) != 0, // IMAGE_SCN_MEM_READ
				IsWritable:     (characteristics & 0x80000000) != 0, // IMAGE_SCN_MEM_WRITE
			}

			// Calculate entropy and hashes for the section data
			p.fillSectionHashesAndEntropy(&section)

			p.Sections = append(p.Sections, section)
			validSections++
		}
	}

	// Single summary message at the end
	if validSections < numSections {
		fmt.Printf("⚠️  Enhanced parser successfully processed %d/%d sections\n", validSections, numSections)
	}

	return nil
}

// parseBasicHeadersFromRaw extracts basic header information from raw PE data
// parseBasicHeadersFromRaw: estrae informazioni header base dai dati raw PE
func (p *PEFile) parseBasicHeadersFromRaw() error {
	if len(p.RawData) < 64 {
		return fmt.Errorf("file too small for PE headers")
	}

	// Get PE header offset
	peOffset := int(p.RawData[60]) | int(p.RawData[61])<<8 | int(p.RawData[62])<<16 | int(p.RawData[63])<<24

	if peOffset+24 >= len(p.RawData) {
		return fmt.Errorf("invalid PE header offset")
	}

	// Check PE signature
	if string(p.RawData[peOffset:peOffset+4]) != "PE\x00\x00" {
		return fmt.Errorf("invalid PE signature")
	}

	// Extract machine type (COFF header bytes 4-6)
	machine := uint16(p.RawData[peOffset+4]) | uint16(p.RawData[peOffset+5])<<8

	// Extract timestamp (COFF header bytes 8-12)
	timestamp := uint32(p.RawData[peOffset+8]) | uint32(p.RawData[peOffset+9])<<8 |
		uint32(p.RawData[peOffset+10])<<16 | uint32(p.RawData[peOffset+11])<<8

	// Extract optional header size (COFF header bytes 20-22)
	optHeaderSize := uint16(p.RawData[peOffset+20]) | uint16(p.RawData[peOffset+21])<<8

	// Try to extract basic optional header fields if available
	optHeaderOffset := peOffset + 24
	if optHeaderOffset+28 <= len(p.RawData) && optHeaderSize >= 28 {
		// Extract magic number to determine 32 vs 64 bit
		magic := uint16(p.RawData[optHeaderOffset]) | uint16(p.RawData[optHeaderOffset+1])<<8

		if magic == 0x10b { // PE32
			if optHeaderOffset+96 <= len(p.RawData) {
				p.entryPoint = uint32(p.RawData[optHeaderOffset+16]) | uint32(p.RawData[optHeaderOffset+17])<<8 |
					uint32(p.RawData[optHeaderOffset+18])<<16 | uint32(p.RawData[optHeaderOffset+19])<<24
				p.imageBase = uint64(uint32(p.RawData[optHeaderOffset+28]) | uint32(p.RawData[optHeaderOffset+29])<<8 |
					uint32(p.RawData[optHeaderOffset+30])<<16 | uint32(p.RawData[optHeaderOffset+31])<<24)
				p.sizeOfImage = uint32(p.RawData[optHeaderOffset+56]) | uint32(p.RawData[optHeaderOffset+57])<<8 |
					uint32(p.RawData[optHeaderOffset+58])<<16 | uint32(p.RawData[optHeaderOffset+59])<<24
				p.sizeOfHeaders = uint32(p.RawData[optHeaderOffset+60]) | uint32(p.RawData[optHeaderOffset+61])<<8 |
					uint32(p.RawData[optHeaderOffset+62])<<16 | uint32(p.RawData[optHeaderOffset+63])<<24
				p.checksum = uint32(p.RawData[optHeaderOffset+64]) | uint32(p.RawData[optHeaderOffset+65])<<8 |
					uint32(p.RawData[optHeaderOffset+66])<<16 | uint32(p.RawData[optHeaderOffset+67])<<24
				p.subsystem = uint16(p.RawData[optHeaderOffset+68]) | uint16(p.RawData[optHeaderOffset+69])<<8
				p.dllCharacteristics = uint16(p.RawData[optHeaderOffset+70]) | uint16(p.RawData[optHeaderOffset+71])<<8
			}
		} else if magic == 0x20b { // PE32+
			if optHeaderOffset+112 <= len(p.RawData) {
				p.entryPoint = uint32(p.RawData[optHeaderOffset+16]) | uint32(p.RawData[optHeaderOffset+17])<<8 |
					uint32(p.RawData[optHeaderOffset+18])<<16 | uint32(p.RawData[optHeaderOffset+19])<<24
				p.imageBase = uint64(p.RawData[optHeaderOffset+24]) | uint64(p.RawData[optHeaderOffset+25])<<8 |
					uint64(p.RawData[optHeaderOffset+26])<<16 | uint64(p.RawData[optHeaderOffset+27])<<24 |
					uint64(p.RawData[optHeaderOffset+28])<<32 | uint64(p.RawData[optHeaderOffset+29])<<40 |
					uint64(p.RawData[optHeaderOffset+30])<<48 | uint64(p.RawData[optHeaderOffset+31])<<56
				p.sizeOfImage = uint32(p.RawData[optHeaderOffset+56]) | uint32(p.RawData[optHeaderOffset+57])<<8 |
					uint32(p.RawData[optHeaderOffset+58])<<16 | uint32(p.RawData[optHeaderOffset+59])<<24
				p.sizeOfHeaders = uint32(p.RawData[optHeaderOffset+60]) | uint32(p.RawData[optHeaderOffset+61])<<8 |
					uint32(p.RawData[optHeaderOffset+62])<<16 | uint32(p.RawData[optHeaderOffset+63])<<24
				p.checksum = uint32(p.RawData[optHeaderOffset+64]) | uint32(p.RawData[optHeaderOffset+65])<<8 |
					uint32(p.RawData[optHeaderOffset+66])<<16 | uint32(p.RawData[optHeaderOffset+67])<<24
				p.subsystem = uint16(p.RawData[optHeaderOffset+68]) | uint16(p.RawData[optHeaderOffset+69])<<8
				p.dllCharacteristics = uint16(p.RawData[optHeaderOffset+70]) | uint16(p.RawData[optHeaderOffset+71])<<8
			}
		}
	}
	// Set basic machine info
	switch machine {
	case 0x014c:
		p.Machine = "i386"
	case 0x8664:
		p.Machine = "amd64"
	case 0x01c0:
		p.Machine = "arm"
	case 0xaa64:
		p.Machine = "arm64"
	default:
		p.Machine = fmt.Sprintf("unknown(0x%x)", machine)
	}

	// Convert timestamp if valid
	if timestamp > 0 {
		p.TimeDateStamp = time.Unix(int64(timestamp), 0).UTC().Format("2006-01-02 15:04:05 MST")
	} else {
		p.TimeDateStamp = "Not set"
	}

	// Headers extracted successfully (quiet mode)
	return nil
}

// isFileStripped checks if the PE file has been previously stripped or corrupted
// Returns true if the file shows signs of being modified/stripped
func (p *PEFile) isFileStripped() bool {
	indicators := 0

	// Check for corrupted/unusual section names
	for _, section := range p.Sections {
		if strings.HasPrefix(section.Name, "<") {
			indicators++
		}
		// Check for completely zeroed sections (common after stripping)
		if section.Size > 0 && section.Offset > 0 {
			data, err := p.ReadBytes(section.Offset, int(section.Size))
			if err == nil && isAllZeros(data) {
				indicators++
			}
		}
	}

	// Check for missing Rich Header (often stripped)
	if p.PE != nil && p.PE.OptionalHeader != nil {
		// Rich Header is usually present in unstripped MSVC compiled files
		richHeaderResult := p.hasRichHeader()
		if !richHeaderResult {
			indicators++
		}
	}

	// Check for missing debug sections
	hasDebugSections := false
	for _, section := range p.Sections {
		if strings.HasPrefix(section.Name, ".debug") ||
			strings.HasPrefix(section.Name, ".zdebug") {
			hasDebugSections = true
			break
		}
	}
	if !hasDebugSections {
		indicators++
	}

	// If we have multiple indicators, the file is likely stripped
	return indicators >= 2
}

// hasRichHeader checks if the file contains a Rich Header
func (p *PEFile) hasRichHeader() bool {
	if len(p.RawData) < 64 {
		return false
	}

	// Get PE header offset
	peOffset := uint32(p.RawData[0x3C]) | uint32(p.RawData[0x3D])<<8 |
		uint32(p.RawData[0x3E])<<16 | uint32(p.RawData[0x3F])<<24

	if peOffset >= uint32(len(p.RawData)) {
		return false
	}

	// Search for Rich Header signature in the stub area
	richSignature := []byte{0x52, 0x69, 0x63, 0x68} // "Rich"
	searchStart := 64
	searchEnd := int(peOffset)

	for i := searchStart; i < searchEnd-3; i++ {
		if bytes.Equal(p.RawData[i:i+4], richSignature) {
			return true
		}
	}

	return false
}

// isAllZeros checks if a byte slice contains only zero bytes
func isAllZeros(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return len(data) > 0
}

// isValidSectionData validates section data for potentially stripped files
func (p *PEFile) isValidSectionData(virtualAddr uint32, virtualSize uint32, rawDataPtr int64, rawDataSize int64) bool {
	// Check for completely empty section (both virtual and raw)
	if virtualAddr == 0 && virtualSize == 0 && rawDataPtr == 0 && rawDataSize == 0 {
		return false // Completely empty section
	}

	// Allow sections with virtual data but no raw data (common in UPX)
	if virtualSize > 0 && rawDataSize == 0 {
		return true // Virtual-only section (e.g., UPX0)
	}

	// Check if raw data pointer is within file bounds (only if raw data exists)
	if rawDataPtr > 0 && rawDataSize > 0 {
		if rawDataPtr >= int64(len(p.RawData)) || rawDataPtr+rawDataSize > int64(len(p.RawData)) {
			return false // Points outside file
		}
	}

	// Virtual address of 0 with non-zero size is suspicious (but allow if rawDataSize > 0)
	if virtualAddr == 0 && virtualSize > 0 && rawDataSize == 0 {
		return false
	}

	// Check for impossibly large sizes
	maxReasonableSize := int64(len(p.RawData)) * 10 // Allow more expansion for virtual sections
	if rawDataSize > maxReasonableSize {
		return false
	}
	// Virtual size can be much larger (especially for UPX)
	if int64(virtualSize) > maxReasonableSize*10 {
		return false
	}

	return true
}

// isUPXSignaturePresent checks if the raw data contains UPX signatures
func isUPXSignaturePresent(rawData []byte) bool {
	// Check for UPX signature in the first few KB
	if len(rawData) > 2048 {
		dataStr := string(rawData[:2048])
		return strings.Contains(dataStr, "UPX!") || strings.Contains(dataStr, "UPX")
	}
	return false
}
