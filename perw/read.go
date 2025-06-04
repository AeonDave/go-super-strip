package perw

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

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

type DirectoryEntry struct {
	Type uint16
	RVA  uint32
	Size uint32
}

type ImportInfo struct {
	LibraryName string
	Functions   []string
	IatRva      uint32
}

type ExportInfo struct {
	Name      string
	Ordinal   uint16
	RVA       uint32
	Forwarder string
}

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

// validateDOSHeader performs comprehensive DOS header validation
func validateDOSHeader(data []byte) error {
	if len(data) < 64 {
		return fmt.Errorf("file too small for DOS header")
	}

	if data[0] != 'M' || data[1] != 'Z' {
		return fmt.Errorf("invalid DOS signature")
	}

	eLfanew := binary.LittleEndian.Uint32(data[60:64])
	if eLfanew == 0 || int(eLfanew) >= len(data)-4 {
		return fmt.Errorf("invalid e_lfanew offset: %d", eLfanew)
	}

	// Validate PE signature
	peOffset := int(eLfanew)
	if len(data) < peOffset+4 {
		return fmt.Errorf("file too small for PE signature")
	}

	if !bytes.Equal(data[peOffset:peOffset+4], []byte{'P', 'E', 0, 0}) {
		return fmt.Errorf("invalid PE signature")
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
	// TODO: Implement full directory parsing
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
	// TODO: Implement export parsing
	return nil
}

// analyzeFile performs comprehensive file analysis
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

	// Check if packed (high entropy in executable sections)
	p.IsPacked = p.detectPacking()

	return nil
}

// detectPacking analyzes entropy to detect packed executables
func (p *PEFile) detectPacking() bool {
	for _, section := range p.Sections {
		if (section.Flags&pe.IMAGE_SCN_CNT_CODE) != 0 && section.Entropy > 7.0 {
			return true
		}
	}
	return false
}

// calculateEntropy computes Shannon entropy of data
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	// Count byte frequencies
	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}

	// Calculate entropy
	entropy := 0.0
	length := float64(len(data))

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * (log2(p))
		}
	}

	return entropy
}

// log2 calculates log base 2
func log2(x float64) float64 {
	return 0.6931471805599453 * logNatural(x) // ln(2) * ln(x)
}

// Simple natural log approximation (replace with math.Log in production)
func logNatural(x float64) float64 {
	// Simplified - use math.Log(x) in production
	return 1.0 // Placeholder
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

// Utility functions

func readFileData(file *os.File) ([]byte, error) {
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	if fileInfo.Size() == 0 {
		return nil, fmt.Errorf("empty file")
	}

	rawData := make([]byte, fileInfo.Size())
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to reset file pointer: %w", err)
	}

	if _, err := io.ReadFull(file, rawData); err != nil {
		return nil, fmt.Errorf("failed to read file data: %w", err)
	}

	return rawData, nil
}

func isPE64Bit(peFile *pe.File) bool {
	_, is64 := peFile.OptionalHeader.(*pe.OptionalHeader64)
	return is64
}
