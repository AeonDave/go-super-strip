package elfrw

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"math"
)

// Analyze provides detailed analysis of the ELF file
func (e *ELFFile) Analyze() error {
	// Calculate entropy for all sections
	e.calculateSectionEntropy()

	fmt.Printf("=== ELF File Analysis: %s ===\n", e.FileName)

	// Basic file information
	fmt.Printf("File Format: ELF (%s-bit)\n", func() string {
		if e.Is64Bit {
			return "64"
		}
		return "32"
	}())

	fileSize := int64(len(e.RawData))
	fmt.Printf("File Size: %d bytes (%.2f MB)\n", fileSize, float64(fileSize)/(1024*1024))

	// ELF header information
	fileType := e.GetFileType()
	fmt.Printf("File Type: %s\n", getFileTypeString(fileType))
	fmt.Printf("Architecture: %s\n", getArchitectureString())
	fmt.Printf("Endianness: %s\n", func() string {
		if e.IsLittleEndian() {
			return "Little Endian"
		}
		return "Big Endian"
	}())

	// Entry point and other important addresses
	if len(e.RawData) >= 24 {
		// Parse entry point from ELF header
		var entryPoint uint64
		if e.Is64Bit {
			if len(e.RawData) >= 32 {
				if e.IsLittleEndian() {
					entryPoint = uint64(e.RawData[24]) | uint64(e.RawData[25])<<8 | uint64(e.RawData[26])<<16 | uint64(e.RawData[27])<<24 |
						uint64(e.RawData[28])<<32 | uint64(e.RawData[29])<<40 | uint64(e.RawData[30])<<48 | uint64(e.RawData[31])<<56
				}
			}
		} else {
			if len(e.RawData) >= 28 {
				if e.IsLittleEndian() {
					entryPoint = uint64(e.RawData[24]) | uint64(e.RawData[25])<<8 | uint64(e.RawData[26])<<16 | uint64(e.RawData[27])<<24
				}
			}
		}
		fmt.Printf("Entry Point: 0x%X\n", entryPoint)
	}

	// Sections analysis
	fmt.Printf("\n=== Section Analysis ===\n")
	fmt.Printf("Number of sections: %d\n", len(e.Sections))

	totalSectionSize := uint64(0)
	maxEntropy := 0.0
	minEntropy := 8.0
	avgEntropy := 0.0
	packedSections := 0

	for i, section := range e.Sections {
		fmt.Printf("Section %d: %s\n", i+1, section.Name)
		fmt.Printf("  Type: %s (0x%X)\n", getSectionTypeString(section.Type), section.Type)
		fmt.Printf("  Flags: %s (0x%X)\n", getSectionFlagsString(section.Flags), section.Flags)
		fmt.Printf("  Offset: 0x%08X\n", section.Offset)
		fmt.Printf("  Size: %d bytes\n", section.Size)

		// Calculate and display entropy
		entropy := e.getSectionEntropy(i)
		fmt.Printf("  Entropy: %.2f", entropy)
		if entropy > 7.5 {
			fmt.Printf(" (HIGH - possibly packed/encrypted)")
			packedSections++
		} else if entropy < 1.0 {
			fmt.Printf(" (LOW - mostly zeros/repeated data)")
		}
		fmt.Println()

		// Update entropy statistics
		if entropy > maxEntropy {
			maxEntropy = entropy
		}
		if entropy < minEntropy {
			minEntropy = entropy
		}
		avgEntropy += entropy

		// Calculate and display hashes for non-empty sections
		if section.Size > 0 && section.Offset+section.Size <= uint64(len(e.RawData)) {
			sectionData := e.RawData[section.Offset : section.Offset+section.Size]

			md5Hash := md5.Sum(sectionData)
			sha1Hash := sha1.Sum(sectionData)
			sha256Hash := sha256.Sum256(sectionData)

			fmt.Printf("  MD5: %x\n", md5Hash)
			fmt.Printf("  SHA1: %x\n", sha1Hash)
			fmt.Printf("  SHA256: %x\n", sha256Hash)
		}

		fmt.Println()
		totalSectionSize += section.Size
	}

	if len(e.Sections) > 0 {
		avgEntropy /= float64(len(e.Sections))
		fmt.Printf("Entropy Statistics: Min=%.2f, Max=%.2f, Avg=%.2f\n", minEntropy, maxEntropy, avgEntropy)

		// Packing analysis
		fmt.Printf("Likely Packed: %t", packedSections > 0)
		if packedSections > 0 {
			fmt.Printf(" (%d sections with high entropy)", packedSections)
		}
		fmt.Println()
	}

	// Segments analysis
	fmt.Printf("=== Segment Analysis ===\n")
	fmt.Printf("Number of segments: %d\n", len(e.Segments))

	for i, segment := range e.Segments {
		fmt.Printf("Segment %d:\n", i)
		fmt.Printf("  Type: %s (0x%X)\n", getSegmentTypeString(segment.Type), segment.Type)
		fmt.Printf("  Flags: %s (0x%X)\n", getSegmentFlagsString(segment.Flags), segment.Flags)
		fmt.Printf("  Offset: 0x%08X\n", segment.Offset)
		fmt.Printf("  Size: %d bytes\n", segment.Size)
		fmt.Printf("  Loadable: %t\n", segment.Loadable)
		fmt.Println()
	}

	// Space analysis
	fmt.Printf("=== Space Analysis ===\n")
	fmt.Printf("Total section size: %d bytes\n", totalSectionSize)
	fmt.Printf("File overhead: %d bytes\n", uint64(fileSize)-totalSectionSize)

	// Check for space for new sections
	if err := e.analyzeSpaceForNewSections(); err != nil {
		fmt.Printf("Warning: Could not analyze space for new sections: %v\n", err)
	}

	return nil
}

// analyzeSpaceForNewSections analyzes available space for adding new sections
func (e *ELFFile) analyzeSpaceForNewSections() error {
	fileSize := int64(len(e.RawData))

	// Find the end of the last section
	var lastSectionEnd uint64
	for _, section := range e.Sections {
		sectionEnd := section.Offset + section.Size
		if sectionEnd > lastSectionEnd {
			lastSectionEnd = sectionEnd
		}
	}

	availableSpace := uint64(fileSize) - lastSectionEnd

	fmt.Printf("Last section ends at: 0x%X\n", lastSectionEnd)
	fmt.Printf("File ends at: 0x%X\n", fileSize)
	fmt.Printf("Available space at end of file: %d bytes\n", availableSpace)

	if availableSpace > 0 {
		fmt.Printf("✓ There is space for additional section data\n")
	} else {
		fmt.Printf("✗ No space available at end of file\n")
	}

	return nil
}

// calculateSectionEntropy calculates entropy for all sections
func (e *ELFFile) calculateSectionEntropy() {
	// This is called during analysis, entropy is calculated on-demand
}

// getSectionEntropy returns the entropy for a specific section
func (e *ELFFile) getSectionEntropy(sectionIndex int) float64 {
	if sectionIndex >= len(e.Sections) {
		return 0.0
	}

	section := e.Sections[sectionIndex]
	if section.Size == 0 || section.Offset+section.Size > uint64(len(e.RawData)) {
		return 0.0
	}

	sectionData := e.RawData[section.Offset : section.Offset+section.Size]
	return calculateELFEntropy(sectionData)
}

// calculateELFEntropy computes Shannon entropy of data
func calculateELFEntropy(data []byte) float64 {
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
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// isGoBinary detects if this is a Go compiled binary
func (e *ELFFile) isGoBinary() bool {
	// Check for Go-specific sections
	goSections := []string{
		".go.buildinfo",
		".gopclntab",
		".gosymtab",
		".go.fipsinfo",
		".note.go.buildid",
	}

	foundGoSections := 0
	for _, section := range e.Sections {
		for _, goSection := range goSections {
			if section.Name == goSection {
				foundGoSections++
				break
			}
		}
	}
	// If we find 2 or more Go-specific sections, it's likely a Go binary
	return foundGoSections >= 2
}

// Helper functions for string representations
func getFileTypeString(fileType uint16) string {
	switch fileType {
	case 1:
		return "Relocatable file"
	case 2:
		return "Executable file"
	case 3:
		return "Shared object file"
	case 4:
		return "Core file"
	default:
		return fmt.Sprintf("Unknown (%d)", fileType)
	}
}

func getArchitectureString() string {
	// This would need to be read from the ELF header
	// For now, return a placeholder
	return "x86_64"
}

func getSectionTypeString(sectionType uint32) string {
	switch sectionType {
	case 0:
		return "SHT_NULL"
	case 1:
		return "SHT_PROGBITS"
	case 2:
		return "SHT_SYMTAB"
	case 3:
		return "SHT_STRTAB"
	case 4:
		return "SHT_RELA"
	case 5:
		return "SHT_HASH"
	case 6:
		return "SHT_DYNAMIC"
	case 7:
		return "SHT_NOTE"
	case 8:
		return "SHT_NOBITS"
	case 9:
		return "SHT_REL"
	case 11:
		return "SHT_DYNSYM"
	default:
		return fmt.Sprintf("Unknown (0x%X)", sectionType)
	}
}

func getSectionFlagsString(flags uint64) string {
	var flagStrs []string

	if flags&0x1 != 0 {
		flagStrs = append(flagStrs, "WRITE")
	}
	if flags&0x2 != 0 {
		flagStrs = append(flagStrs, "ALLOC")
	}
	if flags&0x4 != 0 {
		flagStrs = append(flagStrs, "EXECINSTR")
	}
	if flags&0x10 != 0 {
		flagStrs = append(flagStrs, "MERGE")
	}
	if flags&0x20 != 0 {
		flagStrs = append(flagStrs, "STRINGS")
	}

	if len(flagStrs) == 0 {
		return "None"
	}

	result := flagStrs[0]
	for i := 1; i < len(flagStrs); i++ {
		result += " | " + flagStrs[i]
	}
	return result
}

func getSegmentTypeString(segmentType uint32) string {
	switch segmentType {
	case 0:
		return "PT_NULL"
	case 1:
		return "PT_LOAD"
	case 2:
		return "PT_DYNAMIC"
	case 3:
		return "PT_INTERP"
	case 4:
		return "PT_NOTE"
	case 5:
		return "PT_SHLIB"
	case 6:
		return "PT_PHDR"
	case 7:
		return "PT_TLS"
	default:
		return fmt.Sprintf("Unknown (0x%X)", segmentType)
	}
}

func getSegmentFlagsString(flags uint32) string {
	var flagStrs []string

	if flags&0x1 != 0 {
		flagStrs = append(flagStrs, "EXECUTE")
	}
	if flags&0x2 != 0 {
		flagStrs = append(flagStrs, "WRITE")
	}
	if flags&0x4 != 0 {
		flagStrs = append(flagStrs, "READ")
	}

	if len(flagStrs) == 0 {
		return "None"
	}

	result := flagStrs[0]
	for i := 1; i < len(flagStrs); i++ {
		result += " | " + flagStrs[i]
	}
	return result
}
