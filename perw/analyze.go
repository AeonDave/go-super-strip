package perw

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"math"
)

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
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// Analyze provides comprehensive analysis of the PE file
func (p *PEFile) Analyze() error {
	// Calculate entropy and packing detection for all sections
	p.calculateSectionEntropy()
	p.IsPacked = p.detectPacking()

	fmt.Printf("=== PE File Analysis: %s ===\n", p.FileName)

	// Basic file information
	fmt.Printf("File Format: PE (%s-bit)\n", func() string {
		if p.Is64Bit {
			return "64"
		}
		return "32"
	}())
	fmt.Printf("File Size: %d bytes (%.2f MB)\n", p.FileSize, float64(p.FileSize)/(1024*1024))
	fmt.Printf("Image Base: 0x%X\n", p.ImageBase)
	fmt.Printf("Entry Point: 0x%X\n", p.EntryPoint)
	fmt.Printf("Size of Image: %d bytes\n", p.SizeOfImage)
	fmt.Printf("Size of Headers: %d bytes\n", p.SizeOfHeaders)

	// File type and characteristics
	fileType := p.GetFileType()
	fmt.Printf("File Type: %s\n", fileType)

	// Decode subsystem
	subsystemName := p.getSubsystemName()
	fmt.Printf("Subsystem: %d (%s)\n", p.Subsystem, subsystemName)

	// Decode DLL characteristics
	dllChars := p.decodeDLLCharacteristics()
	fmt.Printf("DLL Characteristics: 0x%X (%s)\n", p.DllCharacteristics, dllChars)

	// Security features
	fmt.Printf("Checksum: 0x%X", p.Checksum)
	if p.Checksum == 0 {
		fmt.Printf(" (not set)")
	}
	fmt.Println()

	if p.HasOverlay {
		fmt.Printf("Overlay: Present (offset: 0x%X, size: %d bytes)\n", p.OverlayOffset, p.OverlaySize)
	} else {
		fmt.Printf("Overlay: Not present\n")
	}

	if p.SignatureOffset > 0 {
		fmt.Printf("Digital Signature: Present (offset: 0x%X, size: %d bytes)\n", p.SignatureOffset, p.SignatureSize)
	} else {
		fmt.Printf("Digital Signature: Not present\n")
	}

	// Packing analysis
	fmt.Printf("Likely Packed: %t", p.IsPacked)
	if p.IsPacked {
		fmt.Printf(" (high entropy in executable sections)")
	}
	fmt.Println()

	// Sections analysis
	fmt.Printf("\n=== Section Analysis ===\n")
	fmt.Printf("Number of sections: %d\n", len(p.Sections))

	totalSectionSize := int64(0)
	maxEntropy := 0.0
	minEntropy := 8.0
	avgEntropy := 0.0

	for i, section := range p.Sections {
		fmt.Printf("Section %d: %s\n", i+1, section.Name)
		fmt.Printf("  Virtual Address: 0x%08X\n", section.VirtualAddress)
		fmt.Printf("  Virtual Size: %d bytes\n", section.VirtualSize)
		fmt.Printf("  File Offset: 0x%08X\n", section.Offset)
		fmt.Printf("  File Size: %d bytes\n", section.Size)
		fmt.Printf("  Flags: 0x%08X", section.Flags)

		// Decode section flags
		flags := p.decodeSectionFlags(section.Flags)
		if len(flags) > 0 {
			fmt.Printf(" (%s)", flags)
		}
		fmt.Println()

		fmt.Printf("  Entropy: %.2f", section.Entropy)
		if section.Entropy > 7.5 {
			fmt.Printf(" (HIGH - possibly packed/encrypted)")
		} else if section.Entropy < 1.0 {
			fmt.Printf(" (LOW - mostly zeros/repeated data)")
		}
		fmt.Println()

		// Update entropy statistics
		if section.Entropy > maxEntropy {
			maxEntropy = section.Entropy
		}
		if section.Entropy < minEntropy {
			minEntropy = section.Entropy
		}
		avgEntropy += section.Entropy

		fmt.Printf("  MD5: %s\n", section.MD5Hash)
		fmt.Printf("  SHA1: %s\n", section.SHA1Hash)
		fmt.Printf("  SHA256: %s\n", section.SHA256Hash)
		fmt.Println()

		totalSectionSize += section.Size
	}

	if len(p.Sections) > 0 {
		avgEntropy /= float64(len(p.Sections))
		fmt.Printf("Entropy Statistics: Min=%.2f, Max=%.2f, Avg=%.2f\n", minEntropy, maxEntropy, avgEntropy)
	}

	// Space analysis
	fmt.Printf("\n=== Space Analysis ===\n")
	fmt.Printf("Total section size: %d bytes\n", totalSectionSize)
	fmt.Printf("File overhead: %d bytes\n", p.FileSize-totalSectionSize)

	// Calculate file structure efficiency
	efficiency := float64(totalSectionSize) / float64(p.FileSize) * 100
	fmt.Printf("File efficiency: %.1f%% (section data vs total file size)\n", efficiency)

	// Check for space between sections and headers for new sections
	if err := p.analyzeSpaceForNewSections(); err != nil {
		fmt.Printf("Warning: Could not analyze space for new sections: %v\n", err)
	}

	// Directory entries analysis
	p.analyzeDirectoryEntries() // Import analysis
	if len(p.Imports) > 0 {
		fmt.Printf("\n=== Import Analysis ===\n")
		fmt.Printf("Imported libraries: %d\n", len(p.Imports))
		totalFunctions := 0
		for _, imp := range p.Imports {
			fmt.Printf("  %s (%d functions)\n", imp.LibraryName, len(imp.Functions))
			totalFunctions += len(imp.Functions)
		}
		fmt.Printf("Total imported functions: %d\n", totalFunctions)

		// Show most commonly imported functions
		fmt.Println("Most imported functions:")
		funcCount := make(map[string]int)
		for _, imp := range p.Imports {
			for _, fn := range imp.Functions {
				funcCount[fn]++
			}
		}
		// Print top 5 most common functions
		count := 0
		for fn, cnt := range funcCount {
			if cnt > 1 && count < 5 {
				fmt.Printf("  %s (imported %d times)\n", fn, cnt)
				count++
			}
		}
	}

	// Export analysis
	if len(p.Exports) > 0 {
		fmt.Printf("\n=== Export Analysis ===\n")
		fmt.Printf("Exported functions: %d\n", len(p.Exports))
		for i, exp := range p.Exports {
			if i < 10 { // Show only first 10 to avoid clutter
				fmt.Printf("  %s (ordinal: %d, RVA: 0x%08X)\n", exp.Name, exp.Ordinal, exp.RVA)
			}
		}
		if len(p.Exports) > 10 {
			fmt.Printf("  ... and %d more exports\n", len(p.Exports)-10)
		}
	}

	return nil
}

// calculateSectionEntropy calculates entropy for all sections
func (p *PEFile) calculateSectionEntropy() {
	for i, section := range p.Sections {
		if section.Size > 0 && section.Offset+section.Size <= int64(len(p.RawData)) {
			sectionData := p.RawData[section.Offset : section.Offset+section.Size]
			p.Sections[i].Entropy = calculateEntropy(sectionData)
		}
	}
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

// getSubsystemName returns human-readable subsystem name
func (p *PEFile) getSubsystemName() string {
	switch p.Subsystem {
	case 1:
		return "Native"
	case 2:
		return "Windows GUI"
	case 3:
		return "Windows Console"
	case 5:
		return "OS/2 Console"
	case 7:
		return "POSIX Console"
	case 8:
		return "Native Win9x Driver"
	case 9:
		return "Windows CE GUI"
	case 10:
		return "EFI Application"
	case 11:
		return "EFI Boot Service Driver"
	case 12:
		return "EFI Runtime Driver"
	case 13:
		return "EFI ROM"
	case 14:
		return "Xbox"
	case 16:
		return "Windows Boot Application"
	default:
		return "Unknown"
	}
}

// decodeDLLCharacteristics returns human-readable DLL characteristics
func (p *PEFile) decodeDLLCharacteristics() string {
	var characteristics []string

	if p.DllCharacteristics&0x0001 != 0 {
		characteristics = append(characteristics, "PROCESS_INIT")
	}
	if p.DllCharacteristics&0x0002 != 0 {
		characteristics = append(characteristics, "PROCESS_TERM")
	}
	if p.DllCharacteristics&0x0004 != 0 {
		characteristics = append(characteristics, "THREAD_INIT")
	}
	if p.DllCharacteristics&0x0008 != 0 {
		characteristics = append(characteristics, "THREAD_TERM")
	}
	if p.DllCharacteristics&0x0040 != 0 {
		characteristics = append(characteristics, "DYNAMIC_BASE")
	}
	if p.DllCharacteristics&0x0080 != 0 {
		characteristics = append(characteristics, "FORCE_INTEGRITY")
	}
	if p.DllCharacteristics&0x0100 != 0 {
		characteristics = append(characteristics, "NX_COMPAT")
	}
	if p.DllCharacteristics&0x0200 != 0 {
		characteristics = append(characteristics, "NO_ISOLATION")
	}
	if p.DllCharacteristics&0x0400 != 0 {
		characteristics = append(characteristics, "NO_SEH")
	}
	if p.DllCharacteristics&0x0800 != 0 {
		characteristics = append(characteristics, "NO_BIND")
	}
	if p.DllCharacteristics&0x1000 != 0 {
		characteristics = append(characteristics, "APPCONTAINER")
	}
	if p.DllCharacteristics&0x2000 != 0 {
		characteristics = append(characteristics, "WDM_DRIVER")
	}
	if p.DllCharacteristics&0x4000 != 0 {
		characteristics = append(characteristics, "GUARD_CF")
	}
	if p.DllCharacteristics&0x8000 != 0 {
		characteristics = append(characteristics, "TERMINAL_SERVER_AWARE")
	}

	if len(characteristics) == 0 {
		return "None"
	}

	result := characteristics[0]
	for i := 1; i < len(characteristics); i++ {
		result += ", " + characteristics[i]
	}
	return result
}

// decodeSectionFlags returns human-readable section flags
func (p *PEFile) decodeSectionFlags(flags uint32) string {
	var flagStrs []string

	if flags&pe.IMAGE_SCN_CNT_CODE != 0 {
		flagStrs = append(flagStrs, "CODE")
	}
	if flags&pe.IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
		flagStrs = append(flagStrs, "INITIALIZED_DATA")
	}
	if flags&pe.IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
		flagStrs = append(flagStrs, "UNINITIALIZED_DATA")
	}
	if flags&pe.IMAGE_SCN_MEM_EXECUTE != 0 {
		flagStrs = append(flagStrs, "EXECUTABLE")
	}
	if flags&pe.IMAGE_SCN_MEM_READ != 0 {
		flagStrs = append(flagStrs, "READABLE")
	}
	if flags&pe.IMAGE_SCN_MEM_WRITE != 0 {
		flagStrs = append(flagStrs, "WRITABLE")
	}
	if flags&0x10000000 != 0 { // IMAGE_SCN_MEM_SHARED
		flagStrs = append(flagStrs, "SHARED")
	}
	if flags&0x02000000 != 0 { // IMAGE_SCN_MEM_DISCARDABLE
		flagStrs = append(flagStrs, "DISCARDABLE")
	}

	if len(flagStrs) == 0 {
		return "None"
	}

	result := flagStrs[0]
	for i := 1; i < len(flagStrs); i++ {
		result += ", " + flagStrs[i]
	}
	return result
}

// analyzeDirectoryEntries provides detailed directory analysis
func (p *PEFile) analyzeDirectoryEntries() {
	fmt.Printf("\n=== Directory Entries ===\n")
	directoryNames := []string{
		"Export Table", "Import Table", "Resource Table", "Exception Table",
		"Certificate Table", "Base Relocation Table", "Debug", "Architecture",
		"Global Ptr", "TLS Table", "Load Config Table", "Bound Import",
		"IAT", "Delay Import Descriptor", "COM+ Runtime Header", "Reserved",
	}

	entriesFound := 0
	for i, dir := range p.Directories {
		if dir.RVA != 0 || dir.Size != 0 {
			name := "Unknown"
			if i < len(directoryNames) {
				name = directoryNames[i]
			}
			fmt.Printf("  %s: RVA=0x%08X, Size=%d bytes\n", name, dir.RVA, dir.Size)
			entriesFound++
		}
	}

	if entriesFound == 0 {
		fmt.Printf("  No directory entries found (may need manual parsing)\n")
	}
}

// analyzeSpaceForNewSections analyzes available space for adding new sections
func (p *PEFile) analyzeSpaceForNewSections() error {
	if len(p.RawData) < 100 {
		return fmt.Errorf("PE file too small for analysis")
	}

	peHeaderOffset := int64(p.RawData[60]) | int64(p.RawData[61])<<8 | int64(p.RawData[62])<<16 | int64(p.RawData[63])<<24

	// Read COFF header to get optional header size
	optionalHeaderSize := uint16(p.RawData[peHeaderOffset+20]) | uint16(p.RawData[peHeaderOffset+21])<<8
	sectionHeaderOffset := peHeaderOffset + 24 + int64(optionalHeaderSize)

	// Calculate where section headers end
	sectionHeaderTableSize := int64(len(p.Sections)) * 40
	sectionHeaderTableEnd := sectionHeaderOffset + sectionHeaderTableSize

	// Find first section offset
	var firstSectionOffset int64 = 0x7FFFFFFF
	for _, section := range p.Sections {
		if section.Offset < firstSectionOffset {
			firstSectionOffset = section.Offset
		}
	}

	availableSpace := firstSectionOffset - sectionHeaderTableEnd

	fmt.Printf("\n=== Section Header Space Analysis ===\n")
	fmt.Printf("Section header table offset: 0x%X\n", sectionHeaderOffset)
	fmt.Printf("Section header table ends at: 0x%X\n", sectionHeaderTableEnd)
	fmt.Printf("First section offset: 0x%X\n", firstSectionOffset)
	fmt.Printf("Available space for new headers: %d bytes\n", availableSpace)
	fmt.Printf("Can fit %d more section headers\n", availableSpace/40)

	if availableSpace >= 40 {
		fmt.Printf("✓ There is space for at least one more section header\n")
	} else {
		fmt.Printf("✗ No space for additional section headers\n")
	}

	return nil
}

// AnalyzePE provides detailed analysis of PE file structure
func (p *PEFile) AnalyzePE() error {
	fmt.Printf("=== PE File Analysis: %s ===\n", p.FileName)
	fmt.Printf("File size: %d bytes (%.2f MB)\n", p.FileSize, float64(p.FileSize)/(1024*1024))
	fmt.Printf("Architecture: ")
	if p.Is64Bit {
		fmt.Println("64-bit")
	} else {
		fmt.Println("32-bit")
	}
	fmt.Printf("Entry point: 0x%08X\n", p.EntryPoint)
	fmt.Printf("Image base: 0x%016X\n", p.ImageBase)
	fmt.Printf("Size of image: 0x%08X (%d bytes)\n", p.SizeOfImage, p.SizeOfImage)
	fmt.Printf("Size of headers: 0x%08X (%d bytes)\n", p.SizeOfHeaders, p.SizeOfHeaders)

	// PE Header information
	peHeaderOffset := int64(binary.LittleEndian.Uint32(p.RawData[60:64]))
	optionalHeaderSize := binary.LittleEndian.Uint16(p.RawData[peHeaderOffset+20 : peHeaderOffset+22])
	sectionHeaderOffset := peHeaderOffset + 4 + 20 + int64(optionalHeaderSize)

	fmt.Printf("\n=== Headers ===\n")
	fmt.Printf("PE header offset: 0x%X\n", peHeaderOffset)
	fmt.Printf("Optional header size: %d bytes\n", optionalHeaderSize)
	fmt.Printf("Section header table offset: 0x%X\n", sectionHeaderOffset)

	// Section analysis
	fmt.Printf("\n=== Sections (%d total) ===\n", len(p.Sections))
	var firstSectionOffset int64 = 0x7FFFFFFF
	for i, section := range p.Sections {
		fmt.Printf("[%2d] %-15s Offset: 0x%08X  Size: %8d  VAddr: 0x%08X  VSize: %8d  Flags: 0x%08X\n",
			i, section.Name, section.Offset, section.Size, section.VirtualAddress, section.VirtualSize, section.Flags)

		// Show entropy and hashes for non-empty sections
		if section.Size > 0 {
			fmt.Printf("     Entropy: %6.4f  MD5: %s\n", section.Entropy, section.MD5Hash)
			fmt.Printf("     SHA1: %s\n", section.SHA1Hash)
			fmt.Printf("     SHA256: %s\n", section.SHA256Hash)
		}

		if section.Offset < firstSectionOffset {
			firstSectionOffset = section.Offset
		}
	}

	// Calculate space for additional sections
	sectionHeaderTableSize := int64(len(p.Sections)) * 40
	sectionHeaderTableEnd := sectionHeaderOffset + sectionHeaderTableSize
	availableSpace := firstSectionOffset - sectionHeaderTableEnd

	fmt.Printf("\n=== Section Header Analysis ===\n")
	fmt.Printf("Section header table size: %d bytes\n", sectionHeaderTableSize)
	fmt.Printf("Section header table ends at: 0x%X\n", sectionHeaderTableEnd)
	fmt.Printf("First section starts at: 0x%X\n", firstSectionOffset)
	fmt.Printf("Available space for new headers: %d bytes\n", availableSpace)
	fmt.Printf("Can fit %d more section headers\n", availableSpace/40)

	if availableSpace >= 40 {
		fmt.Println("✓ Space available for additional section headers")
	} else {
		fmt.Println("✗ No space for additional section headers")
	}

	// Check for overlay
	if p.HasOverlay {
		fmt.Printf("\n=== Overlay Detected ===\n")
		fmt.Printf("Overlay offset: 0x%X\n", p.OverlayOffset)
		fmt.Printf("Overlay size: %d bytes\n", p.OverlaySize)
	}

	// Import/Export analysis
	if len(p.Imports) > 0 {
		fmt.Printf("\n=== Imports (%d libraries) ===\n", len(p.Imports))
		for _, imp := range p.Imports {
			fmt.Printf("%-30s (%d functions)\n", imp.LibraryName, len(imp.Functions))
		}
	}

	if len(p.Exports) > 0 {
		fmt.Printf("\n=== Exports (%d functions) ===\n", len(p.Exports))
		for _, exp := range p.Exports {
			fmt.Printf("%-30s Ordinal: %d  RVA: 0x%08X\n", exp.Name, exp.Ordinal, exp.RVA)
		}
	}

	// Security features
	fmt.Printf("\n=== Security Features ===\n")
	if p.SignatureSize > 0 {
		fmt.Printf("✓ Digital signature present (%d bytes)\n", p.SignatureSize)
	} else {
		fmt.Println("✗ No digital signature")
	}

	if p.IsPacked {
		fmt.Println("⚠ File appears to be packed/compressed")
	} else {
		fmt.Println("✓ File appears unpacked")
	}

	return nil
}
