package perw

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"gosstrip/common"
	"strings"
)

// printOverlayAnalysis prints overlay presence, offset, size, and entropy
func (p *PEFile) printOverlayAnalysis() {
	fmt.Println("🗂️  OVERLAY ANALYSIS")
	fmt.Println("═════════════════════")
	if len(p.Sections) == 0 || p.RawData == nil {
		fmt.Println("No overlay analysis possible (no sections or file data)")
		return
	}
	last := p.Sections[len(p.Sections)-1]
	present, offset, size, entropy := OverlayInfo(p.FileSize, int64(last.FileOffset), int64(last.Size), p.RawData)
	if present {
		fmt.Printf("%s Overlay present at 0x%X, size %s, entropy %.2f\n", common.SymbolWarn, offset, common.FormatFileSize(size), entropy)
	} else {
		fmt.Printf("%s No overlay detected\n", common.SymbolCheck)
	}
	fmt.Println()
}

// printExportAnalysis prints exported symbols
func (p *PEFile) printExportAnalysis() {
	fmt.Println("🔍 EXPORT ANALYSIS")
	fmt.Println("══════════════════")
	var exportNames []string
	for _, e := range p.Exports {
		exportNames = append(exportNames, e.Name)
	}
	fmt.Print(FormatExportedSymbols(exportNames))
	fmt.Println()
}

// printSectionAnomalies prints section anomaly analysis
func (p *PEFile) printSectionAnomalies() {
	fmt.Println("🚨 SECTION ANOMALY ANALYSIS")
	fmt.Println("════════════════════════════")
	infos := make([]SectionInfo, len(p.Sections))
	for i, s := range p.Sections {
		infos[i] = SectionInfo{
			Name:         s.Name,
			FileOffset:   int64(s.FileOffset),
			Size:         int64(s.Size),
			IsExecutable: s.IsExecutable,
			IsWritable:   s.IsWritable,
		}
	}
	issues := AnalyzeSectionAnomalies(infos)
	if len(issues) == 0 {
		fmt.Printf("%s No section anomalies detected\n", common.SymbolCheck)
	} else {
		for _, issue := range issues {
			fmt.Println(issue)
		}
	}
	fmt.Println()
}

// Analyze provides comprehensive analysis of the PE file
func (p *PEFile) Analyze() error {
	// Calculate entropy and packing detection for all sections
	p.calculateSectionEntropy()
	p.IsPacked = p.detectPacking()

	// Print comprehensive analysis
	p.printHeader()
	p.printBasicInfo()
	p.printPEHeaders()
	p.printSectionAnalysis()
	p.printImportsAnalysis()
	p.printExportAnalysis()
	p.printOverlayAnalysis()
	PrintSignatureAnalysis(p)
	p.printSectionAnomalies()
	PrintSuspiciousStrings(p)
	p.printVersionInfo()
	p.printSecurityAnalysis()
	p.printSpaceAnalysis()
	p.printRecommendations()
	return nil
}

// printHeader prints a styled report header
func (p *PEFile) printHeader() {
	fmt.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                           PE FILE ANALYSIS REPORT                          ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// printBasicInfo prints basic file information
func (p *PEFile) printBasicInfo() {
	fmt.Println("📁 BASIC FILE INFORMATION")
	fmt.Println("═══════════════════════════")
	fmt.Printf("File Name:       %s\n", p.FileName)
	fmt.Printf("File Size:       %s (%d bytes)\n", common.FormatFileSize(p.FileSize), p.FileSize)
	fmt.Printf("Architecture:    %s\n", map[bool]string{true: "x64 (64-bit)", false: "x86 (32-bit)"}[p.Is64Bit])
	if p.Machine != "" {
		fmt.Printf("Machine Type:    %s\n", p.Machine)
	}
	if p.TimeDateStamp != "" {
		fmt.Printf("Compile Time:    %s\n", p.TimeDateStamp)
	}
	fmt.Println()
}

// printPEHeaders prints PE header information
func (p *PEFile) printPEHeaders() {
	fmt.Println("🏗️  PE HEADER INFORMATION")
	fmt.Println("═══════════════════════════")
	if p.PDB != "" {
		fmt.Printf("Debug Info:      %s\n", p.PDB)
	}
	if p.GUIDAge != "" {
		fmt.Printf("GUID/Age:        %s\n", p.GUIDAge)
	}
	fmt.Printf("Sections:        %d total\n", len(p.Sections))
	fmt.Printf("Packed Status:   %s\n", map[bool]string{true: "❌ Likely PACKED", false: "✅ Not packed"}[p.IsPacked])
	fmt.Printf("Image Base:      0x%X\n", p.ImageBase())
	fmt.Printf("Entry Point:     0x%X\n", p.EntryPoint())
	fmt.Printf("Size of Image:   %d bytes\n", p.SizeOfImage())
	fmt.Printf("Size of Headers: %d bytes\n", p.SizeOfHeaders())
	fmt.Printf("File Type:       EXE\n")
	subsystemName := getSubsystemName(p.Subsystem())
	fmt.Printf("Subsystem:       %d (%s)\n", p.Subsystem(), subsystemName)
	dllChars := decodeDLLCharacteristics(p.DllCharacteristics())
	fmt.Printf("DLL Characteristics: 0x%X (%s)\n", p.DllCharacteristics(), dllChars)
	fmt.Println()
}

// printSectionAnalysis prints detailed section analysis
func (p *PEFile) printSectionAnalysis() {
	fmt.Println("📊 SECTION ANALYSIS")
	fmt.Println("═══════════════════")
	if len(p.Sections) == 0 {
		fmt.Println("❌ No sections found")
		return
	}
	var (
		totalSize          int64
		executableSections int
		writableSections   int
	)
	for _, section := range p.Sections {
		totalSize += int64(section.Size)
		if section.IsExecutable {
			executableSections++
		}
		if section.IsWritable {
			writableSections++
		}
	}
	fmt.Printf("Total Sections:     %d\nExecutable Secs:    %d\nWritable Secs:      %d\nTotal Size:         %s\n\n",
		len(p.Sections), executableSections, writableSections, common.FormatFileSize(totalSize))
	fmt.Println("SECTION TABLE:")
	fmt.Println("┌──────────────────┬─────────────┬─────────────┬─────────────┬─────────────┬──────────┐")
	fmt.Println("│ Name             │ Virtual Addr│ File Offset │ Size        │ Permissions │ Entropy  │")
	fmt.Println("├──────────────────┼─────────────┼─────────────┼─────────────┼─────────────┼──────────┤")
	for _, section := range p.Sections {
		permissions := common.FormatPermissions(section.IsExecutable, section.IsReadable, section.IsWritable)
		entropyColor := common.GetEntropyColor(section.Entropy)
		fmt.Printf("│ %-16s │ 0x%08X  │ 0x%08X  │ %-11s │ %-11s │ %s%.2f%s     │\n",
			common.TruncateString(section.Name, 16),
			section.VirtualAddress,
			section.FileOffset,
			common.FormatFileSize(int64(section.Size)),
			permissions,
			entropyColor,
			section.Entropy,
			"\033[0m")
	}
	fmt.Println("└──────────────────┴─────────────┴─────────────┴─────────────┴─────────────┴──────────┘")
	fmt.Println()
}

// printImportsAnalysis prints import analysis
func (p *PEFile) printImportsAnalysis() {
	fmt.Println("📦 IMPORTS ANALYSIS")
	fmt.Println("═══════════════════")
	if len(p.Imports) == 0 {
		fmt.Println("❌ No imports found")
		return
	}
	fmt.Printf("Total Imported DLLs: %d\n\nIMPORTED LIBRARIES:\n", len(p.Imports))
	for i, imp := range p.Imports {
		fmt.Printf("  %2d. %s\n", i+1, imp.DLL)
	}
	fmt.Println()
}

// printVersionInfo prints version information
func (p *PEFile) printVersionInfo() {
	fmt.Println("📋 VERSION INFORMATION")
	fmt.Println("══════════════════════")
	if len(p.VersionInfo) == 0 {
		fmt.Println("❌ No version information found")
		return
	}
	for key, value := range p.VersionInfo {
		fmt.Printf("%-20s %s\n", key+":", value)
	}
	fmt.Println()
}

// printSecurityAnalysis prints security analysis
func (p *PEFile) printSecurityAnalysis() {
	fmt.Println("🔒 SECURITY ANALYSIS")
	fmt.Println("════════════════════")
	minEntropy, maxEntropy, avgEntropy := p.getEntropyStats()
	fmt.Printf("Entropy Stats:      Min=%.2f, Max=%.2f, Avg=%.2f\n", minEntropy, maxEntropy, avgEntropy)
	if p.IsPacked {
		fmt.Println("Packing Status:     ❌ LIKELY PACKED (High entropy detected)")
		fmt.Println("Security Risk:      ⚠️  MEDIUM (Packed executables can hide malware)")
	} else {
		fmt.Println("Packing Status:     ✅ Not packed")
		fmt.Println("Security Risk:      ✅ LOW (Normal entropy patterns)")
	}
	switch {
	case avgEntropy > 7.5:
		fmt.Println("Entropy Warning:    ❌ Very high entropy (>7.5) - possible encryption/compression")
	case avgEntropy > 6.5:
		fmt.Println("Entropy Warning:    ⚠️  High entropy (>6.5) - investigate further")
	default:
		fmt.Println("Entropy Warning:    ✅ Normal entropy levels")
	}
	fmt.Println()
}

// printSpaceAnalysis prints space utilization analysis
func (p *PEFile) printSpaceAnalysis() {
	fmt.Println("💾 SPACE ANALYSIS")
	fmt.Println("═════════════════")
	var totalSectionSize int64
	for _, section := range p.Sections {
		totalSectionSize += int64(section.Size)
	}
	overhead := p.FileSize - totalSectionSize
	efficiency := float64(totalSectionSize) / float64(p.FileSize) * 100
	fmt.Printf("Total Section Size: %s\nFile Overhead:      %s\nFile Efficiency:    %.1f%%\n",
		common.FormatFileSize(totalSectionSize),
		common.FormatFileSize(overhead),
		efficiency)
	switch {
	case efficiency < 80:
		fmt.Println("Efficiency Status:  ❌ LOW - File has significant overhead")
	case efficiency < 90:
		fmt.Println("Efficiency Status:  ⚠️  MEDIUM - Some optimization possible")
	default:
		fmt.Println("Efficiency Status:  ✅ HIGH - Well optimized")
	}
	fmt.Println()
}

// printRecommendations prints optimization recommendations
func (p *PEFile) printRecommendations() {
	fmt.Println("💡 OPTIMIZATION RECOMMENDATIONS")
	fmt.Println("═══════════════════════════════")
	var recommendations []string
	var totalSectionSize int64
	for _, section := range p.Sections {
		totalSectionSize += int64(section.Size)
	}
	efficiency := float64(totalSectionSize) / float64(p.FileSize) * 100
	if efficiency < 90 {
		recommendations = append(recommendations, "• Use -s -c flags to strip and compact sections")
	}
	if p.IsPacked {
		recommendations = append(recommendations, "• File appears packed - unpacking may be required first")
	} else {
		recommendations = append(recommendations, "• File is not packed - safe to apply obfuscation (-o flag)")
	}
	for _, section := range p.Sections {
		if section.Name == ".debug" || section.Name == ".pdata" || section.Name == ".xdata" {
			recommendations = append(recommendations, "• Debug sections detected - stripping will reduce size")
			break
		}
	}
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "• File appears well optimized - minimal gains expected")
	}
	for _, rec := range recommendations {
		fmt.Println(rec)
	}
	fmt.Println()
}

// getEntropyStats returns min, max, and average entropy for sections
func (p *PEFile) getEntropyStats() (min, max, avg float64) {
	if len(p.Sections) == 0 {
		return 0, 0, 0
	}
	min, max, sum := p.Sections[0].Entropy, p.Sections[0].Entropy, 0.0
	for _, section := range p.Sections {
		if section.Entropy < min {
			min = section.Entropy
		}
		if section.Entropy > max {
			max = section.Entropy
		}
		sum += section.Entropy
	}
	avg = sum / float64(len(p.Sections))
	return
}

// calculateSectionEntropy calculates entropy for all sections
func (p *PEFile) calculateSectionEntropy() {
	for i, section := range p.Sections {
		if section.Size > 0 && uint32(section.Offset)+section.Size <= uint32(len(p.RawData)) {
			p.Sections[i].Entropy = CalculateEntropy(p.RawData[section.Offset : section.Offset+section.Size])
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

// PE utility methods for richer analysis
// (functions removed because already present in compat.go)

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
	for i, dir := range p.Directories() {
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
	var firstSectionOffset uint32 = 0x7FFFFFFF
	for _, section := range p.Sections {
		if section.Offset < firstSectionOffset {
			firstSectionOffset = section.Offset
		}
	}

	availableSpace := int64(firstSectionOffset) - sectionHeaderTableEnd

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
	fmt.Printf("Entry point: 0x%08X\n", p.EntryPoint())
	fmt.Printf("Image base: 0x%016X\n", p.ImageBase())
	fmt.Printf("Size of image: 0x%08X (%d bytes)\n", p.SizeOfImage(), p.SizeOfImage())
	fmt.Printf("Size of headers: 0x%08X (%d bytes)\n", p.SizeOfHeaders(), p.SizeOfHeaders())

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
	var firstSectionOffset uint32 = 0x7FFFFFFF
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
	availableSpace := int64(firstSectionOffset) - sectionHeaderTableEnd

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
	if p.SignatureSize() > 0 {
		fmt.Printf("✓ Digital signature present (%d bytes)\n", p.SignatureSize())
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

func getSubsystemName(subsystem uint16) string {
	switch subsystem {
	case 2:
		return "Windows GUI"
	case 3:
		return "Windows Console"
	default:
		return "Unknown"
	}
}

func decodeDLLCharacteristics(flags uint16) string {
	var out []string
	if flags&0x40 != 0 {
		out = append(out, "DYNAMIC_BASE")
	}
	if flags&0x100 != 0 {
		out = append(out, "NX_COMPAT")
	}
	if flags&0x8000 != 0 {
		out = append(out, "TERMINAL_SERVER_AWARE")
	}
	if len(out) == 0 {
		return "None"
	}
	return strings.Join(out, ", ")
}
