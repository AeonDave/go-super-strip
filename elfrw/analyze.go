package elfrw

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"gosstrip/common"
	"strings"
)

func (e *ELFFile) Analyze() error {
	e.calculateSectionEntropy()
	e.IsPacked = e.detectPacking()
	e.printBasicInfo()
	e.printELFHeaders()
	e.printDynamicAnalysis()
	e.printImportsAnalysis()
	e.printExportsAnalysis()
	e.printSectionHeaders()
	e.printSectionAnomalies()
	e.printSymbolAnalysis()
	common.PrintSuspiciousStrings(e.RawData)
	e.printPackingAnalysis()
	return nil
}

func analyzeSectionAnomalies(sections []SectionInfo, fileSize int64) []string {
	var issues []string

	isDebugSection := func(name string) bool {
		debugPrefixes := []string{
			".debug_",
			".zdebug_",
			".gdb_index",
			".note.",
			".comment",
		}
		for _, prefix := range debugPrefixes {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
		return false
	}

	for i, s := range sections {
		// Skip all checks for debug sections
		if isDebugSection(s.Name) {
			continue
		}

		// Check for zero-sized sections
		if s.Size == 0 && i != SHT_NULL {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' has zero size")
		}

		// Check for executable and writable sections (RWX)
		if s.IsExecutable && s.IsWritable {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' is both executable and writable (RWX)")
		}

		// Check for empty or invalid section names
		if i != SHT_NULL && (len(s.Name) == 0 || s.Name == "\x00") {
			issues = append(issues, common.SymbolWarn+" Section with empty or invalid name")
		}

		// Check for overlapping sections
		if i > 0 && s.FileOffset < sections[i-1].FileOffset+sections[i-1].Size {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' overlaps previous section")
		}

		// Check for suspicious section names
		if isSuspiciousSectionNameELF(s.Name) {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' has suspicious/unusual name")
		}

		// Check for abnormally large sections
		if s.Size > 100*1024*1024 { // > 100MB
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' is unusually large ("+formatSizeELF(s.Size)+")")
		}

		// Check for sections with very high entropy
		if s.Entropy > 7.8 && s.Size > 1024 {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' has very high entropy ("+fmt.Sprintf("%.2f", s.Entropy)+") - possible encryption/packing")
		}

		// Check for unusually large sections relative to file size
		if s.Size > fileSize/2 {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' is unusually large relative to file size ("+formatSizeELF(s.Size)+")")
		}

		// Check for negative file offsets
		if s.FileOffset < 0 {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' has invalid file offset")
		}

		// Check for non-aligned file offsets
		if s.FileOffset > 0 && s.FileOffset%0x10 != 0 {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' has non-aligned file offset (0x"+fmt.Sprintf("%X", s.FileOffset)+")")
		}

		// Check for executable sections with unexpected names
		if s.IsExecutable && !isExpectedExecutableSectionELF(s.Name) {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' is executable but has unexpected name")
		}

		// Check for writable sections with unexpected names
		if s.IsWritable && !isExpectedWritableSectionELF(s.Name) {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' is writable but has unexpected name")
		}

		// Check for unusual section order
		if i > 0 && isWrongSectionOrderELF(sections[i-1].Name, s.Name) {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' appears after '"+sections[i-1].Name+"' (unusual order)")
		}

		// Check for large gaps between sections
		if i > 0 {
			prevEnd := sections[i-1].FileOffset + sections[i-1].Size
			gap := s.FileOffset - prevEnd
			if gap > 64*1024 { // Gap > 64KB
				issues = append(issues, common.SymbolWarn+" Large gap ("+formatSizeELF(gap)+") between '"+sections[i-1].Name+"' and '"+s.Name+"'")
			}
		}

		// Check for sections with unusual permissions
		if strings.HasPrefix(s.Name, ".text") && !s.IsExecutable {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' should be executable but isn't")
		}
		if strings.HasPrefix(s.Name, ".data") && !s.IsWritable {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' should be writable but isn't")
		}
		if strings.HasPrefix(s.Name, ".rodata") && s.IsWritable {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' should be read-only but is writable")
		}
	}

	analyzeGlobalSectionAnomaliesELF(sections, &issues)
	return issues
}

func isSuspiciousSectionNameELF(name string) bool {
	nameLower := strings.ToLower(name)
	for _, suspicious := range common.SuspiciousSectionNames {
		if strings.Contains(nameLower, suspicious) {
			return true
		}
	}
	for _, c := range name {
		if c < 32 || c > 126 {
			return true
		}
	}
	return false
}

func isExpectedExecutableSectionELF(name string) bool {
	executableSections := []string{".text", ".init", ".fini", ".plt", ".got"}
	name = strings.ToLower(name)
	for _, expected := range executableSections {
		if strings.HasPrefix(name, strings.ToLower(expected)) {
			return true
		}
	}
	return false
}

func isExpectedWritableSectionELF(name string) bool {
	writableSections := []string{".data", ".bss", ".got", ".dynamic", ".tdata", ".tbss"}
	name = strings.ToLower(name)
	for _, expected := range writableSections {
		if strings.HasPrefix(name, strings.ToLower(expected)) {
			return true
		}
	}
	return false
}

func isWrongSectionOrderELF(prev, current string) bool {
	// In ELF, .text typically comes before .data, which comes before .bss
	if strings.HasPrefix(strings.ToLower(prev), ".data") &&
		strings.HasPrefix(strings.ToLower(current), ".text") {
		return true
	}
	if strings.HasPrefix(strings.ToLower(prev), ".bss") &&
		(strings.HasPrefix(strings.ToLower(current), ".text") ||
			strings.HasPrefix(strings.ToLower(current), ".data")) {
		return true
	}

	return false
}

func analyzeGlobalSectionAnomaliesELF(sections []SectionInfo, issues *[]string) {
	isDebugSection := func(name string) bool {
		debugPrefixes := []string{
			".debug_",
			".zdebug_",
			".gdb_index",
			".note.",
			".comment",
		}
		for _, prefix := range debugPrefixes {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
		return false
	}

	// Filter out debug sections
	var nonDebugSections []SectionInfo
	for _, s := range sections {
		if !isDebugSection(s.Name) {
			nonDebugSections = append(nonDebugSections, s)
		}
	}

	// Check for too few sections
	if len(nonDebugSections) < 3 {
		*issues = append(*issues, common.SymbolWarn+" Very few sections ("+fmt.Sprintf("%d", len(nonDebugSections))+") - possible packing")
	}

	// Check for too many sections
	if len(nonDebugSections) > 30 {
		*issues = append(*issues, common.SymbolWarn+" Unusually many sections ("+fmt.Sprintf("%d", len(nonDebugSections))+")")
	}

	// Check for missing executable sections
	hasExecutable := false
	for _, s := range nonDebugSections {
		if s.IsExecutable {
			hasExecutable = true
			break
		}
	}
	if !hasExecutable {
		*issues = append(*issues, common.SymbolWarn+" No executable sections found")
	}

	// Check for duplicate section names
	nameCount := make(map[string]int)
	for _, s := range nonDebugSections {
		nameCount[s.Name]++
	}
	for name, count := range nameCount {
		if count > 1 {
			*issues = append(*issues, common.SymbolWarn+" Duplicate section name '"+name+"' ("+fmt.Sprintf("%d", count)+" times)")
		}
	}
}

func formatSizeELF(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	} else {
		return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
	}
}

func getSectionTypeName(sectionType uint32) string {
	switch sectionType {
	case 0:
		return "NULL"
	case 1:
		return "PROGBITS"
	case 2:
		return "SYMTAB"
	case 3:
		return "STRTAB"
	case 4:
		return "RELA"
	case 5:
		return "HASH"
	case 6:
		return "DYNAMIC"
	case 7:
		return "NOTE"
	case 8:
		return "NOBITS"
	case 9:
		return "REL"
	case 10:
		return "SHLIB"
	case 11:
		return "DYNSYM"
	default:
		return fmt.Sprintf("UNK_%X", sectionType)
	}
}

func formatPresence(present bool) string {
	if present {
		return "✅ Present"
	}
	return "❌ Missing"
}

func getDynamicTagName(tag int64) string {
	switch tag {
	case 0:
		return "DT_NULL"
	case 1:
		return "DT_NEEDED"
	case 2:
		return "DT_PLTRELSZ"
	case 3:
		return "DT_PLTGOT"
	case 4:
		return "DT_HASH"
	case 5:
		return "DT_STRTAB"
	case 6:
		return "DT_SYMTAB"
	default:
		return fmt.Sprintf("DT_UNKNOWN_%X", tag)
	}
}

func (e *ELFFile) calculateSectionEntropy() {
	for i := range e.Sections {
		section := &e.Sections[i]
		if section.Size > 0 && section.Offset+section.Size <= int64(len(e.RawData)) {
			section.Entropy = common.CalculateEntropy(e.RawData[section.Offset : section.Offset+section.Size])
		}
	}
}

func (e *ELFFile) detectPacking() bool {
	if len(e.Sections) == 0 {
		return false
	}

	highEntropyCount := 0
	anomalousCount := 0
	totalValidSections := 0

	for _, section := range e.Sections {
		// Skip debug sections
		if e.isDebugSection(section.Name) {
			continue
		}

		if section.Size == 0 {
			continue
		}

		totalValidSections++

		if section.Entropy > 7.0 {
			highEntropyCount++
		}

		// Check for anomalous sections (executable and writable)
		if section.IsExecutable && section.IsWritable {
			anomalousCount++
		}
	}

	if totalValidSections == 0 {
		return false
	}

	highEntropyRatio := float64(highEntropyCount) / float64(totalValidSections)
	anomalousRatio := float64(anomalousCount) / float64(totalValidSections)

	// Anomalous sections are a strong indicator of packing
	if anomalousRatio > 0 {
		return true
	}

	// High entropy ratio indicates packing/compression
	if highEntropyRatio >= 0.5 {
		return true
	}

	// Few sections with high entropy also indicates packing
	if totalValidSections <= 3 && highEntropyCount >= 1 {
		return true
	}

	return false
}

func (e *ELFFile) isDebugSection(name string) bool {
	debugPrefixes := []string{
		".debug",
		".zdebug",
		".gdb_index",
		".note.",
		".comment",
	}
	for _, prefix := range debugPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func (e *ELFFile) printBasicInfo() {
	fmt.Println("� BINARY INFORMATION")
	fmt.Println("═════════════════════")

	// Basic file information
	fmt.Printf("File Name:       %s\n", e.FileName)
	fmt.Printf("File Size:       %s (%d bytes)\n", common.FormatFileSize(e.FileSize), e.FileSize)

	// Calculate and display file hashes
	if e.RawData != nil {
		md5Hash := md5.Sum(e.RawData)
		sha256Hash := sha256.Sum256(e.RawData)
		fmt.Printf("MD5 Hash:        %x\n", md5Hash)
		fmt.Printf("SHA256 Hash:     %x\n", sha256Hash)
	}

	// ELF specific info
	fmt.Printf("Architecture:    %s\n", func() string {
		if e.Is64Bit {
			return "x64 (64-bit)"
		}
		return "x86 (32-bit)"
	}())

	fmt.Printf("Endianness:      %s\n", func() string {
		if e.isLittleEndian() {
			return "Little Endian (LSB)"
		}
		return "Big Endian (MSB)"
	}())

	// Detect language and compiler
	language, compiler := e.detectLanguageAndCompiler()
	if language != "" {
		fmt.Printf("Language:        %s\n", language)
	}
	if compiler != "" {
		fmt.Printf("Compiler:        %s\n", compiler)
	}

	fmt.Printf("Sections:        %d total\n", len(e.Sections))

	// Space utilization analysis
	fmt.Printf("\n💾 SPACE UTILIZATION:\n")
	var totalSectionSize int64
	for _, section := range e.Sections {
		if section.Type != 8 { // Skip NOBITS sections
			totalSectionSize += section.Size
		}
	}
	overhead := e.FileSize - totalSectionSize
	efficiency := float64(totalSectionSize) / float64(e.FileSize) * 100
	fmt.Printf("Total Section Size: %s\n", common.FormatFileSize(totalSectionSize))
	fmt.Printf("File Overhead:      %s\n", common.FormatFileSize(overhead))
	fmt.Printf("File Efficiency:    %.1f%%\n", efficiency)

	// Overlay analysis
	fmt.Printf("\n🗂️  OVERLAY ANALYSIS:\n")
	if len(e.Sections) > 0 && e.RawData != nil {
		var lastSectionEnd int64
		for _, section := range e.Sections {
			if section.Type != 8 { // Skip NOBITS
				sectionEnd := section.Offset + section.Size
				if sectionEnd > lastSectionEnd {
					lastSectionEnd = sectionEnd
				}
			}
		}

		overlaySize := e.FileSize - lastSectionEnd
		if overlaySize > 0 {
			overlayPercent := float64(overlaySize) / float64(e.FileSize) * 100
			fmt.Printf("Overlay Present:    YES (%s, %.1f%%)\n", common.FormatFileSize(overlaySize), overlayPercent)
			if overlaySize > 1024 {
				fmt.Printf("Overlay Warning:    ⚠️  Large overlay detected - possible embedded data\n")
			}
		} else {
			fmt.Printf("Overlay Present:    NO\n")
		}
	} else {
		fmt.Printf("Overlay Present:    Cannot determine\n")
	}

	fmt.Println()
}

func (e *ELFFile) printELFHeaders() {
	fmt.Println("🏗️  ELF HEADER INFORMATION")
	fmt.Println("═══════════════════════════")

	// Basic ELF Header info
	fmt.Printf("ELF Class:       %s\n", map[bool]string{true: "ELF64", false: "ELF32"}[e.Is64Bit])
	fmt.Printf("Data Encoding:   %s\n", func() string {
		if e.isLittleEndian() {
			return "Little Endian (LSB)"
		}
		return "Big Endian (MSB)"
	}())
	fmt.Printf("File Type:       %s (0x%X)\n", e.getFileTypeName(), e.getFileType())
	fmt.Printf("Machine:         %s\n", e.machineType)
	fmt.Printf("Entry Point:     0x%016X\n", e.entryPoint)
	fmt.Printf("Sections:        %d total\n", len(e.Sections))
	fmt.Printf("Segments:        %d total\n", len(e.Segments))
	fmt.Printf("Packed Status:   %s\n", map[bool]string{true: "📦 Likely PACKED", false: "✅ Not packed"}[e.IsPacked])

	// Dynamic analysis
	if e.isDynamic {
		fmt.Printf("Dynamic Linking: ✅ YES")
		if e.hasInterpreter {
			fmt.Printf(" (with interpreter)")
		}
		fmt.Println()
	} else {
		fmt.Printf("Dynamic Linking: ❌ NO (static binary)\n")
	}

	var (
		executableSections = 0
		writableSections   = 0
		debugSections      = 0
		loadableSegments   = 0
	)

	for _, section := range e.Sections {
		if section.IsExecutable {
			executableSections++
		}
		if section.IsWritable {
			writableSections++
		}
		if e.isDebugSection(section.Name) {
			debugSections++
		}
	}

	for _, segment := range e.Segments {
		if segment.Type == PT_LOAD {
			loadableSegments++
		}
	}

	fmt.Printf("Executable Secs: %d\n", executableSections)
	fmt.Printf("Writable Secs:   %d\n", writableSections)
	fmt.Printf("Debug Secs:      %d\n", debugSections)
	fmt.Printf("Loadable Segs:   %d\n", loadableSegments)

	// File integrity analysis
	fmt.Printf("\n🔧 FILE INTEGRITY & COMPLIANCE:\n")
	var issues []string
	var warnings []string
	complianceChecks := 0
	complianceViolations := 0

	// Check 1: Valid ELF magic
	complianceChecks++
	if len(e.RawData) < 4 || string(e.RawData[0:4]) != "\x7fELF" {
		issues = append(issues, "Invalid ELF magic signature")
		complianceViolations++
	}

	// Check 2: Entry point validation
	complianceChecks++
	if e.entryPoint == 0 && e.getFileType() != 3 { // Not a shared object
		warnings = append(warnings, "Entry point is zero for executable")
	}

	// Check 3: Section/segment consistency
	complianceChecks++
	if len(e.Sections) == 0 && len(e.Segments) == 0 {
		issues = append(issues, "No sections or segments found")
		complianceViolations++
	}

	// Check 4: Dynamic linking consistency
	complianceChecks++
	if e.isDynamic && !e.hasInterpreter && e.getFileType() == 2 { // ET_EXEC
		warnings = append(warnings, "Dynamic executable without interpreter")
	}

	if len(issues) == 0 && len(warnings) == 0 {
		fmt.Printf("File Status:     ✅ No issues detected\n")
	} else {
		if len(issues) > 0 {
			fmt.Printf("Critical Issues: ❌ %d found\n", len(issues))
			for _, issue := range issues {
				fmt.Printf("  • %s\n", issue)
			}
		}
		if len(warnings) > 0 {
			fmt.Printf("Warnings:        ⚠️  %d found\n", len(warnings))
			for _, warning := range warnings {
				fmt.Printf("  • %s\n", warning)
			}
		}
	}

	fmt.Printf("ELF Compliance:  %d/%d checks passed\n", complianceChecks-complianceViolations, complianceChecks)

	if complianceViolations == 0 {
		fmt.Printf("Compliance:      ✅ EXCELLENT\n")
	} else if complianceViolations <= 2 {
		fmt.Printf("Compliance:      ⚠️  PARTIAL\n")
	} else {
		fmt.Printf("Compliance:      ❌ POOR\n")
	}

	// Memory layout analysis
	fmt.Printf("\n🧠 MEMORY LAYOUT:\n")
	var totalVirtualSize uint64
	var usedSpace int64

	for _, segment := range e.Segments {
		if segment.Type == PT_LOAD {
			totalVirtualSize += segment.MemSize
		}
	}

	for _, section := range e.Sections {
		if section.Type != SHT_NOBITS {
			usedSpace += section.Size
		}
	}

	if totalVirtualSize > 0 {
		usedPercent := float64(usedSpace) / float64(totalVirtualSize) * 100
		wastePercent := 100 - usedPercent

		fmt.Printf("Virtual Size:    %s (0x%X)\n", common.FormatFileSize(int64(totalVirtualSize)), totalVirtualSize)
		fmt.Printf("Used Space:      %s (%.1f%%)\n", common.FormatFileSize(usedSpace), usedPercent)
		fmt.Printf("Alignment Waste: %s (%.1f%%)\n", common.FormatFileSize(int64(totalVirtualSize)-usedSpace), wastePercent)

		if wastePercent > 50 {
			fmt.Printf("Memory Usage:    ❌ HIGH WASTE (>50%%)\n")
		} else if wastePercent > 25 {
			fmt.Printf("Memory Usage:    ⚠️  MODERATE WASTE (>25%%)\n")
		} else {
			fmt.Printf("Memory Usage:    ✅ EFFICIENT (<25%% waste)\n")
		}
	}

	// Program Headers info
	fmt.Printf("\n📦 PROGRAM HEADERS (%d total):\n", len(e.Segments))
	fmt.Printf("┌────┬──────────────┬─────────────┬─────────────┬──────────────────┐\n")
	fmt.Printf("│ #  │ Type         │ Offset      │ Size        │ Flags            │\n")
	fmt.Printf("├────┼──────────────┼─────────────┼─────────────┼──────────────────┤\n")
	for i, segment := range e.Segments {
		fmt.Printf("│ %2d │ %-12s │ 0x%08X  │ %-11s │ %-16s │\n",
			i,
			getSegmentTypeName(segment.Type),
			segment.Offset,
			common.FormatFileSize(int64(segment.FileSize)),
			decodeSegmentFlags(segment.Flags))
	}
	fmt.Printf("└────┴──────────────┴─────────────┴─────────────┴──────────────────┘\n")

	fmt.Println()
}

func (e *ELFFile) printSectionHeaders() {
	fmt.Println("🏛️  SECTION HEADER ANALYSIS")
	fmt.Println("═══════════════════════════")

	var (
		executableSections = 0
		writableSections   = 0
		debugSections      = 0
		totalSectionSize   int64
		loadedSectionSize  int64
	)

	for _, section := range e.Sections {
		if section.IsExecutable {
			executableSections++
		}
		if section.IsWritable {
			writableSections++
		}
		if e.isDebugSection(section.Name) {
			debugSections++
		}
		totalSectionSize += section.Size
		if section.Type != SHT_NOBITS {
			loadedSectionSize += section.Size
		}
	}

	fmt.Printf("Total Sections:   %d\n", len(e.Sections))
	fmt.Printf("Executable:       %d\n", executableSections)
	fmt.Printf("Writable:         %d\n", writableSections)
	fmt.Printf("Debug Related:    %d\n", debugSections)
	fmt.Printf("Total Size:       %s\n", common.FormatFileSize(totalSectionSize))
	fmt.Printf("Loaded Size:      %s\n", common.FormatFileSize(loadedSectionSize))
	// Section table
	fmt.Printf("\n📋 SECTION TABLE:\n")
	fmt.Printf("┌───┬─────────────────────┬─────────────┬─────────────┬─────────────┬──────┬─────────┐\n")
	fmt.Printf("│ # │ Name                │ Type        │ Offset      │ Size        │ Flag │ Entropy │\n")
	fmt.Printf("├───┼─────────────────────┼─────────────┼─────────────┼─────────────┼──────┼─────────┤\n")

	for i, section := range e.Sections {
		truncatedName := section.Name
		if len(truncatedName) > 19 {
			truncatedName = truncatedName[:16] + "..."
		}

		typeStr := getSectionTypeName(section.Type)
		if len(typeStr) > 11 {
			typeStr = typeStr[:8] + "..."
		}

		// Format permissions
		perms := ""
		if section.IsReadable {
			perms += "R"
		} else {
			perms += "-"
		}
		if section.IsWritable {
			perms += "W"
		} else {
			perms += "-"
		}
		if section.IsExecutable {
			perms += "X"
		} else {
			perms += "-"
		}

		entropyStr := ""
		entropyStr = fmt.Sprintf("%.2f", section.Entropy)
		if section.Entropy > 7.5 {
			entropyStr += "🔺"
		} else if section.Entropy < 1.0 {
			entropyStr += "🔻"
		} else {
			entropyStr += "🔹"
		}

		fmt.Printf("│%2d │ %-19s │ %-11s │ 0x%08X  │ %-11s │ %-4s │ %-6s │\n",
			i,
			truncatedName,
			typeStr,
			section.Offset,
			common.FormatFileSize(section.Size),
			perms,
			entropyStr)
	}
	fmt.Printf("└───┴─────────────────────┴─────────────┴─────────────┴─────────────┴──────┴─────────┘\n")
	fmt.Println()
}

func (e *ELFFile) printSectionAnomalies() {
	fmt.Println("🚨 SECTION ANOMALY ANALYSIS")
	fmt.Println("════════════════════════════")

	infos := make([]SectionInfo, len(e.Sections))
	for i, s := range e.Sections {
		infos[i] = SectionInfo{
			Name:         s.Name,
			FileOffset:   s.Offset,
			Size:         s.Size,
			IsExecutable: s.IsExecutable,
			IsWritable:   s.IsWritable,
			IsReadable:   s.IsReadable,
			Entropy:      s.Entropy,
		}
	}
	issues := analyzeSectionAnomalies(infos, e.FileSize)
	if len(issues) == 0 {
		fmt.Printf("%s No section anomalies detected\n", "✅")
	} else {
		for _, issue := range issues {
			fmt.Println(issue)
		}
	}

	fmt.Println()
}

func (e *ELFFile) printSymbolAnalysis() {
	fmt.Println("🔤 SYMBOL ANALYSIS")
	fmt.Println("══════════════════")

	// Parse symbols directly from sections
	symbols := e.parseSymbolsFromSections()

	if len(symbols) == 0 {
		fmt.Printf("❌ No symbols found\n")
		fmt.Println()
		return
	}

	fmt.Printf("Total Symbols: %d\n\n", len(symbols))

	// Categorize symbols
	globalSymbols := 0
	localSymbols := 0
	functionSymbols := 0
	objectSymbols := 0
	importedSymbols := 0

	for _, symbol := range symbols {
		// Basic categorization based on symbol properties
		if symbol.Value == 0 && symbol.Name != "" {
			importedSymbols++
		}

		if strings.Contains(symbol.Name, "func") || strings.HasSuffix(symbol.Name, "@plt") {
			functionSymbols++
		} else if symbol.Size > 0 {
			objectSymbols++
		}

		// Simple binding estimation
		if strings.HasPrefix(symbol.Name, "_") || strings.Contains(symbol.Name, "local") {
			localSymbols++
		} else {
			globalSymbols++
		}
	}

	fmt.Printf("SYMBOL STATISTICS:\n")
	fmt.Printf("  Global symbols:   %d\n", globalSymbols)
	fmt.Printf("  Local symbols:    %d\n", localSymbols)
	fmt.Printf("  Function symbols: %d\n", functionSymbols)
	fmt.Printf("  Object symbols:   %d\n", objectSymbols)
	fmt.Printf("  Imported symbols: %d\n", importedSymbols)
	fmt.Println()
}

func (e *ELFFile) printDynamicAnalysis() {
	fmt.Println("🔗 DYNAMIC LINKING ANALYSIS")
	fmt.Println("═══════════════════════════")

	if !e.isDynamic {
		fmt.Printf("Static Binary:    ✅ NO dynamic linking required\n")
		fmt.Printf("Dependencies:     None (statically linked)\n")
		fmt.Printf("Security Impact:  ✅ Lower attack surface\n")
		fmt.Println()
		return
	}

	fmt.Printf("Dynamic Binary:   ✅ YES\n")
	fmt.Printf("Interpreter:      %s\n", func() string {
		if e.hasInterpreter {
			return "✅ Present"
		}
		return "❌ Missing"
	}())

	// Analyze dynamic sections
	var (
		hasDynamic    = false
		hasDynSym     = false
		hasDynStr     = false
		hasGot        = false
		hasPlt        = false
		hasRela       = false
		hasVersioning = false
	)

	for _, section := range e.Sections {
		switch section.Name {
		case ".dynamic":
			hasDynamic = true
		case ".dynsym":
			hasDynSym = true
		case ".dynstr":
			hasDynStr = true
		case ".got", ".got.plt":
			hasGot = true
		case ".plt", ".plt.got", ".plt.sec":
			hasPlt = true
		case ".rela.dyn", ".rela.plt", ".rel.dyn", ".rel.plt":
			hasRela = true
		case ".gnu.version", ".gnu.version_r", ".gnu.version_d":
			hasVersioning = true
		}
	}

	fmt.Printf("\n🔧 DYNAMIC SECTIONS ANALYSIS:\n")
	fmt.Printf("Dynamic Info:     %s\n", formatPresence(hasDynamic))
	fmt.Printf("Symbol Table:     %s\n", formatPresence(hasDynSym))
	fmt.Printf("String Table:     %s\n", formatPresence(hasDynStr))
	fmt.Printf("GOT (Global):     %s\n", formatPresence(hasGot))
	fmt.Printf("PLT (Procedure):  %s\n", formatPresence(hasPlt))
	fmt.Printf("Relocations:      %s\n", formatPresence(hasRela))
	fmt.Printf("Versioning:       %s\n", formatPresence(hasVersioning))

	// Security analysis
	fmt.Printf("\n🛡️  SECURITY FEATURES:\n")

	// Check for RELRO
	relroStatus := "❌ NO RELRO"
	for _, segment := range e.Segments {
		if segment.Type == 0x6474e552 { // PT_GNU_RELRO
			relroStatus = "✅ RELRO enabled"
			break
		}
	}
	fmt.Printf("RELRO:            %s\n", relroStatus)

	// Check for NX/Execute Disable
	nxStatus := "❌ NO NX protection"
	hasExecutableStack := false
	for _, segment := range e.Segments {
		if segment.Type == 0x6474e551 { // PT_GNU_STACK
			if segment.Flags&1 == 0 { // Not executable
				nxStatus = "✅ NX enabled (non-exec stack)"
			} else {
				hasExecutableStack = true
			}
			break
		}
	}
	if hasExecutableStack {
		nxStatus = "⚠️  Executable stack detected"
	}
	fmt.Printf("NX/DEP:           %s\n", nxStatus)

	// PIE/ASLR support
	pieStatus := "❌ NO PIE"
	fileType := e.getFileType()
	if fileType == 3 { // ET_DYN
		pieStatus = "✅ PIE enabled"
	} else if fileType == 2 { // ET_EXEC
		pieStatus = "⚠️  Fixed address executable"
	}
	fmt.Printf("PIE/ASLR:         %s\n", pieStatus)

	// Stack canary detection (heuristic)
	canaryStatus := "❌ NO stack canaries"
	for _, section := range e.Sections {
		if strings.Contains(section.Name, "stack_chk") ||
			(section.Name == ".rodata" && section.Size > 0) {
			// Basic heuristic - could be improved
			canaryStatus = "🤔 Possibly present"
			break
		}
	}
	fmt.Printf("Stack Canaries:   %s\n", canaryStatus)

	// Dynamic entries analysis
	if len(e.DynamicEntries) > 0 {
		fmt.Printf("\n📋 DYNAMIC ENTRIES (%d total):\n", len(e.DynamicEntries))

		entryCount := 0
		for _, entry := range e.DynamicEntries {
			if entryCount < 10 { // Limit output
				tagName := getDynamicTagName(entry.Tag)
				fmt.Printf("  %-20s: 0x%016X\n", tagName, entry.Value)
				entryCount++
			}
		}
		if len(e.DynamicEntries) > 10 {
			fmt.Printf("  ... and %d more entries\n", len(e.DynamicEntries)-10)
		}
	}

	fmt.Println()
}

func (e *ELFFile) printImportsAnalysis() {
	fmt.Println("📦 IMPORTS ANALYSIS")
	fmt.Println("═══════════════════")

	if !e.isDynamic {
		fmt.Printf("Static Binary:    ✅ No imports (statically linked)\n")
		fmt.Printf("Dependencies:     None\n")
		fmt.Println()
		return
	}

	// Parse dynamic section to find needed libraries
	dynamicLibraries := e.parseDynamicLibraries()
	dynamicSymbols := e.parseDynamicSymbols()

	if len(dynamicLibraries) == 0 {
		fmt.Printf("❌ No dynamic libraries found\n")
		fmt.Println()
		return
	}

	fmt.Printf("Total Dynamic Libraries: %d\n", len(dynamicLibraries))
	fmt.Printf("Total Imported Symbols: %d\n", len(dynamicSymbols))

	if len(dynamicLibraries) > 0 {
		fmt.Printf("\nDYNAMIC LIBRARIES:\n")
		for i, lib := range dynamicLibraries {
			fmt.Printf("%2d. %s\n", i+1, lib)
		}
	}

	if len(dynamicSymbols) > 0 {
		fmt.Printf("\n📚 IMPORTED FUNCTIONS:\n")

		// Group symbols by library (best effort)
		libFunctions := make(map[string][]string)
		var ungrouped []string

		for _, symbol := range dynamicSymbols {
			if symbol.Name == "" || symbol.Name == "UND" {
				continue
			}

			// Try to categorize by common patterns
			lib := e.categorizeSymbol(symbol.Name)
			if lib != "" {
				libFunctions[lib] = append(libFunctions[lib], symbol.Name)
			} else {
				ungrouped = append(ungrouped, symbol.Name)
			}
		}

		// Display categorized functions
		for lib, functions := range libFunctions {
			if len(functions) > 0 {
				fmt.Printf("\n📚 %s (%d functions):\n", lib, len(functions))
				for _, fn := range functions {
					fmt.Printf("   • %s\n", fn)
				}
			}
		}

		// Display uncategorized functions
		if len(ungrouped) > 0 {
			fmt.Printf("\n📚 Other/Unknown Library (%d functions):\n", len(ungrouped))
			for _, fn := range ungrouped {
				fmt.Printf("   • %s\n", fn)
			}
		}
	}

	// Security analysis of imports
	fmt.Printf("\n🛡️  IMPORT SECURITY ANALYSIS:\n")

	riskyFunctions := []string{
		"system", "exec", "popen", "dlopen", "dlsym",
		"gets", "strcpy", "strcat", "sprintf", "scanf",
		"malloc", "free", "mmap", "mprotect",
	}

	var foundRisky []string
	for _, symbol := range dynamicSymbols {
		for _, risky := range riskyFunctions {
			if strings.Contains(symbol.Name, risky) {
				foundRisky = append(foundRisky, symbol.Name)
			}
		}
	}

	if len(foundRisky) > 0 {
		fmt.Printf("Risky Functions:  ⚠️  %d found\n", len(foundRisky))
		for _, fn := range foundRisky {
			fmt.Printf("  • %s\n", fn)
		}
	} else {
		fmt.Printf("Risky Functions:  ✅ None detected\n")
	}

	fmt.Println()
}

func (e *ELFFile) printExportsAnalysis() {
	fmt.Println("🔍 EXPORTS ANALYSIS")
	fmt.Println("═══════════════════")

	// Parse both static and dynamic symbols for exports
	staticSymbols := e.parseStaticSymbols()
	dynamicSymbols := e.parseDynamicSymbols()

	var exportedSymbols []Symbol

	// Find exported symbols (global binding, defined)
	for _, symbol := range staticSymbols {
		if symbol.Binding == 1 && symbol.Section != 0 { // STB_GLOBAL and not undefined
			exportedSymbols = append(exportedSymbols, symbol)
		}
	}

	for _, symbol := range dynamicSymbols {
		if symbol.Binding == 1 && symbol.Section != 0 { // STB_GLOBAL and not undefined
			exportedSymbols = append(exportedSymbols, symbol)
		}
	}

	if len(exportedSymbols) == 0 {
		fmt.Printf("❌ No exported symbols found\n")
		fmt.Println()
		return
	}

	fmt.Printf("Total Exported Symbols: %d\n", len(exportedSymbols))

	// Categorize exports
	var functions []Symbol
	var objects []Symbol
	var others []Symbol

	for _, symbol := range exportedSymbols {
		switch symbol.Type {
		case 2: // STT_FUNC
			functions = append(functions, symbol)
		case 1: // STT_OBJECT
			objects = append(objects, symbol)
		default:
			others = append(others, symbol)
		}
	}

	if len(functions) > 0 {
		fmt.Printf("\n📚 EXPORTED FUNCTIONS (%d):\n", len(functions))
		for i, fn := range functions {
			if i < 20 { // Limit display
				fmt.Printf("   • %s (RVA: 0x%08X, size: %d bytes)\n", fn.Name, fn.Value, fn.Size)
			}
		}
		if len(functions) > 20 {
			fmt.Printf("   ... and %d more functions\n", len(functions)-20)
		}
	}

	if len(objects) > 0 {
		fmt.Printf("\n📦 EXPORTED OBJECTS (%d):\n", len(objects))
		for i, obj := range objects {
			if i < 15 { // Limit display
				fmt.Printf("   • %s (RVA: 0x%08X, size: %d bytes)\n", obj.Name, obj.Value, obj.Size)
			}
		}
		if len(objects) > 15 {
			fmt.Printf("   ... and %d more objects\n", len(objects)-15)
		}
	}

	if len(others) > 0 {
		fmt.Printf("\n🔧 OTHER EXPORTS (%d):\n", len(others))
		for i, other := range others {
			if i < 10 { // Limit display
				fmt.Printf("   • %s (RVA: 0x%08X, type: %d)\n", other.Name, other.Value, other.Type)
			}
		}
		if len(others) > 10 {
			fmt.Printf("   ... and %d more symbols\n", len(others)-10)
		}
	}

	fmt.Println()
}

func (e *ELFFile) parseDynamicLibraries() []string {
	var libraries []string

	_, found := e.findSectionByName(".dynamic")
	if !found {
		return libraries
	}

	strIndex, found := e.findSectionByName(".dynstr")
	if !found {
		return libraries
	}

	for _, entry := range e.DynamicEntries {
		if entry.Tag == 1 { // DT_NEEDED
			if libName := e.readStringFromSection(strIndex, int(entry.Value)); libName != "" {
				libraries = append(libraries, libName)
			}
		}
	}

	return libraries
}

func (e *ELFFile) parseDynamicSymbols() []Symbol {
	var symbols []Symbol

	dynsymIndex, found := e.findSectionByName(".dynsym")
	if !found {
		return symbols
	}

	strIndex, found := e.findSectionByName(".dynstr")
	if !found {
		return symbols
	}

	symbols = e.parseSymbolsFromSection(dynsymIndex, strIndex)

	var importedSymbols []Symbol
	for _, sym := range symbols {
		if sym.Section == 0 && sym.Name != "" {
			importedSymbols = append(importedSymbols, sym)
		}
	}

	return importedSymbols
}

func (e *ELFFile) categorizeSymbol(symbolName string) string {
	// Simple categorization based on common patterns
	if strings.HasPrefix(symbolName, "__libc_") ||
		strings.Contains(symbolName, "printf") ||
		strings.Contains(symbolName, "malloc") ||
		strings.Contains(symbolName, "free") {
		return "libc.so.6"
	}
	if strings.Contains(symbolName, "math") ||
		strings.Contains(symbolName, "sin") ||
		strings.Contains(symbolName, "cos") {
		return "libm.so.6"
	}
	return "unknown"
}

func (e *ELFFile) parseStaticSymbols() []Symbol {
	return []Symbol{} // Placeholder implementation
}

func (e *ELFFile) detectLanguageAndCompiler() (string, string) {
	// Look for common section patterns
	language := "Unknown"
	compiler := "Unknown"

	for _, section := range e.Sections {
		if section.Name == ".comment" {
			// In a real implementation, we'd parse the comment section
			language = "C/C++"
			compiler = "GCC/Clang"
			break
		}
		if strings.Contains(section.Name, ".go.") {
			language = "Go"
			compiler = "Go compiler"
			break
		}
	}

	return language, compiler
}

func (e *ELFFile) printPackingAnalysis() {
	fmt.Println("📦 PACKING ANALYSIS")
	fmt.Println("═══════════════════")

	fmt.Printf("File appears to be packed: %t\n", e.IsPacked)
	if e.IsPacked {
		fmt.Printf("❌ Packing detected\n")
	} else {
		fmt.Printf("✅ No packing detected\n")
	}

	fmt.Println()
}

func (e *ELFFile) parseSymbolsFromSections() []Symbol {
	var symbols []Symbol
	symbols = append(symbols, e.parseSymbolTable(".symtab", ".strtab")...)
	symbols = append(symbols, e.parseSymbolTable(".dynsym", ".dynstr")...)
	return symbols
}

func (e *ELFFile) parseSymbolTable(symtabName, strtabName string) []Symbol {
	var symbols []Symbol
	var symtabSection *Section
	var strtabSection *Section

	for _, section := range e.Sections {
		if section.Name == symtabName {
			symtabSection = &section
		}
		if section.Name == strtabName {
			strtabSection = &section
		}
	}
	if symtabSection == nil || strtabSection == nil {
		return symbols // Symbol table or string table not found
	}
	if strtabSection.Offset+strtabSection.Size > int64(len(e.RawData)) {
		return symbols // Invalid string table
	}
	stringTableData := e.RawData[strtabSection.Offset : strtabSection.Offset+strtabSection.Size]
	var entrySize int64
	if e.Is64Bit {
		entrySize = 24 // sizeof(Elf64_Sym)
	} else {
		entrySize = 16 // sizeof(Elf32_Sym)
	}

	if symtabSection.Size%entrySize != 0 {
		return symbols // Invalid symbol table size
	}

	numSymbols := symtabSection.Size / entrySize

	for i := int64(0); i < numSymbols; i++ {
		offset := symtabSection.Offset + i*entrySize

		if offset+entrySize > int64(len(e.RawData)) {
			break // Prevent out of bounds
		}

		symbolData := e.RawData[offset : offset+entrySize]
		symbol := e.parseSymbolEntry(symbolData, stringTableData)

		if symbol.Name != "" { // Skip empty symbols
			symbols = append(symbols, symbol)
		}
	}

	return symbols
}

func (e *ELFFile) parseSymbolEntry(data []byte, stringTable []byte) Symbol {
	symbol := Symbol{}

	if e.Is64Bit {
		nameOffset := e.readUint32FromBytes(data[0:4])
		info := data[4]
		// other := data[5]  // Not used currently
		// sectionIndex := e.readUint16FromBytes(data[6:8])  // Not used currently
		symbol.Value = e.readUint64FromBytes(data[8:16])
		symbol.Size = e.readUint64FromBytes(data[16:24])
		symbol.Binding = info >> 4
		symbol.Type = info & 0x0F
		if int(nameOffset) < len(stringTable) {
			symbol.Name = e.readNullTerminatedString(stringTable[nameOffset:])
		}
	} else {
		// ELF32 symbol structure
		nameOffset := e.readUint32FromBytes(data[0:4])
		symbol.Value = uint64(e.readUint32FromBytes(data[4:8]))
		symbol.Size = uint64(e.readUint32FromBytes(data[8:12]))
		info := data[12]
		// other := data[13]  // Not used currently
		// sectionIndex := e.readUint16FromBytes(data[14:16])  // Not used currently
		symbol.Binding = info >> 4
		symbol.Type = info & 0x0F
		if int(nameOffset) < len(stringTable) {
			symbol.Name = e.readNullTerminatedString(stringTable[nameOffset:])
		}
	}

	return symbol
}

func (e *ELFFile) readUint32FromBytes(data []byte) uint32 {
	if len(data) < 4 {
		return 0
	}
	if e.isLittleEndian() {
		return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	}
	return uint32(data[3]) | uint32(data[2])<<8 | uint32(data[1])<<16 | uint32(data[0])<<24
}

func (e *ELFFile) readUint64FromBytes(data []byte) uint64 {
	if len(data) < 8 {
		return 0
	}
	if e.isLittleEndian() {
		return uint64(data[0]) | uint64(data[1])<<8 | uint64(data[2])<<16 | uint64(data[3])<<24 |
			uint64(data[4])<<32 | uint64(data[5])<<40 | uint64(data[6])<<48 | uint64(data[7])<<56
	}
	return uint64(data[7]) | uint64(data[6])<<8 | uint64(data[5])<<16 | uint64(data[4])<<24 |
		uint64(data[3])<<32 | uint64(data[2])<<40 | uint64(data[1])<<48 | uint64(data[0])<<56
}

func (e *ELFFile) readNullTerminatedString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data) // No null terminator found
}

func (e *ELFFile) findSectionByName(name string) (uint16, bool) {
	count := e.ELF.GetSectionCount()
	for i := uint16(0); i < count; i++ {
		sectionName, err := e.ELF.GetSectionName(i)
		if err == nil && sectionName == name {
			return i, true
		}
	}
	return 0, false
}

func (e *ELFFile) readStringFromSection(sectionIndex uint16, offset int) string {
	sectionData, err := e.ELF.GetSectionContent(sectionIndex)
	if err != nil || offset >= len(sectionData) || offset < 0 {
		return ""
	}

	end := offset
	for end < len(sectionData) && sectionData[end] != 0 {
		end++
	}

	return string(sectionData[offset:end])
}

func (e *ELFFile) parseSymbolsFromSection(symIndex, strIndex uint16) []Symbol {
	var symbols []Symbol

	symData, err := e.ELF.GetSectionContent(symIndex)
	if err != nil {
		return symbols
	}

	strData, err := e.ELF.GetSectionContent(strIndex)
	if err != nil {
		return symbols
	}

	// Symbol table entry size depends on architecture
	var entrySize int
	if e.Is64Bit {
		entrySize = 24 // 64-bit symbol table entry
	} else {
		entrySize = 16 // 32-bit symbol table entry
	}

	// Parse each symbol entry
	for offset := 0; offset < len(symData); offset += entrySize {
		if offset+entrySize > len(symData) {
			break
		}

		symbol := e.parseSymbolEntry(symData[offset:offset+entrySize], strData)
		if symbol.Name != "" {
			symbols = append(symbols, symbol)
		}
	}

	return symbols
}
