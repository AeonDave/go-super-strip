package perw

import (
	"debug/pe"
	"fmt"
	"gosstrip/common"
	"strings"
)

// printExportAnalysis prints detailed export analysis
func (p *PEFile) printExportAnalysis() {
	fmt.Println("🔍 EXPORT ANALYSIS")
	fmt.Println("══════════════════")
	if len(p.Exports) == 0 {
		fmt.Println("❌ No exported symbols found")
		fmt.Println()
		return
	}

	fmt.Printf("Total Exported Functions: %d\n\n", len(p.Exports))
	fmt.Println("EXPORTED FUNCTIONS:")

	for _, exp := range p.Exports {
		if exp.Ordinal != 0 {
			fmt.Printf("   • %s (Ordinal: %d, RVA: 0x%08X)\n", exp.Name, exp.Ordinal, exp.RVA)
		} else {
			fmt.Printf("   • %s (RVA: 0x%08X)\n", exp.Name, exp.RVA)
		}
	}

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
	p.printSectionAnomalies()
	p.printImportsAnalysis()
	p.printExportAnalysis()
	PrintSuspiciousStrings(p)
	return nil
}

// printHeader prints a styled report header
func (p *PEFile) printHeader() {
	fmt.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                           PE FILE ANALYSIS REPORT                            ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// printBasicInfo prints comprehensive binary information including version, security and space analysis
func (p *PEFile) printBasicInfo() {
	fmt.Println("� BINARY INFORMATION")
	fmt.Println("═════════════════════")

	// Basic file information
	fmt.Printf("File Name:       %s\n", p.FileName)
	fmt.Printf("File Size:       %s (%d bytes)\n", common.FormatFileSize(p.FileSize), p.FileSize)
	fmt.Printf("Architecture:    %s\n", map[bool]string{true: "x64 (64-bit)", false: "x86 (32-bit)"}[p.Is64Bit])
	if p.Machine != "" {
		fmt.Printf("Machine Type:    %s\n", p.Machine)
	}
	if p.TimeDateStamp != "" {
		fmt.Printf("Compile Time:    %s\n", p.TimeDateStamp)
	}

	// Language and compiler detection
	language, compiler := p.detectLanguageAndCompiler()
	if language != "" {
		fmt.Printf("Language:        %s\n", language)
	}
	if compiler != "" {
		fmt.Printf("Compiler:        %s\n", compiler)
	}

	// Version information
	if len(p.VersionInfo) > 0 {
		fmt.Printf("\n📄 VERSION DETAILS:\n")
		for key, value := range p.VersionInfo {
			fmt.Printf("%-20s %s\n", key+":", value)
		}
	}

	// Security analysis
	fmt.Printf("\n🔒 SECURITY PROFILE:\n")
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

	// Space utilization analysis
	fmt.Printf("\n💾 SPACE UTILIZATION:\n")
	var totalSectionSize int64
	for _, section := range p.Sections {
		totalSectionSize += int64(section.Size)
	}
	overhead := p.FileSize - totalSectionSize
	efficiency := float64(totalSectionSize) / float64(p.FileSize) * 100
	fmt.Printf("Total Section Size: %s\n", common.FormatFileSize(totalSectionSize))
	fmt.Printf("File Overhead:      %s\n", common.FormatFileSize(overhead))
	fmt.Printf("File Efficiency:    %.1f%%\n", efficiency)

	// Overlay analysis
	fmt.Printf("\n🗂️  OVERLAY ANALYSIS:\n")
	if len(p.Sections) > 0 && p.RawData != nil {
		last := p.Sections[len(p.Sections)-1]
		present, offset, size, entropy := OverlayInfo(p.FileSize, int64(last.FileOffset), int64(last.Size), p.RawData)
		if present {
			fmt.Printf("Overlay Status:     %s Present at 0x%X\n", common.SymbolWarn, offset)
			fmt.Printf("Overlay Size:       %s\n", common.FormatFileSize(size))
			fmt.Printf("Overlay Entropy:    %.2f\n", entropy)
		} else {
			fmt.Printf("Overlay Status:     %s No overlay detected\n", common.SymbolCheck)
		}
	} else {
		fmt.Printf("Overlay Status:     ❓ Unable to analyze (no sections or file data)\n")
	}

	// Digital signature analysis
	fmt.Printf("\n🔏 DIGITAL SIGNATURE:\n")
	if p.SignatureSize() > 0 {
		fmt.Printf("Signature Status:   %s Present (%d bytes)\n", common.SymbolCheck, p.SignatureSize())
	} else {
		fmt.Printf("Signature Status:   %s No digital signature found\n", common.SymbolWarn)
	}

	fmt.Println()
}

// printPEHeaders prints enhanced PE header information for professionals
func (p *PEFile) printPEHeaders() {
	fmt.Println("🏗️  PE HEADER INFORMATION")
	fmt.Println("═══════════════════════════")
	if p.PDB != "" && p.PDB != "@" && !strings.HasPrefix(p.PDB, "@") {
		fmt.Printf("Debug Info:      %s\n", p.PDB)
	}
	if p.GUIDAge != "" {
		fmt.Printf("GUID/Age:        %s\n", p.GUIDAge)
	}

	// Enhanced header information
	fmt.Printf("Sections:        %d total\n", len(p.Sections))
	fmt.Printf("Packed Status:   %s\n", map[bool]string{true: "❌ Likely PACKED", false: "✅ Not packed"}[p.IsPacked])
	fmt.Printf("Image Base:      0x%X\n", p.ImageBase())
	fmt.Printf("Entry Point:     0x%X (RVA)\n", p.EntryPoint())

	fmt.Printf("Size of Image:   %d bytes (%s)\n", p.SizeOfImage(), common.FormatFileSize(int64(p.SizeOfImage())))
	fmt.Printf("Size of Headers: %d bytes\n", p.SizeOfHeaders())

	// Checksum information
	checksum := p.Checksum()
	if checksum != 0 {
		fmt.Printf("Checksum:        0x%X\n", checksum)
	} else {
		fmt.Printf("Checksum:        Not set\n")
	}

	fmt.Printf("File Type:       %s\n", p.GetFileType())
	subsystemName := getSubsystemName(p.Subsystem())
	fmt.Printf("Subsystem:       %d (%s)\n", p.Subsystem(), subsystemName)

	// Enhanced DLL characteristics
	dllChars := decodeDLLCharacteristics(p.DllCharacteristics())
	fmt.Printf("DLL Characteristics: 0x%X (%s)\n", p.DllCharacteristics(), dllChars)

	// Directory entries count
	directories := p.Directories()
	nonEmptyDirs := 0
	for _, dir := range directories {
		if dir.RVA != 0 || dir.Size != 0 {
			nonEmptyDirs++
		}
	}
	if nonEmptyDirs > 0 {
		fmt.Printf("Data Directories: %d active entries\n", nonEmptyDirs)
	}

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

// printImportsAnalysis prints import analysis grouped by DLL with duplicate function counting
func (p *PEFile) printImportsAnalysis() {
	fmt.Println("📦 IMPORTS ANALYSIS")
	fmt.Println("═══════════════════")
	if len(p.Imports) == 0 {
		fmt.Println("❌ No imports found")
		return
	}

	// Separate DLLs with functions from those without
	dllsWithFunctions := []ImportInfo{}
	dllsWithoutFunctions := []ImportInfo{}
	totalFunctions := 0

	for _, imp := range p.Imports {
		if len(imp.Functions) > 0 {
			dllsWithFunctions = append(dllsWithFunctions, imp)
			totalFunctions += len(imp.Functions)
		} else {
			dllsWithoutFunctions = append(dllsWithoutFunctions, imp)
		}
	}

	fmt.Printf("Total Imported Functions: %d\n", totalFunctions)
	fmt.Printf("Total DLLs: %d (%d with functions, %d without)\n\n",
		len(p.Imports), len(dllsWithFunctions), len(dllsWithoutFunctions))

	// Display DLLs with functions
	if len(dllsWithFunctions) > 0 {
		fmt.Println("IMPORTED LIBRARIES WITH FUNCTIONS:")
		for i, imp := range dllsWithFunctions {
			dllName := strings.ToUpper(imp.DLL)

			// Count function occurrences
			functionCount := make(map[string]int)
			for _, fn := range imp.Functions {
				functionCount[fn]++
			}

			uniqueFunctions := len(functionCount)
			fmt.Printf("\n📚 %s (%d functions, %d unique)\n", dllName, len(imp.Functions), uniqueFunctions)

			// Show functions with their counts
			for fn, count := range functionCount {
				if count > 1 {
					fmt.Printf("   • %s (×%d)\n", fn, count)
				} else {
					fmt.Printf("   • %s\n", fn)
				}
			}

			// Add separator between DLLs (except for last one)
			if i < len(dllsWithFunctions)-1 {
				fmt.Println("   ────────────────────────────────────")
			}
		}
	}

	// Display DLLs without functions separately
	if len(dllsWithoutFunctions) > 0 {
		fmt.Printf("\n\n📋 LIBRARIES WITHOUT FUNCTIONS (%d):\n", len(dllsWithoutFunctions))
		for _, imp := range dllsWithoutFunctions {
			fmt.Printf("   • %s\n", strings.ToUpper(imp.DLL))
		}
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

// detectLanguageAndCompiler analyzes the PE file to determine programming language and compiler
func (p *PEFile) detectLanguageAndCompiler() (language, compiler string) {
	// Check for Go runtime signatures
	if p.detectGoLanguage() {
		language = "Go"
		compiler = p.detectGoCompiler()
		return
	}

	// Check for .NET runtime
	if p.detectDotNetLanguage() {
		language = ".NET"
		compiler = p.detectDotNetCompiler()
		return
	}

	// Check for C/C++ runtime libraries
	if p.detectCppLanguage() {
		language = "C/C++"
		compiler = p.detectCppCompiler()
		return
	}

	// Check for Rust signatures
	if p.detectRustLanguage() {
		language = "Rust"
		compiler = "rustc"
		return
	}

	// Check for Delphi/Pascal
	if p.detectDelphiLanguage() {
		language = "Delphi/Pascal"
		compiler = p.detectDelphiCompiler()
		return
	}

	// Check for Visual Basic
	if p.detectVBLanguage() {
		language = "Visual Basic"
		compiler = "VB Compiler"
		return
	}

	// Check by imports and sections for other languages
	language, compiler = p.detectByImportsAndSections()
	return
}

// detectGoLanguage checks for Go runtime signatures
func (p *PEFile) detectGoLanguage() bool {
	// Check for Go-specific sections
	for _, section := range p.Sections {
		if strings.Contains(section.Name, "zdebug_") ||
			strings.Contains(section.Name, "debug_gdb_") ||
			section.Name == ".symtab" {
			return true
		}
	}

	// Check for Go runtime imports
	for _, imp := range p.Imports {
		for _, fn := range imp.Functions {
			if strings.Contains(fn, "runtime.") ||
				strings.Contains(fn, "syscall.") ||
				strings.Contains(fn, "go.") {
				return true
			}
		}
	}

	// Check for Go strings in binary
	dataStr := string(p.RawData)
	goIndicators := []string{
		"runtime.main", "runtime.goexit", "go.buildid",
		"runtime.newproc", "runtime.morestack", "golang.org",
	}

	for _, indicator := range goIndicators {
		if strings.Contains(dataStr, indicator) {
			return true
		}
	}

	return false
}

// detectGoCompiler determines Go compiler version
func (p *PEFile) detectGoCompiler() string {
	dataStr := string(p.RawData)

	// Look for Go version strings
	if strings.Contains(dataStr, "go1.21") {
		return "Go 1.21.x"
	} else if strings.Contains(dataStr, "go1.20") {
		return "Go 1.20.x"
	} else if strings.Contains(dataStr, "go1.19") {
		return "Go 1.19.x"
	} else if strings.Contains(dataStr, "go1.18") {
		return "Go 1.18.x"
	} else if strings.Contains(dataStr, "go1.") {
		return "Go 1.x"
	}

	return "Go Compiler"
}

// detectDotNetLanguage checks for .NET runtime
func (p *PEFile) detectDotNetLanguage() bool {
	// Check for .NET imports
	for _, imp := range p.Imports {
		dllLower := strings.ToLower(imp.DLL)
		if strings.Contains(dllLower, "mscoree") ||
			strings.Contains(dllLower, "mscorlib") ||
			strings.Contains(dllLower, "system.") {
			return true
		}
	}

	// Check for .NET sections
	for _, section := range p.Sections {
		if section.Name == ".text" || section.Name == ".rsrc" || section.Name == ".reloc" {
			// Check for .NET metadata in .text section
			if section.Size > 0 && strings.Contains(string(p.RawData[section.Offset:section.Offset+min(section.Size, 1024)]), "RuntimeCompatibility") {
				return true
			}
		}
	}

	return false
}

// detectDotNetCompiler determines .NET compiler
func (p *PEFile) detectDotNetCompiler() string {
	dataStr := string(p.RawData)

	if strings.Contains(dataStr, "Microsoft") && strings.Contains(dataStr, ".NET") {
		if strings.Contains(dataStr, "Framework") {
			return ".NET Framework"
		} else if strings.Contains(dataStr, "Core") {
			return ".NET Core"
		} else if strings.Contains(dataStr, "5.0") || strings.Contains(dataStr, "6.0") || strings.Contains(dataStr, "7.0") {
			return ".NET 5+"
		}
		return ".NET Compiler"
	}

	return ".NET Compiler"
}

// detectCppLanguage checks for C/C++ runtime
func (p *PEFile) detectCppLanguage() bool {
	// Check for C/C++ runtime imports
	for _, imp := range p.Imports {
		dllLower := strings.ToLower(imp.DLL)
		if strings.Contains(dllLower, "msvcr") ||
			strings.Contains(dllLower, "msvcp") ||
			strings.Contains(dllLower, "ucrtbase") ||
			strings.Contains(dllLower, "vcruntime") {
			return true
		}

		for _, fn := range imp.Functions {
			if strings.Contains(fn, "malloc") ||
				strings.Contains(fn, "free") ||
				strings.Contains(fn, "printf") ||
				strings.Contains(fn, "__") {
				return true
			}
		}
	}

	return false
}

// detectCppCompiler determines C/C++ compiler
func (p *PEFile) detectCppCompiler() string {
	dataStr := string(p.RawData)

	// Check for compiler signatures
	if strings.Contains(dataStr, "Microsoft") && (strings.Contains(dataStr, "VC++") || strings.Contains(dataStr, "MSVC")) {
		if strings.Contains(dataStr, "14.3") {
			return "MSVC 2022"
		} else if strings.Contains(dataStr, "14.2") {
			return "MSVC 2019"
		} else if strings.Contains(dataStr, "14.1") {
			return "MSVC 2017"
		}
		return "Microsoft Visual C++"
	}

	if strings.Contains(dataStr, "GCC") || strings.Contains(dataStr, "gcc") {
		return "GCC"
	}

	if strings.Contains(dataStr, "clang") || strings.Contains(dataStr, "LLVM") {
		return "Clang/LLVM"
	}

	if strings.Contains(dataStr, "MinGW") {
		return "MinGW"
	}

	// Check imports for specific compiler patterns
	for _, imp := range p.Imports {
		if strings.Contains(strings.ToLower(imp.DLL), "msvcr") {
			return "Microsoft Visual C++"
		}
	}

	return "C/C++ Compiler"
}

// detectRustLanguage checks for Rust runtime
func (p *PEFile) detectRustLanguage() bool {
	dataStr := string(p.RawData)

	rustIndicators := []string{
		"rust_", "rustc", "std::panic", "core::panic",
		"alloc::", "std::thread", "__rust_",
	}

	for _, indicator := range rustIndicators {
		if strings.Contains(dataStr, indicator) {
			return true
		}
	}

	return false
}

// detectDelphiLanguage checks for Delphi/Pascal runtime
func (p *PEFile) detectDelphiLanguage() bool {
	dataStr := string(p.RawData)

	delphiIndicators := []string{
		"Borland", "CodeGear", "Embarcadero", "TObject",
		"System.pas", "SysUtils", "Classes.pas",
	}

	for _, indicator := range delphiIndicators {
		if strings.Contains(dataStr, indicator) {
			return true
		}
	}

	return false
}

// detectDelphiCompiler determines Delphi compiler version
func (p *PEFile) detectDelphiCompiler() string {
	dataStr := string(p.RawData)

	if strings.Contains(dataStr, "Embarcadero") {
		return "Embarcadero Delphi"
	} else if strings.Contains(dataStr, "CodeGear") {
		return "CodeGear Delphi"
	} else if strings.Contains(dataStr, "Borland") {
		return "Borland Delphi"
	}

	return "Delphi Compiler"
}

// detectVBLanguage checks for Visual Basic
func (p *PEFile) detectVBLanguage() bool {
	dataStr := string(p.RawData)

	vbIndicators := []string{
		"VB5!", "VB6!", "MSVBVM", "oleaut32", "COMCTL32",
	}

	for _, indicator := range vbIndicators {
		if strings.Contains(dataStr, indicator) {
			return true
		}
	}

	return false
}

// detectByImportsAndSections tries to detect language by imports and sections
func (p *PEFile) detectByImportsAndSections() (language, compiler string) {
	// Check for specific DLL patterns
	for _, imp := range p.Imports {
		dllLower := strings.ToLower(imp.DLL)

		// Python
		if strings.Contains(dllLower, "python") {
			return "Python", "Python Runtime"
		}

		// Java (JNI)
		if strings.Contains(dllLower, "jvm") || strings.Contains(dllLower, "java") {
			return "Java", "Java Runtime"
		}

		// Node.js/JavaScript
		if strings.Contains(dllLower, "node") || strings.Contains(dllLower, "v8") {
			return "JavaScript", "Node.js/V8"
		}
	}

	// Check version info for additional clues
	if len(p.VersionInfo) > 0 {
		for key, value := range p.VersionInfo {
			keyLower := strings.ToLower(key)
			valueLower := strings.ToLower(value)

			if strings.Contains(keyLower, "language") || strings.Contains(valueLower, "language") {
				if strings.Contains(valueLower, "c++") {
					return "C++", "C++ Compiler"
				} else if strings.Contains(valueLower, "c#") {
					return "C#", ".NET Compiler"
				}
			}
		}
	}

	return "", ""
}

// min helper function
func min(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
