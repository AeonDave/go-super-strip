package perw

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"gosstrip/common"
	"regexp"
	"sort"
	"strings"
	"time"
)

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

func (p *PEFile) printSectionAnomalies() {
	fmt.Println("🚨 SECTION ANOMALY ANALYSIS")
	fmt.Println("════════════════════════════")
	infos := make([]SectionInfo, len(p.Sections))
	for i, s := range p.Sections {
		infos[i] = SectionInfo{
			Name:         s.Name,
			FileOffset:   int64(s.FileOffset),
			Size:         s.Size,
			IsExecutable: s.IsExecutable,
			IsWritable:   s.IsWritable,
		}
	}
	issues := analyzeSectionAnomalies(infos)
	if len(issues) == 0 {
		fmt.Printf("%s No section anomalies detected\n", common.SymbolCheck)
	} else {
		for _, issue := range issues {
			fmt.Println(issue)
		}
	}
	fmt.Println()
}

func (p *PEFile) Analyze() error {
	p.calculateSectionEntropy()
	p.IsPacked = p.detectPacking()
	p.printBasicInfo()
	p.printPEHeaders()
	p.printDynamicAnalysis()
	p.printSectionAnalysis()
	p.printSectionAnomalies()
	p.printImportsAnalysis()
	p.printExportAnalysis()
	p.printSymbolAnalysis()
	common.PrintSuspiciousStrings(p.RawData)
	p.printPackingAnalysis()
	return nil
}

func (p *PEFile) calculateSectionEntropy() {
	for i, section := range p.Sections {
		if section.Size > 0 && section.Offset+section.Size <= int64(len(p.RawData)) {
			p.Sections[i].Entropy = common.CalculateEntropy(p.RawData[section.Offset : section.Offset+section.Size])
		}
	}
}

func (p *PEFile) detectPacking() bool {
	if len(p.Sections) == 0 {
		return false
	}

	highEntropyCount := 0
	anomalousCount := 0
	totalValidSections := 0

	for _, section := range p.Sections {

		if isDebugSection(section.Name) {
			continue
		}

		if section.Size == 0 {
			continue
		}

		totalValidSections++

		if section.Entropy > 7.0 {
			highEntropyCount++
		}

		if section.IsExecutable && section.IsWritable {
			anomalousCount++
		}
	}

	if totalValidSections == 0 {
		return false
	}

	highEntropyRatio := float64(highEntropyCount) / float64(totalValidSections)
	anomalousRatio := float64(anomalousCount) / float64(totalValidSections)

	if anomalousRatio > 0 {

		return true
	}

	if highEntropyRatio >= 0.5 {

		return true
	}

	if totalValidSections <= 3 && highEntropyCount >= 1 {

		return true
	}

	return false
}

func (p *PEFile) printBasicInfo() {
	fmt.Println("📁 BINARY INFORMATION")
	fmt.Println("═════════════════════")

	fmt.Printf("File Name:       %s\n", p.FileName)
	fmt.Printf("File Size:       %s (%d bytes)\n", common.FormatFileSize(p.FileSize), p.FileSize)

	if p.RawData != nil {
		md5Hash := md5.Sum(p.RawData)
		sha256Hash := sha256.Sum256(p.RawData)
		fmt.Printf("MD5 Hash:        %s\n", hex.EncodeToString(md5Hash[:]))
		fmt.Printf("SHA256 Hash:     %s\n", hex.EncodeToString(sha256Hash[:]))
	}

	fmt.Printf("Architecture:    %s\n", map[bool]string{true: "x64 (64-bit)", false: "x86 (32-bit)"}[p.Is64Bit])
	if p.Machine != "" {
		fmt.Printf("Machine Type:    %s\n", p.Machine)
	}

	language, compiler := p.detectLanguageAndCompiler()
	if language != "" {
		fmt.Printf("Language:        %s\n", language)
	}
	if compiler != "" {
		fmt.Printf("Compiler:        %s\n", compiler)
	}

	fmt.Printf("Sections:        %d total\n", len(p.Sections))
	fmt.Printf("\n💾 SPACE UTILIZATION:\n")
	var totalSectionSize int64
	for _, section := range p.Sections {
		totalSectionSize += section.Size
	}
	overhead := p.FileSize - totalSectionSize
	efficiency := float64(totalSectionSize) / float64(p.FileSize) * 100
	fmt.Printf("Total Section Size: %s\n", common.FormatFileSize(totalSectionSize))
	fmt.Printf("File Overhead:      %s\n", common.FormatFileSize(overhead))
	fmt.Printf("File Efficiency:    %.1f%%\n", efficiency)

	fmt.Printf("\n🗂️  OVERLAY ANALYSIS:\n")
	if len(p.Sections) > 0 && p.RawData != nil {
		last := p.Sections[len(p.Sections)-1]
		present, offset, size, entropy := overlayInfo(p.FileSize, last.Offset, last.Size, p.RawData)
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

	fmt.Println()
}

func (p *PEFile) printPEHeaders() {
	fmt.Println("🏗️  PE HEADER INFORMATION")
	fmt.Println("═══════════════════════════")

	fmt.Printf("Packed Status:   %s\n", map[bool]string{true: "📦 Likely PACKED", false: "✅ Not packed"}[p.IsPacked])
	fmt.Printf("Image Base:      0x%X\n", p.imageBase)
	fmt.Printf("Entry Point:     0x%X (RVA)\n", p.entryPoint)
	fmt.Printf("Size of Image:   %d bytes (%s)\n", p.sizeOfImage, common.FormatFileSize(int64(p.sizeOfImage)))
	fmt.Printf("Size of Headers: %d bytes\n", p.sizeOfHeaders)

	checksum := p.checksum
	if checksum != 0 {
		fmt.Printf("Checksum:        0x%X\n", checksum)
	} else {
		fmt.Printf("Checksum:        Not set\n")
	}

	fmt.Printf("File Type:       %s\n", p.GetFileType())
	subsystemName := getSubsystemName(p.subsystem)
	fmt.Printf("Subsystem:       %d (%s)\n", p.subsystem, subsystemName)

	dllChars := decodeDLLCharacteristics(p.dllCharacteristics)
	fmt.Printf("DLL Characteristics: 0x%X (%s)\n", p.dllCharacteristics, dllChars)

	directories := p.directories
	nonEmptyDirs := 0
	for _, dir := range directories {
		if dir.RVA != 0 || dir.Size != 0 {
			nonEmptyDirs++
		}
	}
	if nonEmptyDirs > 0 {
		fmt.Printf("Data Directories: %d active entries\n", nonEmptyDirs)
	}

	if p.TimeDateStamp != "" {
		fmt.Printf("\n⏰ TIMESTAMP INFO:\n")
		fmt.Printf("Compile Time:    %s\n", p.TimeDateStamp)

		if p.TimeDateStamp != "Not set" && p.TimeDateStamp != "-" {
			if timestamp, err := time.Parse("2006-01-02 15:04:05 MST", p.TimeDateStamp); err == nil {
				now := time.Now().UTC()
				age := now.Sub(timestamp)
				ageDays := age.Hours() / 24

				if ageDays < 0 {
					fmt.Printf("File Age:        0 days (compiled today)\n")
				} else {
					fmt.Printf("File Age:        %s\n", common.FormatFileAge(ageDays))
				}
			}
		}
	}

	versionInfo := p.VersionInfo
	if versionInfo != nil && len(versionInfo) > 0 {
		fmt.Printf("\n📄 VERSION DETAILS:\n")

		keyOrder := []string{"FileDescription", "FileVersion", "ProductVersion", "CompanyName", "LegalCopyright", "OriginalFilename", "ProductName", "InternalName"}

		for _, key := range keyOrder {
			if value, exists := versionInfo[key]; exists {
				fmt.Printf("%-20s %s\n", key+":", value)
			}
		}

		for key, value := range versionInfo {
			found := false
			for _, orderedKey := range keyOrder {
				if key == orderedKey {
					found = true
					break
				}
			}
			if !found {
				fmt.Printf("%-20s %s\n", key+":", value)
			}
		}
	}

	fmt.Printf("\n🔧 RICH HEADER INFO:\n")

	if len(p.RawData) > PE_MIN_DATA_FOR_RICH_ANALYSIS {
		richFound := false

		searchLimit := PE_RICH_HEADER_SEARCH_LIMIT
		if len(p.RawData) < searchLimit {
			searchLimit = len(p.RawData)
		}
		for i := 0; i < searchLimit-4; i++ {
			if string(p.RawData[i:i+4]) == "Rich" {
				richFound = true
				break
			}
		}

		if richFound {
			fmt.Printf("Rich Header:     ✅ Present (compiler metadata)\n")
		} else {
			fmt.Printf("Rich Header:     ⚠️ Not found or stripped\n")
		}
	} else {
		fmt.Printf("Rich Header:     ❓ Cannot analyze (insufficient data)\n")
	}

	if p.PDBPath != "" && p.PDBPath != "@" && !strings.HasPrefix(p.PDBPath, "@") {
		fmt.Printf("\n🐛 DEBUG INFO:\n")
		fmt.Printf("Debug Info:      %s\n", p.PDBPath)
		if p.guidAge != "" {
			fmt.Printf("GUID/Age:        %s\n", p.guidAge)
		}
	}

	fmt.Printf("\n🔧 FILE INTEGRITY & COMPLIANCE:\n")
	var issues []string
	var warnings []string
	checks := 0
	failures := 0

	// Check 1: PE parsed
	checks++
	if p.PE == nil {
		issues = append(issues, "PE Parser:        ❌ PE headers not parsed")
		failures++
	}

	// Check 2: Sections present
	checks++
	if len(p.Sections) == 0 {
		issues = append(issues, "Sections:         ❌ No sections present")
		failures++
	}

	// Check 3: SizeOfImage sanity
	checks++
	if p.sizeOfImage == 0 {
		issues = append(issues, "SizeOfImage:      ❌ Not set")
		failures++
	} else {
		// Max end of sections should not exceed SizeOfImage
		var maxEnd uint32
		for _, s := range p.Sections {
			end := s.VirtualAddress + s.VirtualSize
			if end > maxEnd {
				maxEnd = end
			}
		}
		if maxEnd != 0 && maxEnd > p.sizeOfImage {
			warnings = append(warnings, fmt.Sprintf("SizeOfImage:      ⚠️ Smaller than sections (max end 0x%X)", maxEnd))
			failures++
		}
	}

	// Check 4: Entry point validity
	checks++
	if p.entryPoint == 0 {
		warnings = append(warnings, "Entry Point:      ⚠️ Not set")
		failures++
	} else {
		var epSection *Section
		for i := range p.Sections {
			s := &p.Sections[i]
			start := s.VirtualAddress
			end := s.VirtualAddress + max32(s.VirtualSize, uint32(s.Size))
			if p.entryPoint >= start && p.entryPoint < end {
				epSection = s
				break
			}
		}
		if epSection == nil {
			issues = append(issues, fmt.Sprintf("Entry Point:      ❌ RVA 0x%X not inside any section", p.entryPoint))
			failures++
		} else if !epSection.IsExecutable {
			warnings = append(warnings, fmt.Sprintf("Entry Point:      ⚠️ In non-executable section '%s'", epSection.Name))
			failures++
		}
	}

	// Check 5: Sections order and overlap in file
	checks++
	if len(p.Sections) > 0 {
		prevEnd := int64(0)
		firstOffset := int64(-1)
		for idx, s := range p.Sections {
			if idx == 0 {
				firstOffset = int64(s.FileOffset)
			}
			end := int64(s.FileOffset) + s.Size
			if s.Size > 0 {
				if int64(s.FileOffset) < prevEnd {
					issues = append(issues, fmt.Sprintf("Sections:         ❌ Overlap at section '%s' (file offsets)", s.Name))
					failures++
				}
				prevEnd = end
			}
			if end > p.FileSize {
				issues = append(issues, fmt.Sprintf("Section Bounds:   ❌ Section '%s' exceeds file size", s.Name))
				failures++
			}
		}
		// Header size should not exceed first section offset
		if firstOffset >= 0 && p.sizeOfHeaders > 0 && int64(p.sizeOfHeaders) > firstOffset {
			warnings = append(warnings, fmt.Sprintf("SizeOfHeaders:    ⚠️ Larger (0x%X) than first section offset (0x%X)", p.sizeOfHeaders, uint32(firstOffset)))
			failures++
		}
	}

	// Check 6: Data directories within image
	checks++
	if len(p.directories) > 0 && p.sizeOfImage > 0 {
		for _, d := range p.directories {
			if d.RVA == 0 || d.Size == 0 {
				continue
			}
			end := d.RVA + d.Size
			if end > p.sizeOfImage {
				warnings = append(warnings, fmt.Sprintf("Data Directory:   ⚠️ Type %d out of image (end 0x%X > SizeOfImage 0x%X)", d.Type, end, p.sizeOfImage))
				failures++
			}
		}
	}

	// Check 7: Suspicious RWX sections
	checks++
	for _, s := range p.Sections {
		if s.IsExecutable && s.IsWritable {
			warnings = append(warnings, fmt.Sprintf("Section Flags:    ⚠️ Section '%s' is executable and writable", s.Name))
			failures++
		}
	}

	// Summarize
	if len(issues) == 0 && len(warnings) == 0 {
		fmt.Printf("Structure:       ✅ No integrity issues found\n")
	} else {
		for _, msg := range issues {
			fmt.Println(msg)
		}
		for _, msg := range warnings {
			fmt.Println(msg)
		}
	}

	fmt.Printf("PE Compliance:   %d/%d checks passed\n", checks-failures, checks)

	if failures == 0 {
		fmt.Printf("Overall Status:  ✅ Fully compliant PE file\n")
	} else if failures <= 2 {
		fmt.Printf("Overall Status:  ⚠️ Minor issues detected\n")
	} else {
		fmt.Printf("Overall Status:  ❌ Significant issues detected\n")
	}

	fmt.Printf("\n🧠 MEMORY LAYOUT:\n")
	imageSize := p.sizeOfImage
	fmt.Printf("Image Size:      %s (0x%X)\n", common.FormatFileSize(int64(imageSize)), imageSize)

	var usedSpace int64
	for _, section := range p.Sections {
		usedSpace += section.Size
	}

	usedPercent := float64(usedSpace) / float64(imageSize) * 100
	wastePercent := 100 - usedPercent

	fmt.Printf("Used Space:      %s (%.1f%%)\n", common.FormatFileSize(usedSpace), usedPercent)
	fmt.Printf("Alignment Waste: %s (%.1f%%)\n", common.FormatFileSize(int64(imageSize)-usedSpace), wastePercent)

	if wastePercent > 50 {
		fmt.Printf("Efficiency:      ❌ Poor (>50%% waste)\n")
	} else if wastePercent > 25 {
		fmt.Printf("Efficiency:      ⚠️ Fair (>25%% waste)\n")
	} else {
		fmt.Printf("Efficiency:      ✅ Good\n")
	}

	fmt.Println()
}

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
		totalSize += section.Size
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
	fmt.Println("┌──────────────────┬─────────────┬─────────────┬─────────────┬─────────────┬─────────┐")
	fmt.Println("│ Name             │ Virtual Addr│ File Offset │ Size        │ Permissions │ Entropy │")
	fmt.Println("├──────────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────┤")
	for _, section := range p.Sections {
		permissions := common.FormatPermissions(section.IsExecutable, section.IsReadable, section.IsWritable)
		entropyColor := common.GetEntropyColor(section.Entropy)
		entropyStr := fmt.Sprintf("%.2f", section.Entropy)
		if section.Entropy > 7.5 {
			entropyStr += "🔺"
		} else if section.Entropy < 1.0 {
			entropyStr += "🔻"
		} else {
			entropyStr += "🔹"
		}
		fmt.Printf("│ %-16s │ 0x%08X  │ 0x%08X  │ %-11s │ %-11s │ %s%-6s%s │\n",
			common.TruncateString(section.Name, 16),
			section.VirtualAddress,
			section.FileOffset,
			common.FormatFileSize(section.Size),
			permissions,
			entropyColor,
			entropyStr,
			"\033[0m")
	}
	fmt.Println("└──────────────────┴─────────────┴─────────────┴─────────────┴─────────────┴─────────┘")
	fmt.Println()
}

func (p *PEFile) printImportsAnalysis() {
	fmt.Println("📦 IMPORTS ANALYSIS")
	fmt.Println("═══════════════════")
	if len(p.Imports) == 0 {
		fmt.Println("❌ No imports found")
		fmt.Println()
		return
	}

	var dllsWithFunctions []ImportInfo
	var dllsWithoutFunctions []ImportInfo
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

	if len(dllsWithFunctions) > 0 {

		sort.Slice(dllsWithFunctions, func(i, j int) bool {
			return strings.ToUpper(dllsWithFunctions[i].LibraryName) < strings.ToUpper(dllsWithFunctions[j].LibraryName)
		})

		fmt.Println("IMPORTED LIBRARIES WITH FUNCTIONS:")
		for _, imp := range dllsWithFunctions {
			dllName := strings.ToUpper(imp.LibraryName)

			functionCount := make(map[string]int)
			for _, fn := range imp.Functions {
				functionCount[fn]++
			}

			uniqueFunctions := len(functionCount)
			fmt.Printf("\n📚 %s (%d functions, %d unique)\n", dllName, len(imp.Functions), uniqueFunctions)

			functionNames := make([]string, 0, len(functionCount))
			for fn := range functionCount {
				functionNames = append(functionNames, fn)
			}
			sort.Strings(functionNames)

			for _, fn := range functionNames {
				count := functionCount[fn]
				if count > 1 {
					fmt.Printf("   • %s (×%d)\n", fn, count)
				} else {
					fmt.Printf("   • %s\n", fn)
				}
			}
		}
	}

	if len(dllsWithoutFunctions) > 0 {

		sort.Slice(dllsWithoutFunctions, func(i, j int) bool {
			return strings.ToUpper(dllsWithoutFunctions[i].LibraryName) < strings.ToUpper(dllsWithoutFunctions[j].LibraryName)
		})

		fmt.Printf("\n\n📋 LIBRARIES WITHOUT FUNCTIONS (%d):\n", len(dllsWithoutFunctions))
		for _, imp := range dllsWithoutFunctions {
			fmt.Printf("   • %s\n", strings.ToUpper(imp.LibraryName))
		}
	}

	fmt.Println()
}

func (p *PEFile) detectLanguageAndCompiler() (language, compiler string) {
	if p.RawData == nil {
		return "", ""
	}

	dataStr := string(p.RawData)
	if strings.Contains(dataStr, "go:buildid") ||
		strings.Contains(dataStr, "runtime.") ||
		strings.Contains(dataStr, "go1.") ||
		strings.Contains(dataStr, "golang.org/") {
		language = "Go"
		if match := regexp.MustCompile(`go1\.([0-9]{1,2})(?:\.([0-9]{1,2}))?`).FindStringSubmatch(dataStr); len(match) > 0 {
			compiler = "Go " + match[0]
		} else {
			compiler = "Go (version unknown)"
		}
		return
	}

	if strings.Contains(dataStr, "System.") ||
		strings.Contains(dataStr, "mscorlib") ||
		strings.Contains(dataStr, "Microsoft.") ||
		strings.Contains(dataStr, ".ctor") ||
		strings.Contains(dataStr, "System.Private.CoreLib") {
		language = "C#/.NET"
		if strings.Contains(dataStr, ".NET Framework") {
			compiler = ".NET Framework"
		} else if strings.Contains(dataStr, ".NET Core") || strings.Contains(dataStr, "System.Private.CoreLib") {
			compiler = ".NET Core/5+"
		} else {
			compiler = ".NET (version unknown)"
		}
		return
	}

	if strings.Contains(dataStr, "rust_panic") ||
		strings.Contains(dataStr, "core::panic") ||
		strings.Contains(dataStr, "alloc::vec") ||
		strings.Contains(dataStr, "__rust_") ||
		strings.Contains(dataStr, "std::") {
		language = "Rust"
		if match := regexp.MustCompile(`rustc ([0-9]+\.[0-9]+\.[0-9]+)`).FindStringSubmatch(dataStr); len(match) > 1 {
			compiler = "rustc " + match[1]
		} else {
			compiler = "rustc (version unknown)"
		}
		return
	}

	if strings.Contains(dataStr, "__libc_") ||
		strings.Contains(dataStr, "__glibc_") ||
		strings.Contains(dataStr, "libgcc") ||
		strings.Contains(dataStr, "__cxa_") ||
		strings.Contains(dataStr, "mingw") {
		if strings.Contains(dataStr, "__cplusplus") ||
			strings.Contains(dataStr, "libstdc++") ||
			strings.Contains(dataStr, "__cxa_") {
			language = "C++"
		} else {
			language = "C"
		}

		if match := regexp.MustCompile(`GCC: \([^)]+\) ([0-9]+\.[0-9]+\.[0-9]+)`).FindStringSubmatch(dataStr); len(match) > 1 {
			compiler = "GCC " + match[1]
		} else if strings.Contains(dataStr, "mingw") {
			if match := regexp.MustCompile(`mingw[^0-9]*([0-9]+\.[0-9]+)`).FindStringSubmatch(dataStr); len(match) > 1 {
				compiler = "MinGW-w64 " + match[1]
			} else {
				compiler = "MinGW-w64"
			}
		} else if strings.Contains(dataStr, "libgcc") {
			compiler = "GCC (version unknown)"
		} else {
			compiler = "Unknown C/C++ compiler"
		}
		return
	}

	if strings.Contains(dataStr, "VCRUNTIME") ||
		strings.Contains(dataStr, "vcruntime") ||
		strings.Contains(dataStr, "MSVCR") ||
		strings.Contains(dataStr, "api-ms-win-crt") {
		if strings.Contains(dataStr, "std::") ||
			strings.Contains(dataStr, "class ") ||
			strings.Contains(dataStr, "namespace ") {
			language = "C++"
		} else {
			language = "C"
		}

		if strings.Contains(dataStr, "vcruntime140") {
			compiler = "MSVC 2015-2022"
		} else if strings.Contains(dataStr, "vcruntime120") {
			compiler = "MSVC 2013"
		} else if strings.Contains(dataStr, "vcruntime110") {
			compiler = "MSVC 2012"
		} else {
			compiler = "MSVC (version unknown)"
		}
		return
	}

	if strings.Contains(dataStr, "python") ||
		strings.Contains(dataStr, "PyObject") ||
		strings.Contains(dataStr, "_Py_") {
		language = "Python"

		if match := regexp.MustCompile(`Python ([0-9]+\.[0-9]+)`).FindStringSubmatch(dataStr); len(match) > 1 {
			compiler = "Python " + match[1]
		} else {
			compiler = "Python (version unknown)"
		}
		return
	}

	if strings.Contains(dataStr, "java.") ||
		strings.Contains(dataStr, "com.oracle") ||
		strings.Contains(dataStr, "graalvm") {
		language = "Java"

		if strings.Contains(dataStr, "graalvm") {
			compiler = "GraalVM Native Image"
		} else {
			compiler = "Java (native compiled)"
		}
		return
	}

	if len(p.Imports) == 0 && len(p.Exports) == 0 {
		language = "Assembly/Binary"
		compiler = "Unknown assembler"
		return
	}

	return "", ""
}

func (p *PEFile) printSymbolAnalysis() {
	fmt.Println("🔤 SYMBOL ANALYSIS")
	fmt.Println("══════════════════")

	// In PE files, symbols are primarily imports and exports
	totalSymbols := len(p.Imports) + len(p.Exports)

	// Count total functions
	totalFunctions := 0
	for _, imp := range p.Imports {
		totalFunctions += len(imp.Functions)
	}

	if totalSymbols == 0 && totalFunctions == 0 {
		fmt.Printf("❌ No symbols found\n")
		fmt.Println()
		return
	}

	fmt.Printf("Total Symbols: %d\n\n", totalFunctions+len(p.Exports))

	// Categorize symbols
	importedSymbols := totalFunctions
	exportedSymbols := len(p.Exports)

	// Estimate function vs data symbols (heuristic)
	functionSymbols := 0
	objectSymbols := 0

	for _, exp := range p.Exports {
		if strings.HasPrefix(exp.Name, "?") || // C++ mangled names
			strings.Contains(exp.Name, "Proc") ||
			strings.Contains(exp.Name, "Func") ||
			strings.Contains(exp.Name, "Call") {
			functionSymbols++
		} else {
			objectSymbols++
		}
	}

	// Add imported functions
	functionSymbols += importedSymbols

	fmt.Printf("SYMBOL STATISTICS:\n")
	fmt.Printf("  Exported symbols: %d\n", exportedSymbols)
	fmt.Printf("  Imported symbols: %d\n", importedSymbols)
	fmt.Printf("  Function symbols: %d\n", functionSymbols)
	fmt.Printf("  Object symbols:   %d\n", objectSymbols)
	fmt.Println()
}

func (p *PEFile) printDynamicAnalysis() {
	fmt.Println("🔗 DYNAMIC LINKING ANALYSIS")
	fmt.Println("═══════════════════════════")

	// PE files are typically dynamically linked
	fmt.Printf("Dynamic Binary:   ✅ YES\n")

	// Check for import directory
	hasImportDir := false
	hasExportDir := false
	hasRelocDir := false
	hasTlsDir := false
	hasResourceDir := false
	hasDebugDir := false
	hasSecurityDir := false
	hasClrDir := false

	for _, dir := range p.directories {
		switch dir.Type {
		case IMAGE_DIRECTORY_ENTRY_IMPORT:
			hasImportDir = true
		case IMAGE_DIRECTORY_ENTRY_EXPORT:
			hasExportDir = true
		case IMAGE_DIRECTORY_ENTRY_BASERELOC:
			hasRelocDir = true
		case IMAGE_DIRECTORY_ENTRY_TLS:
			hasTlsDir = true
		case IMAGE_DIRECTORY_ENTRY_RESOURCE:
			hasResourceDir = true
		case IMAGE_DIRECTORY_ENTRY_DEBUG:
			hasDebugDir = true
		case IMAGE_DIRECTORY_ENTRY_SECURITY:
			hasSecurityDir = true
		case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
			hasClrDir = true
		}
	}

	fmt.Printf("\n🔧 DYNAMIC SECTIONS ANALYSIS:\n")
	fmt.Printf("Import Table:     %s\n", formatPresence(hasImportDir))
	if hasExportDir {
		if len(p.Exports) > 0 {
			fmt.Printf("Export Table:     ✅ Present (%d functions)\n", len(p.Exports))
		} else {
			fmt.Printf("Export Table:     ✅ Present (0 functions)\n")
		}
	} else {
		fmt.Printf("Export Table:     ❌ Missing\n")
	}
	fmt.Printf("Relocation:       %s\n", formatPresence(hasRelocDir))
	fmt.Printf("TLS Directory:    %s\n", formatPresence(hasTlsDir))
	fmt.Printf("Resources:        %s\n", formatPresence(hasResourceDir))
	fmt.Printf("Debug Info:       %s\n", formatPresence(hasDebugDir))
	fmt.Printf("Security/Signature: %s\n", formatPresence(hasSecurityDir))
	fmt.Printf("CLR/.NET:         %s\n", formatPresence(hasClrDir))

	// Security analysis
	fmt.Printf("\n🛡️  SECURITY FEATURES:\n")

	// ASLR support
	aslrStatus := "❌ NO ASLR"
	if p.dllCharacteristics&0x0040 != 0 { // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		aslrStatus = "✅ ASLR enabled"
	}
	fmt.Printf("ASLR:             %s\n", aslrStatus)

	// DEP/NX support
	depStatus := "❌ NO DEP/NX"
	if p.dllCharacteristics&0x0100 != 0 { // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
		depStatus = "✅ DEP/NX enabled"
	}
	fmt.Printf("DEP/NX:           %s\n", depStatus)

	// Control Flow Guard
	cfgStatus := "❌ NO CFG"
	if p.dllCharacteristics&0x4000 != 0 { // IMAGE_DLLCHARACTERISTICS_GUARD_CF
		cfgStatus = "✅ CFG enabled"
	}
	fmt.Printf("CFG:              %s\n", cfgStatus)

	// SafeSEH
	sehStatus := "❓ Unknown (64-bit doesn't use SEH)"
	if !p.Is64Bit {
		if p.dllCharacteristics&0x0400 != 0 { // IMAGE_DLLCHARACTERISTICS_NO_SEH
			sehStatus = "❌ NO SafeSEH"
		} else {
			// This is a heuristic, not 100% accurate
			sehStatus = "🤔 Possibly enabled"
		}
	}
	fmt.Printf("SafeSEH:          %s\n", sehStatus)

	fmt.Println()
}

// Helper function to format presence indicators
func formatPresence(present bool) string {
	if present {
		return "✅ Present"
	}
	return "❌ Missing"
}

// max32 returns the maximum of two uint32 values.
func max32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func (p *PEFile) printPackingAnalysis() {
	fmt.Println("📦 PACKING ANALYSIS")
	fmt.Println("═══════════════════")

	if len(p.Sections) == 0 {
		fmt.Printf("Status:          ❓ No sections available for analysis\n")
		fmt.Println()
		return
	}

	highEntropyCount := 0
	anomalousCount := 0
	totalValidSections := 0
	emptyCount := 0
	debugCount := 0

	var totalValidBytes int64
	var highEntropyBytes int64

	for _, section := range p.Sections {
		if isDebugSection(section.Name) {
			debugCount++
			continue
		}

		if section.Size == 0 {
			emptyCount++
			continue
		}

		totalValidSections++
		totalValidBytes += section.Size

		if section.Entropy > 7.0 {
			highEntropyCount++
			highEntropyBytes += section.Size
		}

		if section.IsExecutable && section.IsWritable {
			anomalousCount++
		}
	}

	fmt.Printf("Valid Sections:  %d (filtered %d debug, %d empty)\n",
		totalValidSections, debugCount, emptyCount)

	if totalValidSections > 0 {
		sectionRatio := float64(highEntropyCount) / float64(totalValidSections)
		dataRatio := float64(highEntropyBytes) / float64(totalValidBytes)

		fmt.Printf("High Entropy:    %d/%d sections (%.0f%% sections, %.0f%% data >7.0 entropy)\n",
			highEntropyCount, totalValidSections, sectionRatio*100, dataRatio*100)
	}

	if anomalousCount > 0 {
		fmt.Printf("RWX Sections:    %d sections with execute+write permissions\n", anomalousCount)
	}

	if p.IsPacked {
		fmt.Printf("Status:          ❌ PACKED executable detected\n")
	} else {
		fmt.Printf("Status:          ✅ Normal executable\n")
	}

	fmt.Println()
}

func analyzeSectionAnomalies(sections []SectionInfo) []string {
	var issues []string

	for i, s := range sections {
		if s.Size == 0 {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' has zero size")
		}
		if s.IsExecutable && s.IsWritable {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' is both executable and writable (RWX)")
		}
		if len(s.Name) == 0 || s.Name == "\x00" {
			issues = append(issues, common.SymbolWarn+" Section with empty or invalid name")
		}
		if i > 0 && s.FileOffset < sections[i-1].FileOffset+sections[i-1].Size {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' overlaps previous section")
		}
		// 1. Suspicious section names
		if isSuspiciousSectionName(s.Name) {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' has suspicious/unusual name")
		}
		// 2. Abnormal section sizes
		if s.Size > 100*1024*1024 { // > 100MB
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' is unusually large ("+formatSize(s.Size)+")")
		}
		// 3. Sections with negative file offsets
		if s.FileOffset < 0 {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' has invalid file offset")
		}
		// 4. Sections with non-aligned file offsets
		if s.FileOffset > 0 && s.FileOffset%PE_FILE_ALIGNMENT_DEFAULT != 0 {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' has non-aligned file offset (0x"+fmt.Sprintf("%X", s.FileOffset)+")")
		}
		// 5. Executable sections unexpected
		if s.IsExecutable && !isExpectedExecutableSection(s.Name) {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' is executable but has unexpected name")
		}
		// 6. Writable sections unexpected
		if s.IsWritable && !isExpectedWritableSection(s.Name) {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' is writable but has unexpected name")
		}
		// 7. Unusual section order
		if i > 0 && isWrongSectionOrder(sections[i-1].Name, s.Name) {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' appears after '"+sections[i-1].Name+"' (unusual order)")
		}
		// 8. Gap too large between sections
		if i > 0 {
			prevEnd := sections[i-1].FileOffset + sections[i-1].Size
			gap := s.FileOffset - prevEnd
			if gap > 64*1024 { // Gap > 64KB
				issues = append(issues, common.SymbolWarn+" Large gap ("+formatSize(gap)+") between '"+sections[i-1].Name+"' and '"+s.Name+"'")
			}
		}
		// 9. Sections with unusual permissions
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
	analyzeGlobalSectionAnomalies(sections, &issues)
	return issues
}

func isSuspiciousSectionName(name string) bool {
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

func isExpectedExecutableSection(name string) bool {
	executableSections := []string{".text", ".code", "CODE", ".init", ".fini"}
	name = strings.ToLower(name)
	for _, expected := range executableSections {
		if strings.HasPrefix(name, strings.ToLower(expected)) {
			return true
		}
	}
	return false
}

func isExpectedWritableSection(name string) bool {
	writableSections := []string{".data", ".bss", ".rdata", ".idata", ".tls", ".CRT"}
	name = strings.ToLower(name)
	for _, expected := range writableSections {
		if strings.HasPrefix(name, strings.ToLower(expected)) {
			return true
		}
	}
	return false
}

func isWrongSectionOrder(prev, current string) bool {
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

func isDebugSection(name string) bool {
	name = strings.ToLower(name)
	return strings.HasPrefix(name, ".debug") ||
		strings.HasPrefix(name, ".zdebug") ||
		name == ".symtab" ||
		strings.Contains(name, "gdb")
}

func analyzeGlobalSectionAnomalies(sections []SectionInfo, issues *[]string) {
	if len(sections) < 3 {
		*issues = append(*issues, common.SymbolWarn+" Very few sections ("+fmt.Sprintf("%d", len(sections))+") - possible packing")
	}
	if len(sections) > 20 {
		*issues = append(*issues, common.SymbolWarn+" Unusually many sections ("+fmt.Sprintf("%d", len(sections))+")")
	}
	hasExecutable := false
	for _, s := range sections {
		if s.IsExecutable {
			hasExecutable = true
			break
		}
	}
	if !hasExecutable {
		*issues = append(*issues, common.SymbolWarn+" No executable sections found")
	}
	nameCount := make(map[string]int)
	for _, s := range sections {
		nameCount[s.Name]++
	}
	for name, count := range nameCount {
		if count > 1 {
			*issues = append(*issues, common.SymbolWarn+" Duplicate section name '"+name+"' ("+fmt.Sprintf("%d", count)+" times)")
		}
	}
}

func formatSize(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	} else {
		return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
	}
}

func overlayInfo(fileSize int64, lastSectionOffset int64, lastSectionSize int64, data []byte) (present bool, offset int64, size int64, entropy float64) {
	overlayStart := lastSectionOffset + lastSectionSize
	if overlayStart < fileSize {
		overlayData := data[overlayStart:]
		return true, overlayStart, int64(len(overlayData)), common.CalculateEntropy(overlayData)
	}
	return false, 0, 0, 0
}
