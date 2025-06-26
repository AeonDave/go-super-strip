package perw

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"gosstrip/common"
	"sort"
	"strings"
	"time"
)

func isDebugSection(name string) bool {
	name = strings.ToLower(name)
	return strings.HasPrefix(name, ".debug") ||
		strings.HasPrefix(name, ".zdebug") ||
		name == ".symtab" ||
		strings.Contains(name, "gdb")
}

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

type SectionInfo struct {
	Name         string
	FileOffset   int64
	Size         int64
	IsExecutable bool
	IsWritable   bool
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

func (p *PEFile) Analyze() error {
	// Calculate entropy and packing detection for all sections
	p.calculateSectionEntropy()
	p.IsPacked = p.detectPacking()

	// Print comprehensive analysis
	p.printHeader()
	p.printBasicInfo()
	p.printPEHeaders()
	p.printComprehensiveSecurityAnalysis()
	p.printSectionAnalysis()
	p.printSectionAnomalies()
	p.printImportsAnalysis()
	p.printImportHashAnalysis()
	p.printExportAnalysis()
	p.printNetworkIndicators()
	p.printResourceAnalysis()
	PrintSuspiciousStrings(p)
	return nil
}

func (p *PEFile) printHeader() {
	fmt.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                           PE FILE ANALYSIS REPORT                            ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

func (p *PEFile) calculateSectionEntropy() {
	for i, section := range p.Sections {
		if section.Size > 0 && section.Offset+section.Size <= int64(len(p.RawData)) {
			p.Sections[i].Entropy = CalculateEntropy(p.RawData[section.Offset : section.Offset+section.Size])
		}
	}
}

func (p *PEFile) detectPacking() bool {
	// Use the same logic as packing score for consistency
	score := p.calculatePackingScore()
	return score >= 70 // Same threshold as advanced analysis
}

func (p *PEFile) calculatePackingScore() int {
	// Count only high entropy sections (excluding debug sections)
	highEntropyCount := 0
	totalNonDebugSections := 0

	for _, section := range p.Sections {
		if isDebugSection(section.Name) {
			continue
		}
		totalNonDebugSections++
		if section.Entropy > 7.5 {
			highEntropyCount++
		}
	}

	// Simple entropy-based scoring
	if totalNonDebugSections == 0 {
		return 0
	}

	// Calculate percentage of high entropy sections
	entropyPercentage := float64(highEntropyCount) / float64(totalNonDebugSections)
	score := int(entropyPercentage * 100)

	// Bonus for multiple high entropy sections
	if highEntropyCount > 1 {
		score += 20
	}

	if score > 100 {
		score = 100
	}

	return score
}

func (p *PEFile) printBasicInfo() {
	fmt.Println("📁 BINARY INFORMATION")
	fmt.Println("═════════════════════")

	// Basic file information
	fmt.Printf("File Name:       %s\n", p.FileName)
	fmt.Printf("File Size:       %s (%d bytes)\n", common.FormatFileSize(p.FileSize), p.FileSize)

	// Calculate file hashes
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

	// Enhanced header information
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

	// Overlay analysis
	fmt.Printf("\n🗂️  OVERLAY ANALYSIS:\n")
	if len(p.Sections) > 0 && p.RawData != nil {
		last := p.Sections[len(p.Sections)-1]
		present, offset, size, entropy := OverlayInfo(p.FileSize, last.Offset, last.Size, p.RawData)
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

	// === CORE PE STRUCTURE ===
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

	// === TIMESTAMP ANALYSIS ===
	if p.TimeDateStamp != "" {
		fmt.Printf("\n⏰ TIMESTAMP INFO:\n")
		fmt.Printf("Compile Time:    %s\n", p.TimeDateStamp)

		// Only try to parse if not 'Not set' or similar
		if p.TimeDateStamp != "Not set" && p.TimeDateStamp != "-" {
			if timestamp, err := time.Parse("2006-01-02 15:04:05 MST", p.TimeDateStamp); err == nil {
				now := time.Now().UTC()
				age := now.Sub(timestamp)
				fmt.Printf("Timestamp:       ✅ Normal\n")
				fmt.Printf("File Age:        %.1f days\n", age.Hours()/24)
			} else {
				fmt.Printf("Timestamp:       ⚠️ Unparsable: '%s'\n", p.TimeDateStamp)
			}
		}
	}

	// === VERSION INFORMATION ===
	versionInfo := p.VersionInfo()
	if len(versionInfo) > 0 {
		fmt.Printf("\n📄 VERSION DETAILS:\n")
		// Order version information professionally
		keyOrder := []string{"FileDescription", "FileVersion", "ProductVersion", "CompanyName", "LegalCopyright", "OriginalFilename", "ProductName", "InternalName"}

		// Print in preferred order
		for _, key := range keyOrder {
			if value, exists := versionInfo[key]; exists {
				fmt.Printf("%-20s %s\n", key+":", value)
			}
		}

		// Print any remaining keys not in the ordered list
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

	// === RICH HEADER ANALYSIS ===
	fmt.Printf("\n🔧 RICH HEADER INFO:\n")
	// Check for Rich Header presence (simplified check)
	if len(p.RawData) > 200 {
		richFound := false
		// Look for Rich signature in the first 1KB
		searchLimit := 1024
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

	// === DEBUG INFORMATION ===
	if p.PDB() != "" && p.PDB() != "@" && !strings.HasPrefix(p.PDB(), "@") {
		fmt.Printf("\n🐛 DEBUG INFO:\n")
		fmt.Printf("Debug Info:      %s\n", p.PDB())
		if p.GUIDAge() != "" {
			fmt.Printf("GUID/Age:        %s\n", p.GUIDAge())
		}
	}

	// === FILE INTEGRITY & COMPLIANCE ===
	fmt.Printf("\n🔧 FILE INTEGRITY & COMPLIANCE:\n")
	var issues []string
	var warnings []string
	complianceChecks := 0
	complianceViolations := 0

	// Structural integrity validation
	p.validateSectionLayout(&issues, &warnings)
	p.validateRVAMappings(&issues, &warnings)
	p.validateDataDirectories(&issues, &warnings)

	// Basic PE compliance checks
	if p.PE != nil {
		complianceChecks++
	}
	if len(p.Sections) > 0 {
		complianceChecks++
	}
	if p.SizeOfImage() > 0 {
		complianceChecks++
	}
	if p.EntryPoint() > 0 {
		complianceChecks++
	}

	// Report integrity results
	if len(issues) == 0 && len(warnings) == 0 {
		fmt.Printf("Structure:       ✅ No integrity issues found\n")
	} else {
		if len(issues) > 0 {
			fmt.Printf("Issues:          ❌ %d critical problems found\n", len(issues))
			complianceViolations += len(issues)
		}
		if len(warnings) > 0 {
			fmt.Printf("Warnings:        ⚠️ %d potential issues found\n", len(warnings))
			complianceViolations += len(warnings)
		}
	}

	// Report compliance results
	fmt.Printf("PE Compliance:   %d/%d checks passed\n", complianceChecks-complianceViolations, complianceChecks)

	if complianceViolations == 0 {
		fmt.Printf("Overall Status:  ✅ Fully compliant PE file\n")
	} else if complianceViolations <= 2 {
		fmt.Printf("Overall Status:  ⚠️ Minor issues detected\n")
	} else {
		fmt.Printf("Overall Status:  ❌ Significant issues detected\n")
	}

	// === MEMORY LAYOUT ===
	fmt.Printf("\n🧠 MEMORY LAYOUT:\n")
	imageSize := p.SizeOfImage()
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
			common.FormatFileSize(section.Size),
			permissions,
			entropyColor,
			section.Entropy,
			"\033[0m")
	}
	fmt.Println("└──────────────────┴─────────────┴─────────────┴─────────────┴─────────────┴──────────┘")
	fmt.Println()
}

func (p *PEFile) printImportsAnalysis() {
	fmt.Println("📦 IMPORTS ANALYSIS")
	fmt.Println("═══════════════════")
	if len(p.Imports) == 0 {
		fmt.Println("❌ No imports found")
		fmt.Println() // Add empty line for proper spacing
		return
	}

	// Separate DLLs with functions from those without
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

	// Display DLLs with functions
	if len(dllsWithFunctions) > 0 {
		// Sort DLLs alphabetically
		sort.Slice(dllsWithFunctions, func(i, j int) bool {
			return strings.ToUpper(dllsWithFunctions[i].LibraryName) < strings.ToUpper(dllsWithFunctions[j].LibraryName)
		})

		fmt.Println("IMPORTED LIBRARIES WITH FUNCTIONS:")
		for i, imp := range dllsWithFunctions {
			dllName := strings.ToUpper(imp.LibraryName)

			// Count function occurrences
			functionCount := make(map[string]int)
			for _, fn := range imp.Functions {
				functionCount[fn]++
			}

			uniqueFunctions := len(functionCount)
			fmt.Printf("\n📚 %s (%d functions, %d unique)\n", dllName, len(imp.Functions), uniqueFunctions)

			// Get function names sorted alphabetically
			functionNames := make([]string, 0, len(functionCount))
			for fn := range functionCount {
				functionNames = append(functionNames, fn)
			}
			sort.Strings(functionNames)

			// Show functions with their counts (sorted alphabetically)
			for _, fn := range functionNames {
				count := functionCount[fn]
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
		// Sort DLLs without functions alphabetically
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

func (p *PEFile) getEntropyStats() (mi, ma, avg float64) {
	if len(p.Sections) == 0 {
		return 0, 0, 0
	}
	mi, ma, sum := p.Sections[0].Entropy, p.Sections[0].Entropy, 0.0
	for _, section := range p.Sections {
		if section.Entropy < mi {
			mi = section.Entropy
		}
		if section.Entropy > ma {
			ma = section.Entropy
		}
		sum += section.Entropy
	}
	avg = sum / float64(len(p.Sections))
	return
}

func AnalyzeSectionAnomalies(sections []SectionInfo) []string {
	var issues []string
	for i, s := range sections {
		if s.Size == 0 {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' has zero size")
		}
		if s.IsExecutable && s.IsWritable {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' is both executable and writable")
		}
		if len(s.Name) == 0 || s.Name == "\x00" {
			issues = append(issues, common.SymbolWarn+" Section with empty or invalid name")
		}
		// Overlap check
		if i > 0 && s.FileOffset < sections[i-1].FileOffset+sections[i-1].Size {
			issues = append(issues, common.SymbolWarn+" Section '"+s.Name+"' overlaps previous section")
		}
	}
	return issues
}

func OverlayInfo(fileSize int64, lastSectionOffset int64, lastSectionSize int64, data []byte) (present bool, offset int64, size int64, entropy float64) {
	overlayStart := lastSectionOffset + lastSectionSize
	if overlayStart < fileSize {
		overlayData := data[overlayStart:]
		return true, overlayStart, int64(len(overlayData)), CalculateEntropy(overlayData)
	}
	return false, 0, 0, 0
}

func PrintSuspiciousStrings(p *PEFile) {
	fmt.Println("🔎 SUSPICIOUS CONTENT ANALYSIS")
	fmt.Println("═══════════════════════════════")

	// Categorize findings
	categories := map[string][]string{
		"URLs & Network":     {},
		"File Paths":         {},
		"System Libraries":   {},
		"Debug/Build Info":   {},
		"Encoded/Obfuscated": {},
		"Shell Commands":     {},
	}

	// Extract and categorize strings
	ascii := ExtractSuspiciousStrings(p.RawData, false)
	unicode := ExtractSuspiciousStrings(p.RawData, true)
	allStrings := append(ascii, unicode...)

	if len(allStrings) == 0 {
		fmt.Printf("%s No suspicious content detected\n", common.SymbolCheck)
		fmt.Println()
		return
	}

	// Categorize findings
	for _, s := range allStrings {
		categorized := false

		// URLs and network indicators
		if strings.Contains(s, "http://") || strings.Contains(s, "https://") ||
			strings.Contains(s, "ftp://") || strings.Contains(s, "://") {
			categories["URLs & Network"] = append(categories["URLs & Network"], s)
			categorized = true
		}

		// File paths and executables
		if strings.Contains(s, ".exe") || strings.Contains(s, ".dll") ||
			strings.Contains(s, ".bat") || strings.Contains(s, ".scr") ||
			strings.Contains(s, "C:\\") || strings.Contains(s, "\\\\") {
			categories["File Paths"] = append(categories["File Paths"], s)
			categorized = true
		}

		// System libraries
		if strings.HasSuffix(strings.ToLower(s), ".dll") && !strings.Contains(s, "\\") {
			categories["System Libraries"] = append(categories["System Libraries"], s)
			categorized = true
		}

		// Debug/build information
		if strings.Contains(s, "gcc") || strings.Contains(s, "buildroot") ||
			strings.Contains(s, "libgcc") || strings.Contains(s, ".S") ||
			strings.Contains(s, "debug") {
			categories["Debug/Build Info"] = append(categories["Debug/Build Info"], s)
			categorized = true
		}

		// Shell commands
		if strings.Contains(s, "cmd ") || strings.Contains(s, "powershell") ||
			strings.Contains(s, "bash") || strings.Contains(s, "sh -") {
			categories["Shell Commands"] = append(categories["Shell Commands"], s)
			categorized = true
		}

		// Encoded/obfuscated content (high entropy, special patterns)
		if !categorized && (len(s) > 20 && IsHighEntropyString(s) ||
			strings.Contains(s, "\\x") || ContainsSuspiciousPattern(s)) {
			categories["Encoded/Obfuscated"] = append(categories["Encoded/Obfuscated"], s)
		}
	}

	// Display categorized results
	totalFindings := 0
	for category, items := range categories {
		if len(items) > 0 {
			totalFindings += len(items)
			fmt.Printf("\n📋 %s (%d items):\n", category, len(items))

			// Show all items
			for _, item := range items {
				// Truncate very long strings
				if len(item) > 80 {
					item = item[:77] + "..."
				}
				fmt.Printf("   • %s\n", item)
			}
		}
	}

	if totalFindings == 0 {
		fmt.Printf("%s No categorizable suspicious content found\n", common.SymbolInfo)
	} else {
		fmt.Printf("\n📊 Total suspicious content found: %d items across %d categories\n",
			totalFindings, CountNonEmptyCategories(categories))
	}
	fmt.Println()
}

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

func (p *PEFile) detectDotNetLanguage() bool {
	// Check for .NET imports
	for _, imp := range p.Imports {
		dllLower := strings.ToLower(imp.LibraryName)
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

func (p *PEFile) detectCppLanguage() bool {
	// Check for C/C++ runtime imports
	for _, imp := range p.Imports {
		dllLower := strings.ToLower(imp.LibraryName)
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
		if strings.Contains(strings.ToLower(imp.LibraryName), "msvcr") {
			return "Microsoft Visual C++"
		}
	}

	return "C/C++ Compiler"
}

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

func (p *PEFile) detectByImportsAndSections() (language, compiler string) {
	// Check for specific DLL patterns
	for _, imp := range p.Imports {
		dllLower := strings.ToLower(imp.LibraryName)

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
	versionInfo := p.VersionInfo()
	if len(versionInfo) > 0 {
		for key, value := range versionInfo {
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

func (p *PEFile) printComprehensiveSecurityAnalysis() {
	fmt.Println("🔐 SECURITY & PROTECTION ANALYSIS")
	fmt.Println("══════════════════════════════════")

	// === BINARY PROTECTION FEATURES ===
	dllChars := p.DllCharacteristics()

	// ASLR (Address Space Layout Randomization)
	aslrEnabled := (dllChars & 0x0040) != 0
	fmt.Printf("ASLR:               %s %s\n",
		map[bool]string{true: common.SymbolCheck, false: common.SymbolCross}[aslrEnabled],
		map[bool]string{true: "Enabled", false: "Disabled"}[aslrEnabled])

	// DEP/NX (Data Execution Prevention)
	depEnabled := (dllChars & 0x0100) != 0
	fmt.Printf("DEP/NX:             %s %s\n",
		map[bool]string{true: common.SymbolCheck, false: common.SymbolCross}[depEnabled],
		map[bool]string{true: "Enabled", false: "Disabled"}[depEnabled])

	// Control Flow Guard
	cfgEnabled := (dllChars & 0x4000) != 0
	fmt.Printf("Control Flow Guard: %s %s\n",
		map[bool]string{true: common.SymbolCheck, false: common.SymbolCross}[cfgEnabled],
		map[bool]string{true: "Enabled", false: "Disabled"}[cfgEnabled])

	// SEH (Structured Exception Handling)
	sehEnabled := (dllChars & 0x0400) == 0 // NO_SEH flag is inverted
	fmt.Printf("SEH Protection:     %s %s\n",
		map[bool]string{true: common.SymbolCheck, false: common.SymbolCross}[sehEnabled],
		map[bool]string{true: "Enabled", false: "Disabled"}[sehEnabled])

	// === CODE SIGNING & CERTIFICATES ===
	directories := p.Directories()
	hasCertificate := len(directories) > 4 && (directories[4].RVA != 0 || directories[4].Size != 0)

	fmt.Printf("Digital Signature:  ")
	if hasCertificate {
		fmt.Printf("%s Present (%d bytes)\n", common.SymbolCheck, directories[4].Size)
		fmt.Printf("Certificate Status: %s Signed binary (verification required)\n", common.SymbolInfo)
	} else {
		fmt.Printf("%s Not signed\n", common.SymbolWarn)
		fmt.Printf("Certificate Status: %s Unsigned binary (higher risk)\n", common.SymbolWarn)
	}

	// === PACKING ANALYSIS ===
	packingScore := p.calculatePackingScore()
	fmt.Printf("\n📦 PACKING ANALYSIS:\n")
	fmt.Printf("═══════════════════\n")

	fmt.Printf("Packing Score:      %d/100 ", packingScore)
	if packingScore >= 70 {
		fmt.Printf("(%s Likely packed/encrypted)\n", common.SymbolCross)
	} else if packingScore >= 40 {
		fmt.Printf("(%s Possibly packed)\n", common.SymbolWarn)
	} else {
		fmt.Printf("(%s Probably not packed)\n", common.SymbolCheck)
	}

	// Entropy statistics
	minEntropy, maxEntropy, avgEntropy := p.getEntropyStats()
	fmt.Printf("Entropy Analysis:   Min=%.2f, Max=%.2f, Avg=%.2f\n", minEntropy, maxEntropy, avgEntropy)

	// Count high entropy sections (excluding debug)
	highEntropySections := 0
	for _, section := range p.Sections {
		if isDebugSection(section.Name) {
			continue
		}
		if section.Entropy > 7.5 {
			highEntropySections++
		}
	}
	fmt.Printf("High Entropy Secs:  %d sections > 7.5 entropy (excluding debug)\n", highEntropySections)

	// === OVERALL SECURITY SCORE ===
	securityScore := 0
	if aslrEnabled {
		securityScore += 20
	}
	if depEnabled {
		securityScore += 20
	}
	if cfgEnabled {
		securityScore += 25
	}
	if sehEnabled {
		securityScore += 15
	}
	if hasCertificate {
		securityScore += 20
	}

	fmt.Printf("Security Score:     %d/100 ", securityScore)
	if securityScore >= 80 {
		fmt.Printf("(%s Excellent)\n", common.SymbolCheck)
	} else if securityScore >= 60 {
		fmt.Printf("(%s Good)\n", common.SymbolInfo)
	} else if securityScore >= 40 {
		fmt.Printf("(%s Fair)\n", common.SymbolWarn)
	} else {
		fmt.Printf("(%s Poor)\n", common.SymbolCross)
	}

	fmt.Println()
}

func (p *PEFile) printResourceAnalysis() {
	fmt.Println("📦 RESOURCE ANALYSIS")
	fmt.Println("═══════════════════")

	// Check if resource directory exists
	directories := p.Directories()
	if len(directories) > 2 && (directories[2].RVA != 0 || directories[2].Size != 0) {
		fmt.Printf("Resource Table:  %s Present (RVA: 0x%08X, Size: %d)\n",
			common.SymbolCheck, directories[2].RVA, directories[2].Size)

		fmt.Printf("Resource Types:  Analysis requires parsing (common: Icons, Version, Manifests)\n")
	} else {
		fmt.Printf("Resource Table:  %s Not present\n", common.SymbolInfo)
	}
	fmt.Println()
}

func (p *PEFile) printImportHashAnalysis() {
	fmt.Println("🔍 IMPORT HASH ANALYSIS")
	fmt.Println("══════════════════════")

	if len(p.Imports) == 0 {
		fmt.Printf("Import Hash:     %s No imports to analyze\n", common.SymbolInfo)
		fmt.Println()
		return
	}

	// Create normalized import list for hashing
	var importList []string
	for _, imp := range p.Imports {
		normalizedDLL := strings.ToLower(strings.TrimSuffix(imp.LibraryName, ".dll"))
		for _, fn := range imp.Functions {
			if fn != "" {
				importList = append(importList, normalizedDLL+"."+strings.ToLower(fn))
			}
		}
	}

	sort.Strings(importList)

	// Simple hash calculation (for demonstration)
	importString := strings.Join(importList, ",")
	fmt.Printf("Import Count:    %d unique functions\n", len(importList))
	fmt.Printf("Import String:   %s...\n", common.TruncateString(importString, 60))

	// Calculate some basic metrics
	uniqueDLLs := len(p.Imports)
	avgFuncsPerDLL := float64(len(importList)) / float64(uniqueDLLs)

	fmt.Printf("DLL Diversity:   %d libraries\n", uniqueDLLs)
	fmt.Printf("Avg Funcs/DLL:   %.1f\n", avgFuncsPerDLL)

	// Check for suspicious import patterns
	suspiciousAPIs := map[string]string{
		"virtualalloc":       "Memory allocation (often used in code injection)",
		"virtualprotect":     "Memory protection modification (shellcode execution)",
		"createprocess":      "Process creation (lateral movement/execution)",
		"writeprocessmemory": "Cross-process memory writing (process injection)",
		"readprocessmemory":  "Cross-process memory reading (information theft)",
		"createremotethread": "Remote thread creation (DLL injection)",
		"loadlibrary":        "Dynamic library loading (reflective DLL loading)",
		"getprocaddress":     "API address resolution (API hashing/obfuscation)",
		"createfile":         "File creation/modification (persistence/data theft)",
		"writefile":          "File writing (data exfiltration/dropper)",
		"regsetvalue":        "Registry modification (persistence)",
		"regcreatekey":       "Registry key creation (persistence)",
	}

	suspiciousCount := 0
	var detectedAPIs []string
	for _, imp := range importList {
		for suspicious, reason := range suspiciousAPIs {
			if strings.Contains(imp, suspicious) {
				suspiciousCount++
				detectedAPIs = append(detectedAPIs, fmt.Sprintf("%s (%s)", imp, reason))
				break
			}
		}
	}

	if suspiciousCount > 0 {
		fmt.Printf("Suspicious APIs: %s %d potentially risky functions\n",
			common.SymbolWarn, suspiciousCount)
		fmt.Println("DETECTED RISKY APIs:")
		for _, api := range detectedAPIs {
			fmt.Printf("   • %s\n", api)
		}
	} else {
		fmt.Printf("Suspicious APIs: %s No obviously risky functions detected\n",
			common.SymbolCheck)
	}
	fmt.Println()
}

func (p *PEFile) printNetworkIndicators() {
	fmt.Println("🌐 NETWORK INDICATORS")
	fmt.Println("═══════════════════")

	// Check for network-related imports
	networkAPIs := []string{
		"ws2_32.dll", "wininet.dll", "urlmon.dll", "winhttp.dll",
	}

	var networkDLLs []string
	var networkFunctions []string

	for _, imp := range p.Imports {
		dllName := strings.ToLower(imp.LibraryName)
		for _, netDLL := range networkAPIs {
			if strings.Contains(dllName, strings.TrimSuffix(netDLL, ".dll")) {
				networkDLLs = append(networkDLLs, imp.LibraryName)

				// Look for specific network functions
				networkFuncs := []string{
					"internetopen", "internetconnect", "httpopen", "send", "recv",
					"socket", "connect", "bind", "listen", "accept",
				}

				for _, fn := range imp.Functions {
					fnLower := strings.ToLower(fn)
					for _, netFunc := range networkFuncs {
						if strings.Contains(fnLower, netFunc) {
							networkFunctions = append(networkFunctions, fn)
							break
						}
					}
				}
				break
			}
		}
	}

	if len(networkDLLs) > 0 {
		fmt.Printf("Network DLLs:    %s %d found: %v\n",
			common.SymbolWarn, len(networkDLLs), networkDLLs)
		if len(networkFunctions) > 0 {
			fmt.Printf("Network Funcs:   %d functions: %v\n",
				len(networkFunctions), networkFunctions)
		}
	} else {
		fmt.Printf("Network DLLs:    %s None detected\n", common.SymbolCheck)
	}
	fmt.Println()
}

func (p *PEFile) validateSectionLayout(issues, warnings *[]string) {
	if len(p.Sections) == 0 {
		return
	}

	// Basic section validation
	for i, section := range p.Sections {
		// Check if section extends beyond file
		if section.Offset+section.Size > int64(len(p.RawData)) {
			*issues = append(*issues, fmt.Sprintf("Section %d (%s): Extends beyond file end",
				i, section.Name))
		}
	}
}

func (p *PEFile) validateRVAMappings(issues, warnings *[]string) {
	// Basic RVA validation
	if p.PE != nil && len(p.Sections) > 0 {
		// Check if sections have reasonable RVAs
		for i, section := range p.Sections {
			if section.VirtualAddress > 0x80000000 {
				*warnings = append(*warnings, fmt.Sprintf("Section %d: Unusually large RVA (0x%X)", i, section.VirtualAddress))
			}
		}
	}
}

func (p *PEFile) validateDataDirectories(issues, warnings *[]string) {
	directories := p.Directories()

	for i, dir := range directories {
		if dir.RVA == 0 && dir.Size == 0 {
			continue // Empty directory is fine
		}

		// Check directory size reasonableness
		if dir.Size > uint32(len(p.RawData))/2 {
			*warnings = append(*warnings, fmt.Sprintf("Directory %d: Unusually large size (%d bytes)", i, dir.Size))
		}
	}
}
