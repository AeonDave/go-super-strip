package perw

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"gosstrip/common"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
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
	p.calculateSectionEntropy()
	p.IsPacked = p.detectPacking()
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
	if len(p.Sections) == 0 {
		return false
	}

	// Indicators for packing detection
	highEntropyCount := 0
	anomalousCount := 0
	totalValidSections := 0 // Only count sections with actual content

	for _, section := range p.Sections {
		// Skip debug sections completely
		if isDebugSection(section.Name) {
			continue
		}

		// Skip empty sections (common in packers)
		if section.Size == 0 {
			continue
		}

		totalValidSections++

		// High entropy indicator (compressed/encrypted data)
		if section.Entropy > 7.0 {
			highEntropyCount++
		}

		// Anomalous permissions (RWX is highly suspicious)
		if section.IsExecutable && section.IsWritable {
			anomalousCount++
		}
	}

	// No valid sections to analyze
	if totalValidSections == 0 {
		return false
	}

	// Calculate indicators
	highEntropyRatio := float64(highEntropyCount) / float64(totalValidSections)
	anomalousRatio := float64(anomalousCount) / float64(totalValidSections)

	// Packing detection logic:
	// 1. High entropy in majority of sections (compressed/encrypted)
	// 2. Any anomalous RWX sections (unpacking stubs)
	// 3. Very few valid sections with high entropy (typical packer pattern)

	if anomalousRatio > 0 {
		// Any RWX section is highly suspicious
		return true
	}

	if highEntropyRatio >= 0.5 {
		// More than half sections have high entropy
		return true
	}

	if totalValidSections <= 3 && highEntropyCount >= 1 {
		// Very few sections with at least one high entropy (typical packer)
		return true
	}

	return false
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
	fmt.Printf("Packed Status:   %s\n", map[bool]string{true: "📦 Likely PACKED", false: "✅ Not packed"}[p.IsPacked])
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
				ageDays := age.Hours() / 24

				// Calculate file age (handle negative age as 0)
				if ageDays < 0 {
					fmt.Printf("File Age:        0 days (compiled today)\n")
				} else {
					fmt.Printf("File Age:        %s\n", formatFileAge(ageDays))
				}
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
	// p.validateSectionLayout(&issues, &warnings)
	// p.validateRVAMappings(&issues, &warnings)
	// p.validateDataDirectories(&issues, &warnings)

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

	// === PACKING ANALYSIS ===
	p.printPackingAnalysis()

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

	// More specific categories for better analysis
	categories := map[string][]string{
		"🌐 Network URLs":          {},
		"🔑 Cryptographic Content": {},
		"💾 Suspicious File Paths": {},
		"⚡ Shell Commands":        {},
		"🎭 Obfuscated Content":    {},
		"🔗 External References":   {},
		"🔧 Versions/Compiler":     {},
		"🏗️ Build Information":    {},
	}

	// Extract and categorize strings with stricter filtering
	ascii := ExtractSuspiciousStrings(p.RawData, false)
	uni := ExtractSuspiciousStrings(p.RawData, true)
	allStrings := append(ascii, uni...)

	if len(allStrings) == 0 {
		fmt.Printf("%s No strings extracted for analysis\n", common.SymbolInfo)
		fmt.Println()
		return
	}

	// Apply multiple filters to reduce false positives
	filteredStrings := filterRelevantStrings(allStrings)

	if len(filteredStrings) == 0 {
		fmt.Printf("%s No suspicious content detected (filtered %d benign strings)\n",
			common.SymbolCheck, len(allStrings))
		fmt.Println()
		return
	}

	// Categorize with improved precision
	for _, s := range filteredStrings {
		categorized := false

		// Versions and compiler information (high confidence)
		if isVersionOrCompilerString(s) {
			categories["🔧 Versions/Compiler"] = append(categories["🔧 Versions/Compiler"], s)
			categorized = true
		}

		// Build information and metadata
		if !categorized && isBuildInformationString(s) {
			categories["🏗️ Build Information"] = append(categories["🏗️ Build Information"], s)
			categorized = true
		}

		// Network URLs and domains (high confidence)
		if !categorized && isNetworkURL(s) {
			categories["🌐 Network URLs"] = append(categories["🌐 Network URLs"], s)
			categorized = true
		}

		// Cryptographic keys, hashes, certificates
		if !categorized && isCryptographicContent(s) {
			categories["🔑 Cryptographic Content"] = append(categories["🔑 Cryptographic Content"], s)
			categorized = true
		}

		// Suspicious file paths (not compiler paths)
		if !categorized && isSuspiciousFilePath(s) {
			categories["💾 Suspicious File Paths"] = append(categories["💾 Suspicious File Paths"], s)
			categorized = true
		}

		// Shell commands and scripts
		if !categorized && isShellCommand(s) {
			categories["⚡ Shell Commands"] = append(categories["⚡ Shell Commands"], s)
			categorized = true
		}

		// Base64, hex, or high-entropy obfuscated content
		if !categorized && isObfuscatedContent(s) {
			categories["🎭 Obfuscated Content"] = append(categories["🎭 Obfuscated Content"], s)
			categorized = true
		}

		// External references (not system libraries)
		if !categorized && isExternalReference(s) {
			categories["🔗 External References"] = append(categories["🔗 External References"], s)
		}
	}

	// Display results with confidence indicators
	totalFindings := 0
	highConfidenceFindings := 0

	for category, items := range categories {
		if len(items) > 0 {
			totalFindings += len(items)

			// Count high-confidence findings
			if strings.Contains(category, "🌐") || strings.Contains(category, "🔑") ||
				strings.Contains(category, "⚡") || strings.Contains(category, "🔧") ||
				strings.Contains(category, "🏗️") {
				highConfidenceFindings += len(items)
			}

			// Limit output per category
			displayCount := len(items)
			if displayCount > 8 {
				displayCount = 8
			}

			fmt.Printf("\n%s (%d items", category, len(items))
			if len(items) > 8 {
				fmt.Printf(", showing top 8")
			}
			fmt.Printf("):\n")

			// Sort items by length/importance for better display
			sortedItems := make([]string, len(items))
			copy(sortedItems, items)
			sort.Slice(sortedItems, func(i, j int) bool {
				return len(sortedItems[i]) < len(sortedItems[j])
			})

			// Show limited items
			for i := 0; i < displayCount; i++ {
				item := sortedItems[i]
				// Truncate very long strings
				if len(item) > 100 {
					item = item[:97] + "..."
				}
				fmt.Printf("   • %s\n", item)
			}

			if len(items) > 8 {
				fmt.Printf("   ... and %d more\n", len(items)-8)
			}
		}
	}

	if totalFindings == 0 {
		fmt.Printf("%s No suspicious content found (analyzed %d strings)\n",
			common.SymbolCheck, len(filteredStrings))
	} else {
		fmt.Printf("\n📊 Analysis Results: %d potentially suspicious items found\n", totalFindings)
		fmt.Printf("   High confidence: %d items\n", highConfidenceFindings)
		fmt.Printf("   Requires review: %d items\n", totalFindings-highConfidenceFindings)
	}
	fmt.Println()
}

// Advanced string filtering and categorization functions
// ========================================================

// filterRelevantStrings applies multiple filters to reduce false positives
func filterRelevantStrings(strs []string) []string {
	var filtered []string

	for _, s := range strs {
		// Skip if too short or too long
		if len(s) < 8 || len(s) > 512 {
			continue
		}

		// Skip empty/whitespace strings
		trimmed := strings.TrimSpace(s)
		if len(trimmed) == 0 {
			continue
		}

		// Skip if it's mostly whitespace or control characters
		printableCount := 0
		for _, r := range s {
			if unicode.IsPrint(r) && r != ' ' && r != '\t' && r != '\n' && r != '\r' {
				printableCount++
			}
		}
		if float64(printableCount)/float64(len(s)) < 0.3 {
			continue
		}

		// Skip benign patterns
		if isLanguageInternalString(s) || isCompilerArtifact(s) || isCommonLibraryString(s) {
			continue
		}

		// Skip pure numeric or repetitive patterns
		if isPureNumeric(s) || isRepetitivePattern(s) {
			continue
		}

		// Skip very low entropy strings
		if calculateEntropy(s) < 1.5 {
			continue
		}

		filtered = append(filtered, s)
	}

	return filtered
}

// isLanguageInternalString detects strings from various language runtimes
func isLanguageInternalString(s string) bool {
	// Go language internals - much more comprehensive
	goPatterns := []string{
		"go:itab", "go:cuinfo", "go:buildid", "go:link", "go:typelink",
		"runtime/internal", "crypto/internal", "internal/",
		"golang.org/", "reflect.", "_type", "gcdata", "interface{",
		".inittask", ".typelink", ".rodata", ".strtab", ".symtab",
		"sync.Once", "sync.Mutex", "runtime.g", "runtime.m",
		"runtime.", "crypto/", "net.", "os.", "syscall.", "time.",
		"encoding/", "compress/", "archive/", "bufio.", "bytes.",
		"context.", "database/", "debug/", "errors.", "expvar.",
		"flag.", "fmt.", "hash/", "html/", "image/", "index/",
		"io/", "log/", "math/", "mime/", "path/", "plugin.",
		"regexp.", "sort.", "strconv.", "strings.", "testing.",
		"text/", "unicode/", "*map[", "[]", "func(", "type ",
		"interface{}", "struct{", "<-chan", "chan<-", "chan ",
		"unsafe.Pointer", "uintptr", "int8", "int16", "int32",
		"uint8", "uint16", "uint32", "uint64", "float32", "float64",
		"complex64", "complex128", "string", "bool", "byte", "rune",
		"*http.", "*url.", "*json.", "*xml.", "hkdfKDF", "HKDF",
		"MarshalBinary", "UnmarshalBinary", "keyExchange", "KeyExchange",
		"PublicKey", "PrivateKey", "Certificate", "x509", "tls", "ecdh",
		"ed25519", "ecdsa", "rsa.", "aes.", "des.", "hmac.", "sha",
		"SessionTicketKey", "TLS", "ALPN", "SNI", "OCSP", "netdns",
		"netFD", "netedns", "netpoll", "compute", "commaOrPeriod",
		"socket", "sockaddr", "socksAddr", "executable", "execute",
		// Additional Go patterns to filter function names and types
		"net/http.", "net/url.", "type:.eq.", "http.socks", ".socks",
		"socksNewDialer", "socksnoDeadline", "socksAuthMethod", "socksReply",
		"socksaLongTimeAgo", "sockssplitHostPort", "/http.", "/url.",
		".String", ".Error", ".URL", ".Userinfo", ".segment",
		"http.segment", "url.URL", "url.Error", "url.Userinfo",
		// More comprehensive Go function filtering
		"io.Copy", "io.copy", "mime.consume", "mime.", "bufio.",
		"crypto/rand", "crypto/cipher", "crypto/subtle", "crypto/ed25519",
		"crypto/rsa", "crypto/ecdsa", "crypto/tls", "crypto/x509",
		"encoding/base64", "encoding/hex", "encoding/json", "encoding/xml",
		"compress/gzip", "compress/zlib", "archive/tar", "archive/zip",
		"image/png", "image/jpeg", "image/gif", "text/template",
		"html/template", "net/textproto", "net/mail", "net/smtp",
		"database/sql", "log/syslog", "go/build", "go/parser",
		// Additional Unicode and conversion functions
		"unicode.", "unicode/", ".convert", "convertCase", ".Case",
		"unicode.convert", "unicode.Case", "unicode.To", "unicode.Is",
	}

	// .NET internals
	dotnetPatterns := []string{
		"System.", "Microsoft.", "mscorlib", ".resources", ".resx",
		"<Module>", "<PrivateImplementationDetails>", "_GLOBAL_OFFSET_TABLE_",
		".cctor", ".ctor", "get_", "set_", "System.Private.CoreLib",
	}

	// C/C++ and GCC patterns
	cPatterns := []string{
		"__libc_", "__glibc_", "_GLOBAL_OFFSET_TABLE_", "__cxa_",
		"_init_", "_fini_", "_start", "__stack_chk_fail",
		"libgcc_", "libstdc++", "__gnu_", "_Unwind_",
	}

	// Rust internals
	rustPatterns := []string{
		"core::panic", "alloc::vec", "std::", "core::", "alloc::",
		"rust_begin_unwind", "rust_panic", "_ZN", "__rust_",
	}

	allPatterns := append(goPatterns, dotnetPatterns...)
	allPatterns = append(allPatterns, cPatterns...)
	allPatterns = append(allPatterns, rustPatterns...)

	for _, pattern := range allPatterns {
		if strings.Contains(s, pattern) {
			return true
		}
	}

	return false
}

// isCompilerArtifact detects compiler/linker generated strings
func isCompilerArtifact(s string) bool {
	patterns := []string{
		// Version strings
		"GCC: (", "clang version", "rustc ", "go1.",
		// Build paths
		"/usr/lib/gcc", "/opt/", "/build/", "/tmp/go-build",
		"/usr/include", "/usr/local/", "/home/", "/root/",
		// Debug info
		".debug_", ".eh_frame", ".plt", ".got", ".bss", ".data",
		"DWARF", "dwarf", ".symtab", ".strtab", ".shstrtab",
		// Tool chains
		"ld-linux", "gcc", "g++", "clang", "rustc", "cargo",
	}

	for _, pattern := range patterns {
		if strings.Contains(s, pattern) {
			return true
		}
	}

	return false
}

// isCommonLibraryString detects standard library references
func isCommonLibraryString(s string) bool {
	patterns := []string{
		"libc.so", "libm.so", "libpthread", "libdl.so", "librt.so",
		"kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
		"ws2_32.dll", "msvcrt.dll", "shell32.dll", "ole32.dll",
		"vcruntime", "api-ms-win-", "ucrtbase.dll",
	}

	for _, pattern := range patterns {
		if strings.Contains(strings.ToLower(s), strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// isPureNumeric checks if string is mostly numeric
func isPureNumeric(s string) bool {
	digitCount := 0
	for _, r := range s {
		if unicode.IsDigit(r) || r == '.' || r == '-' || r == '+' {
			digitCount++
		}
	}
	return float64(digitCount)/float64(len(s)) > 0.8
}

// isRepetitivePattern detects repetitive character patterns
func isRepetitivePattern(s string) bool {
	if len(s) < 8 {
		return false
	}

	// Check for repeated substrings
	for i := 1; i <= len(s)/3; i++ {
		pattern := s[:i]
		repeated := strings.Repeat(pattern, len(s)/i)
		if strings.HasPrefix(s, repeated) && len(repeated) >= len(s)*2/3 {
			return true
		}
	}

	// Check for single character repetition
	charCounts := make(map[rune]int)
	for _, r := range s {
		charCounts[r]++
	}

	for _, count := range charCounts {
		if float64(count)/float64(len(s)) > 0.7 {
			return true
		}
	}

	return false
}

// calculateEntropy calculates Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	entropy := 0.0
	length := float64(len(s))

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// isNetworkURL detects URLs and network indicators with high confidence
func isNetworkURL(s string) bool {
	// Skip if it's a language internal string first
	if isLanguageInternalString(s) {
		return false
	}

	// Skip Go function/type references
	if strings.Contains(s, "type:.eq.") || strings.Contains(s, "net/http.") ||
		strings.Contains(s, "net/url.") || strings.Contains(s, ".String") ||
		strings.Contains(s, ".Error") || strings.Contains(s, ".segment") {
		return false
	}

	// Direct URL schemes - must be complete URLs
	urlPrefixes := []string{"http://", "https://", "ftp://", "ftps://", "ssh://", "telnet://", "ldap://", "ldaps://"}
	for _, prefix := range urlPrefixes {
		if strings.HasPrefix(strings.ToLower(s), prefix) {
			// Make sure it has a domain after the scheme
			remaining := s[len(prefix):]
			if len(remaining) > 3 && strings.Contains(remaining, ".") {
				return true
			}
		}
	}

	// Domain patterns with TLD - must look like real domains
	domainTLDs := []string{".com", ".org", ".net", ".edu", ".gov", ".mil", ".info", ".biz", ".io", ".co"}
	for _, tld := range domainTLDs {
		if strings.Contains(strings.ToLower(s), tld) {
			// Ensure it looks like a real domain (not a file path or Go package)
			if !strings.Contains(s, "/") && !strings.Contains(s, "\\") &&
				!strings.Contains(s, "type:") && !strings.Contains(s, ".go") {
				// Must have domain-like structure
				if regexp.MustCompile(`^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}$`).MatchString(s) {
					return true
				}
			}
		}
	}

	// IP addresses - standalone IPs only
	ipPattern := regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?$`)
	return ipPattern.MatchString(s)
}

// isCryptographicContent detects cryptographic keys, hashes, certificates
func isCryptographicContent(s string) bool {
	// Skip if it's a language internal string first
	if isLanguageInternalString(s) {
		return false
	}

	// Skip strings that look like lookup tables or charset definitions
	if strings.Contains(s, "0123456789") && strings.Contains(s, "abcdef") {
		return false
	}

	// Skip strings with too many control characters or special symbols
	controlCount := 0
	for _, r := range s {
		if r < 32 || r == 127 || (r >= 128 && r <= 159) {
			controlCount++
		}
	}
	if float64(controlCount)/float64(len(s)) > 0.2 {
		return false
	}

	// Base64 encoded content that could be keys/certificates
	if isBase64Like(s) && len(s) >= 44 { // Increased minimum length
		// Common key/cert indicators
		if strings.Contains(s, "BEGIN") && strings.Contains(s, "END") {
			return true
		}
		if strings.Contains(s, "CERTIFICATE") || strings.Contains(s, "PRIVATE KEY") {
			return true
		}
		if strings.Contains(s, "PUBLIC KEY") || strings.Contains(s, "RSA") {
			return true
		}
	}

	// Hex encoded hashes (MD5, SHA1, SHA256, etc.)
	if isHexString(s) {
		if len(s) == 32 || len(s) == 40 || len(s) == 64 || len(s) == 128 {
			// Make sure it's not just a version string or similar
			if !strings.Contains(s, ".") && !strings.Contains(s, "-") {
				return true
			}
		}
	}

	// High entropy strings that could be keys - but exclude common patterns
	if calculateEntropy(s) > 5.5 && len(s) >= 44 && len(s) <= 256 {
		// Additional checks to avoid false positives
		if !strings.Contains(s, "struct") && !strings.Contains(s, "func") &&
			!strings.Contains(s, "map[") && !strings.Contains(s, "interface") &&
			!strings.Contains(s, "SETTINGS") && !strings.Contains(s, "TIMEOUT") {
			return true
		}
	}

	return false
}

// isSuspiciousFilePath detects suspicious file paths (not compiler paths)
func isSuspiciousFilePath(s string) bool {
	// Executable files
	if strings.HasSuffix(strings.ToLower(s), ".exe") ||
		strings.HasSuffix(strings.ToLower(s), ".bat") ||
		strings.HasSuffix(strings.ToLower(s), ".cmd") ||
		strings.HasSuffix(strings.ToLower(s), ".ps1") ||
		strings.HasSuffix(strings.ToLower(s), ".sh") {
		// Exclude compiler paths
		if !isCompilerArtifact(s) {
			return true
		}
	}

	// Suspicious directories
	suspiciousPath := []string{
		"\\temp\\", "\\tmp\\", "%temp%", "%appdata%",
		"/tmp/", "/var/tmp/", "C:\\Windows\\System32\\",
		"\\Users\\", "\\Documents\\", "\\Downloads\\",
	}

	for _, path := range suspiciousPath {
		if strings.Contains(strings.ToLower(s), strings.ToLower(path)) {
			return true
		}
	}

	return false
}

// isShellCommand detects shell commands and scripts
func isShellCommand(s string) bool {
	// Skip if it's a language internal string first
	if isLanguageInternalString(s) {
		return false
	}

	// Skip Windows API functions (not actual commands being executed)
	winAPIFunctions := []string{
		"GetSystemInfo", "GetComputerName", "GetUserName", "GetVersion",
		"CreateProcess", "ShellExecute", "WinExec", "GetProcAddress",
		"LoadLibrary", "GetModuleHandle", "VirtualAlloc", "GetCurrentProcess",
		"SetFileAttributes", "GetFileAttributes", "FindFirstFile", "FindNextFile",
		"RegOpenKey", "RegQueryValue", "RegSetValue", "RegCloseKey",
		"GetTickCount", "GetSystemTime", "GetLocalTime", "Sleep",
	}

	for _, apiFunc := range winAPIFunctions {
		if strings.Contains(s, apiFunc) {
			return false
		}
	}

	// Skip strings with too many special characters or control chars (likely garbage)
	specialCount := 0
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != ' ' && r != '.' && r != '/' && r != '\\' && r != '-' && r != '_' {
			specialCount++
		}
	}
	if float64(specialCount)/float64(len(s)) > 0.3 {
		return false
	}

	// Real shell commands being executed (with arguments or paths) - more specific
	executableCommands := []string{
		// Windows commands with common arguments (must be specific patterns)
		"cmd.exe /c ", "cmd /c ", "powershell.exe -Command", "powershell -Command",
		"powershell.exe -EncodedCommand", "powershell -EncodedCommand",
		"net.exe user", "net.exe localgroup", "sc.exe create", "sc.exe delete",
		"reg.exe add", "reg.exe delete", "taskkill /F", "schtasks /create",
		"regsvr32 /s", "rundll32.exe ", "mshta.exe http", "wscript.exe ",
		// Unix commands with arguments (must be specific patterns)
		"/bin/sh -c", "/bin/bash -c", "chmod +x ", "curl -O", "wget -O",
		"sudo rm", "sudo mv", "sudo cp", "cat /etc/", "ls -la", "ps aux | grep",
	}

	for _, cmd := range executableCommands {
		if strings.Contains(s, cmd) {
			return true
		}
	}

	// Command line execution patterns (executable with arguments) - must be realistic
	if regexp.MustCompile(`^[a-zA-Z0-9_\-/\\]+\.(exe|bat|cmd|ps1|sh)\s+[a-zA-Z0-9\-/\\]`).MatchString(s) {
		return true
	}

	// Script execution patterns - must be realistic command lines
	if regexp.MustCompile(`^(python|node|java|ruby|perl)\s+[a-zA-Z0-9\-/\\._]+\.(py|js|jar|rb|pl)`).MatchString(s) {
		return true
	}

	return false
}

// isObfuscatedContent detects encoded or obfuscated content
func isObfuscatedContent(s string) bool {
	// Skip if it's a language internal string first
	if isLanguageInternalString(s) {
		return false
	}

	// Base64 encoded content - but be more restrictive
	if isBase64Like(s) && len(s) >= 32 {
		// Make sure it doesn't look like a normal identifier
		if !strings.Contains(s, "Key") && !strings.Contains(s, "Token") &&
			!strings.Contains(s, "Binary") && calculateEntropy(s) > 4.0 {
			return true
		}
	}

	// Hex strings - more restrictive
	if isHexString(s) && len(s) >= 32 {
		// Exclude version-like strings
		if !strings.Contains(s, ".") && !strings.Contains(s, "-") &&
			calculateEntropy(s) > 3.5 {
			return true
		}
	}

	// High entropy random-looking strings - much more restrictive
	if calculateEntropy(s) > 5.5 && len(s) >= 32 && len(s) <= 128 {
		// Exclude structured data patterns
		if !strings.Contains(s, "-") && !strings.Contains(s, ".") &&
			!strings.Contains(s, "/") && !strings.Contains(s, "\\") &&
			!strings.Contains(s, "_") && !strings.Contains(s, ":") &&
			!isLanguageInternalString(s) {
			return true
		}
	}

	// URL encoded content
	if strings.Contains(s, "%") && regexp.MustCompile(`%[0-9A-Fa-f]{2}`).MatchString(s) {
		urlDecodedCount := strings.Count(s, "%")
		if float64(urlDecodedCount)/float64(len(s)) > 0.2 {
			return true
		}
	}

	return false
}

// isExternalReference detects external references (not system libraries)
func isExternalReference(s string) bool {
	// Skip if it's a language internal string first
	if isLanguageInternalString(s) {
		return false
	}

	// Skip Go function/type references
	if strings.Contains(s, "net/http.") || strings.Contains(s, "net/url.") ||
		strings.Contains(s, "type:.eq.") || strings.Contains(s, "/http.") ||
		strings.Contains(s, "http.socks") || strings.Contains(s, ".String") ||
		strings.Contains(s, ".Error") || strings.Contains(s, ".URL") {
		return false
	}

	// External domain references (not localhost/internal) - must be real files
	if strings.Contains(s, ".") && !strings.Contains(s, "localhost") {
		if (strings.Contains(s, ".exe") || strings.Contains(s, ".dll") || strings.Contains(s, ".so")) &&
			!isCommonLibraryString(s) {
			return true
		}
	}

	// Registry keys (Windows specific)
	if strings.HasPrefix(s, "HKEY_") || strings.Contains(s, "\\SOFTWARE\\") {
		return true
	}

	// Service names - but not Go internal services
	if (strings.Contains(s, "SERVICE_") || strings.Contains(s, "_SERVICE")) &&
		!strings.Contains(s, "runtime") && !strings.Contains(s, "go") {
		return true
	}

	return false
}

// Helper functions for encoding detection
func isBase64Like(s string) bool {
	if len(s)%4 != 0 {
		return false
	}

	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	return base64Pattern.MatchString(s)
}

func isHexString(s string) bool {
	if len(s)%2 != 0 {
		return false
	}

	hexPattern := regexp.MustCompile(`^[0-9A-Fa-f]+$`)
	return hexPattern.MatchString(s)
}

// isVersionOrCompilerString detects version and compiler information using regex
func isVersionOrCompilerString(s string) bool {
	// Skip if it's a language internal string first
	if isLanguageInternalString(s) {
		return false
	}

	// Version patterns from strip_types.go
	versionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\bgo1\.[0-9]{1,2}(\.[0-9]{1,2})?\b`),                   // Go version
		regexp.MustCompile(`(?i)\bGCC: \([^)]+\) [0-9]+\.[0-9]+\.[0-9]+\b`),        // GCC version strings
		regexp.MustCompile(`\brustc [0-9]+\.[0-9]+\.[0-9]+\b`),                     // Rust compiler version
		regexp.MustCompile(`\bversion [0-9]+\.[0-9]+\.[0-9]+\b`),                   // Generic version strings
		regexp.MustCompile(`(?i)compiler version\s+[0-9]+\.[0-9]+[^\n\x00]{0,20}`), // Compiler version
		regexp.MustCompile(`(?i)linker version\s+[0-9]+\.[0-9]+`),                  // Linker version
		regexp.MustCompile(`(?i)assembler version\s+[0-9]+\.[0-9]+`),               // Assembler version
		regexp.MustCompile(`\bmingw_[a-zA-Z0-9_]{3,}\b`),                           // MinGW symbols
		regexp.MustCompile(`\blibgcc[a-zA-Z0-9_]*\.[a-zA-Z0-9]{1,5}\b`),            // libgcc libraries
		regexp.MustCompile(`\b__GNUC__\b|\b__GNUG__\b`),                            // GCC compiler macros
		regexp.MustCompile(`\b__cplusplus\b`),                                      // C++ macro
	}

	for _, pattern := range versionPatterns {
		if pattern.MatchString(s) {
			return true
		}
	}

	return false
}

// isBuildInformationString detects build information and metadata using regex
func isBuildInformationString(s string) bool {
	// Skip if it's a language internal string first
	if isLanguageInternalString(s) {
		return false
	}

	// Build information patterns from strip_types.go
	buildPatterns := []*regexp.Regexp{
		regexp.MustCompile(`Go build ID: "[a-zA-Z0-9/_\-=+]{20,}"`),                         // Go build ID
		regexp.MustCompile(`\bgo\.buildid\b`),                                               // Build ID marker
		regexp.MustCompile(`\$Id: [a-zA-Z0-9._\-\s/]{10,}\$`),                               // CVS/SVN ID tags
		regexp.MustCompile(`@\(#\)[a-zA-Z0-9._\-\s]{10,}`),                                  // SCCS what strings
		regexp.MustCompile(`\b__DATE__\b|\b__TIME__\b|\b__FILE__\b`),                        // Compiler macros
		regexp.MustCompile(`\bbuild-[a-zA-Z0-9\-]{8,40}\b`),                                 // Build identifiers
		regexp.MustCompile(`\bcommit-[a-f0-9]{7,40}\b`),                                     // Git commit IDs
		regexp.MustCompile(`(?i)build@([a-zA-Z0-9\-]+)`),                                    // Build host
		regexp.MustCompile(`(?i)compiled\s+by\s+[a-zA-Z0-9._\-\s]{5,40}`),                   // Compiled by
		regexp.MustCompile(`(?i)build id\s+[a-zA-Z0-9\-]{8,40}`),                            // Build ID
		regexp.MustCompile(`\b[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9\-.]+)?\+[a-f0-9]{7,40}\b`), // .NET build metadata
		// Source file paths
		regexp.MustCompile(`[A-Za-z]:\\[\\/](?:Users|home|runner|a)[\\/][^\s\x00"]+?\.(?:go|c|cpp|h|hpp|rs|cs|vb)`),
		regexp.MustCompile(`/(?:home|Users|usr|opt|var|runner)/[^\s\x00"]+?\.(?:go|c|cpp|h|hpp|rs|cs|vb)`),
		regexp.MustCompile(`C:\\Users\\[a-zA-Z0-9_\-.]{3,}\\`), // Windows user paths
		regexp.MustCompile(`/home/[a-zA-Z0-9_\-.]{3,}/`),       // Unix user paths
		// PDB and debug paths
		regexp.MustCompile(`(?i)[a-z]:\\[^\s\x00:"*?<>|]+\.pdb`), // Windows PDB path
		regexp.MustCompile(`(?i)/[^\s\x00:"*?<>|]+\.pdb`),        // Unix PDB path
		regexp.MustCompile(`\b[a-zA-Z0-9_]+\.pdb\b`),             // PDB filename
	}

	for _, pattern := range buildPatterns {
		if pattern.MatchString(s) {
			return true
		}
	}

	return false
}

// detectLanguageAndCompiler analyzes the binary to detect programming language and compiler
func (p *PEFile) detectLanguageAndCompiler() (language, compiler string) {
	if p.RawData == nil {
		return "", ""
	}

	// Convert raw data to string for pattern matching
	dataStr := string(p.RawData)

	// Language detection based on runtime signatures and internal strings

	// Go detection (highest priority for Go binaries)
	if strings.Contains(dataStr, "go:buildid") ||
		strings.Contains(dataStr, "runtime.") ||
		strings.Contains(dataStr, "go1.") ||
		strings.Contains(dataStr, "golang.org/") {
		language = "Go"

		// Go compiler version detection
		if match := regexp.MustCompile(`go1\.([0-9]{1,2})(?:\.([0-9]{1,2}))?`).FindStringSubmatch(dataStr); len(match) > 0 {
			compiler = "Go " + match[0]
		} else {
			compiler = "Go (version unknown)"
		}
		return
	}

	// .NET detection
	if strings.Contains(dataStr, "System.") ||
		strings.Contains(dataStr, "mscorlib") ||
		strings.Contains(dataStr, "Microsoft.") ||
		strings.Contains(dataStr, ".ctor") ||
		strings.Contains(dataStr, "System.Private.CoreLib") {
		language = "C#/.NET"

		// .NET version detection
		if strings.Contains(dataStr, ".NET Framework") {
			compiler = ".NET Framework"
		} else if strings.Contains(dataStr, ".NET Core") || strings.Contains(dataStr, "System.Private.CoreLib") {
			compiler = ".NET Core/5+"
		} else {
			compiler = ".NET (version unknown)"
		}
		return
	}

	// Rust detection
	if strings.Contains(dataStr, "rust_panic") ||
		strings.Contains(dataStr, "core::panic") ||
		strings.Contains(dataStr, "alloc::vec") ||
		strings.Contains(dataStr, "__rust_") ||
		strings.Contains(dataStr, "std::") {
		language = "Rust"

		// Rust compiler version detection
		if match := regexp.MustCompile(`rustc ([0-9]+\.[0-9]+\.[0-9]+)`).FindStringSubmatch(dataStr); len(match) > 1 {
			compiler = "rustc " + match[1]
		} else {
			compiler = "rustc (version unknown)"
		}
		return
	}

	// C/C++ detection (GCC/MinGW)
	if strings.Contains(dataStr, "__libc_") ||
		strings.Contains(dataStr, "__glibc_") ||
		strings.Contains(dataStr, "libgcc") ||
		strings.Contains(dataStr, "__cxa_") ||
		strings.Contains(dataStr, "mingw") {

		// Distinguish C vs C++
		if strings.Contains(dataStr, "__cplusplus") ||
			strings.Contains(dataStr, "libstdc++") ||
			strings.Contains(dataStr, "__cxa_") {
			language = "C++"
		} else {
			language = "C"
		}

		// GCC version detection
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

	// MSVC detection (Visual Studio)
	if strings.Contains(dataStr, "VCRUNTIME") ||
		strings.Contains(dataStr, "vcruntime") ||
		strings.Contains(dataStr, "MSVCR") ||
		strings.Contains(dataStr, "api-ms-win-crt") {

		// Check for C++ indicators
		if strings.Contains(dataStr, "std::") ||
			strings.Contains(dataStr, "class ") ||
			strings.Contains(dataStr, "namespace ") {
			language = "C++"
		} else {
			language = "C"
		}

		// MSVC version detection
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

	// Python detection (for compiled Python binaries)
	if strings.Contains(dataStr, "python") ||
		strings.Contains(dataStr, "PyObject") ||
		strings.Contains(dataStr, "_Py_") {
		language = "Python"

		// Python version detection
		if match := regexp.MustCompile(`Python ([0-9]+\.[0-9]+)`).FindStringSubmatch(dataStr); len(match) > 1 {
			compiler = "Python " + match[1]
		} else {
			compiler = "Python (version unknown)"
		}
		return
	}

	// Java detection (for native compiled Java like GraalVM)
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

	// Assembly/Binary-only detection
	if len(p.Imports) == 0 && len(p.Exports) == 0 {
		language = "Assembly/Binary"
		compiler = "Unknown assembler"
		return
	}

	// Default: Unable to detect
	return "", ""
}

// printPackingAnalysis provides detailed analysis of executable packing indicators
func (p *PEFile) printPackingAnalysis() {
	fmt.Printf("\n📦 PACKING ASSESSMENT:\n")

	if len(p.Sections) == 0 {
		fmt.Printf("Status:          ❓ No sections available for analysis\n")
		return
	}

	// Analyze section characteristics
	highEntropyCount := 0
	anomalousCount := 0
	totalValidSections := 0
	emptyCount := 0
	debugCount := 0

	// Calculate data percentages
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

	// Report analysis metrics aligned with other sections
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

	// Simple status assessment
	if p.IsPacked {
		fmt.Printf("Status:          📦 PACKED executable detected\n")
	} else {
		fmt.Printf("Status:          ✅ Normal executable\n")
	}
}

// formatFileAge converts days to a human-readable format (years, months, days)
func formatFileAge(totalDays float64) string {
	if totalDays < 1 {
		return "less than 1 day"
	}

	days := int(totalDays)

	// Calculate years, months, and remaining days
	years := days / 365
	remainingDays := days % 365
	months := remainingDays / 30
	finalDays := remainingDays % 30

	var parts []string

	if years > 0 {
		if years == 1 {
			parts = append(parts, "1 year")
		} else {
			parts = append(parts, fmt.Sprintf("%d years", years))
		}
	}

	if months > 0 {
		if months == 1 {
			parts = append(parts, "1 month")
		} else {
			parts = append(parts, fmt.Sprintf("%d months", months))
		}
	}

	if finalDays > 0 || len(parts) == 0 {
		if finalDays == 1 {
			parts = append(parts, "1 day")
		} else {
			parts = append(parts, fmt.Sprintf("%d days", finalDays))
		}
	}

	// Join with commas and "and" for the last part
	if len(parts) == 1 {
		return parts[0]
	} else if len(parts) == 2 {
		return parts[0] + " and " + parts[1]
	} else {
		return strings.Join(parts[:len(parts)-1], ", ") + ", and " + parts[len(parts)-1]
	}
}
