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
	p.printBasicInfo()
	p.printPEHeaders()
	p.printSectionAnalysis()
	p.printSectionAnomalies()
	p.printImportsAnalysis()
	p.printExportAnalysis()
	PrintSuspiciousStrings(p)
	return nil
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
	if p.TimeDateStamp != "" {
		fmt.Printf("Compile Time:    %s\n", p.TimeDateStamp)
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

	fmt.Printf("Sections:        %d total\n", len(p.Sections))
	fmt.Printf("Packed Status:   %s\n", map[bool]string{true: "📦 Likely PACKED", false: "✅ Not packed"}[p.IsPacked])
	fmt.Printf("Image Base:      0x%X\n", p.ImageBase())
	fmt.Printf("Entry Point:     0x%X (RVA)\n", p.EntryPoint())
	fmt.Printf("Size of Image:   %d bytes (%s)\n", p.SizeOfImage(), common.FormatFileSize(int64(p.SizeOfImage())))
	fmt.Printf("Size of Headers: %d bytes\n", p.SizeOfHeaders())

	checksum := p.Checksum()
	if checksum != 0 {
		fmt.Printf("Checksum:        0x%X\n", checksum)
	} else {
		fmt.Printf("Checksum:        Not set\n")
	}

	fmt.Printf("File Type:       %s\n", p.GetFileType())
	subsystemName := getSubsystemName(p.Subsystem())
	fmt.Printf("Subsystem:       %d (%s)\n", p.Subsystem(), subsystemName)

	dllChars := decodeDLLCharacteristics(p.DllCharacteristics())
	fmt.Printf("DLL Characteristics: 0x%X (%s)\n", p.DllCharacteristics(), dllChars)

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

	versionInfo := p.VersionInfo()
	if len(versionInfo) > 0 {
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

	if len(p.RawData) > 200 {
		richFound := false

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

	if p.PDB() != "" && p.PDB() != "@" && !strings.HasPrefix(p.PDB(), "@") {
		fmt.Printf("\n🐛 DEBUG INFO:\n")
		fmt.Printf("Debug Info:      %s\n", p.PDB())
		if p.GUIDAge() != "" {
			fmt.Printf("GUID/Age:        %s\n", p.GUIDAge())
		}
	}

	fmt.Printf("\n🔧 FILE INTEGRITY & COMPLIANCE:\n")
	var issues []string
	var warnings []string
	complianceChecks := 0
	complianceViolations := 0

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

	fmt.Printf("PE Compliance:   %d/%d checks passed\n", complianceChecks-complianceViolations, complianceChecks)

	if complianceViolations == 0 {
		fmt.Printf("Overall Status:  ✅ Fully compliant PE file\n")
	} else if complianceViolations <= 2 {
		fmt.Printf("Overall Status:  ⚠️ Minor issues detected\n")
	} else {
		fmt.Printf("Overall Status:  ❌ Significant issues detected\n")
	}

	p.printPackingAnalysis()

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

func AnalyzeSectionAnomalies(sections []SectionInfo) []string {
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
		if s.FileOffset > 0 && s.FileOffset%0x200 != 0 {
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
	suspiciousNames := []string{
		"UPX0", "UPX1", "UPX2", "UPX3", "UPX!", ".UPX0", ".UPX1", ".UPX2",
		".aspack", ".ASPack", "ASPack", ".adata",
		".petite",
		"MEW",
		"FSG!",
		".themida", ".Themida", "Themida", "WinLicen",
		".vmp", ".vmp0", ".vmp1", ".vmp2", "VProtect", "VMProtect",
		".enigma", ".enigma1", ".enigma2",
		".obsidium",
		".armadillo",
		".RLPack",
		"PEPACK!!",
		"ProCrypt",
		".svkp",
		".shrink1", ".shrink2", ".shrink3",
		".nsp0", ".nsp1", ".nsp2", "nsp0", "nsp1", "nsp2",
		".MPRESS1", ".MPRESS2",
		".neolite", ".neolit",
		"pebundle", "PEBundle",
		"PEC2TO", "PECompact2", "PEC2", "pec", "pec1", "pec2", "pec3", "pec4", "pec5", "pec6", "PEC2MO",
		"PELOCKnt",
		".perplex",
		"PESHiELD",
		".Upack", ".ByDwing",
		".WWPACK", ".WWP32",
		".yP", ".y0da",
		"BitArts",
		"DAStub",
		"!EPack",
		"kkrunchy",
		".MaskPE",
		"RCryptor", ".RPCrypt",
		".seau",
		".sforce3",
		"_winzip_",

		// Generic suspicious names
		".packed", ".compress", ".crypt", ".encode",
		".stub", ".loader", ".inject", ".shell",
		".payload", ".hook", ".keylog",

		// Other known suspicious/uncommon names
		".boom",
		".ccg",
		".charmve", ".pinclie", // PIN tool
		".ecode", ".edata", // EPL
		".gentee",
		".imrsiv",
		"lz32.dll",             // Crinkler
		".mackt",               // ImpRec
		".mnbvcx1", ".mnbvcx2", // Firseria PUP
		".profile", // NightHawk C2
		".rmnet",   // Ramnit virus
		".spack",
		".taz",                 // PESpin
		".tsuarch", ".tsustub", // TSULoader
		".winapi", // API Override tool

		// Legacy/generic names that can be suspicious
		"CODE", "DATA",
	}

	for _, suspicious := range suspiciousNames {
		if strings.Contains(name, suspicious) {
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
	ascii := ExtractSuspiciousStrings(p.RawData, false)
	uni := ExtractSuspiciousStrings(p.RawData, true)
	allStrings := append(ascii, uni...)
	if len(allStrings) == 0 {
		fmt.Printf("%s No strings extracted for analysis\n", common.SymbolInfo)
		fmt.Println()
		return
	}
	filteredStrings := filterRelevantStrings(allStrings)
	if len(filteredStrings) == 0 {
		fmt.Printf("%s No suspicious content detected (filtered %d benign strings)\n",
			common.SymbolCheck, len(allStrings))
		fmt.Println()
		return
	}

	for _, s := range filteredStrings {
		categorized := false
		if isVersionOrCompilerString(s) {
			categories["🔧 Versions/Compiler"] = append(categories["🔧 Versions/Compiler"], s)
			categorized = true
		}
		if !categorized && isBuildInformationString(s) {
			categories["🏗️ Build Information"] = append(categories["🏗️ Build Information"], s)
			categorized = true
		}
		if !categorized && isNetworkURL(s) {
			categories["🌐 Network URLs"] = append(categories["🌐 Network URLs"], s)
			categorized = true
		}
		if !categorized && isCryptographicContent(s) {
			categories["🔑 Cryptographic Content"] = append(categories["🔑 Cryptographic Content"], s)
			categorized = true
		}
		if !categorized && isSuspiciousFilePath(s) {
			categories["💾 Suspicious File Paths"] = append(categories["💾 Suspicious File Paths"], s)
			categorized = true
		}
		if !categorized && isShellCommand(s) {
			categories["⚡ Shell Commands"] = append(categories["⚡ Shell Commands"], s)
			categorized = true
		}
		if !categorized && isObfuscatedContent(s) {
			categories["🎭 Obfuscated Content"] = append(categories["🎭 Obfuscated Content"], s)
			categorized = true
		}
		if !categorized && isExternalReference(s) {
			categories["🔗 External References"] = append(categories["🔗 External References"], s)
		}
	}
	totalFindings := 0
	for _, items := range categories {
		totalFindings += len(items)
	}
	for category, items := range categories {
		if len(items) > 0 {
			fmt.Printf("\n%s (%d items):\n", category, len(items))
			for _, item := range items {
				fmt.Printf("   • %s\n", item)
			}
		}
	}
	if totalFindings > 0 {
		fmt.Printf("\n📊 Found %d potentially suspicious items\n", totalFindings)
	} else {
		fmt.Printf("\n%s No suspicious content detected\n", common.SymbolCheck)
	}

	fmt.Println()
}

func filterRelevantStrings(strs []string) []string {
	var filtered []string

	for _, s := range strs {

		if len(s) < 8 || len(s) > 512 {
			continue
		}

		trimmed := strings.TrimSpace(s)
		if len(trimmed) == 0 {
			continue
		}

		printableCount := 0
		for _, r := range s {
			if unicode.IsPrint(r) && r != ' ' && r != '\t' && r != '\n' && r != '\r' {
				printableCount++
			}
		}
		if float64(printableCount)/float64(len(s)) < 0.3 {
			continue
		}

		if isLanguageInternalString(s) || isCompilerArtifact(s) || isCommonLibraryString(s) {
			continue
		}

		if common.IsPureNumeric(s) || common.IsRepetitivePattern(s) {
			continue
		}

		if common.CalculateStringEntropy(s) < 1.5 {
			continue
		}

		filtered = append(filtered, s)
	}

	return filtered
}

func isLanguageInternalString(s string) bool {

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

		"net/http.", "net/url.", "type:.eq.", "http.socks", ".socks",
		"socksNewDialer", "socksnoDeadline", "socksAuthMethod", "socksReply",
		"socksaLongTimeAgo", "sockssplitHostPort", "/http.", "/url.",
		".String", ".Error", ".URL", ".Userinfo", ".segment",
		"http.segment", "url.URL", "url.Error", "url.Userinfo",

		"io.Copy", "io.copy", "mime.consume", "mime.", "bufio.",
		"crypto/rand", "crypto/cipher", "crypto/subtle", "crypto/ed25519",
		"crypto/rsa", "crypto/ecdsa", "crypto/tls", "crypto/x509",
		"encoding/base64", "encoding/hex", "encoding/json", "encoding/xml",
		"compress/gzip", "compress/zlib", "archive/tar", "archive/zip",
		"image/png", "image/jpeg", "image/gif", "text/template",
		"html/template", "net/textproto", "net/mail", "net/smtp",
		"database/sql", "log/syslog", "go/build", "go/parser",

		"unicode.", "unicode/", ".convert", "convertCase", ".Case",
		"unicode.convert", "unicode.Case", "unicode.To", "unicode.Is",
	}

	dotnetPatterns := []string{
		"System.", "Microsoft.", "mscorlib", ".resources", ".resx",
		"<Module>", "<PrivateImplementationDetails>", "_GLOBAL_OFFSET_TABLE_",
		".cctor", ".ctor", "get_", "set_", "System.Private.CoreLib",
	}

	cPatterns := []string{
		"__libc_", "__glibc_", "_GLOBAL_OFFSET_TABLE_", "__cxa_",
		"_init_", "_fini_", "_start", "__stack_chk_fail",
		"libgcc_", "libstdc++", "__gnu_", "_Unwind_",
	}

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

func isCompilerArtifact(s string) bool {
	patterns := []string{

		"GCC: (", "clang version", "rustc ", "go1.",

		"/usr/lib/gcc", "/opt/", "/build/", "/tmp/go-build",
		"/usr/include", "/usr/local/", "/home/", "/root/",

		".debug_", ".eh_frame", ".plt", ".got", ".bss", ".data",
		"DWARF", "dwarf", ".symtab", ".strtab", ".shstrtab",

		"ld-linux", "gcc", "g++", "clang", "rustc", "cargo",
	}

	for _, pattern := range patterns {
		if strings.Contains(s, pattern) {
			return true
		}
	}

	return false
}

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

func isNetworkURL(s string) bool {

	if isLanguageInternalString(s) {
		return false
	}

	if strings.Contains(s, "type:.eq.") || strings.Contains(s, "net/http.") ||
		strings.Contains(s, "net/url.") || strings.Contains(s, ".String") ||
		strings.Contains(s, ".Error") || strings.Contains(s, ".segment") {
		return false
	}

	urlPrefixes := []string{"http://", "https://", "ftp://", "ftps://", "ssh://", "telnet://", "ldap://", "ldaps://"}
	for _, prefix := range urlPrefixes {
		if strings.HasPrefix(strings.ToLower(s), prefix) {

			remaining := s[len(prefix):]
			if len(remaining) > 3 && strings.Contains(remaining, ".") {
				return true
			}
		}
	}

	domainTLDs := []string{".com", ".org", ".net", ".edu", ".gov", ".mil", ".info", ".biz", ".io", ".co"}
	for _, tld := range domainTLDs {
		if strings.Contains(strings.ToLower(s), tld) {

			if !strings.Contains(s, "/") && !strings.Contains(s, "\\") &&
				!strings.Contains(s, "type:") && !strings.Contains(s, ".go") {

				if regexp.MustCompile(`^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}$`).MatchString(s) {
					return true
				}
			}
		}
	}

	ipPattern := regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?$`)
	return ipPattern.MatchString(s)
}

func isCryptographicContent(s string) bool {

	if isLanguageInternalString(s) {
		return false
	}

	if strings.Contains(s, "0123456789") && strings.Contains(s, "abcdef") {
		return false
	}

	controlCount := 0
	for _, r := range s {
		if r < 32 || r == 127 || (r >= 128 && r <= 159) {
			controlCount++
		}
	}
	if float64(controlCount)/float64(len(s)) > 0.2 {
		return false
	}

	if common.IsBase64Like(s) && len(s) >= 44 {

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

	if common.IsHexStringStrict(s) {
		if len(s) == 32 || len(s) == 40 || len(s) == 64 || len(s) == 128 {

			if !strings.Contains(s, ".") && !strings.Contains(s, "-") {
				return true
			}
		}
	}

	if common.CalculateStringEntropy(s) > 5.5 && len(s) >= 44 && len(s) <= 256 {

		if !strings.Contains(s, "struct") && !strings.Contains(s, "func") &&
			!strings.Contains(s, "map[") && !strings.Contains(s, "interface") &&
			!strings.Contains(s, "SETTINGS") && !strings.Contains(s, "TIMEOUT") {
			return true
		}
	}

	return false
}

func isSuspiciousFilePath(s string) bool {

	if strings.HasSuffix(strings.ToLower(s), ".exe") ||
		strings.HasSuffix(strings.ToLower(s), ".bat") ||
		strings.HasSuffix(strings.ToLower(s), ".cmd") ||
		strings.HasSuffix(strings.ToLower(s), ".ps1") ||
		strings.HasSuffix(strings.ToLower(s), ".sh") {

		if !isCompilerArtifact(s) {
			return true
		}
	}

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

func isShellCommand(s string) bool {

	if isLanguageInternalString(s) {
		return false
	}

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

	specialCount := 0
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != ' ' && r != '.' && r != '/' && r != '\\' && r != '-' && r != '_' {
			specialCount++
		}
	}
	if float64(specialCount)/float64(len(s)) > 0.3 {
		return false
	}

	executableCommands := []string{

		"cmd.exe /c ", "cmd /c ", "powershell.exe -Command", "powershell -Command",
		"powershell.exe -EncodedCommand", "powershell -EncodedCommand",
		"net.exe user", "net.exe localgroup", "sc.exe create", "sc.exe delete",
		"reg.exe add", "reg.exe delete", "taskkill /F", "schtasks /create",
		"regsvr32 /s", "rundll32.exe ", "mshta.exe http", "wscript.exe ",

		"/bin/sh -c", "/bin/bash -c", "chmod +x ", "curl -O", "wget -O",
		"sudo rm", "sudo mv", "sudo cp", "cat /etc/", "ls -la", "ps aux | grep",
	}

	for _, cmd := range executableCommands {
		if strings.Contains(s, cmd) {
			return true
		}
	}

	if regexp.MustCompile(`^[a-zA-Z0-9_\-/\\]+\.(exe|bat|cmd|ps1|sh)\s+[a-zA-Z0-9\-/\\]`).MatchString(s) {
		return true
	}

	if regexp.MustCompile(`^(python|node|java|ruby|perl)\s+[a-zA-Z0-9\-/\\._]+\.(py|js|jar|rb|pl)`).MatchString(s) {
		return true
	}

	return false
}

func isObfuscatedContent(s string) bool {

	if isLanguageInternalString(s) {
		return false
	}

	if common.IsBase64Like(s) && len(s) >= 32 {

		if !strings.Contains(s, "Key") && !strings.Contains(s, "Token") &&
			!strings.Contains(s, "Binary") && common.CalculateStringEntropy(s) > 4.0 {
			return true
		}
	}

	if common.IsHexStringStrict(s) && len(s) >= 32 {

		if !strings.Contains(s, ".") && !strings.Contains(s, "-") &&
			common.CalculateStringEntropy(s) > 3.5 {
			return true
		}
	}

	if common.CalculateStringEntropy(s) > 5.5 && len(s) >= 32 && len(s) <= 128 {

		if !strings.Contains(s, "-") && !strings.Contains(s, ".") &&
			!strings.Contains(s, "/") && !strings.Contains(s, "\\") &&
			!strings.Contains(s, "_") && !strings.Contains(s, ":") &&
			!isLanguageInternalString(s) {
			return true
		}
	}

	if strings.Contains(s, "%") && regexp.MustCompile(`%[0-9A-Fa-f]{2}`).MatchString(s) {
		urlDecodedCount := strings.Count(s, "%")
		if float64(urlDecodedCount)/float64(len(s)) > 0.2 {
			return true
		}
	}

	return false
}

func isExternalReference(s string) bool {

	if isLanguageInternalString(s) {
		return false
	}

	if strings.Contains(s, "net/http.") || strings.Contains(s, "net/url.") ||
		strings.Contains(s, "type:.eq.") || strings.Contains(s, "/http.") ||
		strings.Contains(s, "http.socks") || strings.Contains(s, ".String") ||
		strings.Contains(s, ".Error") || strings.Contains(s, ".URL") {
		return false
	}

	if strings.Contains(s, ".") && !strings.Contains(s, "localhost") {
		if (strings.Contains(s, ".exe") || strings.Contains(s, ".dll") || strings.Contains(s, ".so")) &&
			!isCommonLibraryString(s) {
			return true
		}
	}

	if strings.HasPrefix(s, "HKEY_") || strings.Contains(s, "\\SOFTWARE\\") {
		return true
	}

	if (strings.Contains(s, "SERVICE_") || strings.Contains(s, "_SERVICE")) &&
		!strings.Contains(s, "runtime") && !strings.Contains(s, "go") {
		return true
	}

	return false
}

func isVersionOrCompilerString(s string) bool {

	if isLanguageInternalString(s) {
		return false
	}

	versionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\bgo1\.[0-9]{1,2}(\.[0-9]{1,2})?\b`),
		regexp.MustCompile(`(?i)\bGCC: \([^)]+\) [0-9]+\.[0-9]+\.[0-9]+\b`),
		regexp.MustCompile(`\brustc [0-9]+\.[0-9]+\.[0-9]+\b`),
		regexp.MustCompile(`\bversion [0-9]+\.[0-9]+\.[0-9]+\b`),
		regexp.MustCompile(`(?i)compiler version\s+[0-9]+\.[0-9]+[^\n\x00]{0,20}`),
		regexp.MustCompile(`(?i)linker version\s+[0-9]+\.[0-9]+`),
		regexp.MustCompile(`(?i)assembler version\s+[0-9]+\.[0-9]+`),
		regexp.MustCompile(`\bmingw_[a-zA-Z0-9_]{3,}\b`),
		regexp.MustCompile(`\blibgcc[a-zA-Z0-9_]*\.[a-zA-Z0-9]{1,5}\b`),
		regexp.MustCompile(`\b__GNUC__\b|\b__GNUG__\b`),
		regexp.MustCompile(`\b__cplusplus\b`),
	}

	for _, pattern := range versionPatterns {
		if pattern.MatchString(s) {
			return true
		}
	}

	return false
}

func isBuildInformationString(s string) bool {

	if isLanguageInternalString(s) {
		return false
	}

	buildPatterns := []*regexp.Regexp{
		regexp.MustCompile(`Go build ID: "[a-zA-Z0-9/_\-=+]{20,}"`),
		regexp.MustCompile(`\bgo\.buildid\b`),
		regexp.MustCompile(`\$Id: [a-zA-Z0-9._\-\s/]{10,}\$`),
		regexp.MustCompile(`@\(#\)[a-zA-Z0-9._\-\s]{10,}`),
		regexp.MustCompile(`\b__DATE__\b|\b__TIME__\b|\b__FILE__\b`),
		regexp.MustCompile(`\bbuild-[a-zA-Z0-9\-]{8,40}\b`),
		regexp.MustCompile(`\bcommit-[a-f0-9]{7,40}\b`),
		regexp.MustCompile(`(?i)build@([a-zA-Z0-9\-]+)`),
		regexp.MustCompile(`(?i)compiled\s+by\s+[a-zA-Z0-9._\-\s]{5,40}`),
		regexp.MustCompile(`(?i)build id\s+[a-zA-Z0-9\-]{8,40}`),
		regexp.MustCompile(`\b[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9\-.]+)?\+[a-f0-9]{7,40}\b`),
		regexp.MustCompile(`[A-Za-z]:\\[\\/](?:Users|home|runner|a)[\\/][^\s\x00"]+?\.(?:go|c|cpp|h|hpp|rs|cs|vb)`),
		regexp.MustCompile(`/(?:home|Users|usr|opt|var|runner)/[^\s\x00"]+?\.(?:go|c|cpp|h|hpp|rs|cs|vb)`),
		regexp.MustCompile(`C:\\Users\\[a-zA-Z0-9_\-.]{3,}\\`),
		regexp.MustCompile(`/home/[a-zA-Z0-9_\-.]{3,}/`),
		regexp.MustCompile(`(?i)[a-z]:\\[^\s\x00:"*?<>|]+\.pdb`),
		regexp.MustCompile(`(?i)/[^\s\x00:"*?<>|]+\.pdb`),
		regexp.MustCompile(`\b[a-zA-Z0-9_]+\.pdb\b`),
	}

	for _, pattern := range buildPatterns {
		if pattern.MatchString(s) {
			return true
		}
	}

	return false
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

func (p *PEFile) printPackingAnalysis() {
	fmt.Printf("\n📦 PACKING ASSESSMENT:\n")

	if len(p.Sections) == 0 {
		fmt.Printf("Status:          ❓ No sections available for analysis\n")
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
		fmt.Printf("Status:          📦 PACKED executable detected\n")
	} else {
		fmt.Printf("Status:          ✅ Normal executable\n")
	}
}
