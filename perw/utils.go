package perw

import (
	"fmt"
	"gosstrip/common"
	"math"
	"strings"
)

// PrintSignatureAnalysis prints digital signature analysis for a PE file
func PrintSignatureAnalysis(p *PEFile) {
	fmt.Println("🔏 DIGITAL SIGNATURE ANALYSIS")
	fmt.Println("═════════════════════════════")
	if p.SignatureSize != nil && p.SignatureSize() > 0 {
		fmt.Printf("%s Digital signature present (%d bytes)\n", common.SymbolCheck, p.SignatureSize())
	} else {
		fmt.Printf("%s No digital signature found\n", common.SymbolWarn)
	}
	fmt.Println()
}

// PrintSuspiciousStrings prints categorized suspicious strings analysis for a PE file
func PrintSuspiciousStrings(p *PEFile) {
	fmt.Println("🔎 SUSPICIOUS CONTENT ANALYSIS")
	fmt.Println("═══════════════════════════════")

	// Categorize findings
	categories := map[string][]string{
		"URLs & Network":     []string{},
		"File Paths":         []string{},
		"System Libraries":   []string{},
		"Debug/Build Info":   []string{},
		"Encoded/Obfuscated": []string{},
		"Shell Commands":     []string{},
	}

	// Extract and categorize strings
	ascii := extractSuspiciousStrings(p.RawData, false)
	unicode := extractSuspiciousStrings(p.RawData, true)
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
		if !categorized && (len(s) > 20 && isHighEntropyString(s) ||
			strings.Contains(s, "\\x") || containsSuspiciousPattern(s)) {
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
			totalFindings, countNonEmptyCategories(categories))
	}
	fmt.Println()
}

// Helper function to count non-empty categories
func countNonEmptyCategories(categories map[string][]string) int {
	count := 0
	for _, items := range categories {
		if len(items) > 0 {
			count++
		}
	}
	return count
}

// Helper function to detect high entropy strings
func isHighEntropyString(s string) bool {
	if len(s) < 10 {
		return false
	}

	charCount := make(map[rune]int)
	for _, r := range s {
		charCount[r]++
	}

	// Calculate entropy
	entropy := 0.0
	length := float64(len(s))
	for _, count := range charCount {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy > 4.5 // High entropy threshold
}

// Helper function to detect suspicious patterns
func containsSuspiciousPattern(s string) bool {
	// Common shellcode patterns, hex patterns, etc.
	suspiciousPatterns := []string{
		"\\x", "0x", "%x", "\\u", "\\U",
		"[\\", "\\]", "^_", "A\\A", "\\$",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(s, pattern) {
			return true
		}
	}

	return false
}

// extractSuspiciousStrings extracts ASCII/Unicode suspicious strings (URL, shellcode, path, etc)
func extractSuspiciousStrings(data []byte, unicode bool) []string {
	var results []string
	var minLen = 8
	var current []byte
	for i := 0; i < len(data); i++ {
		b := data[i]
		if unicode {
			if i+1 < len(data) && data[i+1] == 0 && b >= 32 && b < 127 {
				current = append(current, b)
				i++ // skip null
			} else if len(current) >= minLen {
				s := string(current)
				if isSuspiciousString(s) {
					results = append(results, "[UNICODE] "+s)
				}
				current = nil
			} else {
				current = nil
			}
		} else {
			if b >= 32 && b < 127 {
				current = append(current, b)
			} else if len(current) >= minLen {
				s := string(current)
				if isSuspiciousString(s) {
					results = append(results, s)
				}
				current = nil
			} else {
				current = nil
			}
		}
	}
	// Check last
	if len(current) >= minLen {
		s := string(current)
		if isSuspiciousString(s) {
			if unicode {
				results = append(results, "[UNICODE] "+s)
			} else {
				results = append(results, s)
			}
		}
	}
	return results
}

// isSuspiciousString is a heuristic for suspicious strings
func isSuspiciousString(s string) bool {
	if len(s) < 8 {
		return false
	}
	// URL, path, powershell, exe, shellcode pattern
	if strings.Contains(s, "http://") || strings.Contains(s, "https://") || strings.Contains(s, ".exe") || strings.Contains(s, "cmd ") || strings.Contains(s, "powershell") || strings.Contains(s, ".dll") || strings.Contains(s, ".bat") || strings.Contains(s, ".scr") || strings.Contains(s, "\\") {
		return true
	}
	// Hex shellcode
	if strings.HasPrefix(s, "\\x") && len(s) > 12 {
		return true
	}
	return false
}

// Overlay analysis utility
func OverlayInfo(fileSize int64, lastSectionOffset int64, lastSectionSize int64, data []byte) (present bool, offset int64, size int64, entropy float64) {
	overlayStart := lastSectionOffset + lastSectionSize
	if overlayStart < fileSize {
		overlayData := data[overlayStart:]
		return true, overlayStart, int64(len(overlayData)), CalculateEntropy(overlayData)
	}
	return false, 0, 0, 0
}

// Export analysis utility (names only)
func FormatExportedSymbols(symbols []string) string {
	if len(symbols) == 0 {
		return common.SymbolWarn + " No exported symbols found"
	}
	out := common.SymbolInfo + " Exported symbols (" + fmt.Sprintf("%d", len(symbols)) + "):\n"
	for _, s := range symbols {
		out += "  - " + s + "\n"
	}
	return out
}

// Section anomaly analysis utility
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

// Helper: entropy calculation (copied from analyze.go, remove duplicate there)
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}
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

// SectionInfo minimal struct for anomaly analysis (to be used in analyze.go)
type SectionInfo struct {
	Name         string
	FileOffset   int64
	Size         int64
	IsExecutable bool
	IsWritable   bool
}
