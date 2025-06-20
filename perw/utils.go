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

// PrintSuspiciousStrings prints suspicious strings analysis for a PE file
func PrintSuspiciousStrings(p *PEFile) {
	fmt.Println("🔎 SUSPICIOUS STRINGS ANALYSIS")
	fmt.Println("══════════════════════════════")
	var suspicious []string
	ascii := extractSuspiciousStrings(p.RawData, false)
	unicode := extractSuspiciousStrings(p.RawData, true)
	suspicious = append(suspicious, ascii...)
	suspicious = append(suspicious, unicode...)
	if len(suspicious) == 0 {
		fmt.Printf("%s No suspicious strings found\n", common.SymbolCheck)
	} else {
		for _, s := range suspicious {
			fmt.Printf("%s %s\n", common.SymbolWarn, s)
		}
	}
	fmt.Println()
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
