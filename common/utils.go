package common

import (
	"crypto/rand"
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"
)

// CalculateStringEntropy calcola l'entropia di Shannon di una stringa
func CalculateStringEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// IsPureNumeric controlla se una stringa è composta principalmente da numeri
func IsPureNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	digitCount := 0
	for _, r := range s {
		if unicode.IsDigit(r) {
			digitCount++
		}
	}
	return float64(digitCount)/float64(len(s)) > 0.8
}

// IsRepetitivePattern rileva pattern ripetitivi in una stringa
func IsRepetitivePattern(s string) bool {
	if len(s) < 8 {
		return false
	}
	// Check for repeated substrings
	for i := 1; i <= len(s)/3; i++ {
		substr := s[:i]
		repeated := true
		for j := i; j+i <= len(s); j += i {
			if s[j:j+i] != substr {
				repeated = false
				break
			}
		}
		if repeated {
			return true
		}
	}
	// Check for single character repetition
	charCounts := make(map[rune]int)
	for _, r := range s {
		charCounts[r]++
	}
	for _, count := range charCounts {
		if count > len(s)/2 {
			return true
		}
	}
	return false
}

// IsBase64Like verifica se una stringa sembra base64 (ma non decodifica)
func IsBase64Like(s string) bool {
	if len(s)%4 != 0 {
		return false
	}
	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	return base64Pattern.MatchString(s)
}

// IsHexStringStrict verifica se una stringa è una sequenza esadecimale (versione aggiornata, usata per analisi stringhe)
func IsHexStringStrict(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	hexPattern := regexp.MustCompile(`^[0-9A-Fa-f]+$`)
	return hexPattern.MatchString(s)
}

// FormatFileAge converte giorni in formato leggibile (anni, mesi, giorni)
func FormatFileAge(totalDays float64) string {
	years := int(totalDays) / 365
	months := (int(totalDays) % 365) / 30
	days := int(totalDays) % 30
	var parts []string
	if years > 0 {
		parts = append(parts, fmt.Sprintf("%d years", years))
	}
	if months > 0 {
		parts = append(parts, fmt.Sprintf("%d months", months))
	}
	if days > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d days", days))
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// GenerateRandomBytes generates a slice of random bytes of the specified size
func GenerateRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate %d random bytes: %w", size, err)
	}
	return b, nil
}

// MatchesPattern checks if a string matches any of the given exact names or prefixes
func MatchesPattern(target string, exactNames, prefixNames []string) bool {
	// Check exact matches
	for _, name := range exactNames {
		if name != "" && target == name {
			return true
		}
	}

	// Check prefix matches
	for _, prefix := range prefixNames {
		if prefix != "" && strings.HasPrefix(target, prefix) {
			return true
		}
	}
	return false
}

// Color and symbol constants (shared)
const (
	ColorRed    = "\033[91m"
	ColorYellow = "\033[93m"
	ColorGreen  = "\033[92m"
	ColorReset  = "\033[0m"

	SymbolCheck = "✅"
	SymbolCross = "❌"
	SymbolWarn  = "⚠️"
	SymbolInfo  = "ℹ️"
)

// FormatFileSize returns a human-readable file size string
func FormatFileSize(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	} else {
		return fmt.Sprintf("%.2f MB", float64(size)/(1024*1024))
	}
}

// FormatPermissions returns a string representing section permissions
func FormatPermissions(exec, read, write bool) string {
	perm := ""
	if read {
		perm += "R"
	} else {
		perm += "-"
	}
	if write {
		perm += "W"
	} else {
		perm += "-"
	}
	if exec {
		perm += "X"
	} else {
		perm += "-"
	}
	return perm
}

// GetEntropyColor returns a color code based on entropy value
func GetEntropyColor(entropy float64) string {
	if entropy > 7.5 {
		return ColorRed // Red
	} else if entropy > 6.5 {
		return ColorYellow // Yellow
	} else {
		return ColorGreen // Green
	}
}

// TruncateString truncates a string to maxLen, adding ... if needed
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
