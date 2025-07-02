package common

import (
	"crypto/rand"
	"fmt"
	"math"
	"strings"
)

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

func GenerateRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate %d random bytes: %w", size, err)
	}
	return b, nil
}

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

func FormatFileSize(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	} else {
		return fmt.Sprintf("%.2f MB", float64(size)/(1024*1024))
	}
}

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

func GetEntropyColor(entropy float64) string {
	if entropy > 7.5 {
		return ColorRed // Red
	} else if entropy > 6.5 {
		return ColorYellow // Yellow
	} else {
		return ColorGreen // Green
	}
}

func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func ZeroFillData(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func RandomFillData(data []byte) error {
	if _, err := rand.Read(data); err != nil {
		return err
	}
	return nil
}

func FirstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
