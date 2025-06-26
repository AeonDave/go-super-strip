package common

import (
	"crypto/rand"
	"fmt"
	"strings"
)

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
