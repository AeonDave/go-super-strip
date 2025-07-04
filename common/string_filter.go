package common

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var (
	// Garbage detection patterns - migliorati
	assemblyArtifactRegex = regexp.MustCompile(`(\w*[\$` + "`" + `%]\d+[\w\$` + "`" + `%]*){3,}`)
	knownGarbageRegex     = regexp.MustCompile(`(?i)\b(?:PC\b.*=|text=.*minpc=|\d+[]\[;:]|\w*\$\w*\d\w*)\b|(?:\bNaN\b|\ballocs?\b|\bpanic\b|\bdying\b)`)
	assemblyCodeRegex     = regexp.MustCompile(`^[a-z]\$\([HM]\d+[,$][a-z$\d]+\)$|^[DTHL]\d+\$[<$(][HTDL]\d+[a-z@$\d<>()]*$`) // Assembly code patterns

	// Internal/runtime patterns
	runtimePrefixes    = regexp.MustCompile(`^(?:go|runtime|std|core|alloc|System|Microsoft|__libc_|__glibc_|rust_|_ZN)[./:]`)
	internalSuffixes   = regexp.MustCompile(`(?:\.(?:dll|so|dylib|resources|resx|inittask|typelink|rodata|strtab|symtab|init|fini|plt|got|eh_frame|ctors|dtors)|<Module>|<PrivateImplementationDetails>)$`)
	lowLevelPatterns   = regexp.MustCompile(`^[@#$%][0-9A-Fa-f]{2,8}$|^\.[a-z]{2,8}[0-9]*$|_GLOBAL_OFFSET_TABLE_|__stack_chk_fail|__cxa_|_Unwind_|_IO_|\.cctor|\.ctor|get_|set_`)
	typeSystemPatterns = regexp.MustCompile(`^\*(?:map\[|struct\s*\{|\[[0-9]+])|^(?:interface\{}|func\(|<-chan|chan<-|chan\s)|^(?:uintptr|int8|int16|int32|uint8|uint16|uint32|uint64|float32|float64|complex64|complex128|string|bool|byte|rune)$|\*\[[0-9]+]struct|\.\.dict\.`)
	goInternalPatterns = regexp.MustCompile(`^\*(?:boring|tls|http|x509|crypto|context|cipher|flate|hpack|aes|hmac|asn1|mlkem|elliptic)\.|^(?:boring|tls|http|x509|crypto|context|cipher|flate|hpack|aes|hmac|asn1|mlkem|elliptic)\.`)

	// Category-specific patterns
	networkURLRegex   = regexp.MustCompile(`^(?:https?|ftp|ssh|telnet|ldap)://[a-zA-Z0-9.-]+|^www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|^[a-zA-Z0-9.-]+\.(?:com|org|net|edu|gov|mil|info|biz|io|co)(?:/|$)|^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?/`)
	emailRegex        = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	uuidRegex         = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	VersionRegex      = regexp.MustCompile(`(?i)\b(?:v|vers|version)\s*\.?\s*([0-9]{1,3}\.){1,2}[0-9]{1,3}(?:-[a-zA-Z0-9]+)?(?:\+[a-zA-Z0-9]+)?\b|go1\.[0-9]{1,2}(?:\.[0-9]{1,2})?\b|GCC: \([^)]+\) [0-9]+\.[0-9]+\.[0-9]+\b`)
	BuildInfoRegex    = regexp.MustCompile(`(?i)(?:Go build ID: "[a-zA-Z0-9/_\-=+]"|build[-\s]?id[:\s]*[a-f0-9]{7,40}|commit[-:\s]*[a-f0-9]{7,40}|revision[-:\s]*[a-f0-9]{7,40}|(?:gcc|clang|rustc|msvc|dotnet|mono|delphi|fpc|dmd)[\s:/\-]+[0-9]+\.[0-9]+(?:\.[0-9]+)?|/build/[^/\s]+/[^/\s]+\.(go|c|cpp|rs|cs|vb)|version\s*[0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	hexStringRegex    = regexp.MustCompile(`^[0-9A-Fa-f]{32,}$`)
	base64Regex       = regexp.MustCompile(`^[A-Za-z0-9+/]{20,}={0,2}$`)
	urlEncodedRegex   = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
	realFilePathRegex = regexp.MustCompile(`^[A-Za-z]:\\[^<>:"|?*\x00-\x1f]+\.[a-zA-Z0-9]{1,4}$|^/[^<>:"|?*\x00-\x1f/]+(/[^<>:"|?*\x00-\x1f/]+)*\.[a-zA-Z0-9]{1,4}$`)
	sensitivePattern  = regexp.MustCompile(`(?i)\b(?:api_?key|secret|access_?token|auth_?token|password|credentials?)\b`)
	dateRegex         = regexp.MustCompile(`(?i)\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*[\s\-.,/]+\d{1,2}|\d{1,2}[\s\-.,/]+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*|\b\d{4}[-/]\d{2}[-/]\d{2}\b`)
)

var (
	suspiciousExtensions = map[string]bool{
		".exe": true, ".bat": true, ".cmd": true, ".ps1": true, ".sh": true,
	}

	cryptoKeywords = map[string]bool{
		"begin": true, "end": true, "certificate": true, "private": true, "public": true,
		"key": true, "encrypted": true, "signature": true, "hash": true, "digest": true,
		"cipher": true, "token": true, "secret": true, "credential": true,
	}

	shellKeywords = map[string]bool{
		"bash": true, "sh": true, "cmd": true, "powershell": true, "sudo": true,
		"chmod": true, "wget": true, "curl": true, "nc": true, "netcat": true,
	}

	internalKeywords = map[string]bool{
		"runtime": true, "syscall": true, "libc": true, "glibc": true, "msvcrt": true,
		"heap": true, "alloc": true, "malloc": true, "debug": true, "trace": true,
	}
)

func PrintSuspiciousStrings(rawData []byte) {
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

	allStrings := extractStrings(rawData)
	if len(allStrings) == 0 {
		fmt.Printf("%s No strings extracted for analysis\n", SymbolInfo)
		fmt.Println()
		return
	}

	filteredStrings := filterAndCategorize(allStrings, categories)
	if len(filteredStrings) == 0 {
		fmt.Printf("%s No suspicious content detected (filtered %d benign strings)\n",
			SymbolCheck, len(allStrings))
		fmt.Println()
		return
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
		fmt.Printf("\n%s No suspicious content detected\n", SymbolCheck)
	}
	fmt.Println()
}

func extractStrings(data []byte) []string {
	var results []string
	var current []byte
	const minLen = 8

	i := 0
	for i < len(data) {
		b := data[i]

		// Check for Unicode (null-terminated wide chars)
		if i+1 < len(data) && data[i+1] == 0 && b >= 32 && b <= 126 {
			// Process as Unicode string
			for i < len(data)-1 && data[i+1] == 0 && data[i] >= 32 && data[i] <= 126 {
				current = append(current, data[i])
				i += 2
			}
		} else if b >= 32 && b <= 126 {
			// Process as ASCII string
			current = append(current, b)
			i++
		} else {
			// End of string
			if len(current) >= minLen {
				s := strings.TrimSpace(string(current))
				if len(s) >= minLen {
					results = append(results, s)
				}
			}
			current = nil
			i++
		}
	}

	// Handle final string
	if len(current) >= minLen {
		s := strings.TrimSpace(string(current))
		if len(s) >= minLen {
			results = append(results, s)
		}
	}

	return results
}

func filterAndCategorize(strs []string, categories map[string][]string) []string {
	var filtered []string
	for _, s := range strs {
		s = strings.TrimSpace(s)
		if isGarbage(s) || isInternalString(s) {
			continue
		}
		categorized := categorizeString(s, categories)
		if categorized {
			filtered = append(filtered, s)
		}
	}

	return filtered
}

func categorizeString(s string, categories map[string][]string) bool {
	sLower := strings.ToLower(s)

	if VersionRegex.MatchString(s) {
		if len(s) < 100 && !strings.Contains(s, "error") && !strings.Contains(s, "failed") &&
			!strings.Contains(s, "malformed") && !strings.Contains(s, "invalid") {
			categories["🔧 Versions/Compiler"] = append(categories["🔧 Versions/Compiler"], s)
			return true
		}
	}

	// Check build information
	if BuildInfoRegex.MatchString(s) || containsDatePattern(sLower) {
		categories["🏗️ Build Information"] = append(categories["🏗️ Build Information"], s)
		return true
	}

	// Check network URLs
	if networkURLRegex.MatchString(sLower) {
		categories["🌐 Network URLs"] = append(categories["🌐 Network URLs"], s)
		return true
	}

	// Check cryptographic content
	if isCryptographicContent(s, sLower) {
		categories["🔑 Cryptographic Content"] = append(categories["🔑 Cryptographic Content"], s)
		return true
	}

	// Check suspicious file paths
	if isSuspiciousFilePath(s, sLower) {
		categories["💾 Suspicious File Paths"] = append(categories["💾 Suspicious File Paths"], s)
		return true
	}

	// Check shell commands
	if isShellCommand(s, sLower) {
		categories["⚡ Shell Commands"] = append(categories["⚡ Shell Commands"], s)
		return true
	}

	// Check obfuscated content
	if isObfuscatedContent(s) {
		categories["🎭 Obfuscated Content"] = append(categories["🎭 Obfuscated Content"], s)
		return true
	}

	// Check external references
	if isExternalReference(s, sLower) {
		categories["🔗 External References"] = append(categories["🔗 External References"], s)
		return true
	}

	return false
}

func isGarbage(s string) bool {
	n := len(s)
	if n < 8 {
		return true
	}

	if assemblyCodeRegex.MatchString(s) {
		return true
	}

	if assemblyArtifactRegex.MatchString(s) || knownGarbageRegex.MatchString(s) {
		return true
	}
	if CalculateStringEntropy(s) < 2.0 {
		return true
	}

	var specialCount, controlCount, letterCount int
	hasNull := false
	for _, r := range s {
		if r == 0 {
			hasNull = true
			break
		}
		switch {
		case unicode.IsLetter(r):
			letterCount++
		case r < 32 || r == 127:
			controlCount++
		case strings.ContainsRune("$`@#^&*()[]{}|\\<>?~+=%", r):
			specialCount++
		}
	}
	controlRatio := float64(controlCount) / float64(n)
	specialRatio := float64(specialCount) / float64(n)
	return hasNull || controlRatio > 0.15 || (specialRatio > 0.4 && float64(letterCount)/float64(n) < 0.3)
}

func isInternalString(s string) bool {
	// Skip symbol-like strings containing parentheses (likely internal code symbols)
	if strings.Contains(s, "(") && strings.Contains(s, ")") {
		return true
	}
	if runtimePrefixes.MatchString(s) || internalSuffixes.MatchString(s) ||
		lowLevelPatterns.MatchString(s) || typeSystemPatterns.MatchString(s) || goInternalPatterns.MatchString(s) {
		return true
	}
	sLower := strings.ToLower(s)
	for keyword := range internalKeywords {
		if strings.Contains(sLower, keyword) {
			return true
		}
	}
	return false
}

func isCryptographicContent(s, sLower string) bool {
	if strings.Contains(s, "0123456789") || len(s) < 20 {
		return false
	}
	hasCryptoKeyword := false
	for keyword := range cryptoKeywords {
		if strings.Contains(sLower, keyword) {
			hasCryptoKeyword = true
			break
		}
	}
	if !hasCryptoKeyword {
		return false
	}
	return (base64Regex.MatchString(s) && len(s) >= 44) ||
		(hexStringRegex.MatchString(s) && (len(s) == 32 || len(s) == 40 || len(s) == 64 || len(s) == 128)) ||
		(CalculateStringEntropy(s) > 6.5 && len(s) >= 44 && len(s) <= 256)
}

func isSuspiciousFilePath(s, sLower string) bool {
	if !realFilePathRegex.MatchString(s) {
		for ext := range suspiciousExtensions {
			if strings.HasSuffix(sLower, ext) && len(s) > len(ext)+3 {
				return true
			}
		}
	} else {
		for ext := range suspiciousExtensions {
			if strings.HasSuffix(sLower, ext) {
				return true
			}
		}
	}
	if strings.Contains(s, "\\") || strings.Contains(s, "/") {
		suspiciousPaths := []string{
			"\\temp\\", "\\tmp\\", "%temp%", "%appdata%", "\\windows\\",
			"\\system32\\", "/etc/passwd", "/etc/shadow", "/root/.ssh",
			"/tmp/", "/var/tmp/", "/bin/", "/usr/bin/",
		}
		for _, path := range suspiciousPaths {
			if strings.Contains(sLower, path) {
				return true
			}
		}
		if (strings.HasPrefix(sLower, "c:\\") || strings.HasPrefix(sLower, "/")) &&
			len(s) > 8 && realFilePathRegex.MatchString(s) {
			return true
		}
	}

	return false
}

func isShellCommand(s, sLower string) bool {
	if len(s) < 10 {
		return false
	}
	letterCount := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			letterCount++
		}
	}
	if float64(letterCount)/float64(len(s)) < 0.3 {
		return false
	}
	for keyword := range shellKeywords {
		if strings.HasPrefix(sLower, keyword+" ") || strings.Contains(s, " "+keyword+" ") {
			return true
		}
	}
	shellPatterns := []string{"#!/bin/", "export ", "$PATH", "$HOME"}
	for _, pattern := range shellPatterns {
		if strings.Contains(s, pattern) {
			return true
		}
	}
	if strings.Contains(s, "${") && strings.Contains(s, "}") {
		return true
	}
	if strings.Contains(s, "$(") && strings.Contains(s, ")") && letterCount > 5 {
		return true
	}
	if (strings.Contains(s, " && ") || strings.Contains(s, " || ") || strings.Contains(s, " | ")) && letterCount > 8 {
		return true
	}

	return false
}

func isObfuscatedContent(s string) bool {
	entropy := CalculateStringEntropy(s)
	length := len(s)

	// Highly suspicious: very high entropy + very long
	if entropy > 7.0 && length > 256 && !strings.ContainsAny(s, "-._:/\\") {
		return true
	}

	// High entropy, but shorter
	if entropy > 6.0 && length >= 32 && length <= 128 {
		if !strings.ContainsAny(s, "-./\\_:") && !strings.ContainsAny(s, "$%@#") {
			return true
		}
	}

	// Base64-encoded strings
	if base64Regex.MatchString(s) && length >= 44 && entropy > 5.0 {
		if !strings.ContainsAny(s, "%$@#") {
			return true
		}
	}

	// Hex strings
	if hexStringRegex.MatchString(s) && length >= 40 && entropy > 4.0 {
		return true
	}

	// URL-encoded blobs
	if urlEncodedRegex.MatchString(s) && length >= 30 {
		encodedCount := len(urlEncodedRegex.FindAllString(s, -1))
		if float64(encodedCount*3)/float64(length) > 0.3 {
			return true
		}
	}

	return false
}

func isExternalReference(s, sLower string) bool {
	// Email check
	if emailRegex.MatchString(s) {
		return true
	}

	// UUID check
	if uuidRegex.MatchString(sLower) {
		return true
	}

	// Registry keys
	if strings.HasPrefix(s, "HKEY_") || strings.Contains(s, "\\SOFTWARE\\") {
		return true
	}

	// API keys/tokens/secrets
	if len(sLower) < 8 && sensitivePattern.MatchString(sLower) {
		return true
	}
	return false
}

func containsDatePattern(s string) bool {
	if strings.Contains(s, "SunMonTueWedThuFriSat") || strings.Contains(s, "JanFebMarAprMayJunJulAugSepOctNovDec") {
		return false
	}
	return dateRegex.MatchString(s)
}
