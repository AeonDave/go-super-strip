package common

import (
	"crypto/rand"
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"
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

func IsHighEntropyData(data []byte) bool {
	entropy := CalculateEntropy(data)
	return entropy > 7.0 // High entropy threshold for binary data
}

func IsHighEntropyString(s string) bool {
	if len(s) < 10 {
		return false
	}
	charCount := make(map[rune]int)
	for _, r := range s {
		charCount[r]++
	}
	entropy := 0.0
	length := float64(len(s))
	for _, count := range charCount {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy > 4.5 // High entropy threshold
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

func extractSuspiciousStrings(data []byte, unicode bool) []string {
	var results []string
	var minLen = 8
	var current []byte
	for i := 0; i < len(data); i++ {
		b := data[i]
		if unicode {
			if i+1 < len(data) && data[i+1] == 0 {
				current = append(current, b)
				i++
			} else {
				if len(current) >= minLen {
					results = append(results, string(current))
				}
				current = nil
			}
		} else {
			if b >= 32 && b <= 126 {
				current = append(current, b)
			} else {
				if len(current) >= minLen {
					results = append(results, string(current))
				}
				current = nil
			}
		}
	}
	if len(current) >= minLen {
		results = append(results, string(current))
	}
	return results
}

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
	ascii := extractSuspiciousStrings(rawData, false)
	uni := extractSuspiciousStrings(rawData, true)
	allStrings := append(ascii, uni...)
	if len(allStrings) == 0 {
		fmt.Printf("%s No strings extracted for analysis\n", SymbolInfo)
		fmt.Println()
		return
	}
	filteredStrings := filterRelevantStrings(allStrings)
	if len(filteredStrings) == 0 {
		fmt.Printf("%s No suspicious content detected (filtered %d benign strings)\n",
			SymbolCheck, len(allStrings))
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
		fmt.Printf("\n%s No suspicious content detected\n", SymbolCheck)
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

		if IsPureNumeric(s) || IsRepetitivePattern(s) {
			continue
		}

		if CalculateStringEntropy(s) < 1.5 {
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
		"libgcc_", "libstdc++", "__gnu_", "_Unwind_", "_IO_",
	}

	rustPatterns := []string{
		"core::panic", "alloc::vec", "std::", "core::", "alloc::",
		"rust_begin_unwind", "rust_panic", "_ZN", "__rust_",
	}

	commonSections := []string{
		".init", ".fini", ".plt", ".got", ".symtab", ".strtab", ".shstrtab",
		".interp", ".note", ".gnu.version", ".gnu.hash", ".dynsym", ".dynstr",
		".rela", ".dynamic", ".eh_frame", ".gcc_except_table", ".ctors", ".dtors",
	}

	allPatterns := append(goPatterns, dotnetPatterns...)
	allPatterns = append(allPatterns, cPatterns...)
	allPatterns = append(allPatterns, rustPatterns...)
	allPatterns = append(allPatterns, commonSections...)

	for _, pattern := range allPatterns {
		if strings.Contains(s, pattern) {
			return true
		}
	}

	return false
}

func isCompilerArtifact(s string) bool {
	patterns := []string{

		"GCC: (", "clang", "LLVM", "compiled", "compiler",
		"clang version", "rustc ", "go1.", "ld-linux", "gcc", "g++", "cargo",

		"/usr/lib/gcc", "/opt/", "/build/", "/tmp/go-build",
		"/usr/include", "/usr/local/", "/home/", "/root/",

		".debug_", ".eh_frame", ".plt", ".got", ".bss", ".data",
		"DWARF", "dwarf", ".symtab", ".strtab", ".shstrtab",

		"optimization", "warning", "error:", "note:", "internal",
		"linker", "assembler", "disassembly", "generated",
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
		"libc.so", "libc", "libstdc++", "libm.so", "libm", "libgcc", "libpthread", "libdl.so",
		"libdl", "librt.so", "libresolv", "librt", "libcrypt",
		"libcrypto", "libutil", "libnsl", "glibc", "ld-linux", "libz", "libnss", "libssl",
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

	urlPrefixes := []string{
		"http://", "https://",
		"ftp://", "ftps://", "sftp://",
		"ssh://", "telnet://", "ldap://", "ldaps://",
		"www.", "smtp://", "pop3://", "imap://",
	}

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

	// Check for base64-like content
	if len(s) >= 20 && IsBase64Like(s) {
		return true
	}

	// Check for high entropy strings that might be encrypted/encoded content
	if len(s) >= 16 && IsHighEntropyString(s) {
		return true
	}

	if IsBase64Like(s) && len(s) >= 44 {

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

	if IsHexStringStrict(s) {
		if len(s) == 32 || len(s) == 40 || len(s) == 64 || len(s) == 128 {

			if !strings.Contains(s, ".") && !strings.Contains(s, "-") {
				return true
			}
		}
	}

	if CalculateStringEntropy(s) > 5.5 && len(s) >= 44 && len(s) <= 256 {

		if !strings.Contains(s, "struct") && !strings.Contains(s, "func") &&
			!strings.Contains(s, "map[") && !strings.Contains(s, "interface") &&
			!strings.Contains(s, "SETTINGS") && !strings.Contains(s, "TIMEOUT") {
			return true
		}
	}

	return false
}

func isSuspiciousFilePath(s string) bool {
	sLower := strings.ToLower(s)
	suspiciousExt := []string{".exe", ".bat", ".cmd", ".ps1", ".sh"}
	for _, ext := range suspiciousExt {
		if strings.HasSuffix(sLower, ext) && !isCompilerArtifact(s) {
			return true
		}
	}
	winPath := []string{
		"\\temp\\", "\\tmp\\", "%temp%", "%appdata%",
		"\\windows\\",
		"\\system32\\", "\\syswow64\\", "\\sysnative\\",
		"\\users\\", "\\documents\\", "\\downloads\\",
		"\\program files\\",
		"\\programdata\\",
		"\\appdata\\local\\",
		"\\appdata\\roaming\\",
		"\\recycle.bin\\",
		"\\system volume information\\",
		"\\documents and settings\\",
		"\\winnt\\",
	}
	unixPath := []string{
		"/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/sudoers",
		"/root/.ssh", "/home/", "/proc/", "/sys/",
		"/dev/", "/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/",
		"/tmp/", "/var/tmp/", "/var/log",
		"/var/run/", "/var/cache/", "/var/backups/",
		"/srv/", "/opt/", "/mnt/", "/media/", "/lost+found",
		"/boot/", "/lib/", "/lib64/",
		"/usr/local/bin/",
		"/usr/local/sbin/", "/run/", "/snap/",
		".conf", ".ini", ".json", ".xml", ".yml", ".yaml",
		".key", ".pem", ".crt", ".cer", ".p12", ".pfx",
		".bashrc, .bash_profile, .profile, .ssh/authorized_keys",
	}
	for _, path := range append(winPath, unixPath...) {
		if strings.Contains(sLower, strings.ToLower(path)) {
			return true
		}
	}
	if strings.HasPrefix(sLower, "c:\\") || strings.HasPrefix(sLower, "/") {
		if len(s) > 8 && !isCompilerArtifact(s) {
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

	unixCommands := []string{
		"sh ", "bash ", "dash ", "zsh ", "ksh ", "csh ", "tcsh ",
		"ls ", "cd ", "pwd ", "mkdir ", "rmdir ", "rm ", "cp ", "mv ",
		"cat ", "more ", "less ", "head ", "tail ", "grep ", "find ",
		"chmod ", "chown ", "chgrp ", "umask ", "touch ", "ln ",
		"ps ", "kill ", "pkill ", "killall ", "top ", "htop ", "free ",
		"df ", "du ", "mount ", "umount ", "fdisk ", "mkfs ", "fsck ",
		"wget ", "curl ", "nc ", "netcat ", "ssh ", "scp ", "sftp ",
		"ping ", "traceroute ", "nslookup ", "dig ", "host ", "ifconfig ",
		"ip ", "netstat ", "route ", "iptables ", "firewall-cmd ",
		"systemctl ", "service ", "init ", "cron ", "at ", "batch ",
		"apt ", "apt-get ", "dpkg ", "yum ", "rpm ", "dnf ", "pacman ",
		"tar ", "gzip ", "gunzip ", "bzip2 ", "bunzip2 ", "zip ", "unzip ",
		"sudo ", "su ", "passwd ", "useradd ", "userdel ", "usermod ",
		"groupadd ", "groupdel ", "groupmod ", "id ", "who ", "w ", "last ",
		"uname ", "hostname ", "date ", "uptime ", "reboot ", "shutdown ",
	}

	for _, cmd := range unixCommands {
		if strings.HasPrefix(s, cmd) || strings.Contains(s, " "+cmd) || strings.Contains(s, "&&"+cmd) ||
			strings.Contains(s, "||"+cmd) || strings.Contains(s, ";"+cmd) || strings.Contains(s, "|"+cmd) {
			return true
		}
	}

	shellPatterns := []string{
		"#!/bin/sh", "#!/bin/bash", "#!/usr/bin/env", "export ", "alias ",
		"function ", "if [", "if [[", "for ", "while ", "case ", "esac",
		"$PATH", "$HOME", "$USER", "$PWD", "$SHELL", "$TERM", "$DISPLAY",
		"${", "$(", "`", "echo ", "printf ", "read ", "eval ", "exec ",
	}

	for _, pattern := range shellPatterns {
		if strings.Contains(s, pattern) {
			return true
		}
	}

	chainPatterns := []string{
		" && ", " || ", " | ", " > ", " >> ", " < ", " << ", " 2> ", " 2>> ",
		" &> ", " &>> ", " 2>&1 ", " 1>&2 ", " ; ", " & ",
	}

	for _, pattern := range chainPatterns {
		if strings.Contains(s, pattern) {
			return true
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

	if IsHighEntropyString(s) {
		return true
	}

	if IsRepetitivePattern(s) {
		return true
	}

	if IsBase64Like(s) && len(s) >= 32 {
		if !strings.Contains(s, "Key") && !strings.Contains(s, "Token") &&
			!strings.Contains(s, "Binary") && CalculateStringEntropy(s) > 4.0 {
			return true
		}
	}

	if IsHexStringStrict(s) && len(s) >= 32 {
		if !strings.Contains(s, ".") && !strings.Contains(s, "-") &&
			CalculateStringEntropy(s) > 3.5 {
			return true
		}
	}

	if CalculateStringEntropy(s) > 5.5 && len(s) >= 32 && len(s) <= 128 {
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

	emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	if emailPattern.MatchString(s) {
		return true
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

	// Check for UUIDs
	uuidPattern := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	if uuidPattern.MatchString(strings.ToLower(s)) {
		return true
	}

	// Check for API keys, tokens, etc.
	if strings.Contains(strings.ToLower(s), "key") || strings.Contains(strings.ToLower(s), "token") ||
		strings.Contains(strings.ToLower(s), "secret") || strings.Contains(strings.ToLower(s), "password") ||
		strings.Contains(strings.ToLower(s), "credential") {
		return true
	}

	return false
}

func isVersionOrCompilerString(s string) bool {

	if isLanguageInternalString(s) {
		return false
	}

	versionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(v|vers|version)\s*\.?\s*([0-9]{1,3}\.){1,2}[0-9]{1,3}(-[a-zA-Z0-9]+)?(\+[a-zA-Z0-9]+)?\b`),
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

	// Check for date patterns
	datePatterns := []string{
		"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
		"january", "february", "march", "april", "june", "july", "august", "september", "october", "november", "december",
		"mon", "tue", "wed", "thu", "fri", "sat", "sun",
		"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
	}

	for _, pattern := range datePatterns {
		if strings.Contains(strings.ToLower(s), pattern) {
			return true
		}
	}

	return false
}

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

func IsBase64Like(s string) bool {
	if len(s)%4 != 0 {
		return false
	}
	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	return base64Pattern.MatchString(s)
}

func IsHexStringStrict(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	hexPattern := regexp.MustCompile(`^[0-9A-Fa-f]+$`)
	return hexPattern.MatchString(s)
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

func PutUint32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func PutUint16(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}
