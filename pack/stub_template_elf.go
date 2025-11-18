package pack

import (
	"strings"

	linstrat "gosstrip/pack/strategies/linux"
)

const elfMemfdPlaceholder = "{{MEMFD_IMPL}}"

// ELFStubTemplate contiene il template base per lo stub ELF
// Questo codice verrà compilato e iniettato con il payload compresso/cifrato

const ELFStubSource = `
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
	
	"github.com/ulikunitz/xz"
	"golang.org/x/crypto/chacha20poly1305"
)

var elfEmbeddedArgs []string

func main() {
	// 1. Leggi metadata e payload dalla fine del file
	exePath, err := os.Executable()
	if err != nil {
		os.Exit(1)
	}
	
	f, err := os.Open(exePath)
	if err != nil {
		os.Exit(1)
	}
	defer f.Close()
	
	// Leggi i metadata dalla fine del file
	// Formato: [payload][metadata][metadata_size:8]
	stat, _ := f.Stat()
	fileSize := stat.Size()
	
	// Leggi metadata size (ultimi 8 bytes)
	f.Seek(fileSize-8, 0)
	var metadataSize uint64
	binary.Read(f, binary.LittleEndian, &metadataSize)
	
	// Leggi metadata
	metadataOffset := fileSize - 8 - int64(metadataSize)
	f.Seek(metadataOffset, 0)
	metadataBytes := make([]byte, metadataSize)
	f.Read(metadataBytes)
	
	// Parse metadata
	metadata := parseMetadata(metadataBytes)
	
	// Leggi payload encrypted
	payloadOffset := metadataOffset - int64(metadata.EncryptedSize)
	f.Seek(payloadOffset, 0)
	encryptedPayload := make([]byte, metadata.EncryptedSize)
	f.Read(encryptedPayload)
	f.Close()
	
	// 2. Decifra payload
	decrypted, err := decrypt(encryptedPayload, metadata.Key, metadata.Nonce, metadata.EncryptionAlgo)
	if err != nil {
		os.Exit(1)
	}
	
	// 3. Decomprimi
	decompressed, err := decompress(decrypted, metadata.CompressionAlgo)
	if err != nil {
		os.Exit(1)
	}
	
	// 3.5 Rimuovi eventuale padding casuale usando OriginalSize
	payload := trimToOriginal(decompressed, metadata.OriginalSize)

	configuredArgs := parseUserParams(metadata.UserParams)
	elfEmbeddedArgs = combineArgs(configuredArgs, os.Args[1:])
	
	// 4. Esegui
	mode := strings.ToLower(strings.TrimSpace(metadata.InMemoryMode))
	switch mode {
	case "memfd", "auto":
		executeInMemory(payload)
	case "", "off":
		executeFromTemp(payload)
	default:
		if metadata.UseInMemory {
			executeInMemory(payload)
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
	m.Key = make([]byte, keySize)
	r.Read(m.Key)
	
	binary.Read(r, binary.LittleEndian, &nonceSize)
	m.Nonce = make([]byte, nonceSize)
	r.Read(m.Nonce)
	
	inMem, _ := r.ReadByte()
	m.UseInMemory = (inMem == 1)
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

// trimToOriginal ritaglia il buffer decompresso alla dimensione originale del payload.
// Quando il padding casuale è abilitato, i byte di padding vengono aggiunti prima e dopo
// il contenuto originale. Possiamo ricostruire l'originale prendendo la slice centrale
// di lunghezza originalSize.
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
	// Fallback se le dimensioni sono inattese
	return data
}

` + elfMemfdPlaceholder + `

// executeFromTemp esegue il payload da file temporaneo
func executeFromTemp(payload []byte) {
	tmp, err := os.CreateTemp("", ".tmp-*")
	if err != nil {
		os.Exit(1)
	}
	tmpPath := tmp.Name()
	
	tmp.Write(payload)
	tmp.Chmod(0755)
	tmp.Close()
	
	cmd := exec.Command(tmpPath, elfEmbeddedArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	
	cmd.Run()
	os.Remove(tmpPath)
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

func combineArgs(configured, runtimeArgs []string) []string {
	if len(configured) == 0 && len(runtimeArgs) == 0 {
		return nil
	}
	args := make([]string, 0, len(configured)+len(runtimeArgs))
	args = append(args, configured...)
	args = append(args, runtimeArgs...)
	return args
}
`

// GetELFStubSource ritorna il codice sorgente dello stub ELF
func GetELFStubSource() string {
	return strings.Replace(ELFStubSource, elfMemfdPlaceholder, linstrat.MemfdRuntime, 1)
}
