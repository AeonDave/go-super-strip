//go:build ignore

package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
)

// elfEmbeddedArgs holds the combined arguments forwarded to the unpacked payload.
var elfEmbeddedArgs []string

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
	elfEmbeddedArgs = combineArgs(configuredArgs, os.Args[1:])

	mode := strings.ToLower(strings.TrimSpace(m.InMemoryMode))
	switch mode {
	case "memfd", "auto":
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
		return nil, fmt.Errorf("unknown compression algorithm: %s", algo)
	}
}

// trimToOriginal slices the decompressed buffer back to the original payload size.
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

// executeFromTemp writes the payload to a temporary executable and runs it.
// This is the default (base_exec) strategy and the fallback for in-memory strategies.
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

// Ensure syscall and unsafe are used (memfd_create strategy uses them directly).
var _ = syscall.Exec
var _ = unsafe.Pointer(nil)
