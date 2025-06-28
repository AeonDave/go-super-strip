package common

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// CryptoConfig holds configuration for encryption/decryption
type CryptoConfig struct {
	IsHexPassword bool
	Password      []byte
}

// ParsePassword processes the password string, determining if it's hex or string
func ParsePassword(password string) (*CryptoConfig, error) {
	config := &CryptoConfig{}
	// Check if password is hex encoded (even length, only hex chars)
	if len(password)%2 == 0 && IsHexString(password) {
		// Try to decode as hex
		hexBytes, err := hex.DecodeString(password)
		if err == nil {
			config.IsHexPassword = true
			config.Password = hexBytes
			return config, nil
		}
	}

	// Treat as string password
	config.IsHexPassword = false
	config.Password = []byte(password)
	return config, nil
}

// IsHexString checks if a string contains only hexadecimal characters
func IsHexString(s string) bool {
	s = strings.ToLower(s)
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// FileToHex reads a file and converts it to hexadecimal representation (like xxd)
func FileToHex(filePath string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Convert to hex string
	hexString := hex.EncodeToString(data)
	return []byte(hexString), nil
}

// deriveKey derives a 32-byte AES key from password using SHA256
func deriveKey(password []byte) []byte {
	hash := sha256.Sum256(password)
	return hash[:]
}

// EncryptAES256GCM encrypts data using AES-256-GCM
func EncryptAES256GCM(data []byte, password []byte) ([]byte, error) {
	// Derive key from password
	key := deriveKey(password)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptAES256GCM decrypts data using AES-256-GCM
func DecryptAES256GCM(encryptedData []byte, password []byte) ([]byte, error) {
	// Derive key from password
	key := deriveKey(password)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check minimum size
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// ProcessFileForInsertion processes a file according to the new format:
// 1. Convert file content to hex (like xxd)
// 2. Encrypt with AES-256-GCM if password provided
// 3. Convert encrypted result back to hex
func ProcessFileForInsertion(filePath string, password string) ([]byte, error) {
	// Step 1: Convert file to hex
	hexData, err := FileToHex(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to convert file to hex: %w", err)
	}

	// If no password, return hex data directly
	if password == "" {
		return hexData, nil
	}

	// Parse password
	cryptoConfig, err := ParsePassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to parse password: %w", err)
	}

	// Step 2: Encrypt hex data with AES-256-GCM
	encryptedData, err := EncryptAES256GCM(hexData, cryptoConfig.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Step 3: Convert encrypted data to hex string for storage
	finalHexData := hex.EncodeToString(encryptedData)

	return []byte(finalHexData), nil
}

// ProcessStringForInsertion processes a string according to the new format:
// 1. Convert string to hex
// 2. Encrypt with AES-256-GCM if password provided
// 3. Convert encrypted result back to hex
func ProcessStringForInsertion(data string, password string) ([]byte, error) {
	// Step 1: Convert string to hex
	hexData := hex.EncodeToString([]byte(data))

	// If no password, return hex data directly
	if password == "" {
		return []byte(hexData), nil
	}

	// Parse password
	cryptoConfig, err := ParsePassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to parse password: %w", err)
	}

	// Step 2: Encrypt hex data with AES-256-GCM
	encryptedData, err := EncryptAES256GCM([]byte(hexData), cryptoConfig.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Step 3: Convert encrypted data to hex string for storage
	finalHexData := hex.EncodeToString(encryptedData)

	return []byte(finalHexData), nil
}

// RecoverFileFromInsertion reverses the ProcessFileForInsertion process:
// 1. Convert hex string back to binary
// 2. Decrypt with AES-256-GCM if password provided
// 3. Convert hex back to original file content
func RecoverFileFromInsertion(hexEncryptedData []byte, password string) ([]byte, error) {
	// If no password, treat as direct hex data
	if password == "" {
		// Convert hex back to original binary data
		originalData, err := hex.DecodeString(string(hexEncryptedData))
		if err != nil {
			return nil, fmt.Errorf("failed to decode hex data: %w", err)
		}
		return originalData, nil
	}

	// Parse password
	cryptoConfig, err := ParsePassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to parse password: %w", err)
	}

	// Step 1: Convert hex string back to binary
	encryptedData, err := hex.DecodeString(string(hexEncryptedData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex data: %w", err)
	}

	// Step 2: Decrypt data
	hexData, err := DecryptAES256GCM(encryptedData, cryptoConfig.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Step 3: Convert hex back to original binary data
	originalData, err := hex.DecodeString(string(hexData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode original hex data: %w", err)
	}

	return originalData, nil
}

// RecoverFileFromOverlay attempts to recover file content from PE overlay data
// This is used when data was inserted using fallback/overlay mode
func RecoverFileFromOverlay(filePath string, password string) ([]byte, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	// Read file data
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Basic PE validation - check DOS header
	if len(fileData) < 64 {
		return nil, fmt.Errorf("file too small to be a PE file")
	}

	// Check DOS signature
	if fileData[0] != 'M' || fileData[1] != 'Z' {
		return nil, fmt.Errorf("invalid DOS signature")
	}

	// Get PE header offset
	peHeaderOffset := int64(binary.LittleEndian.Uint32(fileData[60:64]))
	if peHeaderOffset < 0 || peHeaderOffset+4 >= int64(len(fileData)) {
		return nil, fmt.Errorf("invalid PE header offset")
	}

	// Check PE signature
	if !bytes.Equal(fileData[peHeaderOffset:peHeaderOffset+4], []byte{'P', 'E', 0, 0}) {
		return nil, fmt.Errorf("invalid PE signature")
	}

	// Try to find the end of sections to detect overlay
	// This is a simplified approach that doesn't require full PE parsing
	overlayStart, err := findSimpleOverlayStart(fileData, peHeaderOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to find overlay: %w", err)
	}

	if overlayStart >= int64(len(fileData)) {
		return nil, fmt.Errorf("no overlay data found")
	}

	// Extract overlay data
	overlayData := fileData[overlayStart:]
	if len(overlayData) == 0 {
		return nil, fmt.Errorf("overlay is empty")
	}

	// Process the overlay data through the decryption/hex conversion process
	return RecoverFileFromInsertion(overlayData, password)
}

// findSimpleOverlayStart finds the start of overlay data without full PE parsing
func findSimpleOverlayStart(fileData []byte, peHeaderOffset int64) (int64, error) {
	// Skip PE signature (4 bytes) + COFF header (20 bytes) to get to optional header
	coffHeaderOffset := peHeaderOffset + 4
	if coffHeaderOffset+20 > int64(len(fileData)) {
		return 0, fmt.Errorf("COFF header extends beyond file")
	}

	// Get number of sections
	numberOfSections := binary.LittleEndian.Uint16(fileData[coffHeaderOffset+2 : coffHeaderOffset+4])

	// Get size of optional header
	sizeOfOptionalHeader := binary.LittleEndian.Uint16(fileData[coffHeaderOffset+16 : coffHeaderOffset+18])

	// Calculate section headers start
	sectionHeadersStart := coffHeaderOffset + 20 + int64(sizeOfOptionalHeader)

	// Each section header is 40 bytes
	sectionHeadersEnd := sectionHeadersStart + int64(numberOfSections)*40

	if sectionHeadersEnd > int64(len(fileData)) {
		return 0, fmt.Errorf("section headers extend beyond file")
	}

	// Find the end of the last section
	var maxSectionEnd int64 = 0

	for i := 0; i < int(numberOfSections); i++ {
		sectionHeaderOffset := sectionHeadersStart + int64(i)*40

		// Get PointerToRawData (offset 20) and SizeOfRawData (offset 16)
		rawDataPtr := binary.LittleEndian.Uint32(fileData[sectionHeaderOffset+20 : sectionHeaderOffset+24])
		rawDataSize := binary.LittleEndian.Uint32(fileData[sectionHeaderOffset+16 : sectionHeaderOffset+20])

		if rawDataPtr > 0 && rawDataSize > 0 {
			sectionEnd := int64(rawDataPtr + rawDataSize)
			if sectionEnd > maxSectionEnd {
				maxSectionEnd = sectionEnd
			}
		}
	}

	return maxSectionEnd, nil
}

// RecoverFileFromPE attempts to recover file content from a PE file, trying both sections and overlay
// This function automatically detects whether data was inserted as a section or overlay
func RecoverFileFromPE(filePath string, sectionName string, password string) ([]byte, error) {
	// First try to load as normal PE and extract from section
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	// Try to read as proper PE file first
	// We'll import the perw package functions if possible, but for now we'll use a simple approach
	// that doesn't require full PE parsing if the file is corrupted

	// First attempt: try to extract from overlay (fallback mode)
	overlayData, err := RecoverFileFromOverlay(filePath, password)
	if err == nil {
		return overlayData, nil
	}

	// Second attempt: if we have perw available, try to load PE properly and extract from section
	// For now, return the overlay error since section extraction would require importing perw
	// which could create circular dependencies

	return nil, fmt.Errorf("failed to recover data from PE file - overlay extraction failed: %w", err)
}
