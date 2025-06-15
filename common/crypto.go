package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
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
