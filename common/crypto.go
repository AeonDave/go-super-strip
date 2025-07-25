package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

func parsePassword(password string) []byte {
	if hexBytes, err := hex.DecodeString(password); isHexString(password) && err == nil {
		return hexBytes
	}
	return []byte(password)
}

func isHexString(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func deriveKey(password []byte) [32]byte {
	return sha256.Sum256(password)
}

func EncryptAES256GCM(data, password []byte) ([]byte, error) {
	key := deriveKey(password)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func ProcessFileForInsertion(filePath, password string) ([]byte, error) {
	byteData, err := fileToByte(filePath)
	if err != nil {
		return nil, fmt.Errorf("file to hex conversion failed: %w", err)
	}
	if password == "" {
		return byteData, nil
	}
	encryptedData, err := EncryptAES256GCM(byteData, parsePassword(password))
	if err != nil {
		return nil, fmt.Errorf("data encryption failed: %w", err)
	}
	return encryptedData, nil
}

func fileToByte(filePath string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}
	return data, nil
}

func ProcessStringForInsertion(data, password string) ([]byte, error) {
	byteData := []byte(data)
	if password == "" {
		return byteData, nil
	}
	encryptedData, err := EncryptAES256GCM(byteData, parsePassword(password))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}
	return []byte(hex.EncodeToString(encryptedData)), nil
}
