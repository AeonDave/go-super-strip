package common

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
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
	byteData, err := decodeInlineData(data)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return byteData, nil
	}
	encryptedData, err := EncryptAES256GCM(byteData, parsePassword(password))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}
	return []byte(hex.EncodeToString(encryptedData)), nil
}

// DecryptAES256GCM decrypts data previously encrypted by EncryptAES256GCM.
// The input data must be nonce||ciphertext where nonce has size gcm.NonceSize().
func DecryptAES256GCM(data, password []byte) ([]byte, error) {
	key := deriveKey(password)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("ciphertext too short: %d < %d", len(data), ns)
	}
	nonce := data[:ns]
	ciphertext := data[ns:]
	pt, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	return pt, nil
}

func ProcessExtractedData(data []byte, password string) ([]byte, error) {
	result := make([]byte, len(data))
	copy(result, data)
	if password == "" {
		return result, nil
	}
	key := parsePassword(password)
	if plaintext, err := DecryptAES256GCM(result, key); err == nil {
		return plaintext, nil
	}
	trimmed := bytes.TrimRight(result, "\x00")
	hexCandidate := strings.TrimSpace(string(trimmed))
	if hexCandidate != "" && len(hexCandidate)%2 == 0 && isHexString(hexCandidate) {
		if decoded, err := hex.DecodeString(hexCandidate); err == nil {
			if plaintext, err := DecryptAES256GCM(decoded, key); err == nil {
				return plaintext, nil
			}
		}
	}
	return nil, fmt.Errorf("failed to decrypt payload: ensure the password matches and the section was encrypted")
}

func decodeInlineData(data string) ([]byte, error) {
	trimmed := strings.TrimSpace(data)
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "0x") {
		hexPart := trimmed[2:]
		if len(hexPart)%2 != 0 {
			return nil, fmt.Errorf("hex payload must contain an even number of characters")
		}
		if !isHexString(hexPart) {
			return nil, fmt.Errorf("invalid hex payload")
		}
		decoded, err := hex.DecodeString(hexPart)
		if err != nil {
			return nil, fmt.Errorf("failed to decode hex payload: %w", err)
		}
		return decoded, nil
	}
	return []byte(data), nil
}
