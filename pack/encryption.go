package pack

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptPayload cifra il payload secondo la configurazione
func EncryptPayload(data []byte, config *PackConfig) ([]byte, []byte, []byte, error) {
	switch config.EncryptionAlgorithm {
	case "xor":
		return encryptXOR(data, config)
	case "aes-256-gcm":
		return encryptAESGCM(data, config)
	case "chacha20":
		return encryptChaCha20(data, config)
	case "none":
		return data, nil, nil, nil
	default:
		return nil, nil, nil, fmt.Errorf("unsupported encryption algorithm: %s", config.EncryptionAlgorithm)
	}
}

// DecryptPayload decifra il payload
func DecryptPayload(data []byte, key []byte, nonce []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case "xor":
		return decryptXOR(data, key)
	case "aes-256-gcm":
		return decryptAESGCM(data, key, nonce)
	case "chacha20":
		return decryptChaCha20(data, key, nonce)
	case "none":
		return data, nil
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", algorithm)
	}
}

// encryptXOR cifra con XOR (semplice ma efficace per polimorfismo)
func encryptXOR(data []byte, config *PackConfig) ([]byte, []byte, []byte, error) {
	// Genera o usa chiave fornita
	key := config.EncryptionKey
	if len(key) == 0 {
		key = randomBytes(32)
	}

	encrypted := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		encrypted[i] = data[i] ^ key[i%len(key)]
	}

	return encrypted, key, nil, nil
}

// decryptXOR decifra XOR
func decryptXOR(data []byte, key []byte) ([]byte, error) {
	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		decrypted[i] = data[i] ^ key[i%len(key)]
	}
	return decrypted, nil
}

// encryptAESGCM cifra con AES-256-GCM
func encryptAESGCM(data []byte, config *PackConfig) ([]byte, []byte, []byte, error) {
	// Genera o usa chiave fornita
	key := config.EncryptionKey
	if len(key) == 0 {
		key = randomBytes(32) // AES-256 richiede 32 bytes
	} else if len(key) != 32 {
		return nil, nil, nil, fmt.Errorf("AES-256 requires 32-byte key, got %d", len(key))
	}

	// Crea cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Crea GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Genera nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Cifra
	encrypted := gcm.Seal(nil, nonce, data, nil)

	return encrypted, key, nonce, nil
}

// decryptAESGCM decifra AES-256-GCM
func decryptAESGCM(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 requires 32-byte key, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: expected %d, got %d", gcm.NonceSize(), len(nonce))
	}

	decrypted, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return decrypted, nil
}

// encryptChaCha20 cifra con ChaCha20-Poly1305
func encryptChaCha20(data []byte, config *PackConfig) ([]byte, []byte, []byte, error) {
	// Genera o usa chiave fornita
	key := config.EncryptionKey
	if len(key) == 0 {
		key = randomBytes(chacha20poly1305.KeySize)
	} else if len(key) != chacha20poly1305.KeySize {
		return nil, nil, nil, fmt.Errorf("ChaCha20 requires %d-byte key, got %d", chacha20poly1305.KeySize, len(key))
	}

	// Crea cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create ChaCha20: %w", err)
	}

	// Genera nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Cifra
	encrypted := aead.Seal(nil, nonce, data, nil)

	return encrypted, key, nonce, nil
}

// decryptChaCha20 decifra ChaCha20-Poly1305
func decryptChaCha20(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("ChaCha20 requires %d-byte key, got %d", chacha20poly1305.KeySize, len(key))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20: %w", err)
	}

	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: expected %d, got %d", aead.NonceSize(), len(nonce))
	}

	decrypted, err := aead.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return decrypted, nil
}
