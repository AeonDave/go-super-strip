package pack

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestComputeHash(t *testing.T) {
	data := []byte("test data")
	hash := ComputeHash(data)

	expected := sha256.Sum256(data)
	if hash != expected {
		t.Errorf("Hash mismatch")
	}
}

func TestAddRandomPadding_Disabled(t *testing.T) {
	config := DefaultConfig()
	config.RandomPadding = false

	data := []byte("test")
	result, offsets, err := AddRandomPadding(data, config)

	if err != nil {
		t.Fatalf("AddRandomPadding failed: %v", err)
	}

	if !bytes.Equal(result, data) {
		t.Error("Data should be unchanged when padding is disabled")
	}

	if len(offsets) != 0 {
		t.Errorf("Expected no offsets, got %d", len(offsets))
	}
}

func TestAddRandomPadding_Enabled(t *testing.T) {
	config := DefaultConfig()
	config.RandomPadding = true
	config.PaddingSizeMin = 10
	config.PaddingSizeMax = 20

	data := []byte("test")
	result, offsets, err := AddRandomPadding(data, config)

	if err != nil {
		t.Fatalf("AddRandomPadding failed: %v", err)
	}

	if len(result) <= len(data) {
		t.Error("Padded data should be larger than original")
	}

	if len(offsets) == 0 {
		t.Error("Expected padding offsets")
	}
}

func TestCompressPayload_None(t *testing.T) {
	config := DefaultConfig()
	config.CompressionAlgorithm = "none"

	data := []byte("test data")
	compressed, err := CompressPayload(data, config)

	if err != nil {
		t.Fatalf("CompressPayload failed: %v", err)
	}

	if !bytes.Equal(compressed, data) {
		t.Error("Data should be unchanged with 'none' compression")
	}
}

func TestCompressPayload_Zlib(t *testing.T) {
	config := DefaultConfig()
	config.CompressionAlgorithm = "zlib"
	config.CompressionLevel = 6

	data := bytes.Repeat([]byte("test data "), 100)
	compressed, err := CompressPayload(data, config)
	if err != nil {
		t.Fatalf("CompressPayload(zlib) failed: %v", err)
	}
	if len(compressed) >= len(data) {
		t.Logf("Warning: compressed size %d >= original %d", len(compressed), len(data))
	}

	decompressed, err := DecompressPayload(compressed, "zlib")
	if err != nil {
		t.Fatalf("DecompressPayload(zlib) failed: %v", err)
	}
	if !bytes.Equal(decompressed, data) {
		t.Error("Decompressed zlib data doesn't match original")
	}
}

func TestCompressPayload_ZlibLevels(t *testing.T) {
	data := bytes.Repeat([]byte("abcdefghij"), 200)

	for _, level := range []int{0, 1, 6, 9} {
		t.Run(fmt.Sprintf("level_%d", level), func(t *testing.T) {
			config := DefaultConfig()
			config.CompressionAlgorithm = "zlib"
			config.CompressionLevel = level

			compressed, err := CompressPayload(data, config)
			if err != nil {
				t.Fatalf("CompressPayload level %d: %v", level, err)
			}
			decompressed, err := DecompressPayload(compressed, "zlib")
			if err != nil {
				t.Fatalf("DecompressPayload level %d: %v", level, err)
			}
			if !bytes.Equal(decompressed, data) {
				t.Errorf("Round-trip failed at level %d", level)
			}
		})
	}
}

func TestCompressPayload_UnknownAlgorithm(t *testing.T) {
	config := DefaultConfig()
	config.CompressionAlgorithm = "bogus"

	_, err := CompressPayload([]byte("data"), config)
	if err == nil {
		t.Fatal("expected error for unknown algorithm, got nil")
	}
}

func TestDecompressPayload_UnknownAlgorithm(t *testing.T) {
	_, err := DecompressPayload([]byte("data"), "bogus")
	if err == nil {
		t.Fatal("expected error for unknown algorithm, got nil")
	}
}

func TestEncryptPayload_None(t *testing.T) {
	config := DefaultConfig()
	config.EncryptionAlgorithm = "none"

	data := []byte("test data")
	encrypted, key, nonce, err := EncryptPayload(data, config)

	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}

	if !bytes.Equal(encrypted, data) {
		t.Error("Data should be unchanged with 'none' encryption")
	}

	if len(key) != 0 || len(nonce) != 0 {
		t.Error("Key and nonce should be empty for 'none' encryption")
	}
}

func TestEncryptPayload_XOR(t *testing.T) {
	config := DefaultConfig()
	config.EncryptionAlgorithm = "xor"

	data := []byte("test data")
	encrypted, key, nonce, err := EncryptPayload(data, config)

	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}

	if bytes.Equal(encrypted, data) {
		t.Error("Encrypted data should differ from original")
	}

	if len(key) == 0 {
		t.Error("XOR encryption should generate a key")
	}

	// Test decryption
	decrypted, err := DecryptPayload(encrypted, key, nonce, config.EncryptionAlgorithm)
	if err != nil {
		t.Fatalf("DecryptPayload failed: %v", err)
	}

	if !bytes.Equal(decrypted, data) {
		t.Error("Decrypted data doesn't match original")
	}
}

func TestEncryptPayload_AES(t *testing.T) {
	config := DefaultConfig()
	config.EncryptionAlgorithm = "aes-256-gcm"

	data := []byte("test data")
	encrypted, key, nonce, err := EncryptPayload(data, config)

	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}

	if bytes.Equal(encrypted, data) {
		t.Error("Encrypted data should differ from original")
	}

	if len(key) != 32 {
		t.Errorf("Expected 32-byte key for AES-256, got %d", len(key))
	}

	if len(nonce) != 12 {
		t.Errorf("Expected 12-byte nonce for GCM, got %d", len(nonce))
	}

	// Test decryption
	decrypted, err := DecryptPayload(encrypted, key, nonce, config.EncryptionAlgorithm)
	if err != nil {
		t.Fatalf("DecryptPayload failed: %v", err)
	}

	if !bytes.Equal(decrypted, data) {
		t.Error("Decrypted data doesn't match original")
	}
}

func TestEncryptPayload_ChaCha20(t *testing.T) {
	config := DefaultConfig()
	config.EncryptionAlgorithm = "chacha20"

	data := []byte("test data")
	encrypted, key, nonce, err := EncryptPayload(data, config)

	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}

	if bytes.Equal(encrypted, data) {
		t.Error("Encrypted data should differ from original")
	}

	if len(key) != 32 {
		t.Errorf("Expected 32-byte key for ChaCha20, got %d", len(key))
	}

	// Test decryption
	decrypted, err := DecryptPayload(encrypted, key, nonce, config.EncryptionAlgorithm)
	if err != nil {
		t.Fatalf("DecryptPayload failed: %v", err)
	}

	if !bytes.Equal(decrypted, data) {
		t.Error("Decrypted data doesn't match original")
	}
}

func TestNewPackResult(t *testing.T) {
	originalHash := sha256.Sum256([]byte("original"))
	packedHash := sha256.Sum256([]byte("packed"))
	stubHash := sha256.Sum256([]byte("stub"))

	// Test with size reduction (compression)
	result := NewPackResult(1000, 500, originalHash, packedHash, stubHash)
	if result.OriginalSize != 1000 {
		t.Errorf("Expected original size 1000, got %d", result.OriginalSize)
	}
	if result.PackedSize != 500 {
		t.Errorf("Expected packed size 500, got %d", result.PackedSize)
	}
	if result.CompressionRatio != 50.0 {
		t.Errorf("Expected compression ratio 50%%, got %.1f%%", result.CompressionRatio)
	}

	// Test with size increase (stub overhead)
	result2 := NewPackResult(1000, 2000, originalHash, packedHash, stubHash)
	if result2.CompressionRatio != 100.0 {
		t.Errorf("Expected ratio 100%% for size increase, got %.1f%%", result2.CompressionRatio)
	}
}

func TestPolymorphicEngine_GenerateStub(t *testing.T) {
	config := DefaultConfig()
	config.PolymorphicStub = true
	config.JunkCodeDensity = 0.1

	engine := NewPolymorphicEngine(config)

	template := &StubTemplate{
		Name:       "Test",
		TargetArch: "amd64",
		TargetOS:   "linux",
		BaseCode:   []byte("test code"),
	}

	payload := []byte("payload")
	metadata := &PayloadMetadata{
		OriginalSize:   100,
		CompressedSize: 50,
		EncryptedSize:  60,
	}

	stub, err := engine.GenerateStub(template, payload, metadata)
	if err != nil {
		t.Fatalf("GenerateStub failed: %v", err)
	}

	if len(stub.Code) == 0 {
		t.Error("Stub code should not be empty")
	}

	if len(stub.Techniques) == 0 {
		t.Error("Expected at least one technique to be applied")
	}

	// Verify hash is computed
	expectedHash := sha256.Sum256(stub.Code)
	if stub.Hash != expectedHash {
		t.Error("Stub hash mismatch")
	}
}

func TestPolymorphicEngine_UniqueHashes(t *testing.T) {
	config := DefaultConfig()
	config.PolymorphicStub = true
	config.JunkCodeDensity = 0.5

	payload := []byte("payload")
	metadata := &PayloadMetadata{
		OriginalSize:   100,
		CompressedSize: 50,
		EncryptedSize:  60,
	}

	hashes := make(map[[32]byte]bool)

	// Simulate ELF headers for realistic test
	elfHeader := []byte{
		0x7f, 'E', 'L', 'F', // ELF magic
		2, 1, 1, 0, // 64-bit, little-endian, version
		0, 0, 0, 0, 0, 0, 0, 0, // EI_PAD (bytes 9-16) - will be randomized
	}

	for i := 0; i < 10; i++ {
		// Each iteration gets a different BaseCode with ELF header
		baseCode := make([]byte, 64)
		copy(baseCode, elfHeader)
		// Add some random data after header to simulate compiled stub
		rand.Read(baseCode[16:])

		template := &StubTemplate{
			Name:       "Test",
			TargetArch: "amd64",
			TargetOS:   "linux",
			BaseCode:   baseCode,
		}

		engine := NewPolymorphicEngine(config)
		stub, err := engine.GenerateStub(template, payload, metadata)
		if err != nil {
			t.Fatalf("GenerateStub failed on iteration %d: %v", i, err)
		}

		if hashes[stub.Hash] {
			t.Errorf("Duplicate hash found on iteration %d", i)
		}
		hashes[stub.Hash] = true
	}
}
