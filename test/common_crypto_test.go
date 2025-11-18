package test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"gosstrip/common"
)

func TestProcessFileForInsertionRoundsTripWithPassword(t *testing.T) {
	dir := t.TempDir()
	payloadPath := filepath.Join(dir, "payload.bin")
	original := []byte{0x01, 0x02, 0x03, 0x04}
	if err := os.WriteFile(payloadPath, original, 0600); err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}

	password := "super-secret"
	encrypted, err := common.ProcessFileForInsertion(payloadPath, password)
	if err != nil {
		t.Fatalf("unexpected error encrypting payload: %v", err)
	}
	if string(encrypted) == string(original) {
		t.Fatal("expected encrypted data to differ from original")
	}

	decrypted, err := common.DecryptAES256GCM(encrypted, []byte(password))
	if err != nil {
		t.Fatalf("failed to decrypt payload: %v", err)
	}
	if string(decrypted) != string(original) {
		t.Fatalf("expected decrypted payload to match original, got %x", decrypted)
	}
}

func TestProcessFileForInsertionWithoutPassword(t *testing.T) {
	dir := t.TempDir()
	payloadPath := filepath.Join(dir, "payload.txt")
	original := []byte("hello world")
	if err := os.WriteFile(payloadPath, original, 0600); err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}

	data, err := common.ProcessFileForInsertion(payloadPath, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != string(original) {
		t.Fatalf("expected data to remain unchanged, got %q", data)
	}
}

func TestDecryptAES256GCMRejectsShortCiphertexts(t *testing.T) {
	if _, err := common.DecryptAES256GCM([]byte{0x01, 0x02, 0x03}, []byte("pw")); err == nil {
		t.Fatal("expected error for ciphertext shorter than nonce")
	}
}

func TestProcessStringForInsertionWithAsciiPassword(t *testing.T) {
	payload := "config-data"
	password := "passphrase"
	encryptedHex, err := common.ProcessStringForInsertion(payload, password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cipher, err := hex.DecodeString(string(encryptedHex))
	if err != nil {
		t.Fatalf("encrypted payload is not valid hex: %v", err)
	}
	decrypted, err := common.DecryptAES256GCM(cipher, []byte(password))
	if err != nil {
		t.Fatalf("failed to decrypt payload: %v", err)
	}
	if string(decrypted) != payload {
		t.Fatalf("expected decrypted payload to match original, got %q", decrypted)
	}
}

func TestProcessStringForInsertionHexLiteral(t *testing.T) {
	payload := "0xDEADBEEF"
	data, err := common.ProcessStringForInsertion(payload, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected, err := hex.DecodeString(payload[2:])
	if err != nil {
		t.Fatalf("failed to decode expected hex: %v", err)
	}
	if string(data) != string(expected) {
		t.Fatalf("expected hex payload to be decoded, got %x", data)
	}
}

func TestProcessExtractedDataHandlesHexCiphertext(t *testing.T) {
	payload := []byte("super-secret-data")
	password := "hexpass"
	encrypted, err := common.ProcessStringForInsertion(string(payload), password)
	if err != nil {
		t.Fatalf("failed to encrypt payload: %v", err)
	}
	recovered, err := common.ProcessExtractedData(encrypted, password)
	if err != nil {
		t.Fatalf("failed to process extracted data: %v", err)
	}
	if string(recovered) != string(payload) {
		t.Fatalf("expected recovered payload %q, got %q", payload, recovered)
	}
}
