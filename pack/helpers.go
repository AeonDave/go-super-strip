package pack

import (
	"crypto/sha256"
)

// ComputeHash calcola l'hash SHA256 dei dati
func ComputeHash(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// appendUint64 appende un uint64 in little-endian a un byte slice
func appendUint64(data []byte, val uint64) []byte {
	bytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		bytes[i] = byte(val >> (i * 8))
	}
	return append(data, bytes...)
}

// appendUint32 appende un uint32 in little-endian a un byte slice
func appendUint32(data []byte, val uint32) []byte {
	bytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		bytes[i] = byte(val >> (i * 8))
	}
	return append(data, bytes...)
}

// appendFixedString appende una stringa con dimensione fissa (padding con zero)
func appendFixedString(data []byte, str string, size int) []byte {
	fixed := make([]byte, size)
	copy(fixed, []byte(str))
	return append(data, fixed...)
}

// parseBool converte una stringa in booleano
func parseBool(value string) bool {
	switch value {
	case "true", "1", "yes", "y", "on", "enabled":
		return true
	default:
		return false
	}
}
