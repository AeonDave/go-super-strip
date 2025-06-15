package common

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// GenerateRandomBytes generates a slice of random bytes of the specified size
func GenerateRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate %d random bytes: %w", size, err)
	}
	return b, nil
}

// MatchesPattern checks if a string matches any of the given exact names or prefixes
func MatchesPattern(target string, exactNames, prefixNames []string) bool {
	// Check exact matches
	for _, name := range exactNames {
		if name != "" && target == name {
			return true
		}
	}

	// Check prefix matches
	for _, prefix := range prefixNames {
		if prefix != "" && strings.HasPrefix(target, prefix) {
			return true
		}
	}
	return false
}
