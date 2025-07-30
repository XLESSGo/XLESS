package cosmicdust

import (
	"crypto/rand"
	"fmt"
)

// GenerateRandomBytes generates a slice of cryptographically secure random bytes of the given length.
func GenerateRandomBytes(length int) ([]byte, error) {
	if length < 0 {
		return nil, fmt.Errorf("length cannot be negative")
	}
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
