package obfs

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/blake2b"
)

const (
	scrambleNonceLen  = 8  // Length of the per-packet nonce
	scrambleBlockSize = 64 // Process data in 64-byte blocks
	scrambleKeySize   = blake2b.Size256 // Size of the derived key (32 bytes for BLAKE2b-256)
)

// ScrambleObfuscator implements a simple counter-based stream cipher obfuscation.
// It uses a per-packet random nonce and a pre-shared key (PSK) to derive an
// evolving key stream for each block of the packet.
type ScrambleObfuscator struct {
	PSK []byte // Pre-shared key for key derivation
}

// NewScrambleObfuscator creates a new ScrambleObfuscator instance.
// psk: The pre-shared key used for obfuscation. It must not be empty.
func NewScrambleObfuscator(psk []byte) (*ScrambleObfuscator, error) {
	if len(psk) == 0 {
		return nil, fmt.Errorf("PSK cannot be empty for Scramble obfuscator")
	}
	return &ScrambleObfuscator{PSK: psk}, nil
}

// Obfuscate obfuscates the input byte slice 'in' and writes the result to 'out'.
// It prepends a random nonce, then XORs payload blocks with an evolving key
// derived from the PSK and the current nonce counter.
// Returns the number of bytes written to 'out'. If 'out' is too small, returns 0.
func (o *ScrambleObfuscator) Obfuscate(in, out []byte) int {
	outLen := len(in) + scrambleNonceLen
	if len(out) < outLen {
		return 0 // Output buffer too small
	}

	// Generate a random nonce for this packet
	nonce := make([]byte, scrambleNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0 // Failed to generate random nonce (e.g., insufficient entropy)
	}
	copy(out[:scrambleNonceLen], nonce) // Prepend nonce to the output

	// Initialize the current nonce counter from the generated nonce
	currentNonce := binary.BigEndian.Uint64(nonce)
	payloadOut := out[scrambleNonceLen:] // Pointer to the payload area in the output buffer

	// Process the input payload in blocks
	for i := 0; i < len(in); i += scrambleBlockSize {
		blockEnd := i + scrambleBlockSize
		if blockEnd > len(in) {
			blockEnd = len(in) // Handle the last partial block
		}
		currentInBlock := in[i:blockEnd]
		targetOutBlock := payloadOut[i:blockEnd]

		// Derive a unique key for the current block using PSK and the evolving nonce counter
		// The input to BLAKE2b includes the PSK and the 8-byte nonce counter.
		blockKeyInput := make([]byte, len(o.PSK)+scrambleNonceLen)
		copy(blockKeyInput, o.PSK)
		binary.BigEndian.PutUint64(blockKeyInput[len(o.PSK):], currentNonce)
		blockKey := blake2b.Sum256(blockKeyInput) // Generate a 32-byte key for this block

		// XOR the current input block with the derived block key
		for j := 0; j < len(currentInBlock); j++ {
			targetOutBlock[j] = currentInBlock[j] ^ blockKey[j%scrambleKeySize]
		}
		currentNonce++ // Increment nonce counter for the next block
	}

	return outLen
}

// Deobfuscate deobfuscates the input byte slice 'in' and writes the result to 'out'.
// It extracts the nonce, re-derives the same evolving key stream, and XORs the payload
// to restore the original data.
// Returns the number of bytes written to 'out'. If 'in' is invalid or 'out' is too small, returns 0.
func (o *ScrambleObfuscator) Deobfuscate(in, out []byte) int {
	if len(in) < scrambleNonceLen {
		return 0 // Input is too short to even contain the nonce
	}

	nonceBytes := in[:scrambleNonceLen] // Extract the nonce from the beginning of the input
	payloadIn := in[scrambleNonceLen:]  // The rest is the obfuscated payload
	outLen := len(payloadIn)

	if len(out) < outLen {
		return 0 // Output buffer too small
	}

	// Re-initialize the current nonce counter from the extracted nonce
	currentNonce := binary.BigEndian.Uint64(nonceBytes)

	// Process the input payload in blocks, mirroring the obfuscation process
	for i := 0; i < len(payloadIn); i += scrambleBlockSize {
		blockEnd := i + scrambleBlockSize
		if blockEnd > len(payloadIn) {
			blockEnd = len(payloadIn) // Handle the last partial block
		}
		currentInBlock := payloadIn[i:blockEnd]
		targetOutBlock := out[i:blockEnd]

		// Derive the same block key using PSK and the evolving nonce counter
		blockKeyInput := make([]byte, len(o.PSK)+scrambleNonceLen)
		copy(blockKeyInput, o.PSK)
		binary.BigEndian.PutUint64(blockKeyInput[len(o.PSK):], currentNonce)
		blockKey := blake2b.Sum256(blockKeyInput)

		// XOR the current input block with the derived block key to deobfuscate
		for j := 0; j < len(currentInBlock); j++ {
			targetOutBlock[j] = currentInBlock[j] ^ blockKey[j%scrambleKeySize]
		}
		currentNonce++ // Increment nonce counter for the next block
	}

	return outLen
}

// Ensure ScrambleObfuscator implements Obfuscator interface
var _ Obfuscator = (*ScrambleObfuscator)(nil)
