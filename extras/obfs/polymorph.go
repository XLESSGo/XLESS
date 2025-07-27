package obfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/blake2b"
	mrand "math/rand"
	"sync"
	"time"
)

const (
	pmMinPSKLen        = 16 // Minimum PSK length for AES-256 key derivation
	pmNonceLen         = 12 // AES-GCM nonce length
	pmTagLen           = 16 // AES-GCM authentication tag length
	pmKeyLen           = 32 // AES-256 key length (from BLAKE2b-256 hash)
	pmControlHeaderLen = 4  // Length of the control header (encodes layout info)
	pmMaxPaddingLen    = 64 // Max random padding for each section (Padding1 and Padding2)
)

// PolyMorphObfuscator applies multiple layers of obfuscation with dynamic padding.
// It encrypts the payload with AES-GCM and inserts random padding,
// with layout info encoded in an obfuscated control header.
type PolyMorphObfuscator struct {
	PSK []byte // Pre-shared key for AES key derivation and control header obfuscation
	// Using math/rand for non-cryptographic randomness (padding lengths)
	randSrc *mrand.Rand
	lk      sync.Mutex
}

// NewPolyMorphObfuscator creates a new PolyMorphObfuscator instance.
// psk: The pre-shared key. Must be at least pmMinPSKLen bytes long.
func NewPolyMorphObfuscator(psk []byte) (*PolyMorphObfuscator, error) {
	if len(psk) < pmMinPSKLen {
		return nil, fmt.Errorf("PSK must be at least %d bytes for PolyMorph obfuscator", pmMinPSKLen)
	}
	return &PolyMorphObfuscator{
		PSK:     psk,
		randSrc: mrand.New(mrand.NewSource(time.Now().UnixNano())),
	}, nil
}

// pmDeriveAESKey derives a fixed-size AES key from the PSK using BLAKE2b-256.
func (o *PolyMorphObfuscator) pmDeriveAESKey() []byte {
	hash := blake2b.Sum256(o.PSK)
	return hash[:]
}

// pmDeriveControlKey derives a small key for obfuscating the control header.
func (o *PolyMorphObfuscator) pmDeriveControlKey() byte {
	hash := blake2b.Sum256(append(o.PSK, []byte("control")...)) // Use a different salt for control key
	return hash[0] // Use the first byte of the hash as a simple XOR key
}

// pmRandBytes generates a slice of cryptographically secure random bytes of the given length.
func pmRandBytes(length int) ([]byte, error) {
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

// Obfuscate encrypts the input 'in' and applies dynamic padding and a control header.
// Returns the total length of the obfuscated packet, or 0 if an error occurs or 'out' is too small.
func (o *PolyMorphObfuscator) Obfuscate(in, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()

	// 1. Generate AES-GCM nonce
	nonce := make([]byte, pmNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0 // Failed to generate random nonce
	}

	// 2. Derive AES key from PSK
	aesKey := o.pmDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:pmKeyLen])
	if err != nil {
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	// 3. Encrypt the original payload
	encryptedPayload := aesgcm.Seal(nil, nonce, in, nil)
	payloadWithTagLen := len(encryptedPayload) // Length of (ciphertext + tag)

	// 4. Generate random padding lengths
	padding1Len := o.randSrc.Intn(pmMaxPaddingLen + 1) // 0 to pmMaxPaddingLen
	padding2Len := o.randSrc.Intn(pmMaxPaddingLen + 1) // 0 to pmMaxPaddingLen

	// 5. Construct the control header
	// controlHeader will encode padding1Len and padding2Len
	// Byte 0: padding1Len
	// Byte 1: padding2Len
	// Byte 2: Checksum (XOR sum of first 2 bytes)
	// Byte 3: Reserved (could be used for dynamic layer flags in future)
	var controlHeaderBytes [pmControlHeaderLen]byte
	controlHeaderBytes[0] = byte(padding1Len)
	controlHeaderBytes[1] = byte(padding2Len)
	controlHeaderBytes[2] = controlHeaderBytes[0] ^ controlHeaderBytes[1] // Simple checksum
	controlHeaderBytes[3] = 0 // Reserved

	// Obfuscate the control header with a simple XOR key
	controlXORKey := o.pmDeriveControlKey()
	for i := range controlHeaderBytes {
		controlHeaderBytes[i] ^= controlXORKey
	}

	// 6. Calculate total output length
	outLen := pmControlHeaderLen + padding1Len + pmNonceLen + payloadWithTagLen + padding2Len
	if len(out) < outLen {
		return 0 // Output buffer too small
	}

	// 7. Assemble the obfuscated packet
	currentOffset := 0

	// Copy control header
	copy(out[currentOffset:], controlHeaderBytes[:])
	currentOffset += pmControlHeaderLen

	// Generate and copy padding1
	padding1, err := pmRandBytes(padding1Len)
	if err != nil {
		return 0
	}
	copy(out[currentOffset:], padding1)
	currentOffset += padding1Len

	// Copy Nonce
	copy(out[currentOffset:], nonce)
	currentOffset += pmNonceLen

	// Copy Encrypted Payload (Ciphertext + Tag)
	copy(out[currentOffset:], encryptedPayload)
	currentOffset += payloadWithTagLen

	// Generate and copy padding2
	padding2, err := pmRandBytes(padding2Len)
	if err != nil {
		return 0
	}
	copy(out[currentOffset:], padding2)
	currentOffset += padding2Len

	return outLen
}

// Deobfuscate reconstructs and decrypts the payload from a PolyMorph packet.
// It first de-obfuscates the control header to determine the packet layout,
// then extracts the nonce and encrypted payload for decryption.
// Returns the length of the decrypted data, or 0 if an error occurs (e.g., invalid format, decryption failure).
func (o *PolyMorphObfuscator) Deobfuscate(in, out []byte) int {
	if len(in) < pmControlHeaderLen+pmNonceLen+pmTagLen {
		return 0 // Packet too short to contain even minimal encrypted data
	}

	// 1. Extract and de-obfuscate the control header
	var controlHeaderBytes [pmControlHeaderLen]byte
	copy(controlHeaderBytes[:], in[:pmControlHeaderLen])

	controlXORKey := o.pmDeriveControlKey()
	for i := range controlHeaderBytes {
		controlHeaderBytes[i] ^= controlXORKey
	}

	// Verify checksum
	if controlHeaderBytes[2] != (controlHeaderBytes[0] ^ controlHeaderBytes[1]) {
		return 0 // Control header checksum mismatch, possible tampering
	}

	padding1Len := int(controlHeaderBytes[0])
	padding2Len := int(controlHeaderBytes[1])

	// Basic validation of decoded lengths
	if padding1Len > pmMaxPaddingLen || padding2Len > pmMaxPaddingLen {
		return 0 // Decoded values out of expected range, possible corruption
	}

	// 2. Calculate the start of the nonce and encrypted payload
	nonceStart := pmControlHeaderLen + padding1Len
	encryptedPayloadStart := nonceStart + pmNonceLen

	// Calculate the expected end of the encrypted payload (before padding2)
	expectedEncryptedPayloadEnd := len(in) - padding2Len

	// Check if the input packet has enough data for nonce, ciphertext, and tag
	if len(in) < encryptedPayloadStart+pmTagLen || expectedEncryptedPayloadEnd < encryptedPayloadStart+pmTagLen {
		return 0 // Packet too short for encrypted payload and tag
	}

	// 3. Extract nonce and encrypted payload (ciphertext + tag)
	nonce := in[nonceStart : nonceStart+pmNonceLen]
	encryptedPayloadWithTag := in[encryptedPayloadStart:expectedEncryptedPayloadEnd]

	// 4. Derive AES key from PSK
	aesKey := o.pmDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:pmKeyLen])
	if err != nil {
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	// 5. Decrypt the payload
	decryptedPayload, err := aesgcm.Open(nil, nonce, encryptedPayloadWithTag, nil)
	if err != nil {
		return 0 // Decryption or authentication failed
	}

	// 6. Copy decrypted data to output buffer
	if len(out) < len(decryptedPayload) {
		return 0 // Output buffer too small
	}
	copy(out[:len(decryptedPayload)], decryptedPayload)

	return len(decryptedPayload)
}

// Ensure PolyMorphObfuscator implements Obfuscator interface
var _ Obfuscator = (*PolyMorphObfuscator)(nil)
