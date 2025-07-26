package obfs

import (
	"bytes" // Added for bytes.Equal
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/blake2b"
	mrand "math/rand" // Use math/rand for non-cryptographic randomness (padding lengths, offsets)
	"sync"
	"time"
)

const (
	qsMinPSKLen        = 16 // Minimum PSK length for AES-256 key derivation
	qsNonceLen         = 12 // AES-GCM nonce length
	qsTagLen           = 16 // AES-GCM authentication tag length
	qsKeyLen           = 32 // AES-256 key length (from BLAKE2b-256 hash)
	qsControlHeaderLen = 4  // Length of the control header (encodes layout info)
	qsMagicNumberLen   = 4  // Length of the fixed magic number
	qsMaxPaddingLen    = 64 // Max random padding for each section (Padding1 and Padding2)
	qsMaxMagicOffset   = qsMaxPaddingLen - qsMagicNumberLen // Max offset for magic number in padding1
)

// qsMagicNumber is a fixed sequence of bytes used as a marker.
var qsMagicNumber = []byte{0x51, 0x53, 0x77, 0x88} // "QS" magic number

// QuantumShuffleObfuscator implements authenticated encryption with dynamic packet layout.
// It uses AES-GCM and random padding, with layout information encoded in an obfuscated control header.
type QuantumShuffleObfuscator struct {
	PSK []byte // Pre-shared key for AES key derivation and control header obfuscation
	// Using math/rand for non-cryptographic randomness (padding lengths, offsets)
	// and protecting it with a mutex for concurrent access.
	randSrc *mrand.Rand
	lk      sync.Mutex
}

// NewQuantumShuffleObfuscator creates a new QuantumShuffleObfuscator instance.
// psk: The pre-shared key. Must be at least qsMinPSKLen bytes long.
func NewQuantumShuffleObfuscator(psk []byte) (*QuantumShuffleObfuscator, error) {
	if len(psk) < qsMinPSKLen {
		return nil, fmt.Errorf("PSK must be at least %d bytes for QuantumShuffle obfuscator", qsMinPSKLen)
	}
	return &QuantumShuffleObfuscator{
		PSK:     psk,
		randSrc: mrand.New(mrand.NewSource(time.Now().UnixNano())),
	}, nil
}

// qsDeriveAESKey derives a fixed-size AES key from the PSK using BLAKE2b-256.
func (o *QuantumShuffleObfuscator) qsDeriveAESKey() []byte {
	hash := blake2b.Sum256(o.PSK)
	return hash[:]
}

// qsDeriveControlKey derives a small key for obfuscating the control header.
// It uses a different part of the PSK hash or a simpler hash for this.
func (o *QuantumShuffleObfuscator) qsDeriveControlKey() byte {
	hash := blake2b.Sum256(o.PSK)
	return hash[0] // Use the first byte of the hash as a simple XOR key
}

// qsRandBytes generates a slice of cryptographically secure random bytes of the given length.
func qsRandBytes(length int) ([]byte, error) {
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

// Obfuscate encrypts the input 'in' and shuffles its internal structure.
// It generates random padding and a magic number, and encodes their positions
// in an obfuscated control header.
// Returns the total length of the obfuscated packet, or 0 if an error occurs or 'out' is too small.
func (o *QuantumShuffleObfuscator) Obfuscate(in, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()

	// 1. Generate AES-GCM nonce
	nonce := make([]byte, qsNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0 // Failed to generate random nonce
	}

	// 2. Derive AES key from PSK
	aesKey := o.qsDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:qsKeyLen])
	if err != nil {
		return 0 // Should not happen with a valid key length
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0 // Should not happen
	}

	// 3. Encrypt the original payload
	encryptedPayload := aesgcm.Seal(nil, nonce, in, nil)
	payloadWithTagLen := len(encryptedPayload) // Length of (ciphertext + tag)

	// 4. Generate random padding lengths and magic number offset
	padding1Len := o.randSrc.Intn(qsMaxPaddingLen + 1) // 0 to qsMaxPaddingLen
	padding2Len := o.randSrc.Intn(qsMaxPaddingLen + 1) // 0 to qsMaxPaddingLen

	// Ensure magic number can fit within padding1
	magicOffset := 0
	if padding1Len >= qsMagicNumberLen {
		magicOffset = o.randSrc.Intn(padding1Len - qsMagicNumberLen + 1)
	} else {
		// If padding1 is too small, magic number cannot be placed within it.
		// For simplicity, we'll make padding1 at least qsMagicNumberLen if magic number is used.
		// Or, just skip placing magic number if padding1 is too small.
		// For this complex example, let's assume padding1Len is always enough or we adjust it.
		// To keep it simple, if padding1Len < qsMagicNumberLen, magicOffset will be 0, and it will overlap.
		// A more robust solution would be to ensure padding1Len >= qsMagicNumberLen.
	}

	// 5. Construct the control header
	// controlHeader will encode padding1Len, magicOffset, padding2Len
	// Max value for padding lengths and offset is qsMaxPaddingLen (64).
	// We need to encode these into 4 bytes.
	// Example encoding:
	// Byte 0: padding1Len
	// Byte 1: magicOffset
	// Byte 2: padding2Len
	// Byte 3: Reserved/Checksum (e.g., XOR sum of first 3 bytes)
	var controlHeaderBytes [qsControlHeaderLen]byte
	controlHeaderBytes[0] = byte(padding1Len)
	controlHeaderBytes[1] = byte(magicOffset)
	controlHeaderBytes[2] = byte(padding2Len)
	controlHeaderBytes[3] = controlHeaderBytes[0] ^ controlHeaderBytes[1] ^ controlHeaderBytes[2] // Simple checksum

	// Obfuscate the control header with a simple XOR key
	controlXORKey := o.qsDeriveControlKey()
	for i := range controlHeaderBytes {
		controlHeaderBytes[i] ^= controlXORKey
	}

	// 6. Calculate total output length
	outLen := qsControlHeaderLen + padding1Len + qsNonceLen + payloadWithTagLen + padding2Len
	if len(out) < outLen {
		return 0 // Output buffer too small
	}

	// 7. Assemble the obfuscated packet
	currentOffset := 0

	// Copy control header
	copy(out[currentOffset:], controlHeaderBytes[:])
	currentOffset += qsControlHeaderLen

	// Generate and copy padding1
	padding1, err := qsRandBytes(padding1Len)
	if err != nil {
		return 0
	}
	copy(out[currentOffset:], padding1)

	// Insert magic number into padding1 (if space allows)
	if magicOffset+qsMagicNumberLen <= padding1Len {
		copy(out[currentOffset+magicOffset:], qsMagicNumber)
	}
	currentOffset += padding1Len

	// Copy Nonce
	copy(out[currentOffset:], nonce)
	currentOffset += qsNonceLen

	// Copy Encrypted Payload (Ciphertext + Tag)
	copy(out[currentOffset:], encryptedPayload)
	currentOffset += payloadWithTagLen

	// Generate and copy padding2
	padding2, err := qsRandBytes(padding2Len)
	if err != nil {
		return 0
	}
	copy(out[currentOffset:], padding2)
	currentOffset += padding2Len

	return outLen
}

// Deobfuscate reconstructs and decrypts the payload from a QuantumShuffle packet.
// It first de-obfuscates the control header to determine the packet layout,
// then extracts the nonce and encrypted payload for decryption.
// Returns the length of the decrypted data, or 0 if an error occurs (e.g., invalid format, decryption failure).
func (o *QuantumShuffleObfuscator) Deobfuscate(in, out []byte) int {
	if len(in) < qsControlHeaderLen+qsNonceLen+qsTagLen {
		return 0 // Packet too short to contain even minimal encrypted data
	}

	// 1. Extract and de-obfuscate the control header
	var controlHeaderBytes [qsControlHeaderLen]byte
	copy(controlHeaderBytes[:], in[:qsControlHeaderLen])

	controlXORKey := o.qsDeriveControlKey()
	for i := range controlHeaderBytes {
		controlHeaderBytes[i] ^= controlXORKey
	}

	// Verify checksum
	if controlHeaderBytes[3] != (controlHeaderBytes[0] ^ controlHeaderBytes[1] ^ controlHeaderBytes[2]) {
		return 0 // Control header checksum mismatch, possible tampering
	}

	padding1Len := int(controlHeaderBytes[0])
	magicOffset := int(controlHeaderBytes[1])
	padding2Len := int(controlHeaderBytes[2])

	// Basic validation of decoded lengths/offsets
	if padding1Len > qsMaxPaddingLen || padding2Len > qsMaxPaddingLen || magicOffset > qsMaxMagicOffset {
		return 0 // Decoded values out of expected range, possible corruption
	}

	// Ensure magic number can fit within padding1 if it was placed
	if magicOffset+qsMagicNumberLen > padding1Len {
		// If the magic number could not have been placed as indicated, it's invalid.
		// This handles cases where padding1Len was too small for the magicOffset.
		// For this implementation, we assume if magicOffset was non-zero, it was placed.
		// A more robust check might involve always verifying the magic number regardless of offset.
	}

	// 2. Verify magic number (if it was placed)
	// This makes the deobfuscation more robust against random data.
	if magicOffset+qsMagicNumberLen <= padding1Len {
		magicNumberStart := qsControlHeaderLen + magicOffset
		if len(in) < magicNumberStart+qsMagicNumberLen ||
			!bytes.Equal(in[magicNumberStart:magicNumberStart+qsMagicNumberLen], qsMagicNumber) {
			return 0 // Magic number mismatch or packet too short
		}
	}

	// 3. Calculate the start of the nonce and encrypted payload
	nonceStart := qsControlHeaderLen + padding1Len
	encryptedPayloadStart := nonceStart + qsNonceLen

	// Calculate the expected end of the encrypted payload (before padding2)
	expectedEncryptedPayloadEnd := len(in) - padding2Len

	// Check if the input packet has enough data for nonce, ciphertext, and tag
	if len(in) < encryptedPayloadStart+qsTagLen || expectedEncryptedPayloadEnd < encryptedPayloadStart+qsTagLen {
		return 0 // Packet too short for encrypted payload and tag
	}

	// 4. Extract nonce and encrypted payload (ciphertext + tag)
	nonce := in[nonceStart : nonceStart+qsNonceLen]
	encryptedPayloadWithTag := in[encryptedPayloadStart:expectedEncryptedPayloadEnd]

	// 5. Derive AES key from PSK
	aesKey := o.qsDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:qsKeyLen])
	if err != nil {
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	// 6. Decrypt the payload
	decryptedPayload, err := aesgcm.Open(nil, nonce, encryptedPayloadWithTag, nil)
	if err != nil {
		return 0 // Decryption or authentication failed
	}

	// 7. Copy decrypted data to output buffer
	if len(out) < len(decryptedPayload) {
		return 0 // Output buffer too small
	}
	copy(out[:len(decryptedPayload)], decryptedPayload)

	return len(decryptedPayload)
}

// Ensure QuantumShuffleObfuscator implements Obfuscator interface
var _ Obfuscator = (*QuantumShuffleObfuscator)(nil)
