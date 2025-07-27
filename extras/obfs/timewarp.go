package obfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/blake2b"
	mrand "math/rand"
	"sync"
	"time"
)

const (
	twMinPSKLen        = 16 // Minimum PSK length for AES-256 key derivation
	twNonceLen         = 12 // AES-GCM nonce length
	twTagLen           = 16 // AES-GCM authentication tag length
	twKeyLen           = 32 // AES-256 key length (from BLAKE2b-256 hash)
	twControlHeaderMin = 6  // Min length of control header (PacketID + NumChunks + ChunkSize + Checksum)
	twMaxChunkSize     = 200 // Max size for each payload chunk
)

// TimeWarpObfuscator fragments a packet, encrypts chunks, and shuffles their order.
// A control header guides reconstruction.
type TimeWarpObfuscator struct {
	PSK []byte // Pre-shared key for AES key derivation and control header obfuscation
	// Using math/rand for non-cryptographic randomness (chunk shuffling)
	randSrc *mrand.Rand
	lk      sync.Mutex
}

// NewTimeWarpObfuscator creates a new TimeWarpObfuscator instance.
// psk: The pre-shared key. Must be at least twMinPSKLen bytes long.
func NewTimeWarpObfuscator(psk []byte) (*TimeWarpObfuscator, error) {
	if len(psk) < twMinPSKLen {
		return nil, fmt.Errorf("PSK must be at least %d bytes for TimeWarp obfuscator", twMinPSKLen)
	}
	return &TimeWarpObfuscator{
		PSK:     psk,
		randSrc: mrand.New(mrand.NewSource(time.Now().UnixNano())),
	}, nil
}

// twDeriveAESKey derives a fixed-size AES key from the PSK using BLAKE2b-256.
func (o *TimeWarpObfuscator) twDeriveAESKey() []byte {
	hash := blake2b.Sum256(o.PSK)
	return hash[:]
}

// twDeriveControlKey derives a small key for obfuscating the control header.
func (o *TimeWarpObfuscator) twDeriveControlKey() byte {
	hash := blake2b.Sum256(append(o.PSK, []byte("tw_control")...)) // Different salt
	return hash[0] // Use the first byte of the hash as a simple XOR key
}

// twRandBytes generates a slice of cryptographically secure random bytes of the given length.
func twRandBytes(length int) ([]byte, error) {
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

// Obfuscate fragments the input 'in', encrypts and shuffles chunks, and adds a control header.
// Returns the total length of the obfuscated packet, or 0 if an error occurs or 'out' is too small.
func (o *TimeWarpObfuscator) Obfuscate(in, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()

	// 1. Determine chunking parameters
	chunkSize := o.randSrc.Intn(twMaxChunkSize-1) + 1 // Random chunk size between 1 and twMaxChunkSize
	if chunkSize == 0 { // Should not happen with +1, but for safety
		chunkSize = 1
	}
	numChunks := (len(in) + chunkSize - 1) / chunkSize // Ceiling division

	if numChunks == 0 { // Handle empty input
		numChunks = 1
		chunkSize = 0 // No actual data, but still one "chunk" for metadata
	}

	// 2. Prepare chunk order and packet ID
	originalOrder := o.randSrc.Perm(numChunks) // Generate a random permutation
	packetID := o.randSrc.Uint32()              // Unique ID for this packet

	// 3. Construct the control header
	// Format: PacketID (4 bytes), NumChunks (1 byte), ChunkSize (1 byte), OriginalOrder (N bytes), Checksum (1 byte)
	controlHeaderBaseLen := twControlHeaderMin + numChunks
	controlHeader := make([]byte, controlHeaderBaseLen)
	binary.BigEndian.PutUint32(controlHeader[0:4], packetID)
	controlHeader[4] = byte(numChunks)
	controlHeader[5] = byte(chunkSize)
	for i, v := range originalOrder {
		controlHeader[6+i] = byte(v)
	}
	// Simple XOR checksum for the control header
	checksum := byte(0)
	for i := 0; i < controlHeaderBaseLen-1; i++ {
		checksum ^= controlHeader[i]
	}
	controlHeader[controlHeaderBaseLen-1] = checksum

	// Obfuscate the control header
	controlXORKey := o.twDeriveControlKey()
	for i := range controlHeader {
		controlHeader[i] ^= controlXORKey
	}

	// 4. Encrypt each chunk and collect them
	encryptedChunks := make([][]byte, numChunks)
	totalEncryptedPayloadLen := 0

	aesKey := o.twDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:twKeyLen])
	if err != nil {
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	for i := 0; i < numChunks; i++ {
		chunkStart := i * chunkSize
		chunkEnd := chunkStart + chunkSize
		if chunkEnd > len(in) {
			chunkEnd = len(in)
		}
		currentChunk := in[chunkStart:chunkEnd]

		nonce := make([]byte, twNonceLen)
		if _, err := rand.Read(nonce); err != nil {
			return 0
		}

		// Encrypt the chunk
		encryptedChunk := aesgcm.Seal(nil, nonce, currentChunk, nil)
		// Prepend nonce to the encrypted chunk
		chunkWithNonceAndTag := make([]byte, twNonceLen+len(encryptedChunk))
		copy(chunkWithNonceAndTag[:twNonceLen], nonce)
		copy(chunkWithNonceAndTag[twNonceLen:], encryptedChunk)

		encryptedChunks[i] = chunkWithNonceAndTag
		totalEncryptedPayloadLen += len(chunkWithNonceAndTag)
	}

	// 5. Calculate total output length
	outLen := len(controlHeader) + totalEncryptedPayloadLen
	if len(out) < outLen {
		return 0 // Output buffer too small
	}

	// 6. Assemble the obfuscated packet
	currentOffset := 0

	// Copy control header
	copy(out[currentOffset:], controlHeader)
	currentOffset += len(controlHeader)

	// Copy shuffled encrypted chunks
	shuffledOrder := make([]int, numChunks)
	for i := range shuffledOrder {
		shuffledOrder[i] = i // Initialize with 0, 1, 2...
	}
	o.randSrc.Shuffle(numChunks, func(i, j int) {
		shuffledOrder[i], shuffledOrder[j] = shuffledOrder[j], shuffledOrder[i]
	})

	for _, originalIdx := range shuffledOrder { // Iterate through the shuffled order
		copy(out[currentOffset:], encryptedChunks[originalIdx])
		currentOffset += len(encryptedChunks[originalIdx])
	}

	return outLen
}

// Deobfuscate reconstructs and decrypts the payload from a TimeWarp packet.
// It first de-obfuscates the control header to determine chunking and order,
// then decrypts and reorders the chunks to reconstruct the original payload.
// Returns the length of the decrypted data, or 0 if an error occurs (e.g., invalid format, decryption failure).
func (o *TimeWarpObfuscator) Deobfuscate(in, out []byte) int {
	if len(in) < twControlHeaderMin {
		return 0 // Packet too short for control header
	}

	// 1. De-obfuscate the control header
	var controlHeaderBase [twControlHeaderMin]byte
	copy(controlHeaderBase[:], in[:twControlHeaderMin])

	controlXORKey := o.twDeriveControlKey()
	for i := range controlHeaderBase {
		controlHeaderBase[i] ^= controlXORKey
	}

	// Extract basic info from de-obfuscated header
	packetID := binary.BigEndian.Uint32(controlHeaderBase[0:4])
	numChunks := int(controlHeaderBase[4])
	chunkSize := int(controlHeaderBase[5])

	if numChunks == 0 { // Special case for empty input
		if len(in) == twControlHeaderMin && controlHeaderBase[twControlHeaderMin-1] == (controlHeaderBase[0]^controlHeaderBase[1]^controlHeaderBase[2]^controlHeaderBase[3]^controlHeaderBase[4]) {
			return 0 // Valid empty packet
		}
		return 0 // Invalid empty packet or corrupted
	}

	// Calculate expected control header length including original order
	expectedControlHeaderLen := twControlHeaderMin + numChunks
	if len(in) < expectedControlHeaderLen {
		return 0 // Packet too short for full control header
	}

	fullControlHeader := make([]byte, expectedControlHeaderLen)
	copy(fullControlHeader[:twControlHeaderMin], controlHeaderBase[:]) // Copy de-obfuscated base
	// Copy and de-obfuscate the original order part
	for i := twControlHeaderMin; i < expectedControlHeaderLen; i++ {
		fullControlHeader[i] = in[i] ^ controlXORKey
	}

	// Verify checksum of the full de-obfuscated control header
	checksum := byte(0)
	for i := 0; i < expectedControlHeaderLen-1; i++ {
		checksum ^= fullControlHeader[i]
	}
	if checksum != fullControlHeader[expectedControlHeaderLen-1] {
		return 0 // Control header checksum mismatch
	}

	originalOrder := make([]int, numChunks)
	for i := 0; i < numChunks; i++ {
		originalOrder[i] = int(fullControlHeader[6+i])
		if originalOrder[i] >= numChunks { // Validate order index
			return 0
		}
	}

	// 2. Decrypt and reorder chunks
	aesKey := o.twDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:twKeyLen])
	if err != nil {
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	currentOffset := expectedControlHeaderLen
	decryptedChunks := make([][]byte, numChunks)
	totalDecryptedLen := 0

	// First pass: decrypt all chunks and store them
	for i := 0; i < numChunks; i++ {
		if len(in) < currentOffset+twNonceLen+twTagLen {
			return 0 // Not enough data for chunk nonce + tag
		}

		nonce := in[currentOffset : currentOffset+twNonceLen]
		encryptedChunkWithTagStart := currentOffset + twNonceLen
		// Determine the end of the current encrypted chunk (including tag)
		// This is tricky because chunk size is variable for the last chunk.
		// We can't rely on 'chunkSize' for the encrypted length directly.
		// Instead, we need to infer it. The simplest way is to assume the rest of the packet
		// belongs to the current chunk until the next chunk's start or end of packet.
		// A more robust solution would embed encrypted chunk lengths.
		// For simplicity, we'll assume chunks are tightly packed and infer length.

		// This approach assumes the *encrypted* chunk length is fixed or derivable.
		// With AES-GCM, encrypted length = plaintext length + tag length.
		// If plaintext chunk size is fixed, then encrypted chunk size is fixed.
		// Except for the last chunk.
		// Let's assume a fixed encrypted chunk size for all but the last.
		expectedEncryptedChunkLen := chunkSize + twTagLen // Plaintext + Tag
		if i == numChunks-1 { // Last chunk
			// The last chunk's encrypted length is the remaining data minus nonce and tag
			// This is an approximation and might be fragile if padding is also involved.
			// A better approach for TimeWarp would be to explicitly store encrypted chunk lengths.
			// For this example, we'll assume the remaining data is the last chunk.
			if len(in[encryptedChunkWithTagStart:]) < twTagLen { // Must at least contain a tag
				return 0
			}
			encryptedChunkWithTag := in[encryptedChunkWithTagStart:]
			decryptedChunk, err := aesgcm.Open(nil, nonce, encryptedChunkWithTag, nil)
			if err != nil {
				return 0 // Decryption failed
			}
			decryptedChunks[i] = decryptedChunk
			totalDecryptedLen += len(decryptedChunk)
			currentOffset += twNonceLen + len(encryptedChunkWithTag)
		} else {
			// For non-last chunks, assume a fixed encrypted chunk size
			expectedFullChunkLen := twNonceLen + expectedEncryptedChunkLen
			if len(in) < currentOffset+expectedFullChunkLen {
				return 0 // Not enough data for this fixed-size chunk
			}
			encryptedChunkWithTag := in[encryptedChunkWithTagStart : encryptedChunkWithTagStart+expectedEncryptedChunkLen]
			decryptedChunk, err := aesgcm.Open(nil, nonce, encryptedChunkWithTag, nil)
			if err != nil {
				return 0 // Decryption failed
			}
			decryptedChunks[i] = decryptedChunk
			totalDecryptedLen += len(decryptedChunk)
			currentOffset += expectedFullChunkLen
		}
	}

	// 3. Reorder and copy to output
	if len(out) < totalDecryptedLen {
		return 0 // Output buffer too small
	}

	reconstructedOffset := 0
	for _, originalIdx := range originalOrder {
		if originalIdx >= len(decryptedChunks) { // Should not happen with validated order
			return 0
		}
		copy(out[reconstructedOffset:], decryptedChunks[originalIdx])
		reconstructedOffset += len(decryptedChunks[originalIdx])
	}

	return totalDecryptedLen
}

// Ensure TimeWarpObfuscator implements Obfuscator interface
var _ Obfuscator = (*TimeWarpObfuscator)(nil)
