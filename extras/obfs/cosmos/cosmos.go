package cosmos

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	mrand "math/rand"
	"sync"
	"time"
)

// Constants for Cosmos protocol (moved from main obfs/cosmos.go)
const (
	MinPSKLen         = 32 // Increased PSK length for better security (HMAC-SHA256 needs 32-byte key)
	NonceLen          = 12 // AES-GCM nonce length
	TagLen            = 16 // AES-GCM authentication tag length
	AESKeyLen         = 32 // AES-256 key length (from BLAKE2b-256 hash)
	HMACKeyLen        = 32 // HMAC-SHA256 key length
	HMACSize          = 32 // SHA256 output size (32 bytes)
	SequenceNumLen    = 8  // Sequence number length (uint64)
	StateTokenLen     = SequenceNumLen + HMACSize // Total state token length

	// Dynamic padding/header limits
	MaxDynamicPadding = 128 // Max random padding bytes for various sections
	MinDynamicPadding = 32  // Min random padding bytes

	// Mode A (HTTP GET Mimicry) constants
	HTTPLikeMinLen = 100 // Minimum length for a believable HTTP header part
	MaxContentLen  = 8192 // Max content length for embedded payload

	// Mode B (Generic Binary) constants
	BinaryMagicLen = 4    // Length of magic bytes
	BinaryMagic    = 0x434F534D // "COSM" in ASCII
)

// Obfuscator is the interface that wraps the Obfuscate and Deobfuscate methods.
// Both methods return the number of bytes written to out.
// If a packet is not valid, the methods should return 0.
type Obfuscator interface {
	Obfuscate(in, out []byte) int
	Deobfuscate(in, out []byte) int
}

// CosmosObfuscator implements an encrypted state machine where packet format
// and encryption parameters change based on a synchronized state (sequence number).
type CosmosObfuscator struct {
	PSK []byte // Pre-shared key for all key derivations

	// Internal state
	lk           sync.Mutex
	sequenceNumber uint64 // Current synchronized sequence number

	// Non-cryptographic random source for dynamic lengths/patterns
	randSrc *mrand.Rand
}

// NewCosmosObfuscator creates a new CosmosObfuscator instance.
// psk: The pre-shared key. Must be at least MinPSKLen bytes long.
func NewCosmosObfuscator(psk []byte) (Obfuscator, error) {
	if len(psk) < MinPSKLen {
		return nil, fmt.Errorf("PSK must be at least %d bytes for Cosmos obfuscator (needs for HMAC-SHA256)", MinPSKLen)
	}
	return &CosmosObfuscator{
		PSK:            psk,
		sequenceNumber: 1, // Start from 1, 0 can be reserved for handshake/reset
		randSrc:        mrand.New(mrand.NewSource(time.Now().UnixNano())),
	}, nil
}

// Obfuscate encrypts the input 'in' and embeds it into a state-dependent packet format.
// Returns the total length of the obfuscated packet, or 0 if an error occurs or 'out' is too small.
func (o *CosmosObfuscator) Obfuscate(in, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()

	aesKey, err := DeriveAESKey(o.PSK, o.sequenceNumber)
	if err != nil {
		return 0
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	nonce, err := GenerateRandomBytes(NonceLen)
	if err != nil {
		return 0
	}

	encryptedPayload := aesgcm.Seal(nil, nonce, in, nil)
	payloadWithTagLen := len(encryptedPayload) // Length of (ciphertext + tag)

	if payloadWithTagLen+NonceLen > MaxContentLen {
		// Payload too large for HTTP Content-Length field in Mode A, or general limit.
		return 0
	}

	stateToken, err := GenerateStateToken(o.PSK, o.sequenceNumber, encryptedPayload)
	if err != nil {
		return 0
	}

	var totalOutputLen int

	// Dynamic mode selection based on sequence number
	if o.sequenceNumber%2 == 0 { // Mode A: HTTP GET Mimicry
		totalOutputLen = obfuscateModeA(o.randSrc, stateToken, nonce, encryptedPayload, out)
	} else { // Mode B: Generic Binary with random padding
		totalOutputLen = obfuscateModeB(o.randSrc, stateToken, nonce, encryptedPayload, out)
	}

	if totalOutputLen == 0 { // Check if obfuscateModeX failed
		return 0
	}

	o.sequenceNumber++ // Advance state only after successful obfuscation

	return totalOutputLen
}

// Deobfuscate reconstructs and decrypts the payload from a Cosmos packet,
// advancing the state machine upon successful decryption and validation.
// Returns the length of the decrypted data, or 0 if an error occurs (e.g., state mismatch, decryption failure).
func (o *CosmosObfuscator) Deobfuscate(in, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()

	var (
		stateToken              []byte
		nonce                   []byte
		encryptedPayloadWithTag []byte
	)

	// Attempt to deobfuscate based on the current expected mode
	var err error
	if o.sequenceNumber%2 == 0 { // Expected Mode A: HTTP GET Mimicry
		stateToken, nonce, encryptedPayloadWithTag, err = deobfuscateModeA(in)
	} else { // Expected Mode B: Generic Binary
		stateToken, nonce, encryptedPayloadWithTag, err = deobfuscateModeB(in)
	}

	if err != nil {
		fmt.Printf("Deobfuscation mode failed: %v\n", err) // Log error for debugging
		return 0
	}

	// Verify state token BEFORE decryption
	validState, err := VerifyStateToken(o.PSK, o.sequenceNumber, stateToken, encryptedPayloadWithTag)
	if err != nil || !validState {
		fmt.Printf("State token verification failed: %v, valid: %t\n", err, validState) // Log error
		return 0 // State mismatch or token tampering, drop packet
	}

	aesKey, err := DeriveAESKey(o.PSK, o.sequenceNumber)
	if err != nil {
		return 0
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	decryptedPayload, err := aesgcm.Open(nil, nonce, encryptedPayloadWithTag, nil)
	if err != nil {
		fmt.Printf("Payload decryption failed: %v\n", err) // Log error
		return 0 // Decryption or authentication failed (bad key, corrupted data, or replay)
	}

	if len(out) < len(decryptedPayload) {
		return 0 // Output buffer too small
	}
	copy(out[:len(decryptedPayload)], decryptedPayload)

	o.sequenceNumber++ // Advance state ONLY after successful decryption and verification

	return len(decryptedPayload)
}

// Ensure CosmosObfuscator implements Obfuscator interface
var _ Obfuscator = (*CosmosObfuscator)(nil)
