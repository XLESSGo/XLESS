package hypernova

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	mrand "math/rand"
	"sync"
	"time"
)

// Global constants for Hypernova protocol
const (
	MinPSKLen          = 64 // Increased PSK length for more robust key derivation (e.g., for multiple HMACs/AES keys)
	NonceLen           = 12 // AES-GCM nonce length
	TagLen             = 16 // AES-GCM authentication tag length
	AESKeyLen          = 32 // AES-256 key length
	HMACKeyLen         = 32 // HMAC-SHA256 key length
	HMACSize           = 32 // SHA256 output size (32 bytes)
	SequenceNumLen     = 8  // Sequence number length (uint64)
	CumulativeHashLen  = 32 // Length of cumulative hash (SHA256)
	StateTokenLen      = SequenceNumLen + CumulativeHashLen + HMACSize // Sequence Num + Cumulative Hash + HMAC for integrity

	// General dynamic padding limits
	MaxDynamicPadding = 256 // Max random padding bytes for various sections
	MinDynamicPadding = 64  // Min random padding bytes

	// Mode-specific constants will be defined in modes.go
)

// Obfuscator is the interface that wraps the Obfuscate and Deobfuscate methods.
// Both methods return the number of bytes written to out.
// If a packet is not valid, the methods should return 0.
type Obfuscator interface {
	Obfuscate(in, out []byte) int
	Deobfuscate(in, out []byte) int
}

// HypernovaObfuscator implements a highly complex, stateful obfuscation protocol.
// It uses multi-layered polymorphism, a history-dependent state machine,
// and dynamic traffic shaping elements.
type HypernovaObfuscator struct {
	PSK []byte // Pre-shared key for all key derivations

	// Internal state, protected by mutex
	lk           sync.Mutex
	sendSequenceNumber uint64 // Next sequence number to send
	recvSequenceNumber uint64 // Next expected sequence number to receive

	// Cryptographic state history
	cumulativeStateHash []byte // A running hash of communication history

	// Non-cryptographic random source for dynamic lengths/patterns
	randSrc *mrand.Rand
}

// NewHypernovaObfuscator creates a new HypernovaObfuscator instance.
// psk: The pre-shared key. Must be at least MinPSKLen bytes long.
func NewHypernovaObfuscator(psk []byte) (Obfuscator, error) {
	if len(psk) < MinPSKLen {
		return nil, fmt.Errorf("PSK must be at least %d bytes for Hypernova obfuscator", MinPSKLen)
	}

	initialHash, err := DeriveInitialCumulativeHash(psk)
	if err != nil {
		return nil, fmt.Errorf("failed to derive initial cumulative hash: %w", err)
	}

	return &HypernovaObfuscator{
		PSK:                psk,
		sendSequenceNumber: 1, // Start from 1, 0 can be reserved for handshake/reset
		recvSequenceNumber: 1, // Must be synchronized with peer
		cumulativeStateHash: initialHash,
		randSrc:            mrand.New(mrand.NewSource(time.Now().UnixNano())),
	}, nil
}

// Obfuscate encrypts the input 'in' and embeds it into a state-dependent packet format.
// Returns the total length of the obfuscated packet, or 0 if an error occurs or 'out' is too small.
func (o *HypernovaObfuscator) Obfuscate(in, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()

	// 1. Derive state-dependent AES key
	aesKey, err := DeriveAESKey(o.PSK, o.sendSequenceNumber, o.cumulativeStateHash)
	if err != nil {
		fmt.Printf("Error deriving AES key: %v\n", err)
		return 0
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		fmt.Printf("Error creating AES cipher: %v\n", err)
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("Error creating GCM: %v\n", err)
		return 0
	}

	// 2. Generate AES-GCM nonce
	nonce, err := GenerateRandomBytes(NonceLen)
	if err != nil {
		fmt.Printf("Error generating nonce: %v\n", err)
		return 0
	}

	// 3. Encrypt the original payload
	encryptedPayload := aesgcm.Seal(nil, nonce, in, nil)

	// 4. Generate state token (HMAC over sequence number, cumulative hash, and encrypted payload)
	stateToken, err := GenerateStateToken(o.PSK, o.sendSequenceNumber, o.cumulativeStateHash, encryptedPayload)
	if err != nil {
		fmt.Printf("Error generating state token: %v\n", err)
		return 0
	}

	var totalOutputLen int
	var chosenMode int // Represents which disguise mode is chosen

	// 5. Dynamic mode selection based on a cryptographic hash component
	// This makes mode selection less predictable than simple modulo operations.
	modeSelectorByte := o.cumulativeStateHash[0] // Use first byte of cumulative hash to select mode
	chosenMode = int(modeSelectorByte) % NumDisguiseModes // NumDisguiseModes is defined in modes.go

	switch chosenMode {
	case ModeTLSHandshake:
		totalOutputLen = ObfuscateModeTLSHandshake(o.randSrc, stateToken, nonce, encryptedPayload, o.sendSequenceNumber, out)
	case ModeDNSQuery:
		totalOutputLen = ObfuscateModeDNSQuery(o.randSrc, stateToken, nonce, encryptedPayload, o.sendSequenceNumber, out)
	case ModeSSHKeyExchange:
		totalOutputLen = ObfuscateModeSSHKeyExchange(o.randSrc, stateToken, nonce, encryptedPayload, o.sendSequenceNumber, out)
	default:
		// Fallback or error, should not happen with proper modulo
		fmt.Printf("Unknown disguise mode selected: %d\n", chosenMode)
		return 0
	}

	if totalOutputLen == 0 { // Check if obfuscateModeX failed
		return 0
	}

	// 6. Update cumulative state hash (only on successful obfuscation)
	o.cumulativeStateHash, err = UpdateCumulativeHash(o.PSK, o.cumulativeStateHash, o.sendSequenceNumber, encryptedPayload)
	if err != nil {
		fmt.Printf("Error updating cumulative hash: %v\n", err)
		return 0
	}

	o.sendSequenceNumber++ // Advance send sequence number

	return totalOutputLen
}

// Deobfuscate reconstructs and decrypts the payload from a Hypernova packet,
// advancing the state machine upon successful decryption and validation.
// Returns the length of the decrypted data, or 0 if an error occurs.
func (o *HypernovaObfuscator) Deobfuscate(in, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()

	var (
		stateToken              []byte
		nonce                   []byte
		encryptedPayloadWithTag []byte
		err                     error
	)

	// Determine expected mode based on current cumulative hash
	// This ensures sender and receiver are always in sync on mode choice
	modeSelectorByte := o.cumulativeStateHash[0]
	expectedMode := int(modeSelectorByte) % NumDisguiseModes

	// Attempt to deobfuscate based on the current expected mode
	switch expectedMode {
	case ModeTLSHandshake:
		stateToken, nonce, encryptedPayloadWithTag, err = DeobfuscateModeTLSHandshake(in, o.recvSequenceNumber)
	case ModeDNSQuery:
		stateToken, nonce, encryptedPayloadWithTag, err = DeobfuscateModeDNSQuery(in, o.recvSequenceNumber)
	case ModeSSHKeyExchange:
		stateToken, nonce, encryptedPayloadWithTag, err = DeobfuscateModeSSHKeyExchange(in, o.recvSequenceNumber)
	default:
		fmt.Printf("Unknown expected disguise mode: %d\n", expectedMode)
		return 0
	}

	if err != nil {
		// Log specific parsing errors for debugging, but return 0 to attacker
		// fmt.Printf("Deobfuscation mode failed (%d): %v\n", expectedMode, err)
		return 0
	}

	// 1. Verify state token BEFORE decryption
	validState, err := VerifyStateToken(o.PSK, o.recvSequenceNumber, o.cumulativeStateHash, stateToken, encryptedPayloadWithTag)
	if err != nil || !validState {
		// Log specific verification errors for debugging, but return 0 to attacker
		// fmt.Printf("State token verification failed: %v, valid: %t\n", err, validState)
		return 0 // State mismatch or token tampering, drop packet
	}

	// 2. Derive state-dependent AES key (using the same state as for obfuscation)
	aesKey, err := DeriveAESKey(o.PSK, o.recvSequenceNumber, o.cumulativeStateHash)
	if err != nil {
		fmt.Printf("Error deriving AES key for decryption: %v\n", err)
		return 0
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		fmt.Printf("Error creating AES cipher for decryption: %v\n", err)
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("Error creating GCM for decryption: %v\n", err)
		return 0
	}

	// 3. Decrypt the payload
	decryptedPayload, err := aesgcm.Open(nil, nonce, encryptedPayloadWithTag, nil)
	if err != nil {
		// This means authentication failed (tag mismatch) or corrupted data.
		// fmt.Printf("Payload decryption failed: %v\n", err)
		return 0
	}

	// 4. Copy decrypted data to output buffer
	if len(out) < len(decryptedPayload) {
		return 0 // Output buffer too small
	}
	copy(out[:len(decryptedPayload)], decryptedPayload)

	// 5. Update cumulative state hash (only on successful decryption and verification)
	o.cumulativeStateHash, err = UpdateCumulativeHash(o.PSK, o.cumulativeStateHash, o.recvSequenceNumber, encryptedPayloadWithTag) // Use encryptedPayloadWithTag here for hash consistency
	if err != nil {
		fmt.Printf("Error updating cumulative hash on deobfuscate: %v\n", err)
		return 0
	}

	o.recvSequenceNumber++ // Advance receive sequence number

	return len(decryptedPayload)
}

// Ensure HypernovaObfuscator implements Obfuscator interface
var _ Obfuscator = (*HypernovaObfuscator)(nil)
