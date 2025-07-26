package obfs

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	chameleonNonceLen = 12 // Nonce length for ChaCha20-Poly1305 (fixed)
	chameleonKeyLen   = 32 // Key length for ChaCha20-Poly1305 (fixed)
	chameleonTagLen   = 16 // Authentication tag length for Poly1305 (fixed)
)

// ChameleonObfuscator implements authenticated encryption using ChaCha20-Poly1305.
// It derives a unique key for each packet from a pre-shared key (PSK) and a
// per-packet random nonce. The nonce is prepended to the ciphertext.
// This provides strong confidentiality and integrity.
type ChameleonObfuscator struct {
	PSK []byte // Pre-shared key. Used to derive the actual ChaCha20 key.
}

// NewChameleonObfuscator creates a new ChameleonObfuscator instance.
// psk: The pre-shared key used to derive the ChaCha20 key. It must not be empty.
func NewChameleonObfuscator(psk []byte) (*ChameleonObfuscator, error) {
	if len(psk) == 0 {
		return nil, fmt.Errorf("PSK cannot be empty for Chameleon obfuscator")
	}
	return &ChameleonObfuscator{PSK: psk}, nil
}

// Obfuscate encrypts the input byte slice 'in' and writes the result to 'out'.
// It generates a random nonce, derives a ChaCha20 key from the PSK, encrypts 'in'
// with the nonce, and prepends the nonce to the resulting ciphertext (which includes the auth tag).
// Returns the number of bytes written to 'out'. If 'out' is too small, returns 0.
func (o *ChameleonObfuscator) Obfuscate(in, out []byte) int {
	// The output length includes the nonce, the original plaintext length, and the authentication tag.
	outLen := chameleonNonceLen + len(in) + chameleonTagLen
	if len(out) < outLen {
		return 0 // Output buffer too small
	}

	// Generate a cryptographically secure random nonce
	nonce := make([]byte, chameleonNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0 // Failed to generate random nonce
	}
	copy(out[:chameleonNonceLen], nonce) // Prepend nonce to the output buffer

	// Derive the ChaCha20 key from the PSK.
	// For production-grade key derivation from a password, consider using a KDF like HKDF or Argon2.
	// Here, we use BLAKE2b for simplicity and consistency with other parts of the project.
	key := blake2b.Sum256(o.PSK) // Derive a fixed 32-byte key from the PSK

	// Create a new ChaCha20-Poly1305 AEAD cipher instance
	aead, err := chacha20poly1305.New(key[:chameleonKeyLen])
	if err != nil {
		// This error should ideally not happen if chameleonKeyLen is correct (32 bytes)
		return 0
	}

	// Encrypt the payload using Seal.
	// The 'nil' for additionalData means no associated authenticated data.
	// The result (encryptedPayload) is the ciphertext concatenated with the 16-byte authentication tag.
	encryptedPayload := aead.Seal(nil, nonce, in, nil)

	// Copy the encrypted payload (ciphertext + tag) into the output buffer, after the nonce
	copy(out[chameleonNonceLen:], encryptedPayload)

	return outLen
}

// Deobfuscate decrypts the input byte slice 'in' and writes the result to 'out'.
// It extracts the nonce, derives the key, and attempts to decrypt the payload.
// If decryption fails (e.g., due to data corruption or tampering, indicated by authentication failure),
// it returns 0 to signal an invalid packet.
// Returns the number of bytes written to 'out'. If 'in' is invalid or 'out' is too small, returns 0.
func (o *ChameleonObfuscator) Deobfuscate(in, out []byte) int {
	// Minimum length for a valid encrypted packet: nonce + authentication tag
	if len(in) < chameleonNonceLen+chameleonTagLen {
		return 0 // Input is too short
	}

	nonce := in[:chameleonNonceLen]                 // Extract the nonce
	encryptedPayloadWithTag := in[chameleonNonceLen:] // The rest is ciphertext + tag
	outLen := len(encryptedPayloadWithTag) - chameleonTagLen // Expected plaintext length

	if len(out) < outLen {
		return 0 // Output buffer too small
	}

	// Derive the ChaCha20 key from the PSK using the same method as obfuscation
	key := blake2b.Sum256(o.PSK)

	// Create a new ChaCha20-Poly1305 AEAD cipher instance
	aead, err := chacha20poly1305.New(key[:chameleonKeyLen])
	if err != nil {
		return 0 // Should not happen
	}

	// Decrypt the payload using Open.
	// If decryption is successful and the authentication tag is valid, it returns the plaintext.
	// Otherwise, it returns an error (e.g., crypto/chacha20poly1305: message authentication failed).
	decryptedPayload, err := aead.Open(nil, nonce, encryptedPayloadWithTag, nil)
	if err != nil {
		return 0 // Decryption or authentication failed, indicating invalid or tampered packet
	}

	// Copy the decrypted plaintext into the output buffer
	copy(out[:outLen], decryptedPayload)
	return outLen
}

// Ensure ChameleonObfuscator implements Obfuscator interface
var _ Obfuscator = (*ChameleonObfuscator)(nil)
