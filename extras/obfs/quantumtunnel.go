package obfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"encoding/binary"
	"golang.org/x/crypto/blake2b"
)

const (
	qtMinPSKLen        = 16 // Minimum PSK length for AES-256 key derivation
	qtNonceLen         = 12 // AES-GCM nonce length
	qtTagLen           = 16 // AES-GCM authentication tag length
	qtKeyLen           = 32 // AES-256 key length (from BLAKE2b-256 hash)
	qtMaxSessionIDLen  = 32 // Max length of TLS session ID (where payload is hidden)
)

// qtClientHelloPrefix is a simplified, fixed prefix of a TLS ClientHello.
// This is a minimal example; real ClientHello would be much longer and complex.
// Handshake Type (1 byte): ClientHello (0x01)
// Length (3 bytes): Placeholder for total handshake message length
// TLS Version (2 bytes): TLS 1.2 (0x0303)
// Random (32 bytes): Client random
// Session ID Length (1 byte): Placeholder for session ID length
const qtClientHelloPrefix = "\x16" + // TLS Handshake record type
	"\x03\x01" + // TLS 1.0 (Record Layer Version, often fixed for compatibility)
	"\x00\x00" + // Length placeholder (2 bytes, will be calculated later)
	"\x01" + // Handshake Type: ClientHello
	"\x00\x00\x00" + // Handshake Length placeholder (3 bytes, will be calculated later)
	"\x03\x03" + // TLS 1.2 (ClientHello Version)
	"................................" + // 32 bytes of random data (placeholder)
	"\x00" // Session ID Length (placeholder, will be replaced)

// qtClientHelloSuffix is a simplified, fixed suffix of a TLS ClientHello.
// This includes Cipher Suites, Compression Methods, Extensions, etc.
// This is a minimal example; real ClientHello would be much longer and complex.
const qtClientHelloSuffix = "\x00\x02\xc0\x2b" + // Cipher Suites (e.g., TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	"\x01\x00" + // Compression Methods (1 byte length, 1 byte method: null)
	"\x00\x00" // Extensions Length (placeholder, 2 bytes)


// QuantumTunnelObfuscator embeds encrypted payload within a fake TLS ClientHello.
// It uses AES-GCM for encryption and hides the payload in the Session ID field.
type QuantumTunnelObfuscator struct {
	PSK []byte // Pre-shared key for AES key derivation
}

// NewQuantumTunnelObfuscator creates a new QuantumTunnelObfuscator instance.
// psk: The pre-shared key. Must be at least qtMinPSKLen bytes long.
func NewQuantumTunnelObfuscator(psk []byte) (*QuantumTunnelObfuscator, error) {
	if len(psk) < qtMinPSKLen {
		return nil, fmt.Errorf("PSK must be at least %d bytes for QuantumTunnel obfuscator", qtMinPSKLen)
	}
	return &QuantumTunnelObfuscator{PSK: psk}, nil
}

// qtDeriveAESKey derives a fixed-size AES key from the PSK using BLAKE2b-256.
func (o *QuantumTunnelObfuscator) qtDeriveAESKey() []byte {
	hash := blake2b.Sum256(o.PSK)
	return hash[:]
}

// Obfuscate encrypts the input 'in' and embeds it into a fake TLS ClientHello message.
// The encrypted payload (nonce + ciphertext + tag) is placed in the Session ID field.
// Returns the total length of the obfuscated packet, or 0 if an error occurs or 'out' is too small.
func (o *QuantumTunnelObfuscator) Obfuscate(in, out []byte) int {
	// 1. Generate AES-GCM nonce
	nonce := make([]byte, qtNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0 // Failed to generate random nonce
	}

	// 2. Derive AES key from PSK
	aesKey := o.qtDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:qtKeyLen])
	if err != nil {
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	// 3. Encrypt the original payload
	encryptedPayload := aesgcm.Seal(nil, nonce, in, nil)
	sessionIDContent := make([]byte, qtNonceLen+len(encryptedPayload))
	copy(sessionIDContent[:qtNonceLen], nonce)
	copy(sessionIDContent[qtNonceLen:], encryptedPayload)

	if len(sessionIDContent) > qtMaxSessionIDLen {
		return 0 // Encrypted payload too large for Session ID field
	}

	// 4. Build the fake TLS ClientHello
	prefixBytes := []byte(qtClientHelloPrefix)
	suffixBytes := []byte(qtClientHelloSuffix)

	// Fill random bytes for the ClientHello random field (32 bytes)
	clientRandom := make([]byte, 32)
	if _, err := rand.Read(clientRandom); err != nil {
		return 0
	}
	copy(prefixBytes[9:41], clientRandom) // Offset 9 for random field

	// Set Session ID Length
	prefixBytes[41] = byte(len(sessionIDContent)) // Offset 41 for Session ID Length

	// Calculate total handshake message length (excluding record layer header)
	// ClientHello (1 byte) + Handshake Length (3 bytes) + Version (2 bytes) + Random (32 bytes) +
	// Session ID Length (1 byte) + Session ID Content + Cipher Suites (2 bytes length + content) +
	// Compression Methods (1 byte length + content) + Extensions Length (2 bytes)
	handshakeMessageLen := 2 + 32 + 1 + len(sessionIDContent) + len(suffixBytes)

	// Update Handshake Length (3 bytes at offset 2)
	binary.BigEndian.PutUint32(prefixBytes[6:9], uint32(handshakeMessageLen)) // Only 3 bytes are used, so highest byte will be 0

	// Update Record Layer Length (2 bytes at offset 3)
	// Record Layer Length = Handshake Type (1) + Handshake Length (3) + Handshake Message Content
	recordLayerLen := 1 + 3 + handshakeMessageLen
	binary.BigEndian.PutUint16(prefixBytes[3:5], uint16(recordLayerLen)) // Offset 3 for record layer length

	// 5. Calculate total output length
	outLen := len(prefixBytes) + len(sessionIDContent) + len(suffixBytes)
	if len(out) < outLen {
		return 0 // Output buffer too small
	}

	// 6. Assemble the obfuscated packet
	currentOffset := 0
	copy(out[currentOffset:], prefixBytes)
	currentOffset += len(prefixBytes)

	copy(out[currentOffset:], sessionIDContent)
	currentOffset += len(sessionIDContent)

	copy(out[currentOffset:], suffixBytes)
	currentOffset += len(suffixBytes)

	return outLen
}

// Deobfuscate parses the fake TLS ClientHello, extracts the embedded payload, and decrypts it.
// Returns the length of the decrypted data, or 0 if an error occurs (e.g., invalid format, decryption failure).
func (o *QuantumTunnelObfuscator) Deobfuscate(in, out []byte) int {
	// Minimum expected length for a valid ClientHello with embedded payload
	minExpectedLen := len(qtClientHelloPrefix) + qtTagLen + len(qtClientHelloSuffix) // Assuming min session ID is tag length
	if len(in) < minExpectedLen {
		return 0 // Packet too short
	}

	// 1. Verify basic TLS record layer and handshake type
	if in[0] != 0x16 || in[5] != 0x01 { // Check Record Type (Handshake) and Handshake Type (ClientHello)
		return 0 // Not a ClientHello handshake record
	}

	// 2. Extract Session ID Length (at offset 41 in our simplified prefix)
	sessionIDLen := int(in[41])
	if sessionIDLen > qtMaxSessionIDLen || sessionIDLen < (qtNonceLen+qtTagLen) {
		return 0 // Invalid session ID length or too short to contain nonce+tag
	}

	// 3. Calculate start and end of the embedded payload (Session ID content)
	sessionIDStart := 42 // Offset 41 for length, so content starts at 42
	sessionIDEnd := sessionIDStart + sessionIDLen

	if len(in) < sessionIDEnd {
		return 0 // Packet too short for declared Session ID content
	}

	// 4. Extract nonce and encrypted payload from Session ID content
	embeddedContent := in[sessionIDStart:sessionIDEnd]
	nonce := embeddedContent[:qtNonceLen]
	encryptedPayloadWithTag := embeddedContent[qtNonceLen:]

	// 5. Derive AES key from PSK
	aesKey := o.qtDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:qtKeyLen])
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

// Ensure QuantumTunnelObfuscator implements Obfuscator interface
var _ Obfuscator = (*QuantumTunnelObfuscator)(nil)
