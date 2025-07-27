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
	astroMinPSKLen   = 16 // Minimum PSK length for AES-256 key derivation
	astroNonceLen    = 12 // AES-GCM nonce length
	astroTagLen      = 16 // AES-GCM authentication tag length
	astroKeyLen      = 32 // AES-256 key length (from BLAKE2b-256 hash)
	astroMinPayload  = astroNonceLen + astroTagLen // Minimum size of encrypted payload
	astroMaxFrameLen = 16383 // Max HTTP/2 frame payload length (2^14 - 1 for DATA frames without padding)
)

// astroHeaderTemplates defines a set of plausible HTTP/2 DATA frame prefixes/suffixes.
// In a real system, these would be more complex and potentially dynamic.
// Each template includes the Handshake Type (0x16), Record Layer Version (0x0301 or 0x0303),
// Length (2 bytes, for record layer), Handshake Type (0x01 for ClientHello),
// and a fixed TLS version for the ClientHello itself (0x0303 for TLS 1.2).
// This simplified version only shows the HTTP/2 DATA frame header parts.
var astroHeaderTemplates = [][]byte{
	// Example HTTP/2 DATA frame header (9 bytes):
	// Length (3 bytes) | Type (1 byte: DATA=0x00) | Flags (1 byte: END_STREAM=0x01) | Stream ID (4 bytes)
	// The length part needs to be dynamically adjusted.
	[]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01}, // Stream 1, END_STREAM
	[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}, // Stream 3, no flags
	[]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05}, // Stream 5, END_STREAM
}

// AstroObfuscator performs adaptive header mimicry for traffic camouflage.
// It uses AES-GCM and embeds the encrypted payload into a dynamically generated
// HTTP/2 DATA frame structure.
type AstroObfuscator struct {
	PSK []byte // Pre-shared key for AES key derivation
	lk  sync.Mutex
	// Use math/rand for selecting header templates and generating stream IDs.
	randSrc *mrand.Rand
}

// NewAstroObfuscator creates a new AstroObfuscator instance.
// psk: The pre-shared key. Must be at least astroMinPSKLen bytes long.
func NewAstroObfuscator(psk []byte) (*AstroObfuscator, error) {
	if len(psk) < astroMinPSKLen {
		return nil, fmt.Errorf("PSK must be at least %d bytes for Astro obfuscator", astroMinPSKLen)
	}
	return &AstroObfuscator{
		PSK:     psk,
		randSrc: mrand.New(mrand.NewSource(time.Now().UnixNano())),
	}, nil
}

// astroDeriveAESKey derives a fixed-size AES key from the PSK using BLAKE2b-256.
func (o *AstroObfuscator) astroDeriveAESKey() []byte {
	hash := blake2b.Sum256(o.PSK)
	return hash[:]
}

// Obfuscate encrypts the input 'in' and embeds it into a dynamically crafted HTTP/2 DATA frame.
// Returns the total length of the obfuscated packet, or 0 if an error occurs or 'out' is too small.
func (o *AstroObfuscator) Obfuscate(in, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()

	// 1. Generate AES-GCM nonce
	nonce := make([]byte, astroNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0 // Failed to generate random nonce
	}

	// 2. Derive AES key from PSK
	aesKey := o.astroDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:astroKeyLen])
	if err != nil {
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	// 3. Encrypt the original payload
	encryptedPayload := aesgcm.Seal(nil, nonce, in, nil)
	// The actual data embedded in the HTTP/2 frame will be (Nonce + Ciphertext + Tag)
	embeddedDataLen := astroNonceLen + len(encryptedPayload)

	if embeddedDataLen > astroMaxFrameLen {
		return 0 // Encrypted payload too large to fit in a single HTTP/2 DATA frame payload
	}

	// 4. Select a random header template and build the HTTP/2 frame header.
	templateIdx := o.randSrc.Intn(len(astroHeaderTemplates))
	frameHeader := make([]byte, len(astroHeaderTemplates[templateIdx]))
	copy(frameHeader, astroHeaderTemplates[templateIdx])

	// Update the frame length (first 3 bytes of the 9-byte header)
	// The length field in HTTP/2 frames specifies the length of the payload (excluding the 9-byte header itself).
	binary.BigEndian.PutUint32(frameHeader[0:4], uint32(embeddedDataLen)) // Only 3 bytes are used, so highest byte will be 0

	// 5. Calculate total output length
	outLen := len(frameHeader) + embeddedDataLen
	if len(out) < outLen {
		return 0 // Output buffer too small
	}

	// 6. Assemble the obfuscated packet: [HTTP/2_FRAME_HEADER][NONCE][CIPHERTEXT][TAG]
	currentOffset := 0
	copy(out[currentOffset:], frameHeader)
	currentOffset += len(frameHeader)

	copy(out[currentOffset:], nonce)
	currentOffset += astroNonceLen

	copy(out[currentOffset:], encryptedPayload) // This already contains ciphertext + tag
	currentOffset += len(encryptedPayload)

	return outLen
}

// Deobfuscate parses the HTTP/2 DATA frame, extracts the embedded payload, and decrypts it.
// Returns the length of the decrypted data, or 0 if an error occurs (e.g., invalid format, decryption failure).
func (o *AstroObfuscator) Deobfuscate(in, out []byte) int {
	if len(in) < 9+astroMinPayload { // Min HTTP/2 header (9 bytes) + min payload (nonce+tag)
		return 0 // Packet too short
	}

	// 1. Extract and validate HTTP/2 frame header components
	// Length (3 bytes)
	framePayloadLen := int(binary.BigEndian.Uint32(append([]byte{0x00}, in[0:3]...))) // Prepend 0x00 to read 3 bytes as uint32

	// Frame Type (1 byte) - must be DATA (0x00) for this protocol
	frameType := in[3]
	if frameType != 0x00 {
		return 0 // Not a DATA frame, not a valid Astro packet
	}

	// Flags (1 byte)
	// Stream ID (4 bytes) - can be any non-zero value, but not 0 for DATA frames
	streamID := binary.BigEndian.Uint32(in[5:9])
	if streamID == 0 {
		return 0 // Stream ID 0 is reserved for connection control, not DATA frames
	}

	// 2. Check if the remaining input length matches the expected payload length
	expectedTotalLen := 9 + framePayloadLen // 9 bytes header + payload length
	if len(in) < expectedTotalLen || framePayloadLen < astroMinPayload {
		return 0 // Mismatched length or payload too short for nonce+tag
	}

	// 3. Extract nonce and encrypted payload from the frame payload
	embeddedDataStart := 9 // After the 9-byte header
	embeddedDataEnd := embeddedDataStart + framePayloadLen
	if len(in) < embeddedDataEnd {
		return 0 // Packet truncated
	}

	embeddedData := in[embeddedDataStart:embeddedDataEnd]
	nonce := embeddedData[:astroNonceLen]
	encryptedPayloadWithTag := embeddedData[astroNonceLen:]

	// 4. Derive AES key from PSK
	aesKey := o.astroDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:astroKeyLen])
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

// Ensure AstroObfuscator implements Obfuscator interface
var _ Obfuscator = (*AstroObfuscator)(nil)
