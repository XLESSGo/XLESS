package obfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"sync"
)

const (
	dtlsMinPSKLen       = 16 // Minimum PSK length for AES-256 key derivation
	dtlsNonceLen        = 12 // AES-GCM nonce length
	dtlsTagLen          = 16 // AES-GCM authentication tag length
	dtlsKeyLen          = 32 // AES-256 key length (from BLAKE2b-256 hash)
	dtlsMaxPaddingLen   = 64 // Max random padding
	dtlsHeaderLen       = 13 // Example DTLS header length (Content Type + Version + Epoch + Sequence Number + Length)
	dtlsHandshakeType   = 22 // DTLS handshake content type
	dtlsHandshakeLength = 256 // Fixed length for simplified handshake
)

// DtlsObfuscator implements a stateful obfuscator that mimics a simplified DTLS handshake.
type DtlsObfuscator struct {
	PSK []byte
	lk  sync.Mutex
	// In a real implementation, you would track sequence numbers, epochs, etc.
	// For this example, we'll keep it simple.
	randSrc *mrand.Rand
}

// NewDtlsObfuscator creates a new DtlsObfuscator instance.
func NewDtlsObfuscator(psk []byte) (*DtlsObfuscator, error) {
	if len(psk) < dtlsMinPSKLen {
		return nil, fmt.Errorf("PSK length must be at least %d bytes", dtlsMinPSKLen)
	}
	return &DtlsObfuscator{
		PSK:     psk,
		randSrc: mrand.New(mrand.NewSource(time.Now().UnixNano())),
	}, nil
}

// dtlsDeriveAESKey derives a 256-bit AES key from the PSK using BLAKE2b.
func (o *DtlsObfuscator) dtlsDeriveAESKey() []byte {
	// blake2b.Sum256 returns an array, so we need to slice it to return []byte
	key := blake2b.Sum256(o.PSK)
	return key[:]
}

// Obfuscate wraps the payload in a fake DTLS packet with random padding.
func (o *DtlsObfuscator) Obfuscate(in, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()

	if len(in) == 0 {
		return 0
	}

	aesKey := o.dtlsDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:dtlsKeyLen])
	if err != nil {
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	nonce := make([]byte, dtlsNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0
	}

	// Encrypt the payload
	encryptedPayloadWithTag := aesgcm.Seal(nil, nonce, in, nil)

	// Add random padding
	paddingLen := o.randSrc.Intn(dtlsMaxPaddingLen)
	padding := make([]byte, paddingLen)
	if _, err := rand.Read(padding); err != nil {
		return 0
	}

	// Calculate total packet length
	totalPayloadLen := dtlsNonceLen + len(encryptedPayloadWithTag) + len(padding)
	totalPacketLen := dtlsHeaderLen + totalPayloadLen

	if len(out) < totalPacketLen {
		return 0
	}

	// Build the fake DTLS header
	out[0] = dtlsHandshakeType // Content Type: Handshake
	out[1] = 0xfe             // DTLS 1.0 (major version 254)
	out[2] = 0xfd             // DTLS 1.0 (minor version 253)
	binary.BigEndian.PutUint16(out[3:], 0x0001) // Epoch
	binary.BigEndian.PutUint16(out[5:], 0x0000) // Sequence number (low part)
	binary.BigEndian.PutUint32(out[7:], o.randSrc.Uint32()) // Fake sequence number
	binary.BigEndian.PutUint16(out[11:], uint16(totalPayloadLen)) // Length of encrypted payload + nonce + padding

	// Append nonce, encrypted payload, and padding
	currentOffset := dtlsHeaderLen
	copy(out[currentOffset:], nonce)
	currentOffset += dtlsNonceLen
	copy(out[currentOffset:], encryptedPayloadWithTag)
	currentOffset += len(encryptedPayloadWithTag)
	copy(out[currentOffset:], padding)

	return totalPacketLen
}

// Deobfuscate extracts and decrypts the payload from a fake DTLS packet.
func (o *DtlsObfuscator) Deobfuscate(in, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()

	if len(in) < dtlsHeaderLen+dtlsNonceLen+dtlsTagLen {
		return 0
	}

	// Check for expected DTLS handshake type
	if in[0] != dtlsHandshakeType {
		return 0
	}

	// Extract payload length from header
	encryptedLen := int(binary.BigEndian.Uint16(in[11:13]))

	// Ensure the packet has the expected length
	if len(in) != dtlsHeaderLen+encryptedLen {
		return 0
	}

	// Payload starts after the header
	payloadStart := dtlsHeaderLen
	// The rest is nonce + encrypted payload + tag + padding
	payload := in[payloadStart:]

	// Extract nonce
	nonce := payload[:dtlsNonceLen]

	// Find the end of the encrypted payload (before padding)
	// A simple approach is to assume padding is at the very end
	encryptedPayloadWithTagEnd := len(payload) - (encryptedLen - (dtlsNonceLen + len(in) - (dtlsHeaderLen + dtlsNonceLen)))
	if encryptedPayloadWithTagEnd < dtlsNonceLen+dtlsTagLen {
		return 0
	}
	encryptedPayloadWithTag := payload[dtlsNonceLen:encryptedPayloadWithTagEnd]

	// Decrypt payload
	aesKey := o.dtlsDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:dtlsKeyLen])
	if err != nil {
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}
	decryptedPayload, err := aesgcm.Open(nil, nonce, encryptedPayloadWithTag, nil)
	if err != nil {
		return 0
	}

	if len(out) < len(decryptedPayload) {
		return 0
	}
	copy(out, decryptedPayload)
	return len(decryptedPayload)
}
