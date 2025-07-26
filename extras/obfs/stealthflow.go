package obfs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"strconv"
	"strings"
)

const (
	sfMinPSKLen = 16 // Minimum PSK length for AES-256 key derivation
	sfNonceLen  = 12 // AES-GCM nonce length
	sfTagLen    = 16 // AES-GCM authentication tag length
	sfKeyLen    = 32 // AES-256 key length (from BLAKE2b-256 hash)
)

// sfHTTPHeaderTemplate is a fixed HTTP GET request template.
// The %d placeholder will be replaced with the actual payload length.
const sfHTTPHeaderTemplate = "GET / HTTP/1.1\r\n" +
	"Host: example.com\r\n" +
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36\r\n" +
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n" +
	"Accept-Language: en-US,en;q=0.5\r\n" +
	"Connection: keep-alive\r\n" +
	"Content-Length: %d\r\n" + // Placeholder for actual payload length
	"\r\n"

// StealthFlowObfuscator camouflages traffic as HTTP/1.1 GET requests.
// It encrypts the payload using AES-GCM and embeds it after a fake HTTP header.
type StealthFlowObfuscator struct {
	PSK []byte // Pre-shared key for AES key derivation
}

// NewStealthFlowObfuscator creates a new StealthFlowObfuscator instance.
// psk: The pre-shared key. Must be at least sfMinPSKLen bytes long.
func NewStealthFlowObfuscator(psk []byte) (*StealthFlowObfuscator, error) {
	if len(psk) < sfMinPSKLen {
		return nil, fmt.Errorf("PSK must be at least %d bytes for StealthFlow obfuscator", sfMinPSKLen)
	}
	return &StealthFlowObfuscator{PSK: psk}, nil
}

// sfDeriveKey derives a fixed-size AES key from the PSK using BLAKE2b-256.
func (o *StealthFlowObfuscator) sfDeriveKey() []byte {
	hash := blake2b.Sum256(o.PSK)
	return hash[:]
}

// Obfuscate encrypts the input 'in' and encapsulates it within an HTTP-like structure.
// The encrypted data (nonce + ciphertext + tag) forms the "body" of the fake HTTP request.
// Returns the total length of the obfuscated packet, or 0 if an error occurs or 'out' is too small.
func (o *StealthFlowObfuscator) Obfuscate(in, out []byte) int {
	// 1. Generate AES-GCM nonce
	nonce := make([]byte, sfNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0 // Failed to generate random nonce
	}

	// 2. Derive AES key from PSK
	key := o.sfDeriveKey()
	block, err := aes.NewCipher(key[:sfKeyLen])
	if err != nil {
		return 0 // Should not happen with a valid key length
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0 // Should not happen
	}

	// 3. Encrypt the original payload
	// The 'nil' for additionalData means no associated authenticated data.
	// The result (encryptedPayload) is the ciphertext concatenated with the 16-byte authentication tag.
	encryptedPayload := aesgcm.Seal(nil, nonce, in, nil)
	payloadLen := len(encryptedPayload) // Length of (ciphertext + tag)

	// 4. Format the HTTP header with the correct Content-Length
	httpHeader := fmt.Sprintf(sfHTTPHeaderTemplate, sfNonceLen+payloadLen) // Total length of nonce + encrypted payload
	httpHeaderBytes := []byte(httpHeader)
	headerLen := len(httpHeaderBytes)

	// 5. Calculate total output length
	outLen := headerLen + sfNonceLen + payloadLen
	if len(out) < outLen {
		return 0 // Output buffer too small
	}

	// 6. Copy header, nonce, and encrypted payload to the output buffer
	copy(out[:headerLen], httpHeaderBytes)
	copy(out[headerLen:headerLen+sfNonceLen], nonce)
	copy(out[headerLen+sfNonceLen:outLen], encryptedPayload)

	return outLen
}

// Deobfuscate extracts and decrypts the payload from an HTTP-like obfuscated packet.
// It parses the HTTP header to find the Content-Length and then extracts the nonce
// and encrypted payload for decryption.
// Returns the length of the decrypted data, or 0 if an error occurs (e.g., invalid format, decryption failure).
func (o *StealthFlowObfuscator) Deobfuscate(in, out []byte) int {
	// 1. Find the end of the HTTP header (double CRLF)
	headerEnd := bytes.Index(in, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return 0 // Invalid HTTP header format
	}
	headerEnd += 4 // Include the double CRLF

	// 2. Extract the HTTP header part
	httpHeaderBytes := in[:headerEnd]
	httpHeaderStr := string(httpHeaderBytes)

	// 3. Parse Content-Length from the header
	contentLengthPrefix := "Content-Length: "
	idx := strings.Index(httpHeaderStr, contentLengthPrefix)
	if idx == -1 {
		return 0 // Content-Length header not found
	}
	start := idx + len(contentLengthPrefix)
	end := strings.Index(httpHeaderStr[start:], "\r\n")
	if end == -1 {
		return 0 // Invalid Content-Length line
	}
	contentLengthStr := strings.TrimSpace(httpHeaderStr[start : start+end])
	expectedPayloadLen, err := strconv.Atoi(contentLengthStr)
	if err != nil {
		return 0 // Invalid Content-Length value
	}

	// 4. Check if the remaining input length matches the expected payload length
	actualPayloadStart := headerEnd
	actualPayloadLen := len(in) - actualPayloadStart
	if actualPayloadLen < expectedPayloadLen || expectedPayloadLen < (sfNonceLen+sfTagLen) {
		return 0 // Mismatched length or payload too short for nonce+tag
	}

	// 5. Extract nonce and encrypted payload
	nonce := in[actualPayloadStart : actualPayloadStart+sfNonceLen]
	encryptedPayloadWithTag := in[actualPayloadStart+sfNonceLen : actualPayloadStart+expectedPayloadLen]

	// 6. Derive AES key from PSK
	key := o.sfDeriveKey()
	block, err := aes.NewCipher(key[:sfKeyLen])
	if err != nil {
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	// 7. Decrypt the payload
	// The 'nil' for additionalData means no associated authenticated data.
	// If decryption is successful and the authentication tag is valid, it returns the plaintext.
	// Otherwise, it returns an error (e.g., crypto/chacha20poly1305: message authentication failed).
	decryptedPayload, err := aesgcm.Open(nil, nonce, encryptedPayloadWithTag, nil)
	if err != nil {
		return 0 // Decryption or authentication failed, indicating invalid or tampered packet
	}

	// 8. Copy decrypted data to output buffer
	if len(out) < len(decryptedPayload) {
		return 0 // Output buffer too small for decrypted data
	}
	copy(out[:len(decryptedPayload)], decryptedPayload)

	return len(decryptedPayload)
}

// Ensure StealthFlowObfuscator implements Obfuscator interface
var _ Obfuscator = (*StealthFlowObfuscator)(nil)
