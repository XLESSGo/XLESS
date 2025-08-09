package obfs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/blake2b"
	mrand "math/rand"
	"strings"
	"sync"
	"time"
)

const (
	dnsMinPSKLen = 16
	dnsNonceLen  = 12
	dnsTagLen    = 16
	dnsKeyLen    = 32

	// Max DNS name length is 255. We use a smaller, safe limit for our payload.
	dnsMaxPayloadLen = 100 
	
	// A fixed domain name part to act as a fingerprint
	dnsFingerprintDomain = "obfs.network"
)

// DnsObfuscator implements authenticated encryption with DNS query packet mimicry.
type DnsObfuscator struct {
	PSK []byte
	lk  sync.Mutex
}

// NewDnsObfuscator creates a new DnsObfuscator instance.
func NewDnsObfuscator(psk []byte) (*DnsObfuscator, error) {
	if len(psk) < dnsMinPSKLen {
		return nil, fmt.Errorf("PSK length must be at least %d bytes", dnsMinPSKLen)
	}
	return &DnsObfuscator{
		PSK: psk,
	}, nil
}

// dnsDeriveAESKey derives a 256-bit AES key from the PSK using BLAKE2b.
func (o *DnsObfuscator) dnsDeriveAESKey() []byte {
	return blake2b.Sum256(o.PSK)
}

// encodePayloadToDNSName encodes a payload into a DNS name format with random padding.
func encodePayloadToDNSName(payload []byte) ([]byte, error) {
	if len(payload) > dnsMaxPayloadLen {
		return nil, fmt.Errorf("payload too large for DNS encoding")
	}
	
	// The first label is for our payload.
	// We'll use base64 encoding to support arbitrary bytes.
	// Note: A real implementation would use a safer character set for DNS.
	encodedPayload := fmt.Sprintf("%x", payload)
	
	// Split into DNS labels, max 63 chars each.
	var encodedName bytes.Buffer
	for i := 0; i < len(encodedPayload); i += 60 {
		end := i + 60
		if end > len(encodedPayload) {
			end = len(encodedPayload)
		}
		label := encodedPayload[i:end]
		encodedName.WriteByte(byte(len(label)))
		encodedName.WriteString(label)
	}

	// Add our fixed fingerprint domain as the next label.
	parts := strings.Split(dnsFingerprintDomain, ".")
	for _, part := range parts {
		encodedName.WriteByte(byte(len(part)))
		encodedName.WriteString(part)
	}
	
	encodedName.WriteByte(0x00) // Null terminator
	return encodedName.Bytes(), nil
}

// decodePayloadFromDNSName decodes a payload from a DNS name format.
func decodePayloadFromDNSName(in []byte) ([]byte, error) {
	var hexParts []string
	cursor := 0
	
	// Read our obfuscated labels until the fingerprint domain is found
	parts := strings.Split(dnsFingerprintDomain, ".")
	fingerprintCursor := 0
	
	for cursor < len(in) {
		labelLen := int(in[cursor])
		cursor++
		if labelLen == 0 {
			break
		}
		if cursor+labelLen > len(in) {
			return nil, fmt.Errorf("malformed DNS name label")
		}
		label := string(in[cursor:cursor+labelLen])
		cursor += labelLen
		
		// Check for the fingerprint domain to stop decoding
		if fingerprintCursor < len(parts) && label == parts[fingerprintCursor] {
			fingerprintCursor++
		} else {
			fingerprintCursor = 0
			hexParts = append(hexParts, label)
		}
	}
	
	if fingerprintCursor != len(parts) {
		return nil, fmt.Errorf("fingerprint domain not found")
	}

	hexString := strings.Join(hexParts, "")
	if len(hexString)%2 != 0 {
		return nil, fmt.Errorf("invalid hex string length")
	}
	
	decodedPayload := make([]byte, len(hexString)/2)
	for i := 0; i < len(hexString); i += 2 {
		_, err := fmt.Sscanf(hexString[i:i+2], "%x", &decodedPayload[i/2])
		if err != nil {
			return nil, err
		}
	}
	
	return decodedPayload, nil
}


// Obfuscate wraps the payload in a fake DNS A record query.
func (o *DnsObfuscator) Obfuscate(in, out []byte) int {
	if len(in) == 0 || len(in) > dnsMaxPayloadLen {
		return 0
	}
	
	// 1. Encrypt the payload.
	aesKey := o.dnsDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:dnsKeyLen])
	if err != nil {
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	nonce := make([]byte, dnsNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0
	}
	
	encryptedPayloadWithTag := aesgcm.Seal(nil, nonce, in, nil)
	combinedPayload := append(nonce, encryptedPayloadWithTag...)
	
	// 2. Encode the combined payload into a DNS name.
	encodedName, err := encodePayloadToDNSName(combinedPayload)
	if err != nil {
		return 0
	}
	
	// 3. Build a fake DNS query packet.
	dnsHeader := make([]byte, 12)
	binary.BigEndian.PutUint16(dnsHeader, uint16(mrand.Uint32())) // Dynamic DNS ID
	binary.BigEndian.PutUint16(dnsHeader[2:], 0x0100)             // Flags: Standard Query
	binary.BigEndian.PutUint16(dnsHeader[4:], 0x0001)             // QDCOUNT: 1 question

	qname := encodedName
	qtype := make([]byte, 2)
	binary.BigEndian.PutUint16(qtype, 1) // QTYPE: A record (fixed fingerprint)
	qclass := make([]byte, 2)
	binary.BigEndian.PutUint16(qclass, 1) // QCLASS: IN

	packetLen := 12 + len(qname) + 4
	if len(out) < packetLen {
		return 0
	}
	
	copy(out, dnsHeader)
	copy(out[12:], qname)
	copy(out[12+len(qname):], qtype)
	copy(out[12+len(qname)+2:], qclass)
	
	return packetLen
}

// Deobfuscate extracts and decrypts the payload from a fake DNS packet.
func (o *DnsObfuscator) Deobfuscate(in, out []byte) int {
	if len(in) < 12 {
		return 0
	}
	
	// Find the QNAME section
	qnameStart := 12
	qnameEnd := qnameStart
	for qnameEnd < len(in) && in[qnameEnd] != 0x00 {
		qnameEnd++
	}
	if qnameEnd == len(in) || qnameEnd + 4 > len(in) {
		return 0
	}
	qnameEnd++ // Include null terminator
	
	encodedName := in[qnameStart:qnameEnd]
	
	// Decode the payload from the QNAME
	combinedPayload, err := decodePayloadFromDNSName(encodedName)
	if err != nil {
		return 0
	}
	
	if len(combinedPayload) < dnsNonceLen + dnsTagLen {
		return 0
	}
	
	nonce := combinedPayload[:dnsNonceLen]
	encryptedPayloadWithTag := combinedPayload[dnsNonceLen:]
	
	// Decrypt the payload
	aesKey := o.dnsDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:dnsKeyLen])
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
