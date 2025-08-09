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
	"time" // Added time import for math/rand seed
)

const (
	dnsMinPSKLen = 16 // Minimum PSK length for AES-256 key derivation
	dnsNonceLen  = 12 // AES-GCM nonce length
	dnsTagLen    = 16 // AES-GCM authentication tag length
	dnsKeyLen    = 32 // AES-256 key length (from BLAKE2b-256 hash)

	// Max random padding for various sections of the DNS packet.
	dnsMaxQuestionNameLen = 128
	dnsMaxPayloadLen      = 512
)

// DnsObfuscator is an obfuscator that mimics a DNS A record query.
// It embeds the encrypted payload into the DNS question section.
type DnsObfuscator struct {
	PSK []byte // Pre-shared key for AES key derivation
	lk  sync.Mutex
	// Use math/rand for non-cryptographic randomness (padding lengths, IDs)
	randSrc *mrand.Rand
}

// NewDnsObfuscator creates a new DnsObfuscator instance.
func NewDnsObfuscator(psk []byte) (*DnsObfuscator, error) {
	if len(psk) < dnsMinPSKLen {
		return nil, fmt.Errorf("PSK length must be at least %d bytes", dnsMinPSKLen)
	}
	return &DnsObfuscator{
		PSK:     psk,
		randSrc: mrand.New(mrand.NewSource(time.Now().UnixNano())),
	}, nil
}

// dnsDeriveAESKey derives a 256-bit AES key from the PSK using BLAKE2b.
func (o *DnsObfuscator) dnsDeriveAESKey() []byte {
	key := blake2b.Sum256(o.PSK)
	// blake2b.Sum256 returns an array, so we need to slice it to return []byte
	return key[:]
}

// Obfuscate wraps the payload in a fake DNS query.
func (o *DnsObfuscate) Obfuscate(in, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()

	// 1. Encrypt payload
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
	payloadWithNonceAndTag := append(nonce, encryptedPayloadWithTag...)

	// 2. Pad the payload with random data to mimic a plausible DNS query name length
	paddingLen := o.randSrc.Intn(dnsMaxQuestionNameLen-len(payloadWithNonceAndTag)) + 1
	padding := make([]byte, paddingLen)
	if _, err := rand.Read(padding); err != nil {
		return 0
	}
	obfuscatedName := append(payloadWithNonceAndTag, padding...)

	// 3. Split the name into labels for DNS format (e.g., "label1.label2.com")
	// This is a simplified approach for demonstration. A real-world version
	// would need to handle this more robustly.
	domain := "example.com"
	domainLabels := strings.Split(domain, ".")
	dnsLabels := [][]byte{}
	dnsLabels = append(dnsLabels, obfuscatedName) // Embed obfuscated data as a single long label
	for _, label := range domainLabels {
		dnsLabels = append(dnsLabels, []byte(label))
	}

	// 4. Build the DNS query packet
	packet := new(bytes.Buffer)
	// Header (12 bytes)
	binary.BigEndian.PutUint16(packet.Bytes(), uint16(o.randSrc.Intn(0xFFFF))) // ID
	packet.WriteByte(0x01) // Flags (QR=0, Opcode=0, AA=0, TC=0, RD=1)
	packet.WriteByte(0x00)
	binary.BigEndian.PutUint16(packet.Bytes()[4:], 1) // QDCOUNT (1 question)
	binary.BigEndian.PutUint16(packet.Bytes()[6:], 0) // ANCOUNT
	binary.BigEndian.PutUint16(packet.Bytes()[8:], 0) // NSCOUNT
	binary.BigEndian.PutUint16(packet.Bytes()[10:], 0) // ARCOUNT

	// Question Section
	for _, label := range dnsLabels {
		packet.WriteByte(byte(len(label))) // Label length
		packet.Write(label)
	}
	packet.WriteByte(0x00) // Null terminator for the question name
	binary.BigEndian.PutUint16(packet.Bytes(), 0x0001) // QTYPE: A (Host Address)
	binary.BigEndian.PutUint16(packet.Bytes(), 0x0001) // QCLASS: IN (Internet)

	if len(out) < packet.Len() {
		return 0
	}
	copy(out, packet.Bytes())
	return packet.Len()
}

// Deobfuscate extracts the encrypted payload from a fake DNS query and decrypts it.
func (o *DnsObfuscate) Deobfuscate(in, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()
	// This is a simplified deobfuscation process. A real implementation
	// would need robust DNS parsing.

	// 1. Assume the obfuscated data is in the first question's name field.
	// This requires knowing the structure of the forged packet.
	dnsHeaderLen := 12
	if len(in) < dnsHeaderLen {
		return 0
	}

	// Skip header and read the first label's length and data
	offset := dnsHeaderLen
	if len(in) < offset+1 {
		return 0
	}
	firstLabelLen := int(in[offset])
	offset++

	if len(in) < offset+firstLabelLen {
		return 0
	}
	payloadWithNonceAndTagAndPadding := in[offset : offset+firstLabelLen]

	// 2. Separate payload, nonce, tag, and padding
	if len(payloadWithNonceAndTagAndPadding) < dnsNonceLen+dnsTagLen {
		return 0
	}
	
	// A simple heuristic to find the end of the encrypted payload is to search for a null byte or
	// some other marker. For this example, we'll assume there is no padding at the end of the payload.
	// We'll just take the whole "label" as the encrypted content + nonce + tag.
	// In a real implementation, you'd need a more robust way to signal length.
	
	nonce := payloadWithNonceAndTagAndPadding[:dnsNonceLen]
	encryptedPayloadWithTag := payloadWithNonceAndTagAndPadding[dnsNonceLen:]
	
	// 3. Decrypt the payload
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
		return 0 // Decryption or authentication failed
	}

	if len(out) < len(decryptedPayload) {
		return 0
	}
	copy(out, decryptedPayload)
	return len(decryptedPayload)
}
