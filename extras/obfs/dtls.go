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
	dtlsMinPSKLen = 16
	dtlsNonceLen  = 12
	dtlsTagLen    = 16
	dtlsKeyLen    = 32

	// DTLS record types
	dtlsHandshake = 22
	dtlsAppData   = 23

	// DTLS handshake message types
	dtlsClientHello = 1
	dtlsServerHello = 2

	// DTLS versions
	dtls12 = 0xFEFD
)

// DtlsObfuscator implements a stateful obfuscator that mimics a simplified DTLS handshake.
type DtlsObfuscator struct {
	PSK []byte
	lk  sync.Mutex
	// State machine for send and receive
	sendState int // 0: ClientHello, 1: AppData
	recvState int // 0: ServerHello, 1: AppData
}

// NewDtlsObfuscator creates a new DtlsObfuscator instance.
func NewDtlsObfuscator(psk []byte) (*DtlsObfuscator, error) {
	if len(psk) < dtlsMinPSKLen {
		return nil, fmt.Errorf("PSK length must be at least %d bytes", dtlsMinPSKLen)
	}
	return &DtlsObfuscator{
		PSK:       psk,
		sendState: 0,
		recvState: 0,
	}, nil
}

// dtlsDeriveAESKey derives a 256-bit AES key from the PSK using BLAKE2b.
func (o *DtlsObfuscator) dtlsDeriveAESKey() []byte {
	return blake2b.Sum256(o.PSK)
}

// Obfuscate wraps the payload in a fake DTLS packet based on the current state.
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
	
	encryptedPayloadWithTag := aesgcm.Seal(nil, nonce, in, nil)
	
	var packet []byte
	switch o.sendState {
	case 0: // ClientHello state
		// We embed the payload in the Session ID field.
		sessionIDContent := append(nonce, encryptedPayloadWithTag...)
		
		// Build the ClientHello message
		clientHello := make([]byte, 0, 500)
		clientHello = append(clientHello, dtlsClientHello) // Handshake type
		// Length (placeholder)
		clientHello = append(clientHello, 0x00, 0x00, 0x00) 
		
		// DTLS version (2 bytes)
		binary.BigEndian.PutUint16(clientHello[4:], dtls12)
		
		// Random bytes (32 bytes)
		randomBytes := make([]byte, 32)
		rand.Read(randomBytes)
		clientHello = append(clientHello, randomBytes...)
		
		// Session ID length and content (variable)
		clientHello = append(clientHello, byte(len(sessionIDContent)))
		clientHello = append(clientHello, sessionIDContent...)
		
		// A few fake cipher suites to add to the fingerprint
		clientHello = append(clientHello, 0x00, 0x02) // Cipher suites len
		clientHello = append(clientHello, 0xC0, 0x2B) // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		
		// Add some fake extensions here to make the packet more plausible.
		// This is a simplified example of dynamic padding.
		
		// Backfill the length of the ClientHello message
		binary.BigEndian.PutUint32(clientHello[1:], uint32(len(clientHello)-4))
		
		// Build the full DTLS record
		record := make([]byte, 0, len(clientHello) + 13)
		record = append(record, dtlsHandshake) // Content type
		binary.BigEndian.PutUint16(record[1:], dtls12) // Version
		record = append(record, 0x00, 0x00) // Epoch
		record = append(record, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // Sequence number
		binary.BigEndian.PutUint16(record[11:], uint16(len(clientHello))) // Record length
		record = append(record, clientHello...)
		
		packet = record
		o.sendState = 1 // Transition to AppData state
		
	case 1: // AppData state (post-handshake)
		// Encrypt and send as a normal DTLS Application Data record.
		// The nonce is prepended to the encrypted payload.
		payload := append(nonce, encryptedPayloadWithTag...)
		
		record := make([]byte, 0, len(payload) + 13)
		record = append(record, dtlsAppData) // Content type
		binary.BigEndian.PutUint16(record[1:], dtls12) // Version
		record = append(record, 0x00, 0x01) // Epoch (simple state)
		record = append(record, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // Sequence number
		binary.BigEndian.PutUint16(record[11:], uint16(len(payload))) // Record length
		record = append(record, payload...)
		
		packet = record
	}
	
	if len(out) < len(packet) {
		return 0
	}
	copy(out, packet)
	return len(packet)
}

// Deobfuscate extracts and decrypts the payload from a fake DTLS packet.
func (o *DtlsObfuscator) Deobfuscate(in, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()
	
	if len(in) < 13 {
		return 0
	}
	
	contentType := in[0]
	
	switch o.recvState {
	case 0: // Expecting ServerHello
		if contentType != dtlsHandshake {
			return 0
		}
		// A real implementation would parse the ServerHello and extract parameters.
		// For this simplified example, we transition state without payload extraction.
		o.recvState = 1 // Transition to AppData state
		return 0
	case 1: // Expecting AppData
		if contentType != dtlsAppData {
			return 0
		}
		
		recordLen := binary.BigEndian.Uint16(in[11:13])
		payloadStart := 13
		payloadEnd := payloadStart + int(recordLen)
		
		if len(in) < payloadEnd {
			return 0
		}
		
		payload := in[payloadStart:payloadEnd]
		
		if len(payload) < dtlsNonceLen + dtlsTagLen {
			return 0
		}
		
		nonce := payload[:dtlsNonceLen]
		encryptedPayloadWithTag := payload[dtlsNonceLen:]
		
		// Decrypt the payload
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
	
	return 0
}
