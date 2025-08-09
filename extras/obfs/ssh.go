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
	sshMinPSKLen = 16
	sshNonceLen  = 12
	sshTagLen    = 16
	sshKeyLen    = 32

	// SSH message types used for obfuscation
	sshMsgKexinit = 20
	sshMsgNewkeys = 21

	// Static fake algorithm lists for a plausible SSH fingerprint
	fakeKeyExchangeAlgos = "diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1"
	fakePubkeyAlgos      = "ssh-rsa,ssh-dss"
	fakeCipherAlgos      = "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128"
)

// SshObfuscator implements a stateful obfuscator that mimics a simplified SSH handshake.
type SshObfuscator struct {
	PSK []byte
	lk  sync.Mutex
	// State machine for send and receive
	sendState int // 0: KEXINIT, 1: NEWKEYS
	recvState int // 0: KEXINIT, 1: NEWKEYS
}

// NewSshObfuscator creates a new SshObfuscator instance.
func NewSshObfuscator(psk []byte) (*SshObfuscator, error) {
	if len(psk) < sshMinPSKLen {
		return nil, fmt.Errorf("PSK length must be at least %d bytes", sshMinPSKLen)
	}
	return &SshObfuscator{
		PSK:       psk,
		sendState: 0,
		recvState: 0,
	}, nil
}

// sshDeriveAESKey derives a 256-bit AES key from the PSK using BLAKE2b.
func (o *SshObfuscator) sshDeriveAESKey() []byte {
	return blake2b.Sum256(o.PSK)
}

// Obfuscate wraps the payload in a fake SSH packet based on the current state.
func (o *SshObfuscator) Obfuscate(in, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()

	var packet []byte
	var payloadLen int
	var err error

	if len(in) == 0 {
		return 0
	}

	aesKey := o.sshDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:sshKeyLen])
	if err != nil {
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	nonce := make([]byte, sshNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0
	}

	// Encrypt the payload
	encryptedPayloadWithTag := aesgcm.Seal(nil, nonce, in, nil)

	switch o.sendState {
	case 0: // Send KEXINIT
		// This packet contains the nonce and encrypted data in a dynamic field.
		payload := make([]byte, 16) // Cookie (16 bytes)
		rand.Read(payload)
		
		// This part is the "magic" for obfuscation.
		// We embed the nonce and encrypted payload into a fake algorithm list.
		// A real implementation would use a more sophisticated embedding scheme.
		combinedData := append(nonce, encryptedPayloadWithTag...)

		// Add a fixed algorithm list
		packet = append(packet, []byte(fakeKeyExchangeAlgos)...)
		packet = append(packet, 0x00) // Null terminator for list
		
		// Dynamically add another list containing our payload
		packet = append(packet, byte(len(combinedData)))
		packet = append(packet, combinedData...)
		
		// Add other fake lists to maintain a plausible structure
		packet = append(packet, []byte(fakePubkeyAlgos)...)
		packet = append(packet, 0x00)
		packet = append(packet, []byte(fakeCipherAlgos)...)
		packet = append(packet, 0x00)

		payload = append(payload, packet...)
		payload = append(payload, 0x00) // first_kex_packet_follows (false)
		
		packetLen := len(payload) + 1 + 4 // payload + type + padding length
		
		fullPacket := make([]byte, 4 + packetLen) // Length + packet
		binary.BigEndian.PutUint32(fullPacket, uint32(packetLen))
		fullPacket[4] = byte(len(payload))
		fullPacket[5] = sshMsgKexinit
		copy(fullPacket[6:], payload)
		
		packet = fullPacket
		o.sendState = 1 // Transition to NEWKEYS state

	case 1: // Send encrypted data as an opaque packet (post-handshake)
		// This is a much simpler packet structure.
		// The `in` payload is encrypted and sent directly.
		payload := encryptedPayloadWithTag
		packetLen := len(payload) + 1 + 4 // payload + type + padding length
		
		fullPacket := make([]byte, 4 + packetLen)
		binary.BigEndian.PutUint32(fullPacket, uint32(packetLen))
		fullPacket[4] = byte(mrand.Intn(16) + 4) // Dynamic padding
		fullPacket[5] = sshMsgNewkeys // Use a different message type
		copy(fullPacket[6:], payload)
		
		packet = fullPacket
	}

	if len(out) < len(packet) {
		return 0
	}
	copy(out, packet)
	return len(packet)
}

// Deobfuscate extracts and decrypts the payload from a fake SSH packet.
func (o *SshObfuscator) Deobfuscate(in, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()

	if len(in) < 9 { // Min header size
		return 0
	}

	packetLen := binary.BigEndian.Uint32(in[:4])
	if int(packetLen)+4 != len(in) {
		return 0
	}

	msgType := in[5]

	if o.recvState == 0 && msgType == sshMsgKexinit {
		// Deobfuscate KEXINIT packet
		// This requires reversing the Obfuscate logic to find the embedded data.
		// This is a simplified example, a real one would parse the full packet structure.
		
		// Assuming our combined data is in the second algorithm list
		cursor := 22 + len(fakeKeyExchangeAlgos) // after cookie and first algo list
		combinedDataLen := int(in[cursor])
		combinedDataStart := cursor + 1
		combinedDataEnd := combinedDataStart + combinedDataLen
		
		if len(in) < combinedDataEnd {
			return 0
		}
		
		combinedData := in[combinedDataStart:combinedDataEnd]
		nonce := combinedData[:sshNonceLen]
		encryptedPayloadWithTag := combinedData[sshNonceLen:]
		
		// Decrypt payload
		aesKey := o.sshDeriveAESKey()
		block, err := aes.NewCipher(aesKey[:sshKeyLen])
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
		o.recvState = 1 // Transition to NEWKEYS state
		return len(decryptedPayload)
		
	} else if o.recvState == 1 && msgType == sshMsgNewkeys {
		// Deobfuscate encrypted data packet
		payloadStart := 6
		nonce := in[payloadStart : payloadStart+sshNonceLen]
		encryptedPayloadWithTag := in[payloadStart+sshNonceLen:]
		
		// Decrypt payload
		aesKey := o.sshDeriveAESKey()
		block, err := aes.NewCipher(aesKey[:sshKeyLen])
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
