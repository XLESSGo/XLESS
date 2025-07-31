package hypernova

import (
	"bytes"
	"crypto/rand" // Added for GenerateRandomBytes
	"encoding/binary"
	"fmt"
	"math"
	mrand "math/rand"
	"time" // Added for NTP timestamp generation
)

// Disguise mode identifiers
const (
	ModeDTLSHandshake = 0 // Mimics DTLS ClientHello
	ModeDNSQuery      = 1 // Mimics DNS A record query
	ModeNTPRequest    = 2 // Mimics NTP Request
	ModeGenericUDP    = 3 // Generic UDP packet with random padding
	NumDisguiseModes  = 4 // Total number of disguise modes
)

// Helper function to generate cryptographically secure random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// embedDataIntoVariableLengthField embeds data into a field designed to hold variable length data.
// The data is prefixed with its length. Returns the new byte slice.
func embedDataIntoVariableLengthField(data []byte, fieldLenBytes int) ([]byte, error) {
	if fieldLenBytes != 1 && fieldLenBytes != 2 && fieldLenBytes != 4 {
		return nil, fmt.Errorf("unsupported field length bytes: %d", fieldLenBytes)
	}
	if len(data) > (1<<(fieldLenBytes*8))-1 {
		return nil, fmt.Errorf("data too long for %d-byte length field", fieldLenBytes)
	}

	buf := new(bytes.Buffer)
	lenBytes := make([]byte, fieldLenBytes) // Temporary buffer for length
	switch fieldLenBytes {
	case 1:
		lenBytes[0] = byte(len(data))
	case 2:
		binary.BigEndian.PutUint16(lenBytes, uint16(len(data)))
	case 4:
		binary.BigEndian.PutUint32(lenBytes, uint32(len(data)))
	}
	buf.Write(lenBytes)
	buf.Write(data)
	return buf.Bytes(), nil
}

// extractDataFromVariableLengthField extracts data from a field designed to hold variable length data.
// Returns the extracted data, and the number of bytes consumed from 'in'.
func extractDataFromVariableLengthField(in []byte, fieldLenBytes int) ([]byte, int, error) {
	if len(in) < fieldLenBytes {
		return nil, 0, fmt.Errorf("input too short to read length field (%d bytes)", fieldLenBytes)
	}
	var dataLen int
	switch fieldLenBytes {
	case 1:
		dataLen = int(in[0])
	case 2:
		dataLen = int(binary.BigEndian.Uint16(in[0:2]))
	case 4:
		dataLen = int(binary.BigEndian.Uint32(in[0:4]))
	default:
		return nil, 0, fmt.Errorf("unsupported field length bytes: %d", fieldLenBytes)
	}

	totalConsumed := fieldLenBytes + dataLen
	if len(in) < totalConsumed {
		return nil, 0, fmt.Errorf("input truncated: declared length %d, but only %d bytes available", dataLen, len(in)-fieldLenBytes)
	}
	return in[fieldLenBytes:totalConsumed], totalConsumed, nil
}

// --- Mode: DTLS Handshake Mimicry ---

const (
	dtlsRecordHeaderLen = 13   // Type (1) + Version (2) + Epoch (2) + Sequence Number (6) + Length (2)
	dtlsHandshakeType   = 22   // Handshake
	dtlsVersionTLS12    = 0xFEFD // DTLS 1.2 version
	dtlsClientHelloType = 0x01   // ClientHello message type
	dtlsMinHandshakeLen = 12   // Min ClientHello message len (MsgType+Len+Seq+FragOff+FragLen+Version+Random+SessionIDLen...)
)

// ObfuscateModeDTLSHandshake crafts a packet that mimics a DTLS ClientHello.
// It embeds stateToken, nonce, and encryptedPayload within the DTLS structure.
func ObfuscateModeDTLSHandshake(randSrc *mrand.Rand, stateToken, nonce, encryptedPayload []byte, sequenceNumber uint64, out []byte) int {
	// Total data to embed: State Token + Nonce + Encrypted Payload
	embeddedCoreData := append(stateToken, nonce...)
	embeddedCoreData = append(embeddedCoreData, encryptedPayload...)

	paddingLen := randSrc.Intn(MaxDynamicPadding-MinDynamicPadding+1) + MinDynamicPadding
	randomPadding, err := GenerateRandomBytes(paddingLen)
	if err != nil {
		return 0 // Failed to generate random padding
	}
	
	finalEmbeddedData := append(embeddedCoreData, randomPadding...)

	dtlsMsgBuf := new(bytes.Buffer)
	
	dtlsMsgBuf.WriteByte(dtlsClientHelloType) // Handshake Type: ClientHello
	
	// Placeholder for Handshake Message Length (3 bytes) - will be filled later
	dtlsMsgBuf.Write([]byte{0x00, 0x00, 0x00}) 

	binary.BigEndian.PutUint16(dtlsMsgBuf.Bytes()[dtlsMsgBuf.Len():], 0) // Message Sequence (0 for first)
	dtlsMsgBuf.Write([]byte{0x00, 0x00}) // Advance buffer
	dtlsMsgBuf.Write([]byte{0x00, 0x00, 0x00}) // Fragment Offset (0)
	dtlsMsgBuf.Write([]byte{0x00, 0x00, 0x00}) // Fragment Length (placeholder)

	binary.BigEndian.PutUint16(dtlsMsgBuf.Bytes()[dtlsMsgBuf.Len():], 0x0303) // TLS Version 1.2
	dtlsMsgBuf.Write([]byte{0x00, 0x00}) // Advance buffer

	// Random bytes (32 bytes) - can embed some data here
	randomBytes := make([]byte, 32)
	randSrc.Read(randomBytes)
	copy(randomBytes[0:min(len(randomBytes), len(finalEmbeddedData))], finalEmbeddedData) // Embed data into random
	dtlsMsgBuf.Write(randomBytes)

	dtlsMsgBuf.WriteByte(0x00) // Session ID Length (0)

	// Cipher Suites (example, common ones)
	cipherSuites := []byte{
		0xC0, 0x2B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0xC0, 0x2F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0x00, 0x9C, // TLS_RSA_WITH_AES_128_GCM_SHA256
	}
	binary.BigEndian.PutUint16(dtlsMsgBuf.Bytes()[dtlsMsgBuf.Len():], uint16(len(cipherSuites)))
	dtlsMsgBuf.Write([]byte{0x00, 0x00}) // Advance buffer
	dtlsMsgBuf.Write(cipherSuites)

	dtlsMsgBuf.WriteByte(0x01) // Compression Methods Length (1)
	dtlsMsgBuf.WriteByte(0x00) // Compression Method: Null (0)

	// Extensions (placeholder, for simplicity)
	dtlsMsgBuf.Write([]byte{0x00, 0x00}) // Extensions Length (0)

	handshakeMsgPayload := dtlsMsgBuf.Bytes()
	// Fill handshake message length
	binary.BigEndian.PutUint32(handshakeMsgPayload[1:4], uint32(len(handshakeMsgPayload)-1)) // Total length after MsgType
	binary.BigEndian.PutUint32(handshakeMsgPayload[9:12], uint32(len(handshakeMsgPayload)-1)) // Fragment Length

	// DTLS Record Header
	recordLen := len(handshakeMsgPayload)
	if recordLen > math.MaxUint16 {
		return 0 // DTLS record too large
	}

	packet := make([]byte, dtlsRecordHeaderLen+recordLen)
	packet[0] = dtlsHandshakeType // Record Type: Handshake
	binary.BigEndian.PutUint16(packet[1:3], dtlsVersionTLS12) // DTLS Version 1.2
	binary.BigEndian.PutUint16(packet[3:5], 0) // Epoch (0)
	// Sequence Number (6 bytes) - simplified, usually derived from connection state
	binary.BigEndian.PutUint32(packet[5:9], randSrc.Uint32()) // Just random for obfuscation
	binary.BigEndian.PutUint16(packet[11:13], uint16(recordLen)) // Length of handshake message

	copy(packet[dtlsRecordHeaderLen:], handshakeMsgPayload)

	if len(out) < len(packet) {
		return 0 // Output buffer too small
	}
	copy(out, packet)
	return len(packet)
}

// DeobfuscateModeDTLSHandshake extracts embedded data from a packet mimicking a DTLS ClientHello.
func DeobfuscateModeDTLSHandshake(in []byte, expectedSequenceNumber uint64) ([]byte, []byte, []byte, error) {
	if len(in) < dtlsRecordHeaderLen + dtlsMinHandshakeLen {
		return nil, nil, nil, fmt.Errorf("DTLS handshake packet too short")
	}

	if in[0] != dtlsHandshakeType {
		return nil, nil, nil, fmt.Errorf("incorrect DTLS record type: 0x%X, expected 0x%X", in[0], dtlsHandshakeType)
	}
	if binary.BigEndian.Uint16(in[1:3]) != dtlsVersionTLS12 {
		return nil, nil, nil, 0, fmt.Errorf("DTLS version mismatch: 0x%X, expected 0x%X", binary.BigEndian.Uint16(in[1:3]), dtlsVersionTLS12)
	}
	recordLen := int(binary.BigEndian.Uint16(in[11:13]))
	
	totalPacketLen := dtlsRecordHeaderLen + recordLen
	if len(in) < totalPacketLen {
		return nil, nil, nil, 0, fmt.Errorf("DTLS record truncated: header says %d bytes, but only %d available", recordLen, len(in)-dtlsRecordHeaderLen)
	}

	dtlsHandshakeMsg := in[dtlsRecordHeaderLen:totalPacketLen]

	if dtlsHandshakeMsg[0] != dtlsClientHelloType {
		return nil, nil, nil, 0, fmt.Errorf("DTLS handshake message type incorrect: 0x%X, expected ClientHello 0x%X", dtlsHandshakeMsg[0], dtlsClientHelloType)
	}

	// Extract data from the random field of ClientHello (simplified)
	// This assumes data was embedded at the start of the 32-byte random field
	if len(dtlsHandshakeMsg) < dtlsMinHandshakeLen + 32 {
		return nil, nil, nil, 0, fmt.Errorf("DTLS ClientHello too short to extract embedded data")
	}
	extractedEmbeddedData := dtlsHandshakeMsg[14 : 14 + 32] // Taking the whole random for simplicity, assuming data is at the beginning

	if len(extractedEmbeddedData) < StateTokenLen+NonceLen+TagLen { // At least enough for core parts
		return nil, nil, nil, fmt.Errorf("embedded data too short for state token, nonce, and tag")
	}

	stateToken := extractedEmbeddedData[0:StateTokenLen]
	currentEmbeddedOffset := StateTokenLen

	nonce := extractedEmbeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	encryptedPayloadWithTag := extractedEmbeddedData[currentEmbeddedOffset:]

	return stateToken, nonce, encryptedPayloadWithTag, nil
}


// --- Mode: DNS Query Mimicry ---

const (
	dnsHeaderLen      = 12 // ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
	dnsQuestionMinLen = 4  // QNAME (min 1 byte for root) + QTYPE (2) + QCLASS (2) = 5 (but QNAME can be compressed, for simplicity min 4 here)
	dnsARecordType    = 0x0001 // A record
	dnsINClass        = 0x0001 // IN class
	// dnsMinPacketLen   = dnsHeaderLen + dnsQuestionMinLen + StateTokenLen + NonceLen + TagLen // Rough minimum
)

// ObfuscateModeDNSQuery crafts a packet that mimics a DNS A record query.
// It embeds stateToken, nonce, and encryptedPayload.
func ObfuscateModeDNSQuery(randSrc *mrand.Rand, stateToken, nonce, encryptedPayload []byte, sequenceNumber uint64, out []byte) int {
	// Total data to embed: State Token + Nonce + Encrypted Payload
	embeddedData := append(stateToken, nonce...)
	embeddedData = append(embeddedData, encryptedPayload...)

	// Generate a plausible DNS ID using sequence number
	dnsID := uint16(sequenceNumber % 65535)

	// Flags: Standard query, recursion desired
	dnsFlags := uint16(0x0100) // QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0

	// QDCOUNT: 1 question
	qdCount := uint16(1)

	// QNAME: Create a fake domain name (e.g., based on time or random bytes)
	// Example: random-subdomain.example.com
	subdomainLen := randSrc.Intn(10) + 5 // 5-14 chars
	subdomain := make([]byte, subdomainLen)
	for i := 0; i < subdomainLen; i++ {
		subdomain[i] = byte(randSrc.Intn(26) + 'a') // Random lowercase letters
	}
	qName := []byte{}
	qName = append(qName, byte(len(subdomain)))
	qName = append(qName, subdomain...)
	qName = append(qName, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}...) // example.com, null terminator

	// Embed part of embeddedData into QNAME padding/randomness (if any)
	if len(embeddedData) > 0 {
		qName = qName[:len(qName)-1] // Remove null terminator for now
		qName = append(qName, embeddedData...) // Append embedded data
		qName = append(qName, 0x00) // Re-add null terminator
		embeddedData = []byte{} // All embedded now
	}

	// QTYPE: A record
	qType := uint16(dnsARecordType)
	// QCLASS: IN
	qClass := uint16(dnsINClass)

	// Assemble DNS Header
	dnsHeaderBytes := make([]byte, dnsHeaderLen) // Create a fixed-size buffer
	binary.BigEndian.PutUint16(dnsHeaderBytes[0:2], dnsID)
	binary.BigEndian.PutUint16(dnsHeaderBytes[2:4], dnsFlags)
	binary.BigEndian.PutUint16(dnsHeaderBytes[4:6], qdCount) // QDCOUNT
	binary.BigEndian.PutUint16(dnsHeaderBytes[6:8], 0)       // ANCOUNT
	binary.BigEndian.PutUint16(dnsHeaderBytes[8:10], 0)      // NSCOUNT
	binary.BigEndian.PutUint16(dnsHeaderBytes[10:12], 0)     // ARCOUNT

	// Assemble DNS Question
	dnsQuestionBuf := new(bytes.Buffer)
	dnsQuestionBuf.Write(qName)
	qTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(qTypeBytes, qType)
	dnsQuestionBuf.Write(qTypeBytes) // Write QTYPE
	qClassBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(qClassBytes, qClass)
	dnsQuestionBuf.Write(qClassBytes) // Write QCLASS
	dnsQuestion := dnsQuestionBuf.Bytes()

	totalOutputLen := dnsHeaderLen + len(dnsQuestion)
	if len(out) < totalOutputLen {
		return 0
	}

	outCursor := 0
	copy(out[outCursor:], dnsHeaderBytes)
	outCursor += len(dnsHeaderBytes)
	copy(out[outCursor:], dnsQuestion)
	outCursor += len(dnsQuestion)

	return totalOutputLen
}

// DeobfuscateModeDNSQuery parses a packet mimicking a DNS A record query.
func DeobfuscateModeDNSQuery(in []byte, expectedSequenceNumber uint64) ([]byte, []byte, []byte, error) {
	if len(in) < dnsHeaderLen+dnsQuestionMinLen {
		return nil, nil, nil, fmt.Errorf("DNS packet too short")
	}

	// Parse DNS Header
	// dnsID := binary.BigEndian.Uint16(in[0:2]) // Could verify sequence number here
	// dnsFlags := binary.BigEndian.Uint16(in[2:4]) // Could verify flags
	qdCount := binary.BigEndian.Uint16(in[4:6])
	if qdCount != 1 {
		return nil, nil, nil, fmt.Errorf("DNS QDCOUNT not 1")
	}

	currentOffset := dnsHeaderLen
	
	// Parse QNAME
	qNameBuf := bytes.NewBuffer(in[currentOffset:])
	var embeddedData []byte
	for {
		if qNameBuf.Len() == 0 {
			return nil, nil, nil, fmt.Errorf("DNS QNAME truncated")
		}
		labelLen := int(qNameBuf.Next(1)[0])
		if labelLen == 0 { // Null terminator
			break
		}
		if qNameBuf.Len() < labelLen {
			return nil, nil, nil, fmt.Errorf("DNS QNAME label truncated")
		}
		label := qNameBuf.Next(labelLen)
		embeddedData = append(embeddedData, label...) // Collect labels as embedded data
	}
	
	// Remove known part ("example.com" if it exists)
	exampleCom := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm'}
	if bytes.HasSuffix(embeddedData, exampleCom) {
		embeddedData = embeddedData[:len(embeddedData)-len(exampleCom)]
	}

	// Skip QTYPE and QCLASS
	if qNameBuf.Len() < 4 { return nil, nil, nil, fmt.Errorf("DNS QTYPE/QCLASS truncated") }
	// qType := binary.BigEndian.Uint16(qNameBuf.Next(2))
	// qClass := binary.BigEndian.Uint16(qNameBuf.Next(2))

	// Extract State Token, Nonce, Encrypted Payload from embeddedData
	if len(embeddedData) < StateTokenLen+NonceLen+TagLen {
		return nil, nil, nil, fmt.Errorf("embedded data too short for state token, nonce, and tag")
	}

	stateToken := embeddedData[0:StateTokenLen]
	currentEmbeddedOffset := StateTokenLen

	nonce := embeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	encryptedPayloadWithTag := embeddedData[currentEmbeddedOffset:]

	return stateToken, nonce, encryptedPayloadWithTag, nil
}


// --- Mode: NTP Request Mimicry ---

const (
	ntpPacketLen   = 48
	ntpEmbedOffset = 16 // Offset where data is embedded in NTP packet
)

// ObfuscateModeNTPRequest crafts a packet that mimics an NTP request.
// It embeds stateToken, nonce, and encryptedPayload.
func ObfuscateModeNTPRequest(randSrc *mrand.Rand, stateToken, nonce, encryptedPayload []byte, sequenceNumber uint64, out []byte) int {
	embeddedCoreData := make([]byte, 0, len(stateToken)+len(nonce)+len(encryptedPayload))
	embeddedCoreData = append(embeddedCoreData, stateToken...)
	embeddedCoreData = append(embeddedCoreData, nonce...)
	embeddedCoreData = append(embeddedCoreData, encryptedPayload...)

	packet := make([]byte, ntpPacketLen)

	// NTP header fields (simplified for obfuscation)
	packet[0] = 0b00_011_011 // LI (00), VN (011), Mode (011 - Client)
	packet[1] = 0            // Stratum (unspecified)
	packet[2] = byte(randSrc.Intn(10) + 4) // Poll (4-13)
	packet[3] = byte(randSrc.Intn(5) - 20) // Precision (-20 to -16)

	// Root Delay (4 bytes)
	binary.BigEndian.PutUint32(packet[4:8], randSrc.Uint32())
	// Root Dispersion (4 bytes)
	binary.BigEndian.PutUint32(packet[8:12], randSrc.Uint32())

	// Reference ID (4 bytes) - can be random
	binary.BigEndian.PutUint32(packet[12:16], randSrc.Uint32())

	// Embed data into the rest of the packet, starting from ntpEmbedOffset
	availableSpace := ntpPacketLen - ntpEmbedOffset

	if len(embeddedCoreData) > availableSpace {
		return 0 // Embedded data too large for NTP packet available space
	}

	copy(packet[ntpEmbedOffset:], embeddedCoreData)

	// Fill remaining space with random padding
	remainingSpace := availableSpace - len(embeddedCoreData)
	if remainingSpace > 0 {
		randomPadding, err := GenerateRandomBytes(remainingSpace)
		if err != nil {
			return 0 // Failed to generate random bytes for NTP padding
		}
		copy(packet[ntpEmbedOffset+len(embeddedCoreData):], randomPadding)
	}
	
	if len(out) < len(packet) {
		return 0 // Output buffer too small
	}
	copy(out, packet)
	return len(packet)
}

// DeobfuscateModeNTPRequest extracts embedded data from a packet mimicking an NTP request.
func DeobfuscateModeNTPRequest(in []byte, expectedSequenceNumber uint64) ([]byte, []byte, []byte, error) {
	if len(in) != ntpPacketLen {
		return nil, nil, nil, fmt.Errorf("NTP packet has incorrect length: %d, expected %d", len(in), ntpPacketLen)
	}

	// Basic NTP header check (LI, VN, Mode)
	if (in[0] & 0b11_111_111) != 0b00_011_011 {
		return nil, nil, nil, fmt.Errorf("NTP header mismatch: 0x%X", in[0])
	}

	embeddedData := in[ntpEmbedOffset:]

	if len(embeddedData) < StateTokenLen+NonceLen+TagLen { // At least enough for core parts
		return nil, nil, nil, fmt.Errorf("embedded data too short for state token, nonce, and tag")
	}

	stateToken := embeddedData[0:StateTokenLen]
	currentEmbeddedOffset := StateTokenLen

	nonce := embeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	encryptedPayloadWithTag := embeddedData[currentEmbeddedOffset:]

	return stateToken, nonce, encryptedPayloadWithTag, nil
}


// --- Mode: Generic UDP Packet ---

const (
	genericUDPHeaderLen = 4 // Simple length prefix for the payload
)

// ObfuscateModeGenericUDP creates a generic UDP packet with embedded data and random padding.
// It's a fallback or a simple, high-entropy mode.
func ObfuscateModeGenericUDP(randSrc *mrand.Rand, stateToken, nonce, encryptedPayload []byte, sequenceNumber uint64, out []byte) int {
	embeddedCoreData := append(stateToken, nonce...)
	embeddedCoreData = append(embeddedCoreData, encryptedPayload...)

	// Add random padding to the embedded data
	paddingLen := randSrc.Intn(MaxDynamicPadding-MinDynamicPadding+1) + MinDynamicPadding
	randomPadding, err := GenerateRandomBytes(paddingLen)
	if err != nil {
		return 0 // Failed to generate random padding
	}
	finalEmbeddedData := append(embeddedCoreData, randomPadding...)

	// Prepend a length field for the final embedded data
	totalPayloadLen := len(finalEmbeddedData)
	if totalPayloadLen > math.MaxUint32 { // Ensure it fits in 4 bytes
		return 0 // Payload too large
	}

	packet := make([]byte, genericUDPHeaderLen+totalPayloadLen)
	binary.BigEndian.PutUint32(packet[0:genericUDPHeaderLen], uint32(totalPayloadLen))
	copy(packet[genericUDPHeaderLen:], finalEmbeddedData)

	if len(out) < len(packet) {
		return 0 // Output buffer too small
	}
	copy(out, packet)
	return len(packet)
}

// DeobfuscateModeGenericUDP extracts embedded data from a generic UDP packet.
func DeobfuscateModeGenericUDP(in []byte, expectedSequenceNumber uint64) ([]byte, []byte, []byte, error) {
	if len(in) < genericUDPHeaderLen {
		return nil, nil, nil, fmt.Errorf("generic UDP packet too short for header")
	}

	totalPayloadLen := int(binary.BigEndian.Uint32(in[0:genericUDPHeaderLen]))
	if len(in)-genericUDPHeaderLen < totalPayloadLen {
		return nil, nil, nil, fmt.Errorf("generic UDP packet truncated: header says %d bytes, but only %d available", totalPayloadLen, len(in)-genericUDPHeaderLen)
	}

	embeddedData := in[genericUDPHeaderLen : genericUDPHeaderLen+totalPayloadLen]

	if len(embeddedData) < StateTokenLen+NonceLen+TagLen { // At least enough for core parts
		return nil, nil, nil, fmt.Errorf("embedded data too short for state token, nonce, and tag")
	}

	stateToken := embeddedData[0:StateTokenLen]
	currentEmbeddedOffset := StateTokenLen

	nonce := embeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	encryptedPayloadWithTag := embeddedData[currentEmbeddedOffset:]

	return stateToken, nonce, encryptedPayloadWithTag, nil
}

// min helper function (Go 1.20+ has built-in min, but for older versions or explicit, define it)
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
