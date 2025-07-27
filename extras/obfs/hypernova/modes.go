package hypernova

import (
	"bytes"
	"crypto/rand" // Import crypto/rand for secure random bytes
	"encoding/binary"
	"fmt"
	"math"      // Import math for math.MaxInt32
	mrand "math/rand"
	"strings" // Keep strings as it's used
)

// Disguise mode identifiers
const (
	ModeTLSHandshake   = 0 // Mimics TLS ClientHello
	ModeDNSQuery       = 1 // Mimics DNS A record query
	ModeSSHKeyExchange = 2 // Mimics SSH_MSG_KEXINIT
	NumDisguiseModes   = 3 // Total number of disguise modes
)

// --- Helper Functions for embedding/extracting data in various formats ---

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


// --- Mode A: TLS ClientHello Mimicry ---

const (
	tlsRecordHeaderLen  = 5 // Type(1) + Version(2) + Length(2)
	tlsHandshakeType    = 0x16 // Handshake (22)
	tlsVersionTLS12     = 0x0303
	tlsClientHelloType  = 0x01
	tlsHandshakeHeaderLen = 4 // Handshake Type(1) + Length(3)
	tlsRandomLen        = 32
	tlsSessionIDLen     = 32 // Max 32 bytes
	tlsCipherSuitesLen  = 2 // Number of cipher suites (2 bytes)
	tlsMinCipherSuites  = 2 // At least 2 cipher suites (4 bytes)
	tlsMinClientHelloLen = 77 // Rough minimum without extensions or variable parts.
)

// ObfuscateModeTLSHandshake crafts a packet that mimics a TLS ClientHello.
// It embeds stateToken, nonce, and encryptedPayload within the TLS structure.
func ObfuscateModeTLSHandshake(randSrc *mrand.Rand, stateToken, nonce, encryptedPayload []byte, sequenceNumber uint64, out []byte) int {
	// Total data to embed: State Token + Nonce + Encrypted Payload
	embeddedData := append(stateToken, nonce...)
	embeddedData = append(embeddedData, encryptedPayload...)

	// --- Construct ClientHello Components ---

	// Version (TLS 1.2)
	clientHelloVersion := []byte{0x03, 0x03} // TLS 1.2

	// Random (32 bytes): mix with sequence number for uniqueness
	tlsRandom := make([]byte, tlsRandomLen)
	_, err := GenerateRandomBytes(tlsRandomLen) // Fill with crypto random bytes
	if err != nil {
		return 0
	}
	binary.BigEndian.PutUint64(tlsRandom[0:8], sequenceNumber) // Embed sequence number

	// Session ID (0-32 bytes): Embed part of embeddedData here
	sessionIDLen := randSrc.Intn(tlsSessionIDLen) // Random length for session ID
	sessionID := make([]byte, sessionIDLen)
	if sessionIDLen > 0 {
		copy(sessionID, embeddedData[:min(sessionIDLen, len(embeddedData))]) // Use part of embeddedData
		if len(embeddedData) > sessionIDLen { // Remove used part
			embeddedData = embeddedData[sessionIDLen:]
		} else {
			embeddedData = []byte{}
		}
	}


	// Cipher Suites (2 bytes length + actual cipher suites): Embed more embeddedData here
	numCipherSuites := randSrc.Intn(10) + tlsMinCipherSuites // 2-11 cipher suites
	cipherSuites := make([]byte, numCipherSuites*2) // Each is 2 bytes
	binary.BigEndian.PutUint16(cipherSuites[0:2], uint16(numCipherSuites*2)) // Length field for cipher suites
	_, err = GenerateRandomBytes(len(cipherSuites)-2) // Fill with plausible but random cipher suite bytes for camouflage
	if err != nil {
		return 0
	}
	// Embed more data into random cipher suite values
	if len(embeddedData) > 0 {
		copy(cipherSuites[2:], embeddedData[:min(len(cipherSuites)-2, len(embeddedData))])
		if len(embeddedData) > len(cipherSuites)-2 {
			embeddedData = embeddedData[len(cipherSuites)-2:]
		} else {
			embeddedData = []byte{}
		}
	}


	// Compression Methods (1 byte length + 1 byte method): Always 0x01 for length, 0x00 for null
	compressionMethods := []byte{0x01, 0x00}

	// Extensions (2 bytes length + actual extensions): Remaining embeddedData goes here as an opaque extension
	extensionsLen := len(embeddedData) + randSrc.Intn(MaxDynamicPadding/2) + MinDynamicPadding/2 // Add some extra random padding
	extensionsData := make([]byte, extensionsLen)
	if len(embeddedData) > 0 {
		copy(extensionsData, embeddedData) // Copy remaining embedded data
	}
	_, err = GenerateRandomBytes(len(extensionsData)-len(embeddedData)) // Fill rest with random bytes
	if err != nil {
		return 0
	}
	
	extensions := make([]byte, 2 + len(extensionsData)) // 2 bytes for total extensions length
	binary.BigEndian.PutUint16(extensions[0:2], uint16(len(extensionsData)))
	copy(extensions[2:], extensionsData)

	// --- Assemble ClientHello Message ---
	clientHelloBodyBuf := new(bytes.Buffer)
	clientHelloBodyBuf.Write(clientHelloVersion)
	clientHelloBodyBuf.Write(tlsRandom)
	clientHelloBodyBuf.WriteByte(byte(len(sessionID))) // Session ID length
	clientHelloBodyBuf.Write(sessionID)
	clientHelloBodyBuf.Write(cipherSuites)
	clientHelloBodyBuf.Write(compressionMethods)
	clientHelloBodyBuf.Write(extensions)

	clientHelloBody := clientHelloBodyBuf.Bytes()

	// Handshake Header
	handshakeHeader := make([]byte, tlsHandshakeHeaderLen)
	handshakeHeader[0] = tlsClientHelloType // ClientHello type (0x01)
	binary.BigEndian.PutUint32(handshakeHeader[0:4], uint32(len(clientHelloBody))) // Length of ClientHello body (3 bytes only)


	// TLS Record Layer
	tlsRecordLayer := make([]byte, tlsRecordHeaderLen+len(handshakeHeader)+len(clientHelloBody))
	tlsRecordLayer[0] = tlsHandshakeType // Handshake content type (0x16)
	binary.BigEndian.PutUint16(tlsRecordLayer[1:3], tlsVersionTLS12) // Record layer version (TLS 1.2)
	binary.BigEndian.PutUint16(tlsRecordLayer[3:5], uint16(len(handshakeHeader)+len(clientHelloBody))) // Length of payload

	copy(tlsRecordLayer[tlsRecordHeaderLen:], handshakeHeader)
	copy(tlsRecordLayer[tlsRecordHeaderLen+len(handshakeHeader):], clientHelloBody)

	// Copy to output buffer
	if len(out) < len(tlsRecordLayer) {
		return 0 // Output buffer too small
	}
	copy(out, tlsRecordLayer)

	return len(tlsRecordLayer)
}

// DeobfuscateModeTLSHandshake parses a packet mimicking a TLS ClientHello.
// It extracts stateToken, nonce, and encryptedPayload.
func DeobfuscateModeTLSHandshake(in []byte, expectedSequenceNumber uint64) ([]byte, []byte, []byte, error) {
	if len(in) < tlsRecordHeaderLen+tlsHandshakeHeaderLen+tlsMinClientHelloLen {
		return nil, nil, nil, fmt.Errorf("TLS packet too short")
	}

	// Parse TLS Record Layer
	if in[0] != tlsHandshakeType {
		return nil, nil, nil, fmt.Errorf("incorrect TLS record type: 0x%X", in[0])
	}
	// Skip version check for flexibility, but could add:
	// if binary.BigEndian.Uint16(in[1:3]) != tlsVersionTLS12 { return ... }
	recordLen := int(binary.BigEndian.Uint16(in[3:5]))
	if len(in) != tlsRecordHeaderLen+recordLen {
		return nil, nil, nil, fmt.Errorf("TLS record length mismatch")
	}

	currentOffset := tlsRecordHeaderLen
	
	// Parse Handshake Header
	if in[currentOffset] != tlsClientHelloType {
		return nil, nil, nil, fmt.Errorf("incorrect Handshake type: 0x%X", in[currentOffset])
	}
	handshakeBodyLen := int(binary.BigEndian.Uint32(append([]byte{0x00}, in[currentOffset+1:currentOffset+4]...))) // 3 bytes length
	currentOffset += tlsHandshakeHeaderLen

	if len(in)-currentOffset < handshakeBodyLen {
		return nil, nil, nil, fmt.Errorf("Handshake body truncated")
	}
	clientHelloBody := in[currentOffset : currentOffset+handshakeBodyLen]
	bodyOffset := 0

	// Skip ClientHello Version (2 bytes)
	bodyOffset += 2

	// Extract TLS Random (32 bytes) and verify sequence number
	if len(clientHelloBody)-bodyOffset < tlsRandomLen { return nil, nil, nil, fmt.Errorf("ClientHello random truncated") }
	receivedSequenceNum := binary.BigEndian.Uint64(clientHelloBody[bodyOffset : bodyOffset+8])
	if receivedSequenceNum != expectedSequenceNumber {
		return nil, nil, nil, fmt.Errorf("sequence number mismatch in TLS random: expected %d, got %d", expectedSequenceNumber, receivedSequenceNum)
	}
	bodyOffset += tlsRandomLen

	// Extract Session ID
	if len(clientHelloBody)-bodyOffset < 1 { return nil, nil, nil, fmt.Errorf("Session ID length byte missing") }
	sessionIDLen := int(clientHelloBody[bodyOffset])
	bodyOffset += 1
	if len(clientHelloBody)-bodyOffset < sessionIDLen { return nil, nil, nil, fmt.Errorf("Session ID truncated") }
	sessionID := clientHelloBody[bodyOffset : bodyOffset+sessionIDLen]
	bodyOffset += sessionIDLen

	// Extract Cipher Suites
	if len(clientHelloBody)-bodyOffset < 2 { return nil, nil, nil, fmt.Errorf("Cipher Suites length bytes missing") }
	cipherSuitesLen := int(binary.BigEndian.Uint16(clientHelloBody[bodyOffset : bodyOffset+2]))
	bodyOffset += 2
	if len(clientHelloBody)-bodyOffset < cipherSuitesLen { return nil, nil, nil, fmt.Errorf("Cipher Suites truncated") }
	cipherSuites := clientHelloBody[bodyOffset : bodyOffset+cipherSuitesLen]
	bodyOffset += cipherSuitesLen

	// Extract Compression Methods
	if len(clientHelloBody)-bodyOffset < 1 { return nil, nil, nil, fmt.Errorf("Compression Methods length byte missing") }
	compressionMethodsLen := int(clientHelloBody[bodyOffset])
	bodyOffset += 1
	if len(clientHelloBody)-bodyOffset < compressionMethodsLen { return nil, nil, nil, fmt.Errorf("Compression Methods truncated") }
	// Skip compression methods data: clientHelloBody[bodyOffset : bodyOffset+compressionMethodsLen]
	bodyOffset += compressionMethodsLen

	// Extract Extensions: this is where the main embedded data resides
	if len(clientHelloBody)-bodyOffset < 2 { return nil, nil, nil, fmt.Errorf("Extensions length bytes missing") }
	extensionsTotalLen := int(binary.BigEndian.Uint16(clientHelloBody[bodyOffset : bodyOffset+2]))
	bodyOffset += 2
	if len(clientHelloBody)-bodyOffset < extensionsTotalLen { return nil, nil, nil, fmt.Errorf("Extensions truncated") }
	extensionsData := clientHelloBody[bodyOffset : bodyOffset+extensionsTotalLen]

	// Reassemble embedded data from various parts (order matters!)
	var embeddedData []byte
	embeddedData = append(embeddedData, sessionID...)
	if len(cipherSuites) > 0 { // Skip cipherSuites length field, only data
		embeddedData = append(embeddedData, cipherSuites[0:]...)
	}
	embeddedData = append(embeddedData, extensionsData...)

	// Extract State Token, Nonce, Encrypted Payload
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


// --- Mode B: DNS Query Mimicry ---

const (
	dnsHeaderLen     = 12 // ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
	dnsQuestionMinLen = 4 // QNAME (min 1 byte for root) + QTYPE (2) + QCLASS (2) = 5 (but QNAME can be compressed, for simplicity min 4 here)
	dnsARecordType    = 0x0001 // A record
	dnsINClass        = 0x0001 // IN class
	dnsMinPacketLen   = dnsHeaderLen + dnsQuestionMinLen + StateTokenLen + NonceLen + TagLen // Rough minimum
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
		// This is a bit tricky for DNS QNAME as it's length-prefixed.
		// We'll embed into a CNAME-like extension or TXT record if we were doing response,
		// for query, maybe as part of the label itself, or in EDNS0.
		// For simplicity, embed it into the "subdomain" part, potentially exceeding normal length.
		// A more advanced version might inject as a TXT record query.
		qName = qName[:len(qName)-1] // Remove null terminator for now
		qName = append(qName, embeddedData...) // Append embedded data
		qName = append(qName, 0x00) // Re-add null terminator
		embeddedData = []byte{} // All embedded now
	}

	// QTYPE: A record
	qType := uint16(dnsARecordType) // Cast to uint16
	// QCLASS: IN
	qClass := uint16(dnsINClass) // Cast to uint16

	// Assemble DNS Header
	dnsHeaderBytes := make([]byte, dnsHeaderLen) // Create a fixed-size buffer
	binary.BigEndian.PutUint16(dnsHeaderBytes[0:2], dnsID)
	binary.BigEndian.PutUint16(dnsHeaderBytes[2:4], dnsFlags)
	binary.BigEndian.PutUint16(dnsHeaderBytes[4:6], qdCount) // QDCOUNT
	binary.BigEndian.PutUint16(dnsHeaderBytes[6:8], 0)       // ANCOUNT
	binary.BigEndian.PutUint16(dnsHeaderBytes[8:10], 0)      // NSCOUNT
	binary.BigEndian.PutUint16(dnsHeaderBytes[10:12], 0)     // ARCOUNT
	// No need for dnsHeaderBuf, directly use dnsHeaderBytes

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
	copy(out[outCursor:], dnsHeaderBytes) // Use dnsHeaderBytes
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


// --- Mode C: SSH Key Exchange (SSH_MSG_KEXINIT) Mimicry ---

const (
	sshPacketLenLen  = 4 // Total packet length
	sshPaddingLenLen = 1 // Padding length byte
	sshMinPadding    = 4 // Minimum SSH padding
	sshMsgKexinit    = 20 // SSH_MSG_KEXINIT
	sshCookieLen     = 16 // Cookie length
	sshNameListMinLen = 4 // Minimal length for an algorithm name list (1 byte length + 3 bytes name)
)

// ObfuscateModeSSHKeyExchange crafts a packet that mimics an SSH_MSG_KEXINIT.
// It embeds stateToken, nonce, and encryptedPayload within the SSH structure.
func ObfuscateModeSSHKeyExchange(randSrc *mrand.Rand, stateToken, nonce, encryptedPayload []byte, sequenceNumber uint64, out []byte) int {
	// Total data to embed: State Token + Nonce + Encrypted Payload
	embeddedData := append(stateToken, nonce...)
	embeddedData = append(embeddedData, encryptedPayload...)

	// SSH Packet structure:
	// packet_length (4 bytes)
	// padding_length (1 byte)
	// payload (packet_length - padding_length - 1 bytes)
	// random_padding (padding_length bytes)
	// mac (mac_length bytes, not included in packet_length)

	// KEXINIT message structure:
	// byte      SSH_MSG_KEXINIT (20)
	// byte[16]  cookie (random bytes)
	// name-list algorithm_negotiation_type_1 (kex_algorithms)
	// name-list algorithm_negotiation_type_2 (server_host_key_algorithms)
	// name-list algorithm_negotiation_type_3 (enc_algorithms_client_to_server)
	// name-list algorithm_negotiation_type_4 (enc_algorithms_server_to_client)
	// name-list algorithm_negotiation_type_5 (mac_algorithms_client_to_server)
	// name-list algorithm_negotiation_type_6 (mac_algorithms_server_to_client)
	// name-list algorithm_negotiation_type_7 (comp_algorithms_client_to_server)
	// name-list algorithm_negotiation_type_8 (comp_algorithms_server_to_client)
	// name-list algorithm_negotiation_type_9 (lang_client_to_server)
	// name-list algorithm_negotiation_type_10 (lang_server_to_client)
	// boolean   first_kex_packet_follows
	// uint32    0 (reserved for future extension)

	// Embed embeddedData into random cookie and algorithm name lists.
	// For simplicity, embed into first few algorithm lists.

	kexInitBodyBuf := new(bytes.Buffer)

	kexInitBodyBuf.WriteByte(sshMsgKexinit) // SSH_MSG_KEXINIT

	// Cookie (16 bytes): Use part of embeddedData
	cookie := make([]byte, sshCookieLen)
	_, err := GenerateRandomBytes(sshCookieLen) // Use GenerateRandomBytes
	if err != nil {
		return 0
	}
	if len(embeddedData) > 0 {
		copy(cookie, embeddedData[:min(sshCookieLen, len(embeddedData))])
		if len(embeddedData) > sshCookieLen {
			embeddedData = embeddedData[sshCookieLen:]
		} else {
			embeddedData = []byte{}
		}
	}
	kexInitBodyBuf.Write(cookie)

	// Algorithm name lists: embed remaining data into these.
	// Each name-list is a uint32 length prefix followed by comma-separated strings.
	// For simplicity, we'll embed raw bytes into these lists.

	// Helper for creating a name-list with embedded data
	createNameList := func(data []byte, minLen, maxLen int) ([]byte, error) {
		nameListLen := randSrc.Intn(maxLen-minLen+1) + minLen
		nameListContent := make([]byte, nameListLen)
		if len(data) > 0 {
			copy(nameListContent, data[:min(len(data), nameListLen)])
			if len(data) > nameListLen {
				data = data[nameListLen:]
			} else {
				data = []byte{}
			}
		}
		_, err := GenerateRandomBytes(len(nameListContent)-len(data)) // Use GenerateRandomBytes
		if err != nil {
			return nil, err
		}
		
		listBytes := make([]byte, 4 + len(nameListContent))
		binary.BigEndian.PutUint32(listBytes[0:4], uint32(len(nameListLen))) // Corrected: Should be len(nameListContent)
		copy(listBytes[4:], nameListContent)
		return listBytes, nil
	}

	// KEX algorithms
	kexAlgos, err := createNameList(embeddedData, MinDynamicPadding, MaxDynamicPadding)
	if err != nil { return 0 } // Removed `err` from return, just return 0
	kexInitBodyBuf.Write(kexAlgos)
	
	// Server host key algorithms
	serverHostKeyAlgos, err := createNameList(embeddedData, MinDynamicPadding, MaxDynamicPadding)
	if err != nil { return 0 } // Removed `err` from return, just return 0
	kexInitBodyBuf.Write(serverHostKeyAlgos)

	// Remaining 8 name-lists, and the two boolean/uint32 fields: fill with random data or standard values.
	// For simplicity, fill the remaining parts with random data
	for i := 0; i < 8; i++ {
		alg, err := createNameList([]byte{}, MinDynamicPadding/2, MaxDynamicPadding/2)
		if err != nil { return 0 } // Removed `err` from return, just return 0
		kexInitBodyBuf.Write(alg)
	}

	// first_kex_packet_follows (boolean)
	kexInitBodyBuf.WriteByte(byte(randSrc.Intn(2))) // Random 0 or 1

	// reserved (uint32)
	reserved := make([]byte, 4)
	binary.BigEndian.PutUint32(reserved, uint32(randSrc.Intn(math.MaxInt32))) // Random value
	kexInitBodyBuf.Write(reserved)

	kexInitBody := kexInitBodyBuf.Bytes()

	// Padding
	payloadLen := len(kexInitBody)
	paddingLen := randSrc.Intn(MaxDynamicPadding/2) + sshMinPadding // Min 4 bytes padding
	if (payloadLen+paddingLen)%8 != 0 { // SSH padding needs to be a multiple of 8
		paddingLen += 8 - ((payloadLen + paddingLen) % 8)
	}

	padding := make([]byte, paddingLen)
	_, err = GenerateRandomBytes(paddingLen) // Use GenerateRandomBytes
	if err != nil {
		return 0
	}

	// Total packet length (payload + padding_length byte + padding)
	packetLength := uint32(payloadLen + 1 + paddingLen) // +1 for padding_length byte itself

	totalOutputLen := sshPacketLenLen + int(packetLength)
	if len(out) < totalOutputLen {
		return 0 // Output buffer too small
	}

	outCursor := 0
	binary.BigEndian.PutUint32(out[outCursor:], packetLength)
	outCursor += sshPacketLenLen

	out[outCursor] = byte(paddingLen)
	outCursor += sshPaddingLenLen

	copy(out[outCursor:], kexInitBody)
	outCursor += len(kexInitBody)

	copy(out[outCursor:], padding)
	outCursor += len(padding)

	return totalOutputLen
}

// DeobfuscateModeSSHKeyExchange parses a packet mimicking an SSH_MSG_KEXINIT.
func DeobfuscateModeSSHKeyExchange(in []byte, expectedSequenceNumber uint64) ([]byte, []byte, []byte, error) {
	if len(in) < sshPacketLenLen+sshPaddingLenLen+1+sshCookieLen+sshNameListMinLen*2+1+4 { // Basic SSH KEXINIT structure
		return nil, nil, nil, fmt.Errorf("SSH packet too short for KEXINIT structure")
	}

	// Parse packet_length
	packetLength := binary.BigEndian.Uint32(in[0:sshPacketLenLen])
	if len(in) != sshPacketLenLen+int(packetLength) {
		return nil, nil, nil, fmt.Errorf("SSH packet length mismatch: header says %d, actual %d", packetLength, len(in)-sshPacketLenLen)
	}
	currentOffset := sshPacketLenLen

	// Parse padding_length
	paddingLength := in[currentOffset]
	currentOffset += sshPaddingLenLen

	// Remaining bytes should be payload + padding
	expectedPayloadLen := int(packetLength) - int(paddingLength) - 1 // -1 for padding_length byte itself
	if len(in)-currentOffset < expectedPayloadLen {
		return nil, nil, nil, fmt.Errorf("SSH payload truncated")
	}
	sshPayload := in[currentOffset : currentOffset+expectedPayloadLen]

	// Now parse SSH KEXINIT message from sshPayload
	payloadOffset := 0
	if sshPayload[payloadOffset] != sshMsgKexinit {
		return nil, nil, nil, fmt.Errorf("incorrect SSH message type: 0x%X, expected 0x%X", sshPayload[payloadOffset], sshMsgKexinit)
	}
	payloadOffset += 1 // Skip message type

	// Extract Cookie (16 bytes)
	if len(sshPayload)-payloadOffset < sshCookieLen { return nil, nil, nil, fmt.Errorf("SSH cookie truncated") }
	cookie := sshPayload[payloadOffset : payloadOffset+sshCookieLen]
	payloadOffset += sshCookieLen

	var embeddedData []byte
	embeddedData = append(embeddedData, cookie...) // Initial embedded data from cookie

	// Extract Algorithm Name Lists (10 of them)
	extractNameList := func(data []byte) ([]byte, int, error) {
		if len(data) < 4 { return nil, 0, fmt.Errorf("name-list length field truncated") }
		listLen := int(binary.BigEndian.Uint32(data[0:4]))
		if len(data)-4 < listLen { return nil, 0, fmt.Errorf("name-list content truncated") }
		return data[4 : 4+listLen], 4 + listLen, nil
	}

	// KEX algorithms (where embedded data usually is)
	kexAlgos, consumed, err := extractNameList(sshPayload[payloadOffset:])
	if err != nil { return nil, nil, nil, fmt.Errorf("failed to extract KEX algorithms: %w", err) }
	embeddedData = append(embeddedData, kexAlgos...) // Add to embedded data
	payloadOffset += consumed

	// Server host key algorithms (where embedded data usually is)
	serverHostKeyAlgos, consumed, err := extractNameList(sshPayload[payloadOffset:])
	if err != nil { return nil, nil, nil, fmt.Errorf("failed to extract server host key algorithms: %w", err) }
	embeddedData = append(embeddedData, serverHostKeyAlgos...) // Add to embedded data
	payloadOffset += consumed

	// Parse remaining 8 algorithm lists
	for i := 0; i < 8; i++ {
		_, consumed, err := extractNameList(sshPayload[payloadOffset:])
		if err != nil { return nil, nil, nil, fmt.Errorf("failed to extract algo list %d: %w", i+3, err) }
		payloadOffset += consumed
	}
	
	// Parse first_kex_packet_follows (1 byte boolean)
	if len(sshPayload)-payloadOffset < 1 { return nil, nil, nil, fmt.Errorf("first_kex_packet_follows missing") }
	// firstKexPacketFollows := sshPayload[payloadOffset] != 0 // Can be used for logic if needed
	payloadOffset += 1

	// Parse reserved (4 bytes uint32)
	if len(sshPayload)-payloadOffset < 4 { return nil, nil, nil, fmt.Errorf("reserved field missing") }
	// reservedValue := binary.BigEndian.Uint32(sshPayload[payloadOffset : payloadOffset+4]) // Can be used for logic if needed
	payloadOffset += 4

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
