package cosmicdust

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	mrand "math/rand"
	"strings"
	"time" // Used for NTP timestamp generation
)

// Disguise mode identifiers
const (
	ModeTLSAppData   = 0 // Mimics TLS Application Data fragment
	ModeDNSQuery     = 1 // Mimics DNS A record query
	ModeHTTPFragment = 2 // Mimics HTTP GET/POST body fragment
	ModeNTPRequest   = 3 // Mimics NTP client request
	ModeDecoy        = 4 // Special mode for decoy packets
	NumDisguiseModes = 5 // Total number of disguise modes
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


// --- Mode A: TLS Application Data Mimicry (TLS Record Layer) ---

const (
	tlsRecordHeaderLen = 5 // Type(1) + Version(2) + Length(2)
	tlsAppDataRecordType = 0x17 // Application Data (23)
	tlsVersionTLS12      = 0x0303
	tlsMinAppDataLen     = SegmentStateTokenLen + NonceLen + TagLen // Minimal embedded data
)

// ObfuscateModeTLSAppData crafts a packet that mimics a TLS Application Data record.
// It embeds segmentStateToken, nonce, and encryptedSegmentPayload.
func ObfuscateModeTLSAppData(randSrc *mrand.Rand, segmentStateToken, nonce, encryptedSegmentPayload []byte) ([]byte, error) {
	// Total data to embed: SegmentStateToken + Nonce + Encrypted Segment Payload
	embeddedData := make([]byte, 0, len(segmentStateToken)+len(nonce)+len(encryptedSegmentPayload))
	embeddedData = append(embeddedData, segmentStateToken...)
	embeddedData = append(embeddedData, nonce...)
	embeddedData = append(embeddedData, encryptedSegmentPayload...)

	// Add random padding to embeddedData to make record length variable
	paddingLen := randSrc.Intn(MaxDynamicPadding-MinDynamicPadding+1) + MinDynamicPadding
	randomPadding, err := GenerateRandomBytes(paddingLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random padding: %w", err)
	}
	embeddedData = append(embeddedData, randomPadding...)

	// TLS Record Layer Header
	// Type (1 byte): Application Data (0x17)
	// Version (2 bytes): TLS 1.2 (0x0303)
	// Length (2 bytes): Length of the embeddedData
	recordLen := len(embeddedData)
	if recordLen > math.MaxUint16 { // TLS record length is uint16
		return nil, fmt.Errorf("TLS application data record too large: %d bytes", recordLen)
	}

	packet := make([]byte, tlsRecordHeaderLen+recordLen)
	packet[0] = tlsAppDataRecordType
	binary.BigEndian.PutUint16(packet[1:3], tlsVersionTLS12)
	binary.BigEndian.PutUint16(packet[3:5], uint16(recordLen))
	copy(packet[tlsRecordHeaderLen:], embeddedData)

	return packet, nil
}

// DeobfuscateModeTLSAppData parses a packet mimicking a TLS Application Data record.
// It extracts segmentStateToken, nonce, and encryptedSegmentPayload.
func DeobfuscateModeTLSAppData(in []byte) ([]byte, []byte, []byte, error) {
	if len(in) < tlsRecordHeaderLen+tlsMinAppDataLen {
		return nil, nil, nil, fmt.Errorf("TLS AppData packet too short")
	}

	// Parse TLS Record Layer Header
	if in[0] != tlsAppDataRecordType {
		return nil, nil, nil, fmt.Errorf("incorrect TLS record type: 0x%X, expected 0x%X", in[0], tlsAppDataRecordType)
	}
	// Can add version check: if binary.BigEndian.Uint16(in[1:3]) != tlsVersionTLS12 { ... }
	recordLen := int(binary.BigEndian.Uint16(in[3:5]))
	if len(in) != tlsRecordHeaderLen+recordLen {
		return nil, nil, nil, fmt.Errorf("TLS record length mismatch: header says %d, actual %d", recordLen, len(in)-tlsRecordHeaderLen)
	}

	embeddedData := in[tlsRecordHeaderLen:]

	// Extract SegmentStateToken, Nonce, Encrypted Payload
	if len(embeddedData) < tlsMinAppDataLen {
		return nil, nil, nil, fmt.Errorf("embedded data too short for segment state token, nonce, and tag")
	}

	segmentStateToken := embeddedData[0:SegmentStateTokenLen]
	currentEmbeddedOffset := SegmentStateTokenLen

	nonce := embeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	encryptedSegmentPayload := embeddedData[currentEmbeddedOffset : len(embeddedData)-len(embeddedData[currentEmbeddedOffset:])%TagLen] // Strip potential padding after tag
	// The above line is a simplification. In a real scenario, you'd need a clear way to know where the actual encrypted payload ends and padding begins.
	// For this example, we assume padding comes after the tag and is not part of the HMAC-protected payload.
	// A more robust design would embed the actual encrypted payload length.
	
	// For now, let's assume the encrypted payload is everything from currentEmbeddedOffset until the end,
	// and the padding is just "extra" bytes at the end of the physical packet that are ignored.
	encryptedSegmentPayload = embeddedData[currentEmbeddedOffset:]
	if len(encryptedSegmentPayload) < TagLen {
		return nil, nil, nil, fmt.Errorf("encrypted segment payload too short for tag")
	}


	return segmentStateToken, nonce, encryptedSegmentPayload, nil
}


// --- Mode B: DNS Query Mimicry ---

const (
	dnsHeaderLen     = 12 // ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
	dnsQuestionMinLen = 5 // QNAME (min 1 byte for root) + QTYPE (2) + QCLASS (2)
	dnsARecordType    = 0x0001 // A record
	dnsINClass        = 0x0001 // IN class
	dnsMinPacketLen   = dnsHeaderLen + dnsQuestionMinLen + SegmentStateTokenLen + NonceLen + TagLen // Rough minimum
)

// ObfuscateModeDNSQuery crafts a packet that mimics a DNS A record query.
// It embeds segmentStateToken, nonce, and encryptedSegmentPayload into the QNAME.
func ObfuscateModeDNSQuery(randSrc *mrand.Rand, segmentStateToken, nonce, encryptedSegmentPayload []byte) ([]byte, error) {
	// Total data to embed: SegmentStateToken + Nonce + Encrypted Segment Payload
	embeddedData := make([]byte, 0, len(segmentStateToken)+len(nonce)+len(encryptedSegmentPayload))
	embeddedData = append(embeddedData, segmentStateToken...)
	embeddedData = append(embeddedData, nonce...)
	embeddedData = append(embeddedData, encryptedSegmentPayload...)

	// Generate a plausible DNS ID
	dnsID := uint16(randSrc.Uint32() % 65535)

	// Flags: Standard query, recursion desired
	dnsFlags := uint16(0x0100) // QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0

	// QDCOUNT: 1 question
	qdCount := uint16(1)

	// QNAME: Embed data into a dynamically generated domain name
	// Example: <random_label>.<embedded_data_as_hex_label_or_random_bytes>.<random_tld>.com
	// For simplicity, we'll embed directly into a long label.
	qNameBuf := new(bytes.Buffer)
	
	// First random label
	firstLabelLen := randSrc.Intn(10) + 5 // 5-14 chars
	firstLabel := make([]byte, firstLabelLen)
	for i := 0; i < firstLabelLen; i++ {
		firstLabel[i] = byte(randSrc.Intn(26) + 'a')
	}
	qNameBuf.WriteByte(byte(len(firstLabel)))
	qNameBuf.Write(firstLabel)

	// Embedded data as a label (or split into multiple labels)
	// For simplicity, embed all as one large label, potentially truncated.
	maxEmbeddedLabelLen := 63 // Max DNS label length
	if len(embeddedData) > maxEmbeddedLabelLen {
		qNameBuf.WriteByte(byte(maxEmbeddedLabelLen))
		qNameBuf.Write(embeddedData[:maxEmbeddedLabelLen])
		embeddedData = embeddedData[maxEmbeddedLabelLen:] // Remaining data
	} else if len(embeddedData) > 0 {
		qNameBuf.WriteByte(byte(len(embeddedData)))
		qNameBuf.Write(embeddedData)
		embeddedData = []byte{}
	}

	// Add a common TLD to make it look legitimate
	qNameBuf.WriteByte(byte(7))
	qNameBuf.WriteString("example")
	qNameBuf.WriteByte(byte(3))
	qNameBuf.WriteString("com")
	qNameBuf.WriteByte(0x00) // Null terminator

	qName := qNameBuf.Bytes()

	// QTYPE: A record
	qType := uint16(dnsARecordType)
	// QCLASS: IN
	qClass := uint16(dnsINClass)

	// Assemble DNS Header
	dnsHeaderBytes := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(dnsHeaderBytes[0:2], dnsID)
	binary.BigEndian.PutUint16(dnsHeaderBytes[2:4], dnsFlags)
	binary.BigEndian.PutUint16(dnsHeaderBytes[4:6], qdCount)
	binary.BigEndian.PutUint16(dnsHeaderBytes[6:8], 0) // ANCOUNT
	binary.BigEndian.PutUint16(dnsHeaderBytes[8:10], 0) // NSCOUNT
	binary.BigEndian.PutUint16(dnsHeaderBytes[10:12], 0) // ARCOUNT

	// Assemble DNS Question
	dnsQuestionBuf := new(bytes.Buffer)
	dnsQuestionBuf.Write(qName)
	qTypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(qTypeBytes, qType)
	dnsQuestionBuf.Write(qTypeBytes)
	qClassBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(qClassBytes, qClass)
	dnsQuestionBuf.Write(qClassBytes)
	dnsQuestion := dnsQuestionBuf.Bytes()

	packet := make([]byte, dnsHeaderLen+len(dnsQuestion))
	copy(packet[0:dnsHeaderLen], dnsHeaderBytes)
	copy(packet[dnsHeaderLen:], dnsQuestion)

	return packet, nil
}

// DeobfuscateModeDNSQuery parses a packet mimicking a DNS A record query.
func DeobfuscateModeDNSQuery(in []byte) ([]byte, []byte, []byte, error) {
	if len(in) < dnsHeaderLen+dnsQuestionMinLen {
		return nil, nil, nil, fmt.Errorf("DNS packet too short")
	}

	// Parse DNS Header (skip most fields for simplicity, focus on QNAME)
	qdCount := binary.BigEndian.Uint16(in[4:6])
	if qdCount != 1 {
		return nil, nil, nil, fmt.Errorf("DNS QDCOUNT not 1")
	}

	currentOffset := dnsHeaderLen
	
	// Parse QNAME and extract embedded data
	qNameBuf := bytes.NewBuffer(in[currentOffset:])
	var extractedEmbeddedData []byte
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
		extractedEmbeddedData = append(extractedEmbeddedData, label...)
	}
	
	// Remove known trailing parts of the QNAME (e.g., example.com)
	exampleComSuffix := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm'}
	if bytes.HasSuffix(extractedEmbeddedData, exampleComSuffix) {
		extractedEmbeddedData = extractedEmbeddedData[:len(extractedEmbeddedData)-len(exampleComSuffix)]
	}

	// Extract SegmentStateToken, Nonce, Encrypted Payload from extractedEmbeddedData
	if len(extractedEmbeddedData) < SegmentStateTokenLen+NonceLen+TagLen {
		return nil, nil, nil, fmt.Errorf("extracted embedded data too short for segment state token, nonce, and tag")
	}

	segmentStateToken := extractedEmbeddedData[0:SegmentStateTokenLen]
	currentEmbeddedOffset := SegmentStateTokenLen

	nonce := extractedEmbeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	encryptedSegmentPayload := extractedEmbeddedData[currentEmbeddedOffset:]
	if len(encryptedSegmentPayload) < TagLen {
		return nil, nil, nil, fmt.Errorf("encrypted segment payload too short for tag")
	}

	return segmentStateToken, nonce, encryptedSegmentPayload, nil
}


// --- Mode C: HTTP Fragment Mimicry (mimics a chunk of an HTTP body) ---

const (
	httpFragmentMinLen = 100 // Minimum length for a believable HTTP fragment
	httpHeaderEndLen   = 4   // "\r\n\r\n"
	httpChunkSizeLen   = 2   // Max 2 bytes for chunk size (hex)
)

// ObfuscateModeHTTPFragment crafts a packet that mimics an HTTP body fragment.
// It embeds segmentStateToken, nonce, and encryptedSegmentPayload.
func ObfuscateModeHTTPFragment(randSrc *mrand.Rand, segmentStateToken, nonce, encryptedSegmentPayload []byte) ([]byte, error) {
	// Total data to embed: SegmentStateToken + Nonce + Encrypted Segment Payload
	embeddedData := make([]byte, 0, len(segmentStateToken)+len(nonce)+len(encryptedSegmentPayload))
	embeddedData = append(embeddedData, segmentStateToken...)
	embeddedData = append(embeddedData, nonce...)
	embeddedData = append(embeddedData, encryptedSegmentPayload...)

	// Add random padding to make the fragment size variable
	paddingLen := randSrc.Intn(MaxDynamicPadding-MinDynamicPadding+1) + MinDynamicPadding
	randomPadding, err := GenerateRandomBytes(paddingLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random padding: %w", err)
	}
	embeddedData = append(embeddedData, randomPadding...)

	// HTTP chunked encoding format:
	// <chunk-size> CRLF
	// <chunk-data> CRLF
	// 0 CRLF
	// CRLF

	chunkSize := len(embeddedData)
	chunkSizeHex := []byte(fmt.Sprintf("%x\r\n", chunkSize))
	
	packet := new(bytes.Buffer)
	packet.Write(chunkSizeHex)
	packet.Write(embeddedData)
	packet.WriteString("\r\n") // CRLF after chunk data

	// Optionally add random HTTP headers before the chunk, or after for a full response mimic
	// For a fragment, this is simpler.

	return packet.Bytes(), nil
}

// DeobfuscateModeHTTPFragment parses a packet mimicking an HTTP body fragment.
func DeobfuscateModeHTTPFragment(in []byte) ([]byte, []byte, []byte, error) {
	// Find the first CRLF to get chunk size
	crlfIdx := bytes.Index(in, []byte("\r\n"))
	if crlfIdx == -1 {
		return nil, nil, nil, fmt.Errorf("HTTP fragment: no CRLF after chunk size")
	}

	chunkSizeHex := in[0:crlfIdx]
	chunkSize, err := strconv.ParseInt(string(chunkSizeHex), 16, 64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("HTTP fragment: invalid chunk size hex: %w", err)
	}

	chunkDataStart := crlfIdx + 2 // After CRLF
	expectedChunkDataEnd := chunkDataStart + int(chunkSize)
	
	if len(in) < expectedChunkDataEnd {
		return nil, nil, nil, fmt.Errorf("HTTP fragment: data truncated, expected %d bytes, got %d", int(chunkSize), len(in)-chunkDataStart)
	}

	embeddedData := in[chunkDataStart:expectedChunkDataEnd]

	// Verify trailing CRLF
	if len(in) < expectedChunkDataEnd+2 || !bytes.Equal(in[expectedChunkDataEnd:expectedChunkDataEnd+2], []byte("\r\n")) {
		return nil, nil, nil, fmt.Errorf("HTTP fragment: missing CRLF after chunk data")
	}

	// Extract SegmentStateToken, Nonce, Encrypted Payload
	if len(embeddedData) < SegmentStateTokenLen+NonceLen+TagLen {
		return nil, nil, nil, fmt.Errorf("embedded data too short for segment state token, nonce, and tag")
	}

	segmentStateToken := embeddedData[0:SegmentStateTokenLen]
	currentEmbeddedOffset := SegmentStateTokenLen

	nonce := embeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	encryptedSegmentPayload := embeddedData[currentEmbeddedOffset:]
	if len(encryptedSegmentPayload) < TagLen {
		return nil, nil, nil, fmt.Errorf("encrypted segment payload too short for tag")
	}

	return segmentStateToken, nonce, encryptedSegmentPayload, nil
}


// --- Mode D: NTP Client Request Mimicry ---

const (
	ntpPacketLen = 48 // Standard NTP packet length
)

// ObfuscateModeNTPRequest crafts a packet that mimics an NTP client request.
// It embeds segmentStateToken, nonce, and encryptedSegmentPayload into the NTP packet's unused/randomizable fields.
func ObfuscateModeNTPRequest(randSrc *mrand.Rand, segmentStateToken, nonce, encryptedSegmentPayload []byte) ([]byte, error) {
	// Total data to embed: SegmentStateToken + Nonce + Encrypted Segment Payload
	embeddedData := make([]byte, 0, len(segmentStateToken)+len(nonce)+len(encryptedSegmentPayload))
	embeddedData = append(embeddedData, segmentStateToken...)
	embeddedData = append(embeddedData, nonce...)
	embeddedData = append(embeddedData, encryptedSegmentPayload...)

	// Create a standard NTP client request packet (RFC 5905)
	// Most fields are fixed for a client request, but some are randomizable or unused.
	// We'll embed data into the "Transmit Timestamp" and subsequent unused fields.
	packet := make([]byte, ntpPacketLen)

	// Set LI (0), VN (3), Mode (3 - client)
	packet[0] = 0b00_011_011 // LI=0 (no warning), VN=3 (NTPv3), Mode=3 (client)

	// Stratum (1 byte): 0 (unspecified)
	packet[1] = 0 // Unspecified

	// Poll Interval (1 byte): random value
	packet[2] = byte(randSrc.Intn(10) + 4) // 2^4 to 2^13 seconds

	// Precision (1 byte): random value
	packet[3] = byte(randSrc.Intn(5) - 20) // e.g., -20 to -16

	// Root Delay (4 bytes): random value
	binary.BigEndian.PutUint32(packet[4:8], randSrc.Uint32())

	// Root Dispersion (4 bytes): random value
	binary.BigEndian.PutUint32(packet[8:12], randSrc.Uint32())

	// Reference ID (4 bytes): random value or plausible source ID
	binary.BigEndian.PutUint32(packet[12:16], randSrc.Uint32())

	// Reference Timestamp (8 bytes): 0 for client request
	// Origin Timestamp (8 bytes): 0 for client request
	// Receive Timestamp (8 bytes): 0 for client request

	// Transmit Timestamp (8 bytes): This is the client's send time.
	// We'll embed our data here and in subsequent unused fields.
	// NTP timestamp is seconds since 1900-01-01 00:00:00 UTC.
	ntpEpoch := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now().UTC()
	seconds := uint32(now.Sub(ntpEpoch).Seconds())
	fraction := uint32(float64(now.Nanosecond()) / 1e9 * math.MaxUint32) // Fractional part

	transmitTimestamp := make([]byte, 8)
	binary.BigEndian.PutUint32(transmitTimestamp[0:4], seconds)
	binary.BigEndian.PutUint32(transmitTimestamp[4:8], fraction)

	// Embed embeddedData into transmitTimestamp and subsequent fields
	// Starting from Transmit Timestamp (offset 40)
	embedOffset := 40
	if len(embeddedData) > 0 {
		copy(packet[embedOffset:], embeddedData[:min(len(embeddedData), ntpPacketLen-embedOffset)])
		// Note: NTP packet is fixed 48 bytes. If embeddedData is larger, it will be truncated.
		// A more robust solution would be to fragment embeddedData across multiple NTP packets
		// or use a different disguise if data is too large.
	}
	// Fill remaining with random bytes if embeddedData was smaller
	_, err := GenerateRandomBytes(ntpPacketLen - embedOffset - len(embeddedData))
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes for NTP padding: %w", err)
	}

	return packet, nil
}

// DeobfuscateModeNTPRequest parses a packet mimicking an NTP client request.
func DeobfuscateModeNTPRequest(in []byte) ([]byte, []byte, []byte, error) {
	if len(in) != ntpPacketLen {
		return nil, nil, nil, fmt.Errorf("NTP packet has incorrect length: %d, expected %d", len(in), ntpPacketLen)
	}

	// Basic NTP header check (LI, VN, Mode)
	if (in[0] & 0b11_111_111) != 0b00_011_011 { // LI=0, VN=3, Mode=3 (client)
		return nil, nil, nil, fmt.Errorf("NTP header mismatch: 0x%X", in[0])
	}

	// Extract embedded data from Transmit Timestamp and subsequent fields
	// Starting from Transmit Timestamp (offset 40)
	extractOffset := 40
	embeddedData := in[extractOffset:]

	// Extract SegmentStateToken, Nonce, Encrypted Payload
	if len(embeddedData) < SegmentStateTokenLen+NonceLen+TagLen {
		return nil, nil, nil, fmt.Errorf("embedded data too short for segment state token, nonce, and tag")
	}

	segmentStateToken := embeddedData[0:SegmentStateTokenLen]
	currentEmbeddedOffset := SegmentStateTokenLen

	nonce := embeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	encryptedSegmentPayload := embeddedData[currentEmbeddedOffset:]
	if len(encryptedSegmentPayload) < TagLen {
		return nil, nil, nil, fmt.Errorf("encrypted segment payload too short for tag")
	}

	return segmentStateToken, nonce, encryptedSegmentPayload, nil
}


// --- Mode E: Decoy Packet Generation ---

const (
	decoyMinLen = 100 // Minimum length for a believable decoy packet
	decoyMaxLen = 500 // Maximum length for a believable decoy packet
)

// ObfuscateModeDecoy generates a decoy packet that looks like legitimate traffic
// but contains no actual payload. It uses the cumulative hash to vary its appearance.
func ObfuscateModeDecoy(randSrc *mrand.Rand, cumulativeHash []byte) ([]byte, error) {
	// Decoy packets can mimic any of the other modes, but with random data
	// and without embedding SegmentStateToken/Nonce/Payload.
	// For simplicity, let's make it mimic a random HTTP GET request.

	decoyLen := randSrc.Intn(decoyMaxLen-decoyMinLen+1) + decoyMinLen
	decoyPacket := make([]byte, decoyLen)
	_, err := GenerateRandomBytes(decoyLen) // Fill with random bytes
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes for decoy: %w", err)
	}
	
	// Make it look like a generic HTTP GET
	httpGetLine := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
	if len(httpGetLine) < len(decoyPacket) {
		copy(decoyPacket, httpGetLine)
	} else {
		copy(decoyPacket, httpGetLine[:len(decoyPacket)])
	}
	
	// Add some random bytes to the end to make it variable
	if len(decoyPacket) > len(httpGetLine) {
		_, err = GenerateRandomBytes(len(decoyPacket) - len(httpGetLine))
		if err != nil {
			return nil, fmt.Errorf("failed to generate random bytes for decoy padding: %w", err)
		}
	}

	return decoyPacket, nil
}

// DeobfuscateModeDecoy attempts to identify if an incoming packet is a decoy.
// It returns true if it's a decoy, false otherwise, and an error if parsing fails.
// This is a heuristic check; a real system might use a specific magic number or pattern.
func DeobfuscateModeDecoy(in []byte) (bool, error) {
	// For a real decoy, you'd embed a specific, HMAC-protected "decoy marker"
	// that is distinct from the SegmentStateToken.
	// Here, we'll use a simple heuristic: if it looks like a generic HTTP GET
	// but doesn't contain a valid SegmentStateToken when parsed by other modes,
	// it *might* be a decoy. This is highly unreliable for production.

	// A more robust decoy detection:
	// 1. Decoy packets have a specific magic number/header that no other mode uses.
	// 2. This magic number is followed by an HMAC derived from PSK and current global state hash.
	// 3. Decoy packets explicitly state they are decoys.

	// For now, let's assume a decoy is a simple HTTP GET that is not parseable by other modes.
	// This function would be called *after* other modes fail to parse.
	// If it starts with "GET / HTTP/1.1" and is within decoy length range, we'll consider it.
	if len(in) >= len("GET / HTTP/1.1") && bytes.HasPrefix(in, []byte("GET / HTTP/1.1")) {
		if len(in) >= decoyMinLen && len(in) <= decoyMaxLen {
			// This is a plausible decoy.
			return true, nil
		}
	}
	return false, fmt.
