package cosmicdust

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	mrand "math/rand"
	"strconv"
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
	// The encryptedSegmentPayload's length is already in segmentStateToken.
	embeddedCoreData := make([]byte, 0, len(segmentStateToken)+len(nonce)+len(encryptedSegmentPayload))
	embeddedCoreData = append(embeddedCoreData, segmentStateToken...)
	embeddedCoreData = append(embeddedCoreData, nonce...)
	embeddedCoreData = append(embeddedCoreData, encryptedSegmentPayload...)

	// Add random padding to embeddedCoreData to make record length variable
	paddingLen := randSrc.Intn(MaxDynamicPadding-MinDynamicPadding+1) + MinDynamicPadding
	randomPadding, err := GenerateRandomBytes(paddingLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random padding: %w", err)
	}
	
	// Final embedded data includes core data and padding
	finalEmbeddedData := append(embeddedCoreData, randomPadding...)

	// TLS Record Layer Header
	// Type (1 byte): Application Data (0x17)
	// Version (2 bytes): TLS 1.2 (0x0303)
	// Length (2 bytes): Length of the finalEmbeddedData
	recordLen := len(finalEmbeddedData)
	if recordLen > math.MaxUint16 { // TLS record length is uint16
		return nil, fmt.Errorf("TLS application data record too large: %d bytes", recordLen)
	}

	packet := make([]byte, tlsRecordHeaderLen+recordLen)
	packet[0] = tlsAppDataRecordType
	binary.BigEndian.PutUint16(packet[1:3], tlsVersionTLS12)
	binary.BigEndian.PutUint16(packet[3:5], uint16(recordLen))
	copy(packet[tlsRecordHeaderLen:], finalEmbeddedData)

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
	// Version check (optional but good for strictness)
	if binary.BigEndian.Uint16(in[1:3]) != tlsVersionTLS12 {
		return nil, nil, nil, fmt.Errorf("TLS version mismatch: 0x%X, expected 0x%X", binary.BigEndian.Uint16(in[1:3]), tlsVersionTLS12)
	}
	recordLen := int(binary.BigEndian.Uint16(in[3:5]))
	if len(in) != tlsRecordHeaderLen+recordLen {
		return nil, nil, nil, fmt.Errorf("TLS record length mismatch: header says %d, actual %d", recordLen, len(in)-tlsRecordHeaderLen)
	}

	finalEmbeddedData := in[tlsRecordHeaderLen:]

	// Extract SegmentStateToken
	if len(finalEmbeddedData) < SegmentStateTokenLen {
		return nil, nil, nil, fmt.Errorf("embedded data too short for segment state token")
	}
	segmentStateToken := finalEmbeddedData[0:SegmentStateTokenLen]
	currentEmbeddedOffset := SegmentStateTokenLen

	// Extract metadata from token to get encryptedPayloadLen
	_, _, _, encryptedPayloadLen, err := ExtractSegmentMetadata(segmentStateToken)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to extract metadata from segment state token: %w", err)
	}

	// Extract Nonce
	if len(finalEmbeddedData)-currentEmbeddedOffset < NonceLen {
		return nil, nil, nil, fmt.Errorf("embedded data too short for nonce")
	}
	nonce := finalEmbeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	// Extract Encrypted Payload based on embedded length
	expectedEncryptedEnd := currentEmbeddedOffset + int(encryptedPayloadLen)
	if len(finalEmbeddedData) < expectedEncryptedEnd {
		return nil, nil, nil, fmt.Errorf("embedded data truncated, encrypted payload shorter than specified in token")
	}
	encryptedSegmentPayload := finalEmbeddedData[currentEmbeddedOffset:expectedEncryptedEnd]
	
	// Any data after encryptedSegmentPayload is considered padding and ignored.

	return segmentStateToken, nonce, encryptedSegmentPayload, nil
}


// --- Mode B: DNS Query Mimicry ---

const (
	dnsHeaderLen     = 12 // ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
	dnsQuestionMinLen = 5 // QNAME (min 1 byte for root) + QTYPE (2) + QCLASS (2)
	dnsARecordType    = 0x0001 // A record
	dnsINClass        = 0x0001 // IN class
	dnsMaxLabelLen    = 63 // Max length of a DNS label
)

// ObfuscateModeDNSQuery crafts a packet that mimics a DNS A record query.
// It embeds segmentStateToken, nonce, and encryptedSegmentPayload into the QNAME.
func ObfuscateModeDNSQuery(randSrc *mrand.Rand, segmentStateToken, nonce, encryptedSegmentPayload []byte) ([]byte, error) {
	// Total data to embed: SegmentStateToken + Nonce + Encrypted Segment Payload
	embeddedData := make([]byte, 0, len(segmentStateToken)+len(nonce)+len(encryptedSegmentPayload))
	embeddedData = append(embeddedData, segmentStateToken...)
	embeddedData = append(embeddedData, nonce...)
	embeddedData = append(embeddedData, encryptedSegmentPayload...)

	// Add random padding to embeddedData to make the QNAME length variable
	paddingLen := randSrc.Intn(MaxDynamicPadding-MinDynamicPadding+1) + MinDynamicPadding
	randomPadding, err := GenerateRandomBytes(paddingLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random padding: %w", err)
	}
	embeddedData = append(embeddedData, randomPadding...)


	// Generate a plausible DNS ID
	dnsID := uint16(randSrc.Uint32() % 65535)

	// Flags: Standard query, recursion desired
	dnsFlags := uint16(0x0100) // QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0

	// QDCOUNT: 1 question
	qdCount := uint16(1)

	// QNAME: Embed data into multiple dynamically generated DNS labels
	qNameBuf := new(bytes.Buffer)
	
	currentEmbeddedDataOffset := 0
	// Split embeddedData into 63-byte labels
	for currentEmbeddedDataOffset < len(embeddedData) {
		labelLen := min(len(embeddedData)-currentEmbeddedDataOffset, dnsMaxLabelLen)
		qNameBuf.WriteByte(byte(labelLen))
		qNameBuf.Write(embeddedData[currentEmbeddedDataOffset : currentEmbeddedDataOffset+labelLen])
		currentEmbeddedDataOffset += labelLen
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
	} else {
		return nil, nil, nil, fmt.Errorf("DNS QNAME missing expected suffix")
	}

	// Extract SegmentStateToken
	if len(extractedEmbeddedData) < SegmentStateTokenLen {
		return nil, nil, nil, fmt.Errorf("extracted embedded data too short for segment state token")
	}
	segmentStateToken := extractedEmbeddedData[0:SegmentStateTokenLen]
	currentEmbeddedOffset := SegmentStateTokenLen

	// Extract metadata from token to get encryptedPayloadLen
	_, _, _, encryptedPayloadLen, err := ExtractSegmentMetadata(segmentStateToken)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to extract metadata from segment state token: %w", err)
	}

	// Extract Nonce
	if len(extractedEmbeddedData)-currentEmbeddedOffset < NonceLen {
		return nil, nil, nil, fmt.Errorf("extracted embedded data too short for nonce")
	}
	nonce := extractedEmbeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	// Extract Encrypted Payload based on embedded length
	expectedEncryptedEnd := currentEmbeddedOffset + int(encryptedPayloadLen)
	if len(extractedEmbeddedData) < expectedEncryptedEnd {
		return nil, nil, nil, fmt.Errorf("extracted embedded data truncated, encrypted payload shorter than specified in token")
	}
	encryptedSegmentPayload := extractedEmbeddedData[currentEmbeddedOffset:expectedEncryptedEnd]
	
	// Any data after encryptedSegmentPayload is considered padding and ignored.
	if len(encryptedSegmentPayload) < TagLen {
		return nil, nil, nil, fmt.Errorf("encrypted segment payload too short for tag")
	}

	return segmentStateToken, nonce, encryptedSegmentPayload, nil
}


// --- Mode C: HTTP Fragment Mimicry (mimics a chunk of an HTTP body) ---

const (
	httpFragmentMinLen = 100 // Minimum length for a believable HTTP fragment
	httpCRLF           = "\r\n"
	httpDoubleCRLF     = "\r\n\r\n"
)

// ObfuscateModeHTTPFragment crafts a packet that mimics an HTTP body fragment using chunked encoding.
// It embeds segmentStateToken, nonce, and encryptedSegmentPayload.
func ObfuscateModeHTTPFragment(randSrc *mrand.Rand, segmentStateToken, nonce, encryptedSegmentPayload []byte) ([]byte, error) {
	// Total data to embed: SegmentStateToken + Nonce + Encrypted Segment Payload
	embeddedCoreData := make([]byte, 0, len(segmentStateToken)+len(nonce)+len(encryptedSegmentPayload))
	embeddedCoreData = append(embeddedCoreData, segmentStateToken...)
	embeddedCoreData = append(embeddedCoreData, nonce...)
	embeddedCoreData = append(embeddedCoreData, encryptedSegmentPayload...)

	// Add random padding to embeddedCoreData to make the chunk size variable
	paddingLen := randSrc.Intn(MaxDynamicPadding-MinDynamicPadding+1) + MinDynamicPadding
	randomPadding, err := GenerateRandomBytes(paddingLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random padding: %w", err)
	}
	
	// Final embedded data includes core data and padding
	finalEmbeddedData := append(embeddedCoreData, randomPadding...)

	// HTTP chunked encoding format:
	// <chunk-size> CRLF
	// <chunk-data> CRLF
	// (Optional: trailing headers if this is the last chunk, or 0 CRLF CRLF)

	chunkSize := len(finalEmbeddedData)
	chunkSizeHex := []byte(fmt.Sprintf("%x%s", chunkSize, httpCRLF)) // e.g., "7b\r\n"

	packet := new(bytes.Buffer)
	packet.Write(chunkSizeHex)
	packet.Write(finalEmbeddedData)
	packet.WriteString(httpCRLF) // CRLF after chunk data

	return packet.Bytes(), nil
}

// DeobfuscateModeHTTPFragment parses a packet mimicking an HTTP body fragment.
func DeobfuscateModeHTTPFragment(in []byte) ([]byte, []byte, []byte, error) {
	// Find the first CRLF to get chunk size
	crlfIdx := bytes.Index(in, []byte(httpCRLF))
	if crlfIdx == -1 {
		return nil, nil, nil, fmt.Errorf("HTTP fragment: no CRLF after chunk size")
	}

	chunkSizeHex := in[0:crlfIdx]
	chunkSize, err := strconv.ParseInt(string(chunkSizeHex), 16, 64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("HTTP fragment: invalid chunk size hex: %w", err)
	}

	chunkDataStart := crlfIdx + len(httpCRLF) // After CRLF
	expectedChunkDataEnd := chunkDataStart + int(chunkSize)
	
	if len(in) < expectedChunkDataEnd {
		return nil, nil, nil, fmt.Errorf("HTTP fragment: data truncated, expected %d bytes, got %d", int(chunkSize), len(in)-chunkDataStart)
	}

	finalEmbeddedData := in[chunkDataStart:expectedChunkDataEnd]

	// Verify trailing CRLF
	if len(in) < expectedChunkDataEnd+len(httpCRLF) || !bytes.Equal(in[expectedChunkDataEnd:expectedChunkDataEnd+len(httpCRLF)], []byte(httpCRLF)) {
		return nil, nil, nil, fmt.Errorf("HTTP fragment: missing CRLF after chunk data")
	}

	// Extract SegmentStateToken
	if len(finalEmbeddedData) < SegmentStateTokenLen {
		return nil, nil, nil, fmt.Errorf("embedded data too short for segment state token")
	}
	segmentStateToken := finalEmbeddedData[0:SegmentStateTokenLen]
	currentEmbeddedOffset := SegmentStateTokenLen

	// Extract metadata from token to get encryptedPayloadLen
	_, _, _, encryptedPayloadLen, err := ExtractSegmentMetadata(segmentStateToken)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to extract metadata from segment state token: %w", err)
	}

	// Extract Nonce
	if len(finalEmbeddedData)-currentEmbeddedOffset < NonceLen {
		return nil, nil, nil, fmt.Errorf("embedded data too short for nonce")
	}
	nonce := finalEmbeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	// Extract Encrypted Payload based on embedded length
	expectedEncryptedEnd := currentEmbeddedOffset + int(encryptedPayloadLen)
	if len(finalEmbeddedData) < expectedEncryptedEnd {
		return nil, nil, nil, fmt.Errorf("embedded data truncated, encrypted payload shorter than specified in token")
	}
	encryptedSegmentPayload := finalEmbeddedData[currentEmbeddedOffset:expectedEncryptedEnd]
	
	// Any data after encryptedSegmentPayload is considered padding and ignored.
	if len(encryptedSegmentPayload) < TagLen {
		return nil, nil, nil, fmt.Errorf("encrypted segment payload too short for tag")
	}

	return segmentStateToken, nonce, encryptedSegmentPayload, nil
}


// --- Mode D: NTP Client Request Mimicry ---

const (
	ntpPacketLen = 48 // Standard NTP packet length
	ntpEmbedOffset = 16 // Offset where reference ID starts, good embedding point
)

// ObfuscateModeNTPRequest crafts a packet that mimics an NTP client request.
// It embeds segmentStateToken, nonce, and encryptedSegmentPayload into the NTP packet's unused/randomizable fields.
func ObfuscateModeNTPRequest(randSrc *mrand.Rand, segmentStateToken, nonce, encryptedSegmentPayload []byte) ([]byte, error) {
	// Total data to embed: SegmentStateToken + Nonce + Encrypted Segment Payload
	embeddedCoreData := make([]byte, 0, len(segmentStateToken)+len(nonce)+len(encryptedSegmentPayload))
	embeddedCoreData = append(embeddedCoreData, segmentStateToken...)
	embeddedCoreData = append(embeddedCoreData, nonce...)
	embeddedCoreData = append(embeddedCoreData, encryptedSegmentPayload...)

	// Create a standard NTP client request packet (RFC 5905)
	// Most fields are fixed for a client request, but some are randomizable or unused.
	// We'll embed data into the "Reference ID" and subsequent fields (until Transmit Timestamp).
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

	// Reference ID (4 bytes): This is the first embedding point
	// Transmit Timestamp (8 bytes): This is the client's send time.
	// We'll embed our data here and in subsequent unused fields.
	// NTP timestamp is seconds since 1900-01-01 00:00:00 UTC.
	ntpEpoch := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now().UTC()
	seconds := uint32(now.Sub(ntpEpoch).Seconds())
	fraction := uint32(float64(now.Nanosecond()) / 1e9 * math.MaxUint32) // Fractional part

	transmitTimestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint32(transmitTimestampBytes[0:4], seconds)
	binary.BigEndian.PutUint32(transmitTimestampBytes[4:8], fraction)

	// Available space for embedding: from ntpEmbedOffset to end of packet
	availableSpace := ntpPacketLen - ntpEmbedOffset

	if len(embeddedCoreData) > availableSpace {
		return nil, fmt.Errorf("embedded data (%d bytes) too large for NTP packet available space (%d bytes)", len(embeddedCoreData), availableSpace)
	}

	// Copy embedded data starting from ntpEmbedOffset
	copy(packet[ntpEmbedOffset:], embeddedCoreData)

	// Fill remaining space with random bytes
	remainingSpace := availableSpace - len(embeddedCoreData)
	if remainingSpace > 0 {
		randomPadding, err := GenerateRandomBytes(remainingSpace)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random bytes for NTP padding: %w", err)
		}
		copy(packet[ntpEmbedOffset+len(embeddedCoreData):], randomPadding)
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

	// Extract embedded data from the embedding offset
	embeddedData := in[ntpEmbedOffset:]

	// Extract SegmentStateToken
	if len(embeddedData) < SegmentStateTokenLen {
		return nil, nil, nil, fmt.Errorf("embedded data too short for segment state token")
	}
	segmentStateToken := embeddedData[0:SegmentStateTokenLen]
	currentEmbeddedOffset := SegmentStateTokenLen

	// Extract metadata from token to get encryptedPayloadLen
	_, _, _, encryptedPayloadLen, err := ExtractSegmentMetadata(segmentStateToken)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to extract metadata from segment state token: %w", err)
	}

	// Extract Nonce
	if len(embeddedData)-currentEmbeddedOffset < NonceLen {
		return nil, nil, nil, fmt.Errorf("embedded data too short for nonce")
	}
	nonce := embeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	// Extract Encrypted Payload based on embedded length
	expectedEncryptedEnd := currentEmbeddedOffset + int(encryptedPayloadLen)
	if len(embeddedData) < expectedEncryptedEnd {
		return nil, nil, nil, fmt.Errorf("embedded data truncated, encrypted payload shorter than specified in token")
	}
	encryptedSegmentPayload := embeddedData[currentEmbeddedOffset:expectedEncryptedEnd]
	
	// Any data after encryptedSegmentPayload is considered padding and ignored.
	if len(encryptedSegmentPayload) < TagLen {
		return nil, nil, nil, fmt.Errorf("encrypted segment payload too short for tag")
	}

	return segmentStateToken, nonce, encryptedSegmentPayload, nil
}


// --- Mode E: Decoy Packet Generation ---

const (
	decoyMagicLen     = 4 // Length of magic bytes
	decoyMagic        = 0xDECAFBAD // "DECAFBAD" in hex
	decoyHMACSize     = HMACSize // Use standard HMAC size
	decoyMinTotalLen  = decoyMagicLen + decoyHMACSize + MinDynamicPadding // Minimum length for a believable decoy packet
	decoyMaxTotalLen  = decoyMagicLen + decoyHMACSize + MaxDynamicPadding // Maximum length for a believable decoy packet
)

// ObfuscateModeDecoy generates a decoy packet that looks like legitimate traffic
// but contains no actual payload. It uses the cumulative hash to vary its appearance.
// Decoy packet structure: [DecoyMagicBytes] + [DecoyHMAC] + [RandomPadding]
// DecoyHMAC is HMAC(PSK, cumulativeHash, DecoyMagicBytes + RandomPadding).
func ObfuscateModeDecoy(randSrc *mrand.Rand, psk []byte, cumulativeHash []byte) ([]byte, error) {
	paddingLen := randSrc.Intn(MaxDynamicPadding-MinDynamicPadding+1) + MinDynamicPadding
	randomPadding, err := GenerateRandomBytes(paddingLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random padding for decoy: %w", err)
	}

	decoyMagicBytes := make([]byte, decoyMagicLen)
	binary.BigEndian.PutUint32(decoyMagicBytes, decoyMagic)

	// Data for HMAC calculation: DecoyMagicBytes + RandomPadding
	hmacData := append(decoyMagicBytes, randomPadding...)

	// Derive a specific HMAC key for decoy packets, using cumulative hash
	decoyHMACKey, err := DeriveKey(psk, "cosmicdust_decoy_hmac_salt", cumulativeHash, HMACKeyLen)
	if err != nil {
		return nil, fmt.Errorf("failed to derive decoy HMAC key: %w", err)
	}
	mac := hmac.New(sha256.New, decoyHMACKey)
	mac.Write(hmacData)
	computedHMAC := mac.Sum(nil)

	packet := make([]byte, decoyMagicLen+decoyHMACSize+paddingLen)
	copy(packet[0:decoyMagicLen], decoyMagicBytes)
	copy(packet[decoyMagicLen:decoyMagicLen+decoyHMACSize], computedHMAC)
	copy(packet[decoyMagicLen+decoyHMACSize:], randomPadding)

	return packet, nil
}

// DeobfuscateModeDecoy attempts to identify if an incoming packet is a decoy.
// It returns true if it's a decoy, false otherwise, and an error if parsing fails.
// It strictly verifies the magic bytes and the HMAC.
func DeobfuscateModeDecoy(psk []byte, cumulativeHash []byte, in []byte) (bool, error) {
	if len(in) < decoyMagicLen+decoyHMACSize {
		return false, fmt.Errorf("decoy packet too short for magic and HMAC")
	}

	receivedMagicBytes := in[0:decoyMagicLen]
	receivedHMAC := in[decoyMagicLen : decoyMagicLen+decoyHMACSize]
	receivedPadding := in[decoyMagicLen+decoyHMACSize:]

	// 1. Check Magic Bytes
	expectedMagicBytes := make([]byte, decoyMagicLen)
	binary.BigEndian.PutUint32(expectedMagicBytes, decoyMagic)
	if !bytes.Equal(receivedMagicBytes, expectedMagicBytes) {
		return false, fmt.Errorf("decoy magic bytes mismatch")
	}

	// 2. Recompute HMAC and verify
	hmacData := append(receivedMagicBytes, receivedPadding...)
	decoyHMACKey, err := DeriveKey(psk, "cosmicdust_decoy_hmac_salt", cumulativeHash, HMACKeyLen)
	if err != nil {
		return false, fmt.Errorf("failed to derive decoy HMAC key during verification: %w", err)
	}
	mac := hmac.New(sha256.New, decoyHMACKey)
	mac.Write(hmacData)
	computedHMAC := mac.Sum(nil)

	if !bytes.Equal(computedHMAC, receivedHMAC) {
		return false, fmt.Errorf("decoy HMAC verification failed")
	}

	// If both magic bytes and HMAC are valid, it's a legitimate decoy.
	return true, nil
}
