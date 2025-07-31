package cosmicdust

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	mrand "math/rand"
	"time"
)

const (
	// 定义新的模式常量
	ModeDTLSHandshake = 0 // Previously ModeTLSAppData, now mimicking DTLS
	ModeDNSQuery      = 1
	ModeNTPRequest    = 2
	ModeDecoy         = 3
	// 移除 ModeHTTPFragment

	NumDisguiseModes = 4 // Total number of active disguise modes
)

func embedDataIntoVariableLengthField(data []byte, fieldLenBytes int) ([]byte, error) {
	if fieldLenBytes != 1 && fieldLenBytes != 2 && fieldLenBytes != 4 {
		return nil, fmt.Errorf("unsupported field length bytes: %d", fieldLenBytes)
	}
	if len(data) > (1<<(fieldLenBytes*8))-1 {
		return nil, fmt.Errorf("data too long for %d-byte length field", fieldLenBytes)
	}

	buf := new(bytes.Buffer)
	lenBytes := make([]byte, fieldLenBytes)
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


// --- 新增 DTLS 握手模式 ---
const (
	dtlsRecordHeaderLen = 13 // Type (1) + Version (2) + Epoch (2) + Sequence Number (6) + Length (2)
	dtlsHandshakeType   = 22 // Handshake
	dtlsVersionTLS12    = 0xFEFD // DTLS 1.2 version
	dtlsClientHelloType = 0x01   // ClientHello message type
	dtlsMinHandshakeLen = 12 // Min ClientHello message len (MsgType+Len+Seq+FragOff+FragLen+Version+Random+SessionIDLen...)
)

// ObfuscateModeDTLSHandshake 模仿 DTLS 1.2 ClientHello 握手包结构
func ObfuscateModeDTLSHandshake(randSrc *mrand.Rand, segmentStateToken, nonce, encryptedSegmentPayload []byte) ([]byte, error) {
	embeddedCoreData := make([]byte, 0, len(segmentStateToken)+len(nonce)+len(encryptedSegmentPayload))
	embeddedCoreData = append(embeddedCoreData, segmentStateToken...)
	embeddedCoreData = append(embeddedCoreData, nonce...)
	embeddedCoreData = append(embeddedCoreData, encryptedSegmentPayload...)

	paddingLen := randSrc.Intn(MaxDynamicPadding-MinDynamicPadding+1) + MinDynamicPadding
	randomPadding, err := GenerateRandomBytes(paddingLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random padding: %w", err)
	}
	
	finalEmbeddedData := append(embeddedCoreData, randomPadding...)

	// DTLS Record Header
	// Type (1 byte): Handshake (22)
	// Version (2 bytes): DTLS 1.2 (0xFEFD)
	// Epoch (2 bytes): 0 for initial handshake
	// Sequence Number (6 bytes): Randomly generated for each record
	// Length (2 bytes): Length of the DTLS handshake message

	// DTLS Handshake Message (simplified ClientHello)
	// MsgType (1 byte): ClientHello (0x01)
	// Length (3 bytes): Length of the handshake message payload (excluding MsgType and its length field)
	// Message Sequence (2 bytes): Handshake message sequence number (0 for first message)
	// Fragment Offset (3 bytes): 0
	// Fragment Length (3 bytes): Total length of the handshake message payload
	// Version (2 bytes): TLS 1.2 (0x0303)
	// Random (32 bytes): Client random bytes (can embed some data here)
	// Session ID Length (1 byte): 0 (no session ID)
	// Cipher Suites Length (2 bytes): Common cipher suites
	// Cipher Suites (variable bytes)
	// Compression Methods Length (1 byte): 1
	// Compression Methods (1 byte): 0 (null)
	// Extensions Length (2 bytes): Common extensions
	// Extensions (variable bytes)

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
		return nil, fmt.Errorf("DTLS record too large: %d bytes", recordLen)
	}

	packet := make([]byte, dtlsRecordHeaderLen+recordLen)
	packet[0] = dtlsHandshakeType // Record Type: Handshake
	binary.BigEndian.PutUint16(packet[1:3], dtlsVersionTLS12) // DTLS Version 1.2
	binary.BigEndian.PutUint16(packet[3:5], 0) // Epoch (0)
	// Sequence Number (6 bytes) - simplified, usually derived from connection state
	binary.BigEndian.PutUint32(packet[5:9], randSrc.Uint32()) // Just random for obfuscation
	binary.BigEndian.PutUint16(packet[11:13], uint16(recordLen)) // Length of handshake message

	copy(packet[dtlsRecordHeaderLen:], handshakeMsgPayload)

	return packet, nil
}

// DeobfuscateModeDTLSHandshake 从模仿的 DTLS 握手包中提取嵌入数据
func DeobfuscateModeDTLSHandshake(in []byte) ([]byte, []byte, []byte, int, error) {
	if len(in) < dtlsRecordHeaderLen+dtlsMinHandshakeLen {
		return nil, nil, nil, 0, fmt.Errorf("DTLS handshake packet too short")
	}

	if in[0] != dtlsHandshakeType {
		return nil, nil, nil, 0, fmt.Errorf("incorrect DTLS record type: 0x%X, expected 0x%X", in[0], dtlsHandshakeType)
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
	// The 32-byte random field starts at offset 6 after the initial 12 bytes of Handshake Header (MsgType+Len+MsgSeq+FragOff+FragLen+Version)
	// So relative to handshakeMsg, it starts at byte 14.
	extractedEmbeddedData := dtlsHandshakeMsg[14 : 14 + 32] // Taking the whole random for simplicity, assuming data is at the beginning

	if len(extractedEmbeddedData) < SegmentStateTokenLen {
		return nil, nil, nil, 0, fmt.Errorf("extracted embedded data too short for segment state token")
	}
	segmentStateToken := extractedEmbeddedData[0:SegmentStateTokenLen]
	currentEmbeddedOffset := SegmentStateTokenLen

	_, _, _, encryptedPayloadLen, err := ExtractSegmentMetadata(segmentStateToken)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("failed to extract metadata from segment state token: %w", err)
	}

	if len(extractedEmbeddedData)-currentEmbeddedOffset < NonceLen {
		return nil, nil, nil, 0, fmt.Errorf("extracted embedded data too short for nonce")
	}
	nonce := extractedEmbeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	expectedEncryptedEnd := currentEmbeddedOffset + int(encryptedPayloadLen)
	if len(extractedEmbeddedData) < expectedEncryptedEnd {
		return nil, nil, nil, 0, fmt.Errorf("extracted embedded data truncated, encrypted payload shorter than specified in token")
	}
	encryptedSegmentPayload := extractedEmbeddedData[currentEmbeddedOffset:expectedEncryptedEnd]
	
	if len(encryptedSegmentPayload) < TagLen {
		return nil, nil, nil, 0, fmt.Errorf("encrypted segment payload too short for tag")
	}

	return segmentStateToken, nonce, encryptedSegmentPayload, totalPacketLen, nil
}


const (
	dnsHeaderLen      = 12
	dnsQuestionMinLen = 5
	dnsARecordType    = 0x0001
	dnsINClass        = 0x0001
	dnsMaxLabelLen    = 63
)

func ObfuscateModeDNSQuery(randSrc *mrand.Rand, segmentStateToken, nonce, encryptedSegmentPayload []byte) ([]byte, error) {
	embeddedData := make([]byte, 0, len(segmentStateToken)+len(nonce)+len(encryptedSegmentPayload))
	embeddedData = append(embeddedData, segmentStateToken...)
	embeddedData = append(embeddedData, nonce...)
	embeddedData = append(embeddedData, encryptedSegmentPayload...)

	paddingLen := randSrc.Intn(MaxDynamicPadding-MinDynamicPadding+1) + MinDynamicPadding
	randomPadding, err := GenerateRandomBytes(paddingLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random padding: %w", err)
	}
	embeddedData = append(embeddedData, randomPadding...)


	dnsID := uint16(randSrc.Uint32() % 65535)

	dnsFlags := uint16(0x0100)

	qdCount := uint16(1)

	qNameBuf := new(bytes.Buffer)
	
	currentEmbeddedDataOffset := 0
	for currentEmbeddedDataOffset < len(embeddedData) {
		labelLen := min(len(embeddedData)-currentEmbeddedDataOffset, dnsMaxLabelLen)
		qNameBuf.WriteByte(byte(labelLen))
		qNameBuf.Write(embeddedData[currentEmbeddedDataOffset : currentEmbeddedDataOffset+labelLen])
		currentEmbeddedDataOffset += labelLen
	}

	qNameBuf.WriteByte(byte(7))
	qNameBuf.WriteString("example")
	qNameBuf.WriteByte(byte(3))
	qNameBuf.WriteString("com")
	qNameBuf.WriteByte(0x00)

	qName := qNameBuf.Bytes()

	qType := uint16(dnsARecordType)
	qClass := uint16(dnsINClass)

	dnsHeaderBytes := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(dnsHeaderBytes[0:2], dnsID)
	binary.BigEndian.PutUint16(dnsHeaderBytes[2:4], dnsFlags)
	binary.BigEndian.PutUint16(dnsHeaderBytes[4:6], qdCount)
	binary.BigEndian.PutUint16(dnsHeaderBytes[6:8], 0)
	binary.BigEndian.PutUint16(dnsHeaderBytes[8:10], 0)
	binary.BigEndian.PutUint16(dnsHeaderBytes[10:12], 0)

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

func DeobfuscateModeDNSQuery(in []byte) ([]byte, []byte, []byte, int, error) {
	if len(in) < dnsHeaderLen+dnsQuestionMinLen {
		return nil, nil, nil, 0, fmt.Errorf("DNS packet too short")
	}

	qdCount := binary.BigEndian.Uint16(in[4:6])
	if qdCount != 1 {
		return nil, nil, nil, 0, fmt.Errorf("DNS QDCOUNT not 1")
	}

	currentOffset := dnsHeaderLen
	
	qNameBuf := bytes.NewBuffer(in[currentOffset:])
	var extractedEmbeddedData []byte
	var consumedQNameBytes int = 0
	for {
		if qNameBuf.Len() == 0 {
			return nil, nil, nil, 0, fmt.Errorf("DNS QNAME truncated")
		}
		labelLen := int(qNameBuf.Next(1)[0])
		consumedQNameBytes++
		if labelLen == 0 {
			break
		}
		if qNameBuf.Len() < labelLen {
			return nil, nil, nil, 0, fmt.Errorf("DNS QNAME label truncated")
		}
		label := qNameBuf.Next(labelLen)
		consumedQNameBytes += labelLen
		extractedEmbeddedData = append(extractedEmbeddedData, label...)
	}
	
	exampleComSuffix := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm'}
	if bytes.HasSuffix(extractedEmbeddedData, exampleComSuffix) {
		extractedEmbeddedData = extractedEmbeddedData[:len(extractedEmbeddedData)-len(exampleComSuffix)]
	} else {
		return nil, nil, nil, 0, fmt.Errorf("DNS QNAME missing expected suffix")
	}

	if len(extractedEmbeddedData) < SegmentStateTokenLen {
		return nil, nil, nil, 0, fmt.Errorf("extracted embedded data too short for segment state token")
	}
	segmentStateToken := extractedEmbeddedData[0:SegmentStateTokenLen]
	currentEmbeddedOffset := SegmentStateTokenLen

	_, _, _, encryptedPayloadLen, err := ExtractSegmentMetadata(segmentStateToken)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("failed to extract metadata from segment state token: %w", err)
	}

	if len(extractedEmbeddedData)-currentEmbeddedOffset < NonceLen {
		return nil, nil, nil, 0, fmt.Errorf("extracted embedded data too short for nonce")
	}
	nonce := extractedEmbeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	expectedEncryptedEnd := currentEmbeddedOffset + int(encryptedPayloadLen)
	if len(extractedEmbeddedData) < expectedEncryptedEnd {
		return nil, nil, nil, 0, fmt.Errorf("extracted embedded data truncated, encrypted payload shorter than specified in token")
	}
	encryptedSegmentPayload := extractedEmbeddedData[currentEmbeddedOffset:expectedEncryptedEnd]
	
	if len(encryptedSegmentPayload) < TagLen {
		return nil, nil, nil, 0, fmt.Errorf("encrypted segment payload too short for tag")
	}

	totalPacketLen := dnsHeaderLen + consumedQNameBytes + 2 + 2
	if len(in) < totalPacketLen {
		return nil, nil, nil, 0, fmt.Errorf("DNS packet truncated after QNAME/QTYPE/QCLASS")
	}

	return segmentStateToken, nonce, encryptedSegmentPayload, totalPacketLen, nil
}


// --- 移除 ObfuscateModeHTTPFragment 和 DeobfuscateModeHTTPFragment 函数 ---


const (
	ntpPacketLen = 48
	ntpEmbedOffset = 16
)

func ObfuscateModeNTPRequest(randSrc *mrand.Rand, segmentStateToken, nonce, encryptedSegmentPayload []byte) ([]byte, error) {
	embeddedCoreData := make([]byte, 0, len(segmentStateToken)+len(nonce)+len(encryptedSegmentPayload))
	embeddedCoreData = append(embeddedCoreData, segmentStateToken...)
	embeddedCoreData = append(embeddedCoreData, nonce...)
	embeddedCoreData = append(embeddedCoreData, encryptedSegmentPayload...)

	packet := make([]byte, ntpPacketLen)

	packet[0] = 0b00_011_011

	packet[1] = 0

	packet[2] = byte(randSrc.Intn(10) + 4)

	packet[3] = byte(randSrc.Intn(5) - 20)

	binary.BigEndian.PutUint32(packet[4:8], randSrc.Uint32())

	binary.BigEndian.PutUint32(packet[8:12], randSrc.Uint32())

	ntpEpoch := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now().UTC()
	seconds := uint32(now.Sub(ntpEpoch).Seconds())
	fraction := uint32(float64(now.Nanosecond()) / 1e9 * math.MaxUint32)

	transmitTimestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint32(transmitTimestampBytes[0:4], seconds)
	binary.BigEndian.PutUint32(transmitTimestampBytes[4:8], fraction)

	availableSpace := ntpPacketLen - ntpEmbedOffset

	if len(embeddedCoreData) > availableSpace {
		return nil, fmt.Errorf("embedded data (%d bytes) too large for NTP packet available space (%d bytes)", len(embeddedCoreData), availableSpace)
	}

	copy(packet[ntpEmbedOffset:], embeddedCoreData)

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

func DeobfuscateModeNTPRequest(in []byte) ([]byte, []byte, []byte, int, error) {
	if len(in) != ntpPacketLen {
		return nil, nil, nil, 0, fmt.Errorf("NTP packet has incorrect length: %d, expected %d", len(in), ntpPacketLen)
	}

	if (in[0] & 0b11_111_111) != 0b00_011_011 {
		return nil, nil, nil, 0, fmt.Errorf("NTP header mismatch: 0x%X", in[0])
	}

	embeddedData := in[ntpEmbedOffset:]

	if len(embeddedData) < SegmentStateTokenLen {
		return nil, nil, nil, 0, fmt.Errorf("embedded data too short for segment state token")
	}
	segmentStateToken := embeddedData[0:SegmentStateTokenLen]
	currentEmbeddedOffset := SegmentStateTokenLen

	_, _, _, encryptedPayloadLen, err := ExtractSegmentMetadata(segmentStateToken)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("failed to extract metadata from segment state token: %w", err)
	}

	if len(embeddedData)-currentEmbeddedOffset < NonceLen {
		return nil, nil, nil, 0, fmt.Errorf("embedded data too short for nonce")
	}
	nonce := embeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	expectedEncryptedEnd := currentEmbeddedOffset + int(encryptedPayloadLen)
	if len(embeddedData) < expectedEncryptedEnd {
		return nil, nil, nil, 0, fmt.Errorf("embedded data truncated, encrypted payload shorter than specified in token")
	}
	encryptedSegmentPayload := embeddedData[currentEmbeddedOffset:expectedEncryptedEnd]
	
	if len(encryptedSegmentPayload) < TagLen {
		return nil, nil, nil, 0, fmt.Errorf("encrypted segment payload too short for tag")
	}

	return segmentStateToken, nonce, encryptedSegmentPayload, ntpPacketLen, nil
}


const (
	decoyMagicLen      = 4
	decoyMagic         = 0xDECAFBAD
	decoyHMACSize      = HMACSize
	decoyMinTotalLen   = decoyMagicLen + decoyHMACSize + MinDynamicPadding
	decoyMaxTotalLen   = decoyMagicLen + decoyHMACSize + MaxDynamicPadding
)

func ObfuscateModeDecoy(randSrc *mrand.Rand, psk []byte, cumulativeHash []byte) ([]byte, error) {
	paddingLen := randSrc.Intn(MaxDynamicPadding-MinDynamicPadding+1) + MinDynamicPadding
	randomPadding, err := GenerateRandomBytes(paddingLen)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random padding for decoy: %w", err)
	}

	decoyMagicBytes := make([]byte, decoyMagicLen)
	binary.BigEndian.PutUint32(decoyMagicBytes, decoyMagic)

	hmacData := append(decoyMagicBytes, randomPadding...)

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

func DeobfuscateModeDecoy(psk []byte, cumulativeHash []byte, in []byte) (bool, error) {
	if len(in) < decoyMagicLen+decoyHMACSize {
		return false, fmt.Errorf("decoy packet too short for magic and HMAC")
	}

	receivedMagicBytes := in[0:decoyMagicLen]
	receivedHMAC := in[decoyMagicLen : decoyMagicLen+decoyHMACSize]
	receivedPadding := in[decoyMagicLen+decoyHMACSize:]

	expectedMagicBytes := make([]byte, decoyMagicLen)
	binary.BigEndian.PutUint32(expectedMagicBytes, decoyMagic)
	if !bytes.Equal(receivedMagicBytes, expectedMagicBytes) {
		return false, fmt.Errorf("decoy magic bytes mismatch")
	}

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

	return true, nil
}
