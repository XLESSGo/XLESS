package cosmicdust

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	mrand "math/rand"
	"strconv"
	"strings"
	"time"
)

const (
	ModeTLSAppData   = 0
	ModeDNSQuery     = 1
	ModeHTTPFragment = 2
	ModeNTPRequest   = 3
	ModeDecoy        = 4
	NumDisguiseModes = 5
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


const (
	tlsRecordHeaderLen = 5
	tlsAppDataRecordType = 0x17
	tlsVersionTLS12      = 0x0303
	tlsMinAppDataLen     = SegmentStateTokenLen + NonceLen + TagLen
)

func ObfuscateModeTLSAppData(randSrc *mrand.Rand, segmentStateToken, nonce, encryptedSegmentPayload []byte) ([]byte, error) {
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

	recordLen := len(finalEmbeddedData)
	if recordLen > math.MaxUint16 {
		return nil, fmt.Errorf("TLS application data record too large: %d bytes", recordLen)
	}

	packet := make([]byte, tlsRecordHeaderLen+recordLen)
	packet[0] = tlsAppDataRecordType
	binary.BigEndian.PutUint16(packet[1:3], tlsVersionTLS12)
	binary.BigEndian.PutUint16(packet[3:5], uint16(recordLen))
	copy(packet[tlsRecordHeaderLen:], finalEmbeddedData)

	return packet, nil
}

func DeobfuscateModeTLSAppData(in []byte) ([]byte, []byte, []byte, int, error) {
	if len(in) < tlsRecordHeaderLen+tlsMinAppDataLen {
		return nil, nil, nil, 0, fmt.Errorf("TLS AppData packet too short")
	}

	if in[0] != tlsAppDataRecordType {
		return nil, nil, nil, 0, fmt.Errorf("incorrect TLS record type: 0x%X, expected 0x%X", in[0], tlsAppDataRecordType)
	}
	if binary.BigEndian.Uint16(in[1:3]) != tlsVersionTLS12 {
		return nil, nil, nil, 0, fmt.Errorf("TLS version mismatch: 0x%X, expected 0x%X", binary.BigEndian.Uint16(in[1:3]), tlsVersionTLS12)
	}
	recordLen := int(binary.BigEndian.Uint16(in[3:5]))
	
	totalPacketLen := tlsRecordHeaderLen + recordLen
	if len(in) < totalPacketLen {
		return nil, nil, nil, 0, fmt.Errorf("TLS record truncated: header says %d bytes, but only %d available", recordLen, len(in)-tlsRecordHeaderLen)
	}

	finalEmbeddedData := in[tlsRecordHeaderLen:totalPacketLen]

	if len(finalEmbeddedData) < SegmentStateTokenLen {
		return nil, nil, nil, 0, fmt.Errorf("embedded data too short for segment state token")
	}
	segmentStateToken := finalEmbeddedData[0:SegmentStateTokenLen]
	currentEmbeddedOffset := SegmentStateTokenLen

	_, _, _, encryptedPayloadLen, err := ExtractSegmentMetadata(segmentStateToken)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("failed to extract metadata from segment state token: %w", err)
	}

	if len(finalEmbeddedData)-currentEmbeddedOffset < NonceLen {
		return nil, nil, nil, 0, fmt.Errorf("embedded data too short for nonce")
	}
	nonce := finalEmbeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	expectedEncryptedEnd := currentEmbeddedOffset + int(encryptedPayloadLen)
	if len(finalEmbeddedData) < expectedEncryptedEnd {
		return nil, nil, nil, 0, fmt.Errorf("embedded data truncated, encrypted payload shorter than specified in token")
	}
	encryptedSegmentPayload := finalEmbeddedData[currentEmbeddedOffset:expectedEncryptedEnd]
	
	if len(encryptedSegmentPayload) < TagLen {
		return nil, nil, nil, 0, fmt.Errorf("encrypted segment payload too short for tag")
	}

	return segmentStateToken, nonce, encryptedSegmentPayload, totalPacketLen, nil
}


const (
	dnsHeaderLen     = 12
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


const (
	httpFragmentMinLen = 100
	httpCRLF           = "\r\n"
	httpDoubleCRLF     = "\r\n\r\n"
)

func ObfuscateModeHTTPFragment(randSrc *mrand.Rand, segmentStateToken, nonce, encryptedSegmentPayload []byte) ([]byte, error) {
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

	chunkSize := len(finalEmbeddedData)
	chunkSizeHex := []byte(fmt.Sprintf("%x%s", chunkSize, httpCRLF))

	packet := new(bytes.Buffer)
	packet.Write(chunkSizeHex)
	packet.Write(finalEmbeddedData)
	packet.WriteString(httpCRLF)

	return packet.Bytes(), nil
}

func DeobfuscateModeHTTPFragment(in []byte) ([]byte, []byte, []byte, int, error) {
	crlfIdx := bytes.Index(in, []byte(httpCRLF))
	if crlfIdx == -1 {
		return nil, nil, nil, 0, fmt.Errorf("HTTP fragment: no CRLF after chunk size")
	}

	chunkSizeHex := in[0:crlfIdx]
	chunkSize, err := strconv.ParseInt(string(chunkSizeHex), 16, 64)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("HTTP fragment: invalid chunk size hex: %w", err)
	}

	chunkDataStart := crlfIdx + len(httpCRLF)
	expectedChunkDataEnd := chunkDataStart + int(chunkSize)
	
	if len(in) < expectedChunkDataEnd {
		return nil, nil, nil, 0, fmt.Errorf("HTTP fragment: data truncated, expected %d bytes, got %d", int(chunkSize), len(in)-chunkDataStart)
	}

	finalEmbeddedData := in[chunkDataStart:expectedChunkDataEnd]

	if len(in) < expectedChunkDataEnd+len(httpCRLF) || !bytes.Equal(in[expectedChunkDataEnd:expectedChunkDataEnd+len(httpCRLF)], []byte(httpCRLF)) {
		return nil, nil, nil, 0, fmt.Errorf("HTTP fragment: missing CRLF after chunk data")
	}

	if len(finalEmbeddedData) < SegmentStateTokenLen {
		return nil, nil, nil, 0, fmt.Errorf("embedded data too short for segment state token")
	}
	segmentStateToken := finalEmbeddedData[0:SegmentStateTokenLen]
	currentEmbeddedOffset := SegmentStateTokenLen

	_, _, _, encryptedPayloadLen, err := ExtractSegmentMetadata(segmentStateToken)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("failed to extract metadata from segment state token: %w", err)
	}

	if len(finalEmbeddedData)-currentEmbeddedOffset < NonceLen {
		return nil, nil, nil, 0, fmt.Errorf("embedded data too short for nonce")
	}
	nonce := finalEmbeddedData[currentEmbeddedOffset : currentEmbeddedOffset+NonceLen]
	currentEmbeddedOffset += NonceLen

	expectedEncryptedEnd := currentEmbeddedOffset + int(encryptedPayloadLen)
	if len(finalEmbeddedData) < expectedEncryptedEnd {
		return nil, nil, nil, 0, fmt.Errorf("embedded data truncated, encrypted payload shorter than specified in token")
	}
	encryptedSegmentPayload := finalEmbeddedData[currentEmbeddedOffset:expectedEncryptedEnd]
	
	if len(encryptedSegmentPayload) < TagLen {
		return nil, nil, nil, 0, fmt.Errorf("encrypted segment payload too short for tag")
	}

	totalPacketLen := len(chunkSizeHex) + int(chunkSize) + len(httpCRLF)

	return segmentStateToken, nonce, encryptedSegmentPayload, totalPacketLen, nil
}


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
	decoyMagicLen     = 4
	decoyMagic        = 0xDECAFBAD
	decoyHMACSize     = HMACSize
	decoyMinTotalLen  = decoyMagicLen + decoyHMACSize + MinDynamicPadding
	decoyMaxTotalLen  = decoyMagicLen + decoyHMACSize + MaxDynamicPadding
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
