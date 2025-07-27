package cosmos

import (
	"bytes"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"strconv"
	"strings"
)

// obfuscateModeA (HTTP GET Mimicry) handles the obfuscation for Mode A.
// It returns the total length written to out, or 0 on error.
func obfuscateModeA(randSrc *mrand.Rand, stateToken, nonce, encryptedPayload, out []byte) int {
	httpBodyLen := StateTokenLen + NonceLen + len(encryptedPayload)
	httpHeaders := fmt.Sprintf(
		"GET /%s HTTP/1.1\r\n"+
			"Host: example.com\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.%d.%d Safari/537.36\r\n"+
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"+
			"Connection: keep-alive\r\n"+
			"Content-Length: %d\r\n"+ // This is for the embedded data
			"\r\n",
		strings.Repeat("a", randSrc.Intn(16)+4), // Random URL path length
		randSrc.Intn(50)+70,                    // Chrome major version
		randSrc.Intn(9999)+1000,                // Chrome build version
		randSrc.Intn(99)+10,                    // Chrome patch version
		httpBodyLen,
	)
	httpHeadersBytes := []byte(httpHeaders)

	totalOutputLen := len(httpHeadersBytes) + httpBodyLen

	if len(out) < totalOutputLen {
		return 0
	}

	outCursor := 0
	copy(out[outCursor:], httpHeadersBytes)
	outCursor += len(httpHeadersBytes)

	copy(out[outCursor:], stateToken)
	outCursor += len(stateToken)

	copy(out[outCursor:], nonce)
	outCursor += NonceLen

	copy(out[outCursor:], encryptedPayload)
	outCursor += len(encryptedPayload)

	return totalOutputLen
}

// deobfuscateModeA (HTTP GET Mimicry) attempts to parse and extract data from a Mode A packet.
// It returns stateToken, nonce, encryptedPayloadWithTag, or error.
func deobfuscateModeA(in []byte) ([]byte, []byte, []byte, error) {
	doubleCRLF := bytes.Index(in, []byte("\r\n\r\n"))
	if doubleCRLF == -1 {
		return nil, nil, nil, fmt.Errorf("not a valid HTTP header format (no double CRLF)")
	}
	headerEnd := doubleCRLF + 4 // Include \r\n\r\n

	httpHeader := string(in[:headerEnd])
	contentLengthPrefix := "Content-Length: "
	idx := strings.Index(httpHeader, contentLengthPrefix)
	if idx == -1 {
		return nil, nil, nil, fmt.Errorf("content-Length header not found")
	}
	start := idx + len(contentLengthPrefix)
	end := strings.Index(httpHeader[start:], "\r\n")
	if end == -1 {
		return nil, nil, nil, fmt.Errorf("invalid Content-Length line")
	}
	contentLengthStr := strings.TrimSpace(httpHeader[start : start+end])
	
	payloadLen, err := strconv.Atoi(contentLengthStr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid Content-Length value: %w", err)
	}

	payloadOffset := headerEnd // Payload starts right after HTTP headers
	if len(in) < payloadOffset+payloadLen {
		return nil, nil, nil, fmt.Errorf("packet truncated or Content-Length mismatch: expected %d, got %d", payloadOffset+payloadLen, len(in))
	}

	// Extract state token, nonce, encrypted payload
	if payloadLen < StateTokenLen+NonceLen+TagLen { // Must be enough for state token, nonce, and at least a tag
		return nil, nil, nil, fmt.Errorf("embedded payload too short for state token + nonce + tag")
	}

	stateToken := in[payloadOffset : payloadOffset+StateTokenLen]
	payloadOffset += StateTokenLen

	nonce := in[payloadOffset : payloadOffset+NonceLen]
	payloadOffset += NonceLen

	encryptedPayloadWithTag := in[payloadOffset : headerEnd+payloadLen] // Remaining part is encrypted payload + tag

	return stateToken, nonce, encryptedPayloadWithTag, nil
}

// obfuscateModeB (Generic Binary with random padding) handles the obfuscation for Mode B.
// It returns the total length written to out, or 0 on error.
func obfuscateModeB(randSrc *mrand.Rand, stateToken, nonce, encryptedPayload, out []byte) int {
	prefixPaddingLen := randSrc.Intn(MaxDynamicPadding-MinDynamicPadding+1) + MinDynamicPadding
	suffixPaddingLen := randSrc.Intn(MaxDynamicPadding-MinDynamicPadding+1) + MinDynamicPadding

	// Total Packet Len = MagicLen + LenFieldLen (2) + PrefixPaddingLenField (2) + PrefixPaddingLen + StateTokenLen + NonceLen + EncryptedPayloadWithTagLen + SuffixPaddingLenField (2) + SuffixPaddingLen
	internalPayloadLen := StateTokenLen + NonceLen + len(encryptedPayload) // The data we are hiding
	totalPacketDataLen := BinaryMagicLen + 2 + 2 + prefixPaddingLen + internalPayloadLen + 2 + suffixPaddingLen

	if totalPacketDataLen > 65535 { // Max uint16 for length field
		return 0 // Packet too large
	}

	totalOutputLen := totalPacketDataLen

	if len(out) < totalOutputLen {
		return 0
	}

	outCursor := 0
	// Magic Bytes
	binary.BigEndian.PutUint32(out[outCursor:], BinaryMagic)
	outCursor += BinaryMagicLen

	// Total Packet Length (excluding magic bytes)
	binary.BigEndian.PutUint16(out[outCursor:], uint16(totalOutputLen-BinaryMagicLen))
	outCursor += 2

	// Prefix Padding Length
	binary.BigEndian.PutUint16(out[outCursor:], uint16(prefixPaddingLen))
	outCursor += 2

	// Random Prefix Padding
	prefixPadding, err := GenerateRandomBytes(prefixPaddingLen)
	if err != nil {
		return 0
	}
	copy(out[outCursor:], prefixPadding)
	outCursor += prefixPaddingLen

	// State Token
	copy(out[outCursor:], stateToken)
	outCursor += len(stateToken)

	// Nonce
	copy(out[outCursor:], nonce)
	outCursor += NonceLen

	// Encrypted Payload (Ciphertext + Tag)
	copy(out[outCursor:], encryptedPayload)
	outCursor += len(encryptedPayload)

	// Suffix Padding Length
	binary.BigEndian.PutUint16(out[outCursor:], uint16(suffixPaddingLen))
	outCursor += 2

	// Random Suffix Padding
	suffixPadding, err := GenerateRandomBytes(suffixPaddingLen)
	if err != nil {
		return 0
	}
	copy(out[outCursor:], suffixPadding)
	outCursor += suffixPaddingLen

	return totalOutputLen
}

// deobfuscateModeB (Generic Binary) attempts to parse and extract data from a Mode B packet.
// It returns stateToken, nonce, encryptedPayloadWithTag, or error.
func deobfuscateModeB(in []byte) ([]byte, []byte, []byte, error) {
	if len(in) < BinaryMagicLen+2+2+StateTokenLen+NonceLen+TagLen+2 { // Min length for headers + min payload + padding length fields
		return nil, nil, nil, fmt.Errorf("packet too short for minimal binary mode structure")
	}

	// Verify Magic Bytes
	magic := binary.BigEndian.Uint32(in[0:BinaryMagicLen])
	if magic != BinaryMagic {
		return nil, nil, nil, fmt.Errorf("magic bytes mismatch: got 0x%X, expected 0x%X", magic, BinaryMagic)
	}

	// Verify Total Packet Length
	expectedTotalPacketDataLen := int(binary.BigEndian.Uint16(in[BinaryMagicLen:BinaryMagicLen+2])) + BinaryMagicLen
	if len(in) != expectedTotalPacketDataLen {
		return nil, nil, nil, fmt.Errorf("total packet length mismatch: header says %d, actual %d", expectedTotalPacketDataLen, len(in))
	}

	currentParseOffset := BinaryMagicLen + 2 // After magic and total length field

	// Read Prefix Padding Length
	prefixPaddingLen := int(binary.BigEndian.Uint16(in[currentParseOffset : currentParseOffset+2]))
	currentParseOffset += 2

	if len(in) < currentParseOffset+prefixPaddingLen+StateTokenLen+NonceLen+TagLen+2 { // Ensure enough for remaining parts
		return nil, nil, nil, fmt.Errorf("packet truncated after prefix padding length field")
	}
	currentParseOffset += prefixPaddingLen // Skip prefix padding

	// Extract State Token
	stateToken := in[currentParseOffset : currentParseOffset+StateTokenLen]
	currentParseOffset += StateTokenLen

	// Extract Nonce
	nonce := in[currentParseOffset : currentParseOffset+NonceLen]
	currentParseOffset += NonceLen

	// Read Suffix Padding Length (located at the end of the packet, before actual suffix padding)
	suffixPaddingLenStart := len(in) - 2 // Suffix padding length field is 2 bytes before the end of the packet
	if suffixPaddingLenStart < 0 || len(in) < suffixPaddingLenStart+2 {
		return nil, nil, nil, fmt.Errorf("suffix padding length field missing or truncated")
	}
	suffixPaddingLen := int(binary.BigEndian.Uint16(in[suffixPaddingLenStart : suffixPaddingLenStart+2]))

	// The encrypted payload is everything between (Nonce end) and (Suffix padding length start).
	encryptedPayloadWithTagEnd := suffixPaddingLenStart
	if encryptedPayloadWithTagEnd < currentParseOffset {
		return nil, nil, nil, fmt.Errorf("encrypted payload region invalid")
	}
	encryptedPayloadWithTag := in[currentParseOffset:encryptedPayloadWithTagEnd]

	if len(encryptedPayloadWithTag) < TagLen { // Must at least contain a tag
		return nil, nil, nil, fmt.Errorf("encrypted payload too short for tag")
	}

	return stateToken, nonce, encryptedPayloadWithTag, nil
}
