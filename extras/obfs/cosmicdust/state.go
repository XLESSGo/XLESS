package cosmicdust

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// generateHMAC computes the HMAC for a given data slice using a derived HMAC key.
func generateHMAC(psk []byte, packetID uint64, segmentIndex uint16, cumulativeHash []byte, data []byte) ([]byte, error) {
	hmacKey, err := DeriveHMACKey(psk, packetID, segmentIndex, cumulativeHash)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// GenerateSegmentStateToken creates the token for each segment.
// Token structure: [PacketID (8 bytes)] + [SegmentIndex (2 bytes)] + [TotalSegments (2 bytes)] + [HMAC (32 bytes)]
// The HMAC covers: PacketID + SegmentIndex + TotalSegments + CumulativeHash + EncryptedSegmentPayload.
func GenerateSegmentStateToken(psk []byte, packetID uint64, segmentIndex uint16, totalSegments uint16, cumulativeHash []byte, encryptedSegmentPayload []byte) ([]byte, error) {
	segmentHeader := make([]byte, SegmentHeaderLen)
	binary.BigEndian.PutUint64(segmentHeader[0:SegmentIDLen], packetID)
	binary.BigEndian.PutUint16(segmentHeader[SegmentIDLen:SegmentIDLen+SegmentIndexLen], segmentIndex)
	binary.BigEndian.PutUint16(segmentHeader[SegmentIDLen+SegmentIndexLen:SegmentIDLen+SegmentIndexLen+TotalSegmentsLen], totalSegments)

	// Data for HMAC calculation: SegmentHeader + CumulativeHash + EncryptedSegmentPayload
	hmacData := append(segmentHeader, cumulativeHash...)
	hmacData = append(hmacData, encryptedSegmentPayload...)

	computedHMAC, err := generateHMAC(psk, packetID, segmentIndex, cumulativeHash, hmacData)
	if err != nil {
		return nil, err
	}

	segmentStateToken := make([]byte, SegmentStateTokenLen)
	copy(segmentStateToken[0:SegmentHeaderLen], segmentHeader)
	copy(segmentStateToken[SegmentHeaderLen:SegmentStateTokenLen], computedHMAC)

	return segmentStateToken, nil
}

// ExtractSegmentMetadata extracts PacketID, SegmentIndex, TotalSegments from the SegmentStateToken.
func ExtractSegmentMetadata(segmentStateToken []byte) (uint64, uint16, uint16, error) {
	if len(segmentStateToken) < SegmentHeaderLen {
		return 0, 0, 0, fmt.Errorf("segment state token too short to extract metadata")
	}
	packetID := binary.BigEndian.Uint64(segmentStateToken[0:SegmentIDLen])
	segmentIndex := binary.BigEndian.Uint16(segmentStateToken[SegmentIDLen:SegmentIDLen+SegmentIndexLen])
	totalSegments := binary.BigEndian.Uint16(segmentStateToken[SegmentIDLen+SegmentIndexLen:SegmentIDLen+SegmentIndexLen+TotalSegmentsLen])
	return packetID, segmentIndex, totalSegments, nil
}

// VerifySegmentStateToken verifies the HMAC of a received segment state token.
func VerifySegmentStateToken(psk []byte, packetID uint64, segmentIndex uint16, totalSegments uint16, expectedCumulativeHash []byte, receivedToken []byte, encryptedSegmentPayload []byte) (bool, error) {
	if len(receivedToken) != SegmentStateTokenLen {
		return false, fmt.Errorf("received segment state token has incorrect length: expected %d, got %d", SegmentStateTokenLen, len(receivedToken))
	}

	receivedSegmentHeader := receivedToken[0:SegmentHeaderLen]
	receivedHMAC := receivedToken[SegmentHeaderLen:SegmentStateTokenLen]

	// Reconstruct data for HMAC calculation: receivedSegmentHeader + expectedCumulativeHash + encryptedSegmentPayload
	hmacData := append(receivedSegmentHeader, expectedCumulativeHash...)
	hmacData = append(hmacData, encryptedSegmentPayload...)

	computedHMAC, err := generateHMAC(psk, packetID, segmentIndex, expectedCumulativeHash, hmacData)
	if err != nil {
		return false, fmt.Errorf("failed to recompute HMAC during verification: %w", err)
	}

	if !bytes.Equal(computedHMAC, receivedHMAC) {
		return false, fmt.Errorf("HMAC verification failed for segment state token")
	}

	return true, nil
}

// UpdateCumulativeHash updates the global cumulative state hash.
// It incorporates the old hash, PSK, current packet ID, and the processed data (e.g., original payload).
func UpdateCumulativeHash(psk []byte, oldHash []byte, packetID uint64, processedData []byte) ([]byte, error) {
	hasher := sha256.New()
	hasher.Write(oldHash)
	hasher.Write(psk) // PSK as a fixed secret salt
	
	packetIDBytes := make([]byte, SegmentIDLen)
	binary.BigEndian.PutUint64(packetIDBytes, packetID)
	hasher.Write(packetIDBytes)
	
	hasher.Write(processedData) // Hash the actual data that was sent/received

	return hasher.Sum(nil), nil
}
