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
// Token structure: [PacketID (8 bytes)] + [SegmentIndex (2 bytes)] + [TotalSegments (2 bytes)] + [EncryptedPayloadLen (2 bytes)] + [HMAC (32 bytes)]
// The HMAC covers: PacketID + SegmentIndex + TotalSegments + EncryptedPayloadLen + CumulativeHash + EncryptedSegmentPayload.
func GenerateSegmentStateToken(psk []byte, packetID uint64, segmentIndex uint16, totalSegments uint16, encryptedPayloadLen uint16, cumulativeHash []byte, encryptedSegmentPayload []byte) ([]byte, error) {
	segmentMetadata := make([]byte, SegmentMetadataLen)
	binary.BigEndian.PutUint64(segmentMetadata[0:SegmentIDLen], packetID)
	binary.BigEndian.PutUint16(segmentMetadata[SegmentIDLen:SegmentIDLen+SegmentIndexLen], segmentIndex)
	binary.BigEndian.PutUint16(segmentMetadata[SegmentIDLen+SegmentIndexLen:SegmentIDLen+SegmentIndexLen+TotalSegmentsLen], totalSegments)
	binary.BigEndian.PutUint16(segmentMetadata[SegmentIDLen+SegmentIndexLen+TotalSegmentsLen:SegmentMetadataLen], encryptedPayloadLen)

	// Data for HMAC calculation: SegmentMetadata + CumulativeHash + EncryptedSegmentPayload
	hmacData := append(segmentMetadata, cumulativeHash...)
	hmacData = append(hmacData, encryptedSegmentPayload...)

	computedHMAC, err := generateHMAC(psk, packetID, segmentIndex, cumulativeHash, hmacData)
	if err != nil {
		return nil, err
	}

	segmentStateToken := make([]byte, SegmentStateTokenLen)
	copy(segmentStateToken[0:SegmentMetadataLen], segmentMetadata)
	copy(segmentStateToken[SegmentMetadataLen:SegmentStateTokenLen], computedHMAC)

	return segmentStateToken, nil
}

// ExtractSegmentMetadata extracts PacketID, SegmentIndex, TotalSegments, and EncryptedPayloadLen from the SegmentStateToken.
func ExtractSegmentMetadata(segmentStateToken []byte) (uint64, uint16, uint16, uint16, error) {
	if len(segmentStateToken) < SegmentMetadataLen {
		return 0, 0, 0, 0, fmt.Errorf("segment state token too short to extract metadata")
	}
	packetID := binary.BigEndian.Uint64(segmentStateToken[0:SegmentIDLen])
	segmentIndex := binary.BigEndian.Uint16(segmentStateToken[SegmentIDLen:SegmentIDLen+SegmentIndexLen])
	totalSegments := binary.BigEndian.Uint16(segmentStateToken[SegmentIDLen+SegmentIndexLen:SegmentIDLen+SegmentIndexLen+TotalSegmentsLen])
	encryptedPayloadLen := binary.BigEndian.Uint16(segmentStateToken[SegmentIDLen+SegmentIndexLen+TotalSegmentsLen:SegmentMetadataLen])
	return packetID, segmentIndex, totalSegments, encryptedPayloadLen, nil
}

// VerifySegmentStateToken verifies the HMAC of a received segment state token.
func VerifySegmentStateToken(psk []byte, packetID uint64, segmentIndex uint16, totalSegments uint16, encryptedPayloadLen uint16, expectedCumulativeHash []byte, receivedToken []byte, encryptedSegmentPayload []byte) (bool, error) {
	if len(receivedToken) != SegmentStateTokenLen {
		return false, fmt.Errorf("received segment state token has incorrect length: expected %d, got %d", SegmentStateTokenLen, len(receivedToken))
	}

	receivedSegmentMetadata := receivedToken[0:SegmentMetadataLen]
	receivedHMAC := receivedToken[SegmentMetadataLen:SegmentStateTokenLen]

	// Reconstruct data for HMAC calculation: receivedSegmentMetadata + expectedCumulativeHash + encryptedSegmentPayload
	hmacData := append(receivedSegmentMetadata, expectedCumulativeHash...)
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
