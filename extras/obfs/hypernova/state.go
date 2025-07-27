package hypernova

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// generateHMAC computes the HMAC for a given data slice using a derived HMAC key.
func generateHMAC(psk []byte, cumulativeHash []byte, data []byte) ([]byte, error) {
	hmacKey, err := DeriveHMACKey(psk, cumulativeHash)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// GenerateStateToken generates the state token which includes sequence number, cumulative hash, and an HMAC.
// The HMAC covers the sequence number, the *current* cumulative hash, and the encrypted payload.
func GenerateStateToken(psk []byte, sequenceNumber uint64, cumulativeHash []byte, encryptedPayloadWithTag []byte) ([]byte, error) {
	stateToken := make([]byte, StateTokenLen)

	// Part 1: Sequence Number
	binary.BigEndian.PutUint64(stateToken[0:SequenceNumLen], sequenceNumber)

	// Part 2: Cumulative Hash
	copy(stateToken[SequenceNumLen:SequenceNumLen+CumulativeHashLen], cumulativeHash)

	// Part 3: HMAC over (SequenceNumber + CurrentCumulativeHash + EncryptedPayloadWithTag)
	hmacData := make([]byte, SequenceNumLen+CumulativeHashLen+len(encryptedPayloadWithTag))
	copy(hmacData[0:SequenceNumLen], stateToken[0:SequenceNumLen])
	copy(hmacData[SequenceNumLen:SequenceNumLen+CumulativeHashLen], stateToken[SequenceNumLen:SequenceNumLen+CumulativeHashLen])
	copy(hmacData[SequenceNumLen+CumulativeHashLen:], encryptedPayloadWithTag)

	computedHMAC, err := generateHMAC(psk, cumulativeHash, hmacData)
	if err != nil {
		return nil, err
	}
	copy(stateToken[SequenceNumLen+CumulativeHashLen:], computedHMAC)

	return stateToken, nil
}

// VerifyStateToken verifies the received state token.
// It checks the sequence number, the embedded cumulative hash, and the HMAC.
func VerifyStateToken(psk []byte, expectedSequenceNumber uint64, expectedCumulativeHash []byte, token, encryptedPayloadWithTag []byte) (bool, error) {
	if len(token) != StateTokenLen {
		return false, fmt.Errorf("state token has incorrect length: expected %d, got %d", StateTokenLen, len(token))
	}

	receivedSequenceNum := binary.BigEndian.Uint64(token[0:SequenceNumLen])
	receivedCumulativeHash := token[SequenceNumLen:SequenceNumLen+CumulativeHashLen]
	receivedHMAC := token[StateTokenLen-HMACSize:]

	if receivedSequenceNum != expectedSequenceNumber {
		return false, fmt.Errorf("sequence number mismatch: expected %d, got %d", expectedSequenceNumber, receivedSequenceNum)
	}

	// Verify the embedded cumulative hash matches the receiver's current expected hash
	if !bytes.Equal(receivedCumulativeHash, expectedCumulativeHash) {
		return false, fmt.Errorf("cumulative hash mismatch in state token")
	}

	// Recompute HMAC over (SequenceNumber + ReceivedCumulativeHash + EncryptedPayloadWithTag)
	hmacData := make([]byte, SequenceNumLen+CumulativeHashLen+len(encryptedPayloadWithTag))
	copy(hmacData[0:SequenceNumLen], token[0:SequenceNumLen])
	copy(hmacData[SequenceNumLen:SequenceNumLen+CumulativeHashLen], token[SequenceNumLen:SequenceNumLen+CumulativeHashLen])
	copy(hmacData[SequenceNumLen+CumulativeHashLen:], encryptedPayloadWithTag)

	return generateHMAC(psk, expectedCumulativeHash, hmacData) // Pass expectedCumulativeHash for key derivation consistency
}

// UpdateCumulativeHash updates the cumulative state hash based on the previous hash, sequence number, and data.
// This is critical for the history-dependent state machine.
func UpdateCumulativeHash(psk []byte, oldHash []byte, sequenceNumber uint64, data []byte) ([]byte, error) {
	hasher := sha256.New()

	// Incorporate old hash
	hasher.Write(oldHash)

	// Incorporate PSK (as an additional secret salt)
	hasher.Write(psk)

	// Incorporate sequence number
	seqBytes := make([]byte, SequenceNumLen)
	binary.BigEndian.PutUint64(seqBytes, sequenceNumber)
	hasher.Write(seqBytes)

	// Incorporate the data that was just processed (encrypted payload is fine as it's authenticated)
	hasher.Write(data)

	return hasher.Sum(nil), nil
}
