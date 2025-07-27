package cosmos

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// generateHMAC generates the HMAC for a given data slice using a derived HMAC key.
func generateHMAC(psk []byte, data []byte) ([]byte, error) {
	hmacKey, err := DeriveHMACKey(psk)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// GenerateStateToken generates the sequence number and its HMAC.
func GenerateStateToken(psk []byte, sequenceNumber uint64, encryptedPayloadWithTag []byte) ([]byte, error) {
	stateToken := make([]byte, StateTokenLen)
	binary.BigEndian.PutUint64(stateToken[0:SequenceNumLen], sequenceNumber)

	// HMAC over (SequenceNumber + EncryptedPayloadWithTag)
	hmacData := make([]byte, SequenceNumLen+len(encryptedPayloadWithTag))
	copy(hmacData[0:SequenceNumLen], stateToken[0:SequenceNumLen]) // Copy sequence number part
	copy(hmacData[SequenceNumLen:], encryptedPayloadWithTag)       // Copy payload

	computedHMAC, err := generateHMAC(psk, hmacData)
	if err != nil {
		return nil, err
	}
	copy(stateToken[SequenceNumLen:], computedHMAC)
	return stateToken, nil
}

// VerifyStateToken verifies the received state token.
func VerifyStateToken(psk []byte, expectedSequenceNumber uint64, token, encryptedPayloadWithTag []byte) (bool, error) {
	if len(token) != StateTokenLen {
		return false, fmt.Errorf("state token has incorrect length: expected %d, got %d", StateTokenLen, len(token))
	}

	receivedSequenceNum := binary.BigEndian.Uint64(token[0:SequenceNumLen])
	receivedHMAC := token[SequenceNumLen:]

	if receivedSequenceNum != expectedSequenceNumber {
		return false, fmt.Errorf("sequence number mismatch: expected %d, got %d", expectedSequenceNumber, receivedSequenceNum)
	}

	// HMAC over (SequenceNumber + EncryptedPayloadWithTag)
	hmacData := make([]byte, SequenceNumLen+len(encryptedPayloadWithTag))
	copy(hmacData[0:SequenceNumLen], token[0:SequenceNumLen]) // Copy sequence number part from received token
	copy(hmacData[SequenceNumLen:], encryptedPayloadWithTag)   // Copy payload

	expectedHMAC, err := generateHMAC(psk, hmacData)
	if err != nil {
		return false, err
	}
	return hmac.Equal(receivedHMAC, expectedHMAC), nil
}
