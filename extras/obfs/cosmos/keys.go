package cosmos

import (
	"fmt"
	"golang.org/x/crypto/blake2b"
	"encoding/binary"
)

// DeriveKey derives a fixed-size key from the PSK and a context-specific salt.
func DeriveKey(psk []byte, salt string, keyLen int) ([]byte, error) {
	hasher, err := blake2b.New(keyLen, psk) // BLAKE2b to derive keys from PSK
	if err != nil {
		return nil, fmt.Errorf("failed to create blake2b hasher: %w", err)
	}
	hasher.Write([]byte(salt))
	return hasher.Sum(nil), nil
}

// DeriveAESKey derives the AES key for payload encryption.
// It incorporates the current state (sequence number) into the key derivation.
func DeriveAESKey(psk []byte, sequenceNumber uint64) ([]byte, error) {
	stateBytes := make([]byte, SequenceNumLen)
	binary.BigEndian.PutUint64(stateBytes, sequenceNumber)
	return DeriveKey(psk, fmt.Sprintf("cosmos_aes_key_%d", sequenceNumber), AESKeyLen)
}

// DeriveHMACKey derives the HMAC key for state token.
func DeriveHMACKey(psk []byte) ([]byte, error) {
	return DeriveKey(psk, "cosmos_hmac_key_salt", HMACKeyLen)
}
