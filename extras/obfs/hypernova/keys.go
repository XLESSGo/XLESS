package hypernova

import (
	"fmt"
	"golang.org/x/crypto/blake2b"
	"encoding/binary"
	"crypto/sha256"
)

// DeriveKey derives a fixed-size key from the PSK, a context-specific salt, and an additional context.
// The additional context allows for key diversity based on current state.
func DeriveKey(psk []byte, salt string, additionalContext []byte, keyLen int) ([]byte, error) {
	hasher, err := blake2b.New(keyLen, psk) // BLAKE2b to derive keys from PSK
	if err != nil {
		return nil, fmt.Errorf("failed to create blake2b hasher: %w", err)
	}
	hasher.Write([]byte(salt))
	if additionalContext != nil {
		hasher.Write(additionalContext)
	}
	return hasher.Sum(nil), nil
}

// DeriveAESKey derives the AES key for payload encryption.
// It incorporates the current sequence number and cumulative state hash into the key derivation.
func DeriveAESKey(psk []byte, sequenceNumber uint64, cumulativeHash []byte) ([]byte, error) {
	seqBytes := make([]byte, SequenceNumLen)
	binary.BigEndian.PutUint64(seqBytes, sequenceNumber)
	context := append(seqBytes, cumulativeHash...)
	return DeriveKey(psk, "hypernova_aes_key_salt", context, AESKeyLen)
}

// DeriveHMACKey derives the HMAC key for state token.
// It uses the cumulative state hash as additional context to make the HMAC key change over time.
func DeriveHMACKey(psk []byte, cumulativeHash []byte) ([]byte, error) {
	return DeriveKey(psk, "hypernova_hmac_key_salt", cumulativeHash, HMACKeyLen)
}

// DeriveInitialCumulativeHash computes the initial cumulative hash from the PSK.
// This ensures both client and server start with the same synchronized state.
func DeriveInitialCumulativeHash(psk []byte) ([]byte, error) {
	hasher := sha256.New()
	hasher.Write(psk)
	hasher.Write([]byte("hypernova_initial_hash_seed"))
	return hasher.Sum(nil), nil
}
