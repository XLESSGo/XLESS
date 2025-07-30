package cosmicdust

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/blake2b"
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

// DeriveAESKey derives the AES key for a specific segment.
// It incorporates PSK, cumulativeStateHash, PacketID, and SegmentIndex.
func DeriveAESKey(psk []byte, packetID uint64, segmentIndex uint16, cumulativeHash []byte) ([]byte, error) {
	contextBuf := make([]byte, SegmentIDLen+SegmentIndexLen)
	binary.BigEndian.PutUint64(contextBuf[0:SegmentIDLen], packetID)
	binary.BigEndian.PutUint16(contextBuf[SegmentIDLen:SegmentIDLen+SegmentIndexLen], segmentIndex)
	context := append(contextBuf, cumulativeHash...)
	return DeriveKey(psk, "cosmicdust_aes_key_salt", context, AESKeyLen)
}

// DeriveHMACKey derives the HMAC key for a specific segment's state token.
// It incorporates PSK, cumulativeStateHash, PacketID, and SegmentIndex.
func DeriveHMACKey(psk []byte, packetID uint64, segmentIndex uint16, cumulativeHash []byte) ([]byte, error) {
	contextBuf := make([]byte, SegmentIDLen+SegmentIndexLen)
	binary.BigEndian.PutUint64(contextBuf[0:SegmentIDLen], packetID)
	binary.BigEndian.PutUint16(contextBuf[SegmentIDLen:SegmentIDLen+SegmentIndexLen], segmentIndex)
	context := append(contextBuf, cumulativeHash...)
	return DeriveKey(psk, "cosmicdust_hmac_key_salt", context, HMACKeyLen)
}

// DeriveInitialCumulativeHash computes the initial cumulative hash from the PSK.
// This ensures both client and server start with the same synchronized state.
func DeriveInitialCumulativeHash(psk []byte) ([]byte, error) {
	hasher := sha256.New()
	hasher.Write(psk)
	hasher.Write([]byte("cosmicdust_initial_hash_seed"))
	return hasher.Sum(nil), nil
}
