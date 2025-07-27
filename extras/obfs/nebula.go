package obfs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/blake2b"
	mrand "math/rand"
	"sync"
	"time"
)

const (
	nebulaMinPSKLen        = 16 // Minimum PSK length for AES-256 key derivation
	nebulaNonceLen         = 12 // AES-GCM nonce length
	nebulaTagLen           = 16 // AES-GCM authentication tag length
	nebulaKeyLen           = 32 // AES-256 key length (from BLAKE2b-256 hash)
	nebulaFragmentHeaderLen = 8 // PacketID(4) + FragmentIndex(1) + TotalFragments(1) + Length(2) - (Note: Simplified for example, real-world might use uint16 for index/total)
	nebulaMinFragmentPayload = nebulaNonceLen + nebulaTagLen // Minimum data in a fragment
	nebulaMaxFragmentSize    = 1024 // Max size of a plaintext fragment payload
	nebulaPacketIDBytes      = 4
	nebulaFragmentIdxBytes   = 1
	nebulaTotalFragsBytes    = 1
	nebulaFragmentLenBytes   = 2
	nebulaHeaderChecksumBytes = 1 // Simple XOR checksum for header
)

// NebulaObfuscator fragments payload into small, individually encrypted chunks,
// and manages their chaotic transmission (simulated here by output order).
type NebulaObfuscator struct {
	PSK []byte // Pre-shared key for AES key derivation and header obfuscation
	lk  sync.Mutex
	// Use math/rand for fragment sizing and order.
	randSrc *mrand.Rand
	packetIDCounter uint32 // To assign unique PacketIDs
}

// NewNebulaObfuscator creates a new NebulaObfuscator instance.
// psk: The pre-shared key. Must be at least nebulaMinPSKLen bytes long.
func NewNebulaObfuscator(psk []byte) (*NebulaObfuscator, error) {
	if len(psk) < nebulaMinPSKLen {
		return nil, fmt.Errorf("PSK must be at least %d bytes for Nebula obfuscator", nebulaMinPSKLen)
	}
	return &NebulaObfuscator{
		PSK:             psk,
		randSrc:         mrand.New(mrand.NewSource(time.Now().UnixNano())),
		packetIDCounter: 0, // In real scenario, synchronize this across client/server sessions.
	}, nil
}

// nebulaDeriveAESKey derives a fixed-size AES key from the PSK using BLAKE2b-256.
func (o *NebulaObfuscator) nebulaDeriveAESKey() []byte {
	hash := blake2b.Sum256(o.PSK)
	return hash[:]
}

// Obfuscate fragments the input 'in', encrypts each fragment, and prepares them for chaotic sending.
// This function returns a single large byte slice that conceptually represents a sequence of packets.
// In a real implementation, each fragment would be a separate packet, potentially with randomized delays.
// Returns the total length of the combined obfuscated fragments, or 0 if an error occurs or 'out' is too small.
func (o *NebulaObfuscator) Obfuscate(in, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()

	// Assign a unique Packet ID
	o.packetIDCounter++
	currentPacketID := o.packetIDCounter

	// 1. Fragment the input payload
	var fragments [][]byte
	currentOffset := 0
	for currentOffset < len(in) {
		fragmentLen := o.randSrc.Intn(nebulaMaxFragmentSize/2) + nebulaMaxFragmentSize/2 // Fragment size between 512 and 1024
		if fragmentLen == 0 { // Ensure min fragment size
			fragmentLen = 1
		}
		if currentOffset+fragmentLen > len(in) {
			fragmentLen = len(in) - currentOffset
		}
		fragments = append(fragments, in[currentOffset:currentOffset+fragmentLen])
		currentOffset += fragmentLen
	}
	totalFragments := len(fragments)
	if totalFragments == 0 { // Handle empty input gracefully
		totalFragments = 1
		fragments = append(fragments, []byte{})
	}

	// 2. Encrypt each fragment and construct fragment packets
	encryptedFragmentPackets := make([][]byte, totalFragments)
	totalOutputLen := 0

	aesKey := o.nebulaDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:nebulaKeyLen])
	if err != nil {
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	for i, frag := range fragments {
		nonce := make([]byte, nebulaNonceLen)
		if _, err := rand.Read(nonce); err != nil {
			return 0
		}

		encryptedFrag := aesgcm.Seal(nil, nonce, frag, nil)
		encryptedFragWithNonceAndTagLen := nebulaNonceLen + len(encryptedFrag)

		if encryptedFragWithNonceAndTagLen > math.MaxUint16 { // Fragment length needs to fit in uint16
			return 0 // Fragment too large
		}

		// Construct fragment header
		fragHeader := make([]byte, nebulaFragmentHeaderLen)
		binary.BigEndian.PutUint32(fragHeader[0:4], currentPacketID) // Packet ID
		fragHeader[4] = byte(i)                                       // Fragment Index
		fragHeader[5] = byte(totalFragments)                          // Total Fragments
		binary.BigEndian.PutUint16(fragHeader[6:8], uint16(encryptedFragWithNonceAndTagLen)) // Payload Length

		// Combine header + nonce + encrypted_frag + tag
		fragmentPacket := make([]byte, nebulaFragmentHeaderLen+encryptedFragWithNonceAndTagLen)
		copy(fragmentPacket[:nebulaFragmentHeaderLen], fragHeader)
		copy(fragmentPacket[nebulaFragmentHeaderLen:nebulaFragmentHeaderLen+nebulaNonceLen], nonce)
		copy(fragmentPacket[nebulaFragmentHeaderLen+nebulaNonceLen:], encryptedFrag)

		encryptedFragmentPackets[i] = fragmentPacket
		totalOutputLen += len(fragmentPacket)
	}

	// 3. Shuffle fragment order (simulates chaotic transmission)
	o.randSrc.Shuffle(totalFragments, func(i, j int) {
		encryptedFragmentPackets[i], encryptedFragmentPackets[j] = encryptedFragmentPackets[j], encryptedFragmentPackets[i]
	})

	// 4. Assemble into output buffer
	if len(out) < totalOutputLen {
		return 0 // Output buffer too small
	}
	outCursor := 0
	for _, fragPacket := range encryptedFragmentPackets {
		copy(out[outCursor:], fragPacket)
		outCursor += len(fragPacket)
	}

	return totalOutputLen
}

// Deobfuscate reconstructs and decrypts the payload from a sequence of Nebula fragments.
// It requires all fragments for a given PacketID to be present for successful reconstruction.
// Returns the length of the decrypted data, or 0 if an error occurs (e.g., missing fragments, decryption failure).
func (o *NebulaObfuscator) Deobfuscate(in, out []byte) int {
	// This deobfuscation function assumes 'in' contains ALL fragments for a given packet in any order.
	// In a real system, 'in' would be a stream of incoming packets, and a reassembly buffer
	// would be maintained by the protocol layer above this obfuscator.

	if len(in) < nebulaFragmentHeaderLen+nebulaMinFragmentPayload {
		return 0 // Input too short for even one minimal fragment
	}

	receivedFragments := make(map[uint32]map[byte][]byte) // packetID -> fragmentIndex -> fragmentData
	var packetIDs []uint32 // To keep track of unique packet IDs seen

	currentReadOffset := 0
	for currentReadOffset < len(in) {
		if len(in)-currentReadOffset < nebulaFragmentHeaderLen {
			return 0 // Partial header at end
		}

		// Parse fragment header
		fragHeader := in[currentReadOffset : currentReadOffset+nebulaFragmentHeaderLen]
		packetID := binary.BigEndian.Uint32(fragHeader[0:4])
		fragmentIndex := fragHeader[4]
		totalFragments := fragHeader[5]
		encryptedFragWithNonceAndTagLen := int(binary.BigEndian.Uint16(fragHeader[6:8]))

		expectedFragLen := nebulaFragmentHeaderLen + encryptedFragWithNonceAndTagLen
		if len(in)-currentReadOffset < expectedFragLen {
			return 0 // Fragment truncated
		}

		fragmentData := in[currentReadOffset : currentReadOffset+expectedFragLen]

		if _, ok := receivedFragments[packetID]; !ok {
			receivedFragments[packetID] = make(map[byte][]byte)
			packetIDs = append(packetIDs, packetID) // Add to list for iteration later
		}
		receivedFragments[packetID][fragmentIndex] = fragmentData // Store the full fragment packet

		currentReadOffset += expectedFragLen
	}

	if len(packetIDs) == 0 {
		return 0 // No complete fragments parsed
	}

	// Assuming we are processing the first complete packet found.
	// In a real system, you'd pick one PacketID and wait for all its fragments.
	targetPacketID := packetIDs[0] // Choose the first packet ID we found

	packetFragments := receivedFragments[targetPacketID]
	if len(packetFragments) == 0 {
		return 0 // No fragments for this ID
	}

	// Determine total fragments expected from one of the fragments
	var expectedTotalFragments byte
	// Find any fragment to get totalFragments info
	for _, fData := range packetFragments {
		expectedTotalFragments = fData[5] // Total fragments is at byte offset 5 in header
		break
	}

	if len(packetFragments) != int(expectedTotalFragments) {
		return 0 // Not all fragments received for this packet ID
	}

	// Reassemble fragments in original order and decrypt
	reconstructedPayload := make([][]byte, expectedTotalFragments)
	totalDecryptedLen := 0

	aesKey := o.nebulaDeriveAESKey()
	block, err := aes.NewCipher(aesKey[:nebulaKeyLen])
	if err != nil {
		return 0
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}

	for i := byte(0); i < expectedTotalFragments; i++ {
		fragPacket, ok := packetFragments[i]
		if !ok {
			return 0 // Missing fragment
		}

		// Extract nonce and encrypted payload from fragment packet
		nonceStart := nebulaFragmentHeaderLen
		encryptedPayloadWithTagStart := nonceStart + nebulaNonceLen
		
		// The encrypted payload with tag length is embedded in the header.
		encryptedFragWithNonceAndTagLen := int(binary.BigEndian.Uint16(fragPacket[6:8]))
		
		encryptedPayloadWithTag := fragPacket[encryptedPayloadWithTagStart : nebulaFragmentHeaderLen+encryptedFragWithNonceAndTagLen]
		nonce := fragPacket[nonceStart : nonceStart+nebulaNonceLen]

		decryptedFrag, err := aesgcm.Open(nil, nonce, encryptedPayloadWithTag, nil)
		if err != nil {
			return 0 // Decryption or authentication failed
		}
		reconstructedPayload[i] = decryptedFrag
		totalDecryptedLen += len(decryptedFrag)
	}

	// Copy all decrypted fragments into the output buffer in order
	if len(out) < totalDecryptedLen {
		return 0 // Output buffer too small
	}
	outputCursor := 0
	for _, frag := range reconstructedPayload {
		copy(out[outputCursor:], frag)
		outputCursor += len(frag)
	}

	return totalDecryptedLen
}

// Ensure NebulaObfuscator implements Obfuscator interface
var _ Obfuscator = (*NebulaObfuscator)(nil)
