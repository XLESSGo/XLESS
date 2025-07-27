package cosmicdust

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	mrand "math/rand"
	"sync"
	"time"
)

// Global constants for CosmicDust protocol
const (
	MinPSKLen          = 64 // Increased PSK length for more robust key derivation
	NonceLen           = 12 // AES-GCM nonce length
	TagLen             = 16 // AES-GCM authentication tag length
	AESKeyLen          = 32 // AES-256 key length
	HMACKeyLen         = 32 // HMAC-SHA256 key length
	HMACSize           = 32 // SHA256 output size (32 bytes)
	SequenceNumLen     = 8  // Sequence number length (uint64)
	CumulativeHashLen  = 32 // Length of cumulative hash (SHA256)

	// Segment-specific constants
	SegmentIDLen       = 8  // Unique ID for the original packet (uint64)
	SegmentIndexLen    = 2  // Index of the segment (uint16)
	TotalSegmentsLen   = 2  // Total number of segments for the packet (uint16)
	EncryptedPayloadLenBytes = 2 // Length of encrypted payload (uint16) embedded in token
	SegmentMetadataLen = SegmentIDLen + SegmentIndexLen + TotalSegmentsLen + EncryptedPayloadLenBytes // Metadata for each segment
	SegmentStateTokenLen = SegmentMetadataLen + HMACSize // Segment Header + HMAC for integrity
	
	MaxSegmentPayloadSize = 1200 // Max plaintext payload size for a single segment (e.g., to fit in common MTUs)
	MinSegmentPayloadSize = 100  // Min plaintext payload size for a single segment

	// General dynamic padding limits
	MaxDynamicPadding = 256 // Max random padding bytes for various sections
	MinDynamicPadding = 64  // Min random padding bytes

	// Decoy packet frequency (e.g., 1 in N packets is a decoy)
	DecoyFrequency = 5 // Every 5th physical packet generated might be a decoy
)

// Obfuscator is the interface that wraps the Obfuscate and Deobfuscate methods.
type Obfuscator interface {
	// Obfuscate takes original plaintext and returns multiple obfuscated physical packets.
	// The caller is responsible for sending these packets over the network.
	Obfuscate(in []byte) ([][]byte, error)
	// Deobfuscate takes a single received physical packet.
	// It returns the length of the reassembled original plaintext if a full packet is ready,
	// otherwise 0. An error indicates a parsing or verification failure.
	// The 'out' buffer is used to write the reassembled plaintext.
	Deobfuscate(in []byte, out []byte) (int, error)
}

// CosmicDustObfuscator implements a highly complex, stateful obfuscation protocol.
// It uses multi-layered polymorphism, a history-dependent state machine,
// and dynamic traffic shaping elements.
type CosmicDustObfuscator struct {
	PSK []byte // Pre-shared key for all key derivations

	// Internal state, protected by mutex
	lk           sync.Mutex
	sendPacketID uint64 // Next unique ID for an original packet to send
	recvPacketID uint64 // Next expected unique ID for an original packet to receive

	// Cryptographic state history
	cumulativeStateHash []byte // A running hash of communication history

	// Non-cryptographic random source for dynamic lengths/patterns
	randSrc *mrand.Rand

	// Reassembly buffer for incoming segments
	// packetID -> segmentIndex -> decryptedSegmentPayload
	recvBuffer map[uint64]map[uint16][]byte
	// packetID -> totalSegmentsExpected
	expectedTotalSegments map[uint64]uint16
	// packetID -> currentReassembledSize
	currentReassembledSize map[uint64]int
}

// NewCosmicDustObfuscator creates a new CosmicDustObfuscator instance.
// psk: The pre-shared key. Must be at least MinPSKLen bytes long.
func NewCosmicDustObfuscator(psk []byte) (Obfuscator, error) {
	if len(psk) < MinPSKLen {
		return nil, fmt.Errorf("PSK must be at least %d bytes for CosmicDust obfuscator", MinPSKLen)
	}

	initialHash, err := DeriveInitialCumulativeHash(psk)
	if err != nil {
		return nil, fmt.Errorf("failed to derive initial cumulative hash: %w", err)
	}

	return &CosmicDustObfuscator{
		PSK:                psk,
		sendPacketID:       1, // Start from 1
		recvPacketID:       1, // Must be synchronized with peer
		cumulativeStateHash: initialHash,
		randSrc:            mrand.New(mrand.NewSource(time.Now().UnixNano())), // Corrected: Used UnixNano() directly as seed
		recvBuffer:         make(map[uint64]map[uint16][]byte),
		expectedTotalSegments: make(map[uint64]uint16),
		currentReassembledSize: make(map[uint64]int),
	}, nil
}

// Obfuscate splits the input 'in' into multiple segments, encrypts each,
// and wraps them in dynamically chosen disguises.
// Returns a slice of byte slices, where each inner byte slice is a complete physical packet ready for sending.
func (o *CosmicDustObfuscator) Obfuscate(in []byte) ([][]byte, error) {
	o.lk.Lock()
	defer o.lk.Unlock()

	// 1. Split original payload into logical segments
	var logicalSegments [][]byte
	currentOffset := 0
	for currentOffset < len(in) {
		segmentSize := o.randSrc.Intn(MaxSegmentPayloadSize-MinSegmentPayloadSize+1) + MinSegmentPayloadSize
		if currentOffset+segmentSize > len(in) {
			segmentSize = len(in) - currentOffset
		}
		logicalSegments = append(logicalSegments, in[currentOffset:currentOffset+segmentSize])
		currentOffset += segmentSize
	}
	if len(logicalSegments) == 0 { // Handle empty input
		logicalSegments = append(logicalSegments, []byte{})
	}
	totalSegments := uint16(len(logicalSegments))
	currentPacketID := o.sendPacketID

	var physicalPackets [][]byte

	// 2. Process each logical segment
	for i, segmentPayload := range logicalSegments {
		segmentIndex := uint16(i)

		// 2.1 Derive segment-specific AES key
		aesKey, err := DeriveAESKey(o.PSK, currentPacketID, segmentIndex, o.cumulativeStateHash)
		if err != nil {
			return nil, fmt.Errorf("failed to derive AES key for segment %d: %w", i, err)
		}
		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher for segment %d: %w", i, err)
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create GCM for segment %d: %w", i, err)
		}

		// 2.2 Generate segment-specific Nonce
		nonce, err := GenerateRandomBytes(NonceLen)
		if err != nil {
			return nil, fmt.Errorf("failed to generate nonce for segment %d: %w", i, err)
		}

		// 2.3 Encrypt segment payload
		encryptedSegment := aesgcm.Seal(nil, nonce, segmentPayload, nil)
		encryptedSegmentWithTagLen := len(encryptedSegment)

		// 2.4 Generate SegmentStateToken
		segmentStateToken, err := GenerateSegmentStateToken(o.PSK, currentPacketID, segmentIndex, totalSegments, uint16(encryptedSegmentWithTagLen), o.cumulativeStateHash, encryptedSegment)
		if err != nil {
			return nil, fmt.Errorf("failed to generate segment state token for segment %d: %w", i, err)
		}

		// 2.5 Dynamic mode selection for this physical packet
		// The mode selection is based on a combination of global state and segment index
		modeSelectorByte := (o.cumulativeStateHash[0] + byte(segmentIndex)) % byte(NumDisguiseModes)
		chosenMode := int(modeSelectorByte)

		var physicalPacket []byte
		switch chosenMode {
		case ModeTLSAppData:
			physicalPacket, err = ObfuscateModeTLSAppData(o.randSrc, segmentStateToken, nonce, encryptedSegment)
		case ModeDNSQuery:
			physicalPacket, err = ObfuscateModeDNSQuery(o.randSrc, segmentStateToken, nonce, encryptedSegment)
		case ModeHTTPFragment:
			physicalPacket, err = ObfuscateModeHTTPFragment(o.randSrc, segmentStateToken, nonce, encryptedSegment)
		case ModeNTPRequest:
			physicalPacket, err = ObfuscateModeNTPRequest(o.randSrc, segmentStateToken, nonce, encryptedSegment)
		default:
			return nil, fmt.Errorf("unknown disguise mode selected for segment %d: %d", i, chosenMode)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to obfuscate segment %d in mode %d: %w", i, chosenMode, err)
		}
		physicalPackets = append(physicalPackets, physicalPacket)

		// Optional: Insert decoy packets periodically
		if o.randSrc.Intn(DecoyFrequency) == 0 {
			decoyPacket, err := ObfuscateModeDecoy(o.randSrc, o.PSK, o.cumulativeStateHash)
			if err != nil {
				fmt.Printf("Warning: failed to generate decoy packet: %v\n", err)
			} else {
				physicalPackets = append(physicalPackets, decoyPacket)
			}
		}
	}

	// 3. Update global cumulative state hash (based on the original full payload)
	newCumulativeHash, err := UpdateCumulativeHash(o.PSK, o.cumulativeStateHash, o.sendPacketID, in) // Hash original payload
	if err != nil {
		return nil, fmt.Errorf("failed to update cumulative hash: %w", err)
	}
	o.cumulativeStateHash = newCumulativeHash

	o.sendPacketID++ // Advance global packet ID

	// Shuffle the order of physical packets to further obscure patterns
	o.randSrc.Shuffle(len(physicalPackets), func(i, j int) {
		physicalPackets[i], physicalPackets[j] = physicalPackets[j], physicalPackets[i]
	})

	return physicalPackets, nil
}

// Deobfuscate processes a single received physical packet.
// It attempts to identify its disguise, extract the segment, verify it,
// and reassemble the original payload if all segments for a packet are received.
func (o *CosmicDustObfuscator) Deobfuscate(in []byte, out []byte) (int, error) {
	o.lk.Lock()
	defer o.lk.Unlock()

	// 1. Try to parse the incoming physical packet with all known disguise modes
	var (
		segmentStateToken       []byte
		segmentNonce            []byte
		encryptedSegmentPayload []byte
		err                     error
	)

	// Iterate through all modes to find a match
	foundMatch := false
	for mode := 0; mode < NumDisguiseModes; mode++ {
		switch mode {
		case ModeTLSAppData:
			segmentStateToken, segmentNonce, encryptedSegmentPayload, err = DeobfuscateModeTLSAppData(in)
		case ModeDNSQuery:
			segmentStateToken, segmentNonce, encryptedSegmentPayload, err = DeobfuscateModeDNSQuery(in)
		case ModeHTTPFragment:
			segmentStateToken, segmentNonce, encryptedSegmentPayload, err = DeobfuscateModeHTTPFragment(in)
		case ModeNTPRequest:
			segmentStateToken, segmentNonce, encryptedSegmentPayload, err = DeobfuscateModeNTPRequest(in)
		case ModeDecoy: // Handle decoy packets
			isDecoy, decoyErr := DeobfuscateModeDecoy(o.PSK, o.cumulativeStateHash, in)
			if isDecoy && decoyErr == nil {
				// This is a legitimate decoy packet, just discard it.
				return 0, nil // Return 0 length, no error for a valid decoy
			}
			// If it's not a decoy, or decoy parsing failed, continue trying other modes
			continue
		default:
			continue // Should not happen
		}

		if err == nil { // Successfully parsed a mode
			// parsedMode = mode // Removed unused variable
			foundMatch = true
			break
		}
	}

	if !foundMatch {
		return 0, fmt.Errorf("failed to parse incoming packet with any known disguise mode")
	}

	// 2. Extract segment metadata from SegmentStateToken
	packetID, segmentIndex, totalSegments, encryptedPayloadLen, err := ExtractSegmentMetadata(segmentStateToken)
	if err != nil {
		return 0, fmt.Errorf("failed to extract segment metadata: %w", err)
	}

	// Important: Check if this packet belongs to the current expected global packet ID
	if packetID != o.recvPacketID {
		// This could be an old packet, a replayed packet, or a packet from a desynchronized session.
		// For a strict protocol, we drop it. For a more robust one, we might buffer a small window
		// of future packets or attempt resynchronization.
		return 0, fmt.Errorf("received packet ID %d does not match expected %d", packetID, o.recvPacketID)
	}

	// Verify that the extracted encryptedPayloadLen matches the actual length of encryptedSegmentPayload
	if encryptedPayloadLen != uint16(len(encryptedSegmentPayload)) {
		return 0, fmt.Errorf("encrypted payload length mismatch: token says %d, actual %d", encryptedPayloadLen, len(encryptedSegmentPayload))
	}

	// 3. Verify SegmentStateToken (HMAC)
	verified, err := VerifySegmentStateToken(o.PSK, packetID, segmentIndex, totalSegments, encryptedPayloadLen, o.cumulativeStateHash, segmentStateToken, encryptedSegmentPayload)
	if err != nil || !verified {
		return 0, fmt.Errorf("segment state token verification failed: %w", err)
	}

	// 4. Derive segment-specific AES key (must match sender's derivation)
	aesKey, err := DeriveAESKey(o.PSK, packetID, segmentIndex, o.cumulativeStateHash)
	if err != nil {
		return 0, fmt.Errorf("failed to derive AES key for decryption: %w", err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return 0, fmt.Errorf("failed to create AES cipher for decryption: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, fmt.Errorf("failed to create GCM for decryption: %w", err)
	}

	// 5. Decrypt segment payload
	decryptedSegmentPayload, err := aesgcm.Open(nil, segmentNonce, encryptedSegmentPayload, nil)
	if err != nil {
		return 0, fmt.Errorf("segment decryption failed: %w", err)
	}

	// 6. Store segment in reassembly buffer
	if _, ok := o.recvBuffer[packetID]; !ok {
		o.recvBuffer[packetID] = make(map[uint16][]byte)
		o.expectedTotalSegments[packetID] = totalSegments // Store expected total
		o.currentReassembledSize[packetID] = 0
	}
	if _, ok := o.recvBuffer[packetID][segmentIndex]; ok {
		// Duplicate segment received, ignore or handle as needed (e.g., log)
		return 0, nil
	}
	o.recvBuffer[packetID][segmentIndex] = decryptedSegmentPayload
	o.currentReassembledSize[packetID] += len(decryptedSegmentPayload)

	// 7. Check for full packet reassembly
	if uint16(len(o.recvBuffer[packetID])) == o.expectedTotalSegments[packetID] {
		// All segments received for this packet ID
		reassembledPayload := make([]byte, o.currentReassembledSize[packetID])
		currentWriteOffset := 0
		for i := uint16(0); i < totalSegments; i++ {
			segment, ok := o.recvBuffer[packetID][i]
			if !ok {
				// This should not happen if len(o.recvBuffer[packetID]) == o.expectedTotalSegments[packetID]
				return 0, fmt.Errorf("missing segment %d during reassembly for packet %d", i, packetID)
			}
			copy(reassembledPayload[currentWriteOffset:], segment)
			currentWriteOffset += len(segment)
		}

		// Copy reassembled payload to 'out' buffer
		if len(out) < len(reassembledPayload) {
			return 0, fmt.Errorf("output buffer too small for reassembled payload")
		}
		copy(out, reassembledPayload)

		// 8. Update global cumulative state hash (based on the reassembled full payload)
		newCumulativeHash, err := UpdateCumulativeHash(o.PSK, o.cumulativeStateHash, o.recvPacketID, reassembledPayload) // Hash original payload
		if err != nil {
			return 0, fmt.Errorf("failed to update cumulative hash on deobfuscate: %w", err)
		}
		o.cumulativeStateHash = newCumulativeHash

		o.recvPacketID++ // Advance global receive packet ID
		// Clean up reassembly buffer for this packet ID
		delete(o.recvBuffer, packetID)
		delete(o.expectedTotalSegments, packetID)
		delete(o.currentReassembledSize, packetID)

		return len(reassembledPayload), nil
	}

	// Not all segments received yet
	return 0, nil
}

// Ensure CosmicDustObfuscator implements Obfuscator interface
var _ Obfuscator = (*CosmicDustObfuscator)(nil)
