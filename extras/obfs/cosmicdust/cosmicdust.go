package cosmicdust

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	mrand "math/rand"
	"sync"
	"time"
	"bytes"
)

const (
	MinPSKLen          = 64
	NonceLen           = 12
	TagLen             = 16
	AESKeyLen          = 32
	HMACKeyLen         = 32
	HMACSize           = 32
	SequenceNumLen     = 8
	CumulativeHashLen  = 32

	SegmentIDLen       = 8
	SegmentIndexLen    = 2
	TotalSegmentsLen   = 2
	EncryptedPayloadLenBytes = 2
	SegmentMetadataLen = SegmentIDLen + SegmentIndexLen + TotalSegmentsLen + EncryptedPayloadLenBytes
	SegmentStateTokenLen = SegmentMetadataLen + HMACSize
	
	MaxSegmentPayloadSize = 1200
	MinSegmentPayloadSize = 100

	MaxDynamicPadding = 256
	MinDynamicPadding = 64

	DecoyFrequency = 5
)

type Obfuscator interface {
	Obfuscate(in []byte, out []byte) int
	Deobfuscate(in []byte, out []byte) int
}

var _ Obfuscator = (*CosmicDustObfuscator)(nil)

type CosmicDustObfuscator struct {
	PSK []byte

	lk sync.Mutex
	sendPacketID uint64
	recvPacketID uint64

	cumulativeStateHash []byte

	randSrc *mrand.Rand

	recvBuffer map[uint64]map[uint16][]byte
	expectedTotalSegments map[uint64]uint16
	currentReassembledSize map[uint64]int
}

func NewCosmicDustObfuscator(psk []byte) (Obfuscator, error) {
	if len(psk) < MinPSKLen {
		return nil, fmt.Errorf("PSK must be at least %d bytes for CosmicDust obfuscator", MinPSKLen)
	}

	initialHash, err := DeriveInitialCumulativeHash(psk)
	if err != nil {
		return nil, fmt.Errorf("failed to derive initial cumulative hash: %w", err)
	}

	return &CosmicDustObfuscator{
		PSK:                   psk,
		sendPacketID:          1,
		recvPacketID:          1,
		cumulativeStateHash: initialHash,
		randSrc:               mrand.New(mrand.NewSource(time.Now().UnixNano())),
		recvBuffer:            make(map[uint64]map[uint16][]byte),
		expectedTotalSegments: make(map[uint64]uint16),
		currentReassembledSize: make(map[uint64]int),
	}, nil
}

func (o *CosmicDustObfuscator) Obfuscate(in []byte, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()

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
	if len(logicalSegments) == 0 {
		logicalSegments = append(logicalSegments, []byte{})
	}
	totalSegments := uint16(len(logicalSegments))
	currentPacketID := o.sendPacketID

	var concatenatedPhysicalPackets bytes.Buffer

	for i, segmentPayload := range logicalSegments {
		segmentIndex := uint16(i)

		aesKey, err := DeriveAESKey(o.PSK, currentPacketID, segmentIndex, o.cumulativeStateHash)
		if err != nil {
			return 0
		}
		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return 0
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return 0
		}

		nonce, err := GenerateRandomBytes(NonceLen)
		if err != nil {
			return 0
		}

		encryptedSegment := aesgcm.Seal(nil, nonce, segmentPayload, nil)
		encryptedSegmentWithTagLen := len(encryptedSegment)

		segmentStateToken, err := GenerateSegmentStateToken(o.PSK, currentPacketID, segmentIndex, totalSegments, uint16(encryptedSegmentWithTagLen), o.cumulativeStateHash, encryptedSegment)
		if err != nil {
			return 0
		}

		modeSelectorByte := (o.cumulativeStateHash[0] + byte(segmentIndex)) % byte(NumDisguiseModes)
		chosenMode := int(modeSelectorByte)

		var physicalPacket []byte
		switch chosenMode {
		case ModeDTLSHandshake: // Updated from ModeTLSAppData
			physicalPacket, err = ObfuscateModeDTLSHandshake(o.randSrc, segmentStateToken, nonce, encryptedSegment)
		case ModeDNSQuery:
			physicalPacket, err = ObfuscateModeDNSQuery(o.randSrc, segmentStateToken, nonce, encryptedSegment)
		// Removed ModeHTTPFragment
		case ModeNTPRequest:
			physicalPacket, err = ObfuscateModeNTPRequest(o.randSrc, segmentStateToken, nonce, encryptedSegment)
		case ModeDecoy: // ModeDecoy is now part of the switch for explicit selection
			physicalPacket, err = ObfuscateModeDecoy(o.randSrc, o.PSK, o.cumulativeStateHash)
			if err != nil {
				// If decoy generation fails, log and continue, or handle as per desired behavior
				return 0 // For now, treat as fatal for this packet
			}
		default:
			return 0 // Should not happen if NumDisguiseModes is correct
		}

		if err != nil {
			return 0
		}
		
		concatenatedPhysicalPackets.Write(physicalPacket)

		// Decoy packets are now part of the main switch,
		// so this random insertion logic might need re-evaluation
		// if you want *additional* decoy packets.
		// For now, removing the separate decoy insertion to avoid double-counting
		// if ModeDecoy is chosen via modeSelectorByte.
		/*
		if o.randSrc.Intn(DecoyFrequency) == 0 {
			decoyPacket, err := ObfuscateModeDecoy(o.randSrc, o.PSK, o.cumulativeStateHash)
			if err != nil {
				// Log warning internally if needed, but don't return error
			} else {
				concatenatedPhysicalPackets.Write(decoyPacket)
			}
		}
		*/
	}

	newCumulativeHash, err := UpdateCumulativeHash(o.PSK, o.cumulativeStateHash, o.sendPacketID, in)
	if err != nil {
		return 0
	}
	o.cumulativeStateHash = newCumulativeHash

	o.sendPacketID++

	totalOutputLen := concatenatedPhysicalPackets.Len()
	if len(out) < totalOutputLen {
		return 0
	}
	copy(out, concatenatedPhysicalPackets.Bytes())

	return totalOutputLen
}

func (o *CosmicDustObfuscator) Deobfuscate(in []byte, out []byte) int {
	o.lk.Lock()
	defer o.lk.Unlock()

	currentParseOffset := 0
	var processedAnySegment bool = false

	// Declare all variables that might be used across different branches or loops
	var (
		segmentStateToken       []byte
		segmentNonce            []byte
		encryptedSegmentPayload []byte
		consumedBytes           int
		err                     error
		aesKey                  []byte
		block                   cipher.Block
		aesgcm                  cipher.AEAD
		decryptedSegmentPayload []byte
		verified                bool
	)

	for currentParseOffset < len(in) {
		segmentStart := currentParseOffset
		
		foundMatch := false
		isDecoySegment := false // Flag to explicitly mark if it's a decoy

		// Try to deobfuscate using various modes
		for mode := 0; mode < NumDisguiseModes; mode++ {
			segmentData := in[segmentStart:]
			err = nil // Reset error for each mode attempt

			switch mode {
			case ModeDTLSHandshake: // Updated from ModeTLSAppData
				segmentStateToken, segmentNonce, encryptedSegmentPayload, consumedBytes, err = DeobfuscateModeDTLSHandshake(segmentData)
			case ModeDNSQuery:
				segmentStateToken, segmentNonce, encryptedSegmentPayload, consumedBytes, err = DeobfuscateModeDNSQuery(segmentData)
			// Removed ModeHTTPFragment
			case ModeNTPRequest:
				segmentStateToken, segmentNonce, encryptedSegmentPayload, consumedBytes, err = DeobfuscateModeNTPRequest(segmentData)
			case ModeDecoy:
				var decoyErr error
				isDecoySegment, decoyErr = DeobfuscateModeDecoy(o.PSK, o.cumulativeStateHash, segmentData)
				if isDecoySegment && decoyErr == nil {
					// For decoy, we need to know how many bytes it consumed.
					// This is a heuristic, as decoy length is variable.
					// A robust decoy should embed its length.
					consumedBytes = min(len(segmentData), decoyMaxTotalLen) // Assuming decoyMaxTotalLen is defined
					foundMatch = true // A decoy is a match, but processed differently
					break // Break from mode loop, handle decoy outside
				}
				continue // Not a valid decoy for this segment, try next mode
			default:
				continue
			}

			if err == nil {
				foundMatch = true
				break // Found a valid non-decoy segment, break from mode loop
			}
		}

		if !foundMatch {
			return 0 // No matching segment type found
		}

		// Handle decoy segments
		if isDecoySegment {
			currentParseOffset += consumedBytes
			processedAnySegment = true
			continue // Continue to the next segment in the input 'in'
		}

		// If not a decoy, proceed with normal segment processing
		currentParseOffset += consumedBytes

		packetID, segmentIndex, totalSegments, encryptedPayloadLen, err := ExtractSegmentMetadata(segmentStateToken)
		if err != nil {
			return 0
		}

		if packetID != o.recvPacketID {
			return 0
		}

		if encryptedPayloadLen != uint16(len(encryptedSegmentPayload)) {
			return 0
		}

		verified, err = VerifySegmentStateToken(o.PSK, packetID, segmentIndex, totalSegments, encryptedPayloadLen, o.cumulativeStateHash, segmentStateToken, encryptedSegmentPayload)
		if err != nil || !verified {
			return 0
		}

		aesKey, err = DeriveAESKey(o.PSK, packetID, segmentIndex, o.cumulativeStateHash)
		if err != nil {
			return 0
		}
		block, err = aes.NewCipher(aesKey)
		if err != nil {
			return 0
		}
		aesgcm, err = cipher.NewGCM(block)
		if err != nil {
			return 0
		}

		decryptedSegmentPayload, err = aesgcm.Open(nil, segmentNonce, encryptedSegmentPayload, nil)
		if err != nil {
			return 0
		}

		if _, ok := o.recvBuffer[packetID]; !ok {
			o.recvBuffer[packetID] = make(map[uint16][]byte)
			o.expectedTotalSegments[packetID] = totalSegments
			o.currentReassembledSize[packetID] = 0
		}
		if _, ok := o.recvBuffer[packetID][segmentIndex]; ok {
			return 0
		}
		o.recvBuffer[packetID][segmentIndex] = decryptedSegmentPayload
		o.currentReassembledSize[packetID] += len(decryptedSegmentPayload)
		processedAnySegment = true
	}
	
	if processedAnySegment {
		if _, ok := o.recvBuffer[o.recvPacketID]; ok && uint16(len(o.recvBuffer[o.recvPacketID])) == o.expectedTotalSegments[o.recvPacketID] {
			reassembledPayload := make([]byte, o.currentReassembledSize[o.recvPacketID])
			currentWriteOffset := 0
			for i := uint16(0); i < o.expectedTotalSegments[o.recvPacketID]; i++ {
				segment, ok := o.recvBuffer[o.recvPacketID][i]
				if !ok {
					return 0
				}
				copy(reassembledPayload[currentWriteOffset:], segment)
				currentWriteOffset += len(segment)
			}

			if len(out) < len(reassembledPayload) {
				return 0
			}
			copy(out, reassembledPayload)

			newCumulativeHash, err := UpdateCumulativeHash(o.PSK, o.cumulativeStateHash, o.recvPacketID, reassembledPayload)
			if err != nil {
				return 0
			}
			o.cumulativeStateHash = newCumulativeHash

			o.recvPacketID++
			delete(o.recvBuffer, o.recvPacketID-1)
			delete(o.expectedTotalSegments, o.recvPacketID-1)
			delete(o.currentReassembledSize, o.recvPacketID-1)

			return len(reassembledPayload)
		}
	}

	return 0
}
