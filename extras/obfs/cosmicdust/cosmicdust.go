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

	lk           sync.Mutex
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
		PSK:                psk,
		sendPacketID:       1,
		recvPacketID:       1,
		cumulativeStateHash: initialHash,
		randSrc:            mrand.New(mrand.NewSource(time.Now().UnixNano())),
		recvBuffer:         make(map[uint64]map[uint16][]byte),
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
		case ModeTLSAppData:
			physicalPacket, err = ObfuscateModeTLSAppData(o.randSrc, segmentStateToken, nonce, encryptedSegment)
		case ModeDNSQuery:
			physicalPacket, err = ObfuscateModeDNSQuery(o.randSrc, segmentStateToken, nonce, encryptedSegment)
		case ModeHTTPFragment:
			physicalPacket, err = ObfuscateModeHTTPFragment(o.randSrc, segmentStateToken, nonce, encryptedSegment)
		case ModeNTPRequest:
			physicalPacket, err = ObfuscateModeNTPRequest(o.randSrc, segmentStateToken, nonce, encryptedSegment)
		default:
			return 0
		}

		if err != nil {
			return 0
		}
		
		concatenatedPhysicalPackets.Write(physicalPacket)

		if o.randSrc.Intn(DecoyFrequency) == 0 {
			decoyPacket, err := ObfuscateModeDecoy(o.randSrc, o.PSK, o.cumulativeStateHash)
			if err != nil {
				// Log warning internally if needed, but don't return error
			} else {
				concatenatedPhysicalPackets.Write(decoyPacket)
			}
		}
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

	for currentParseOffset < len(in) {
		segmentStart := currentParseOffset
		
		var (
			segmentStateToken       []byte
			segmentNonce            []byte
			encryptedSegmentPayload []byte
			consumedBytes           int
			err                     error
		)

		foundMatch := false
		for mode := 0; mode < NumDisguiseModes; mode++ {
			segmentData := in[segmentStart:]
			
			switch mode {
			case ModeTLSAppData:
				segmentStateToken, segmentNonce, encryptedSegmentPayload, consumedBytes, err = DeobfuscateModeTLSAppData(segmentData)
			case ModeDNSQuery:
				segmentStateToken, segmentNonce, encryptedSegmentPayload, consumedBytes, err = DeobfuscateModeDNSQuery(segmentData)
			case ModeHTTPFragment:
				segmentStateToken, segmentNonce, encryptedSegmentPayload, consumedBytes, err = DeobfuscateModeHTTPFragment(segmentData)
			case ModeNTPRequest:
				segmentStateToken, segmentNonce, encryptedSegmentPayload, consumedBytes, err = DeobfuscateModeNTPRequest(segmentData)
			case ModeDecoy:
				isDecoy, decoyErr := DeobfuscateModeDecoy(o.PSK, o.cumulativeStateHash, segmentData)
				if isDecoy && decoyErr == nil {
					// For decoy, we need to know how many bytes it consumed.
					// This is a heuristic, as decoy length is variable.
					// A robust decoy should embed its length.
					// For now, assume it consumes up to decoyMaxTotalLen or end of 'in'.
					consumedBytes = min(len(segmentData), decoyMaxTotalLen)
					currentParseOffset += consumedBytes
					foundMatch = true
					processedAnySegment = true
					goto NextSegment
				}
				continue
			default:
				continue
			}

			if err == nil {
				foundMatch = true
				break
			}
		}

		if !foundMatch {
			return 0
		}

		// Advance offset for non-decoy packets
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

		verified, err := VerifySegmentStateToken(o.PSK, packetID, segmentIndex, totalSegments, encryptedPayloadLen, o.cumulativeStateHash, segmentStateToken, encryptedSegmentPayload)
		if err != nil || !verified {
			return 0
		}

		aesKey, err := DeriveAESKey(o.PSK, packetID, segmentIndex, o.cumulativeStateHash)
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

		decryptedSegmentPayload, err := aesgcm.Open(nil, segmentNonce, encryptedSegmentPayload, nil)
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

	NextSegment:
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
