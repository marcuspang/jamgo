package main

import (
	"bytes"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

type Header struct {
	ParentHash       Hash
	StateRoot        Hash
	ExtrinsicHash    Hash
	TimeSlot         uint32
	EpochMarker      *EpochMarker
	WinningTickets   *WinningTickets
	JudgementsMarker []Hash
	AuthorKey        uint32
	VRFSignature     BandersnatchSignature
	Seal             BandersnatchSignature
}

func ValidateHeader(h *Header, currentTime uint64, parentHeader *Header, config *Config) bool {
	// Check if the time slot is in the future
	if h.TimeSlot > uint32(currentTime) {
		return false
	}

	// Check if the time slot is after the parent's time slot
	if parentHeader != nil && h.TimeSlot <= parentHeader.TimeSlot {
		return false
	}

	// Validate parent hash
	if parentHeader != nil {
		expectedParentHash := CalculateHeaderHash(parentHeader)
		if !bytes.Equal(h.ParentHash[:], expectedParentHash[:]) {
			return false
		}
	}

	// Validate extrinsic hash
	if len(h.ExtrinsicHash) != HashSize {
		return false
	}

	// Validate epoch marker
	if h.EpochMarker != nil {
		if len(h.EpochMarker.EpochRandomness) != HashSize {
			return false
		}
		if len(h.EpochMarker.ValidatorKeys) != int(config.ValidatorCount) {
			return false
		}
	}

	// Validate winning tickets
	if h.WinningTickets != nil {
		if len(h.WinningTickets.Tickets) != int(config.SlotsPerEpoch) {
			return false
		}
	}

	// Validate judgements marker
	for _, hash := range h.JudgementsMarker {
		if len(hash) != HashSize {
			return false
		}
	}

	// Validate author key
	if h.AuthorKey >= config.ValidatorCount {
		return false
	}

	// Validate VRF signature
	if !ValidateBandersnatchSignature(h.VRFSignature) {
		return false
	}

	// Validate seal
	if !ValidateBandersnatchSignature(h.Seal) {
		return false
	}

	return true
}

func CalculateStateRoot(state *State) Hash {
	// TODO: calculate a Merkle root of the entire state.
	serializedState := state.Serialize()
	return blake2b.Sum256(serializedState)

}

func CalculateBeefyMMRRoot(beta []struct {
	HeaderHash       Hash
	AccumulationRoot Hash
	StateRoot        Hash
	WorkReportHashes []Hash
}) Hash {
	// TODO: calculate the Merkle Mountain Range root of the beta.
	serializedBeta := SerializeBeta(beta)
	return sha3.Sum256(serializedBeta)

}

func ValidateBandersnatchSignature(sig BandersnatchSignature) bool {
	// TODO
	return true
}

type Config struct {
	ValidatorCount uint32
	SlotsPerEpoch  uint32
}
