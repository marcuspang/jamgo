package main

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

func TestValidateHeader(t *testing.T) {
	config := &Config{
		ValidatorCount: 100,
		SlotsPerEpoch:  600,
	}

	currentTime := uint64(time.Now().Unix())
	validHeader := &Header{
		ParentHash:    Hash{1, 2, 3},
		StateRoot:     Hash{4, 5, 6},
		ExtrinsicHash: Hash{7, 8, 9},
		TimeSlot:      uint32(currentTime) - 1,
		EpochMarker: &EpochMarker{
			EpochRandomness: Hash{10, 11, 12},
			ValidatorKeys:   make([]BandersnatchKey, config.ValidatorCount),
		},
		WinningTickets: &WinningTickets{
			Tickets: make([]Ticket, config.SlotsPerEpoch),
		},
		JudgementsMarker: []Hash{{13, 14, 15}},
		AuthorKey:        0,
		VRFSignature:     BandersnatchSignature{},
		Seal:             BandersnatchSignature{},
	}

	parentHeader := &Header{
		TimeSlot: uint32(currentTime) - 2,
	}

	tests := []struct {
		name     string
		header   *Header
		expected bool
	}{
		{"Valid header", validHeader, true},
		{"Future time slot", &Header{TimeSlot: uint32(currentTime) + 1}, false},
		{"Invalid parent time slot", &Header{TimeSlot: parentHeader.TimeSlot}, false},
		{"Invalid extrinsic hash", &Header{ExtrinsicHash: Hash{1}}, false},
		{"Invalid epoch marker", &Header{EpochMarker: &EpochMarker{ValidatorKeys: []BandersnatchKey{}}}, false},
		{"Invalid winning tickets", &Header{WinningTickets: &WinningTickets{Tickets: []Ticket{}}}, false},
		{"Invalid author key", &Header{AuthorKey: config.ValidatorCount}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateHeader(tt.header, currentTime, parentHeader, config)
			if result != tt.expected {
				t.Errorf("ValidateHeader() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func headerEqual(h1, h2 *Header) bool {
	return bytes.Equal(h1.ParentHash[:], h2.ParentHash[:]) &&
		bytes.Equal(h1.StateRoot[:], h2.StateRoot[:]) &&
		bytes.Equal(h1.ExtrinsicHash[:], h2.ExtrinsicHash[:]) &&
		h1.TimeSlot == h2.TimeSlot &&
		reflect.DeepEqual(h1.EpochMarker, h2.EpochMarker) &&
		reflect.DeepEqual(h1.WinningTickets, h2.WinningTickets) &&
		reflect.DeepEqual(h1.JudgementsMarker, h2.JudgementsMarker) &&
		h1.AuthorKey == h2.AuthorKey &&
		bytes.Equal(h1.VRFSignature.Signature[:], h2.VRFSignature.Signature[:]) &&
		bytes.Equal(h1.Seal.Signature[:], h2.Seal.Signature[:])
}

func epochMarkerEqual(e1, e2 *EpochMarker) bool {
	if (e1 == nil) != (e2 == nil) {
		return false
	}
	if e1 == nil {
		return true
	}
	return bytes.Equal(e1.EpochRandomness[:], e2.EpochRandomness[:]) &&
		len(e1.ValidatorKeys) == len(e2.ValidatorKeys)
}

func winningTicketsEqual(w1, w2 *WinningTickets) bool {
	if (w1 == nil) != (w2 == nil) {
		return false
	}
	if w1 == nil {
		return true
	}
	return len(w1.Tickets) == len(w2.Tickets)
}

func judgementsMarkerEqual(j1, j2 []Hash) bool {
	if len(j1) != len(j2) {
		return false
	}
	for i := range j1 {
		if !bytes.Equal(j1[i][:], j2[i][:]) {
			return false
		}
	}
	return true
}
