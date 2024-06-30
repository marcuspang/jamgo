package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

			assert.Equal(t, tt.expected, result)
		})
	}
}
