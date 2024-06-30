package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStateSerializationDeserialization(t *testing.T) {
	sampleState := createSampleState()

	serialized := sampleState.Serialize()

	deserialized, err := DeserializeState(serialized, 0)
	if err != nil {
		t.Fatalf("Failed to deserialize State: %v", err)
	}

	assert.Equal(t, sampleState, deserialized)
}

func TestSerializeDeserializeAlpha(t *testing.T) {
	testCases := []struct {
		name  string
		alpha [][]Hash
	}{
		{
			name:  "Empty Alpha",
			alpha: [][]Hash{},
		},
		{
			name: "Single hash sequence",
			alpha: [][]Hash{
				{{1, 2, 3}},
			},
		},
		{
			name: "Multiple hash sequences",
			alpha: [][]Hash{
				{{1, 2, 3}, {4, 5, 6}},
				{{7, 8, 9}},
				{{10, 11, 12}, {13, 14, 15}, {16, 17, 18}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serialized := SerializeAlpha(tc.alpha)
			deserialized, offset, err := DeserializeAlpha(serialized, 0)

			assert.ErrorIs(t, err, nil)
			assert.Equal(t, offset, len(serialized))
			assert.Equal(t, tc.alpha, deserialized)
		})
	}
}

func TestSerializeDeserializeBeta(t *testing.T) {
	testCases := []struct {
		name string
		beta []struct {
			HeaderHash       Hash
			AccumulationRoot Hash
			StateRoot        Hash
			WorkReportHashes []Hash
		}
	}{
		{
			name: "Empty Beta",
			beta: []struct {
				HeaderHash       Hash
				AccumulationRoot Hash
				StateRoot        Hash
				WorkReportHashes []Hash
			}{},
		},
		{
			name: "Single Beta entry",
			beta: []struct {
				HeaderHash       Hash
				AccumulationRoot Hash
				StateRoot        Hash
				WorkReportHashes []Hash
			}{
				{
					HeaderHash:       Hash{1, 2, 3},
					AccumulationRoot: Hash{4, 5, 6},
					StateRoot:        Hash{7, 8, 9},
					WorkReportHashes: []Hash{{10, 11, 12}, {13, 14, 15}},
				},
			},
		},
		{
			name: "Multiple Beta entries",
			beta: []struct {
				HeaderHash       Hash
				AccumulationRoot Hash
				StateRoot        Hash
				WorkReportHashes []Hash
			}{
				{
					HeaderHash:       Hash{1, 2, 3},
					AccumulationRoot: Hash{4, 5, 6},
					StateRoot:        Hash{7, 8, 9},
					WorkReportHashes: []Hash{{10, 11, 12}, {13, 14, 15}},
				},
				{
					HeaderHash:       Hash{16, 17, 18},
					AccumulationRoot: Hash{19, 20, 21},
					StateRoot:        Hash{22, 23, 24},
					WorkReportHashes: []Hash{{25, 26, 27}},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serialized := SerializeBeta(tc.beta)
			deserialized, offset, err := DeserializeBeta(serialized, 0)

			assert.ErrorIs(t, err, nil)
			assert.Equal(t, offset, len(serialized))
			assert.Equal(t, tc.beta, deserialized)
		})
	}
}

func TestSerializeDeserializeGamma(t *testing.T) {
	testCases := []struct {
		name  string
		gamma struct {
			ValidatorKeys     []ValidatorKey
			EpochRoot         Hash
			SlotSealers       []Ticket
			TicketAccumulator []Ticket
		}
	}{
		{
			name: "Empty Gamma",
			gamma: struct {
				ValidatorKeys     []ValidatorKey
				EpochRoot         Hash
				SlotSealers       []Ticket
				TicketAccumulator []Ticket
			}{
				ValidatorKeys:     []ValidatorKey{},
				EpochRoot:         Hash{},
				SlotSealers:       []Ticket{},
				TicketAccumulator: []Ticket{},
			},
		},
		{
			name: "Populated Gamma",
			gamma: struct {
				ValidatorKeys     []ValidatorKey
				EpochRoot         Hash
				SlotSealers       []Ticket
				TicketAccumulator []Ticket
			}{
				ValidatorKeys: []ValidatorKey{
					{
						BandersnatchKey: [32]byte{1, 2, 3},
						Ed25519Key:      [32]byte{4, 5, 6},
						BLSKey:          [144]byte{7, 8, 9},
						Metadata:        [128]byte{10, 11, 12},
					},
				},
				EpochRoot: Hash{13, 14, 15},
				SlotSealers: []Ticket{
					{EntryIndex: 1, Proof: []byte{16, 17, 18}},
				},
				TicketAccumulator: []Ticket{
					{EntryIndex: 2, Proof: []byte{19, 20, 21}},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serialized := SerializeGamma(tc.gamma)
			deserialized, offset, err := DeserializeGamma(serialized, 0)

			assert.ErrorIs(t, err, nil)
			assert.Equal(t, offset, len(serialized))
			assert.Equal(t, tc.gamma, deserialized)
		})
	}
}

func TestSerializeDeserializeDelta(t *testing.T) {
	testCases := []struct {
		name  string
		delta map[uint32]ServiceAccount
	}{
		{
			name:  "Empty Delta",
			delta: map[uint32]ServiceAccount{},
		},
		{
			name: "Single Service Account",
			delta: map[uint32]ServiceAccount{
				1: {
					CodeHash:           Hash{1, 2, 3},
					Balance:            1000,
					AccumulateGasLimit: 500,
					OnTransferGasLimit: 250,
					Storage:            map[Hash][]byte{{4, 5, 6}: {7, 8, 9}},
					PreimageLookup:     map[Hash][]byte{{10, 11, 12}: {13, 14, 15}},
					PreimageMeta: map[struct {
						Hash
						Length uint32
					}][]uint32{{Hash: Hash{16, 17, 18}, Length: 3}: {19, 20, 21}},
				},
			},
		},
		{
			name: "Multiple Service Accounts",
			delta: map[uint32]ServiceAccount{
				1: {
					CodeHash:           Hash{1, 2, 3},
					Balance:            1000,
					AccumulateGasLimit: 500,
					OnTransferGasLimit: 250,
					Storage:            map[Hash][]byte{Hash{4, 5, 6}: {7, 8, 9}},
					PreimageLookup:     map[Hash][]byte{Hash{10, 11, 12}: {13, 14, 15}},
					PreimageMeta: map[struct {
						Hash
						Length uint32
					}][]uint32{{Hash: Hash{16, 17, 18}, Length: 3}: {19, 20, 21}},
				},
				2: {
					CodeHash:           Hash{22, 23, 24},
					Balance:            2000,
					AccumulateGasLimit: 1000,
					OnTransferGasLimit: 500,
					Storage:            map[Hash][]byte{{25, 26, 27}: {28, 29, 30}},
					PreimageLookup:     map[Hash][]byte{{31, 32, 33}: {34, 35, 36}},
					PreimageMeta: map[struct {
						Hash
						Length uint32
					}][]uint32{{Hash: Hash{37, 38, 39}, Length: 3}: {40, 41, 42}},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serialized := SerializeDelta(tc.delta)
			deserialized, _, err := DeserializeDelta(serialized, 0)

			assert.ErrorIs(t, err, nil)
			assert.Equal(t, deserialized, tc.delta)
		})
	}
}

func TestSerializeDeserializeEta(t *testing.T) {
	testCases := []struct {
		name string
		eta  [4]Hash
	}{
		{
			name: "All Zero Hashes",
			eta:  [4]Hash{{}, {}, {}, {}},
		},
		{
			name: "Different Hashes",
			eta: [4]Hash{
				{1, 2, 3},
				{4, 5, 6},
				{7, 8, 9},
				{10, 11, 12},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serialized := SerializeEta(tc.eta)
			deserialized, _, err := DeserializeEta(serialized, 0)

			assert.ErrorIs(t, err, nil)
			assert.Equal(t, deserialized, tc.eta)
		})
	}
}

func TestSerializeDeserializeRho(t *testing.T) {
	testCases := []struct {
		name string
		rho  []WorkReportState
	}{
		{
			name: "Empty Rho",
			rho:  []WorkReportState{},
		},
		{
			name: "Single Work Report State",
			rho: []WorkReportState{
				{
					Report: &WorkReport{
						AuthorizerHash: Hash{1, 2, 3},
						Output:         []byte{4, 5, 6},
						Context: RefinementContext{
							AnchorHash:           Hash{7, 8, 9},
							AnchorStateRoot:      Hash{10, 11, 12},
							AnchorBeefyRoot:      Hash{13, 14, 15},
							LookupAnchorHash:     Hash{16, 17, 18},
							LookupAnchorTimeSlot: 1000,
						},
						PackageSpec: AvailabilitySpec{
							PackageHash:  Hash{19, 20, 21},
							BundleLength: 2000,
							ErasureRoot:  Hash{22, 23, 24},
							SegmentRoot:  Hash{25, 26, 27},
						},
						Results: []WorkResult{
							{
								ServiceIndex: 1,
								CodeHash:     Hash{28, 29, 30},
								PayloadHash:  Hash{31, 32, 33},
								GasRatio:     3000,
								Output:       []byte{34, 35, 36},
							},
						},
					},
					Guarantors: []Hash{{37, 38, 39}, {40, 41, 42}},
					Timestamp:  4000,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serialized := SerializeRho(tc.rho)
			deserialized, _, err := DeserializeRho(serialized, 0)

			assert.ErrorIs(t, err, nil)
			assert.Equal(t, deserialized, tc.rho)
		})
	}
}

func TestSerializeDeserializeTau(t *testing.T) {
	testCases := []struct {
		name string
		tau  uint32
	}{
		{
			name: "Zero Tau",
			tau:  0,
		},
		{
			name: "Non-Zero Tau",
			tau:  1234,
		},
		{
			name: "Max Tau",
			tau:  ^uint32(0),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serialized := SerializeTau(tc.tau)
			deserialized, _, err := DeserializeTau(serialized, 0)
			if err != nil {
				t.Fatalf("DeserializeTau error: %v", err)
			}
			if deserialized != tc.tau {
				t.Errorf("Deserialized Tau doesn't match original. Got %v, want %v", deserialized, tc.tau)
			}
		})
	}
}

func TestSerializeDeserializePhi(t *testing.T) {
	testCases := []struct {
		name string
		phi  [][]Hash
	}{
		{
			name: "Empty Phi",
			phi:  [][]Hash{},
		},
		{
			name: "Single Hash Sequence",
			phi: [][]Hash{
				{{1, 2, 3}, {4, 5, 6}},
			},
		},
		{
			name: "Multiple Hash Sequences",
			phi: [][]Hash{
				{{1, 2, 3}, {4, 5, 6}},
				{{7, 8, 9}, {10, 11, 12}, {13, 14, 15}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serialized := SerializePhi(tc.phi)
			deserialized, _, err := DeserializePhi(serialized, 0)

			assert.ErrorIs(t, err, nil)
			assert.Equal(t, deserialized, tc.phi)
		})
	}
}

func TestSerializeDeserializeChi(t *testing.T) {
	testCases := []struct {
		name string
		chi  struct {
			Manager    uint32
			Authorizer uint32
			Validator  uint32
		}
	}{
		{
			name: "All Zero Chi",
			chi: struct {
				Manager    uint32
				Authorizer uint32
				Validator  uint32
			}{0, 0, 0},
		},
		{
			name: "Non-Zero Chi",
			chi: struct {
				Manager    uint32
				Authorizer uint32
				Validator  uint32
			}{1, 2, 3},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serialized := SerializeChi(tc.chi)
			deserialized, _, err := DeserializeChi(serialized, 0)

			assert.ErrorIs(t, err, nil)
			assert.Equal(t, deserialized, tc.chi)
		})
	}
}

func TestSerializeDeserializePsi(t *testing.T) {
	testCases := []struct {
		name string
		psi  struct {
			AllowSet  map[Hash]struct{}
			BanSet    map[Hash]struct{}
			PunishSet map[Hash]struct{}
		}
	}{
		{
			name: "Empty Psi",
			psi: struct {
				AllowSet  map[Hash]struct{}
				BanSet    map[Hash]struct{}
				PunishSet map[Hash]struct{}
			}{
				AllowSet:  make(map[Hash]struct{}),
				BanSet:    make(map[Hash]struct{}),
				PunishSet: make(map[Hash]struct{}),
			},
		},
		{
			name: "Non-Empty Psi",
			psi: struct {
				AllowSet  map[Hash]struct{}
				BanSet    map[Hash]struct{}
				PunishSet map[Hash]struct{}
			}{
				AllowSet:  map[Hash]struct{}{{1, 2, 3}: {}, {4, 5, 6}: {}},
				BanSet:    map[Hash]struct{}{{7, 8, 9}: {}},
				PunishSet: map[Hash]struct{}{{10, 11, 12}: {}, {13, 14, 15}: {}, {16, 17, 18}: {}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serialized := SerializePsi(tc.psi)
			deserialized, _, err := DeserializePsi(serialized, 0)

			assert.ErrorIs(t, err, nil)
			assert.Equal(t, deserialized, tc.psi)
		})
	}
}

func TestSerializeDeserializePi(t *testing.T) {
	testCases := []struct {
		name string
		pi   [2][]struct {
			BlocksProduced      uint32
			TicketsIntroduced   uint32
			PreimagesIntroduced uint32
			PreimageBytes       uint32
			ReportsGuaranteed   uint32
			AssurancesMade      uint32
		}
	}{
		{
			name: "Empty Pi",
			pi: [2][]struct {
				BlocksProduced      uint32
				TicketsIntroduced   uint32
				PreimagesIntroduced uint32
				PreimageBytes       uint32
				ReportsGuaranteed   uint32
				AssurancesMade      uint32
			}{{}, {}},
		},
		{
			name: "Non-Empty Pi",
			pi: [2][]struct {
				BlocksProduced      uint32
				TicketsIntroduced   uint32
				PreimagesIntroduced uint32
				PreimageBytes       uint32
				ReportsGuaranteed   uint32
				AssurancesMade      uint32
			}{
				{
					{1, 2, 3, 4, 5, 6},
					{7, 8, 9, 10, 11, 12},
				},
				{
					{13, 14, 15, 16, 17, 18},
					{19, 20, 21, 22, 23, 24},
					{25, 26, 27, 28, 29, 30},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serialized := SerializePi(tc.pi)
			deserialized, _, err := DeserializePi(serialized, 0)

			assert.ErrorIs(t, err, nil)
			assert.Equal(t, deserialized, tc.pi)
		})
	}
}

func TestSerializeDeserializeHashSequence(t *testing.T) {
	testCases := []struct {
		name   string
		hashes []Hash
	}{
		{
			name:   "Empty sequence",
			hashes: []Hash{},
		},
		{
			name:   "Single hash",
			hashes: []Hash{{1, 2, 3}},
		},
		{
			name: "Multiple hashes",
			hashes: []Hash{
				{1, 2, 3},
				{4, 5, 6},
				{7, 8, 9},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serialized := SerializeHashSequence(tc.hashes)
			deserialized, offset, err := DeserializeHashSequence(serialized, 0)

			assert.ErrorIs(t, err, nil)
			assert.Equal(t, offset, len(serialized))
			assert.Equal(t, tc.hashes, deserialized)
		})
	}
}

func TestSerializeDeserializeHashSequenceSequence(t *testing.T) {
	testCases := []struct {
		name    string
		hashSeq [][]Hash
	}{
		{
			name:    "Empty sequence",
			hashSeq: [][]Hash{},
		},
		{
			name: "Single sequence",
			hashSeq: [][]Hash{
				{{1, 2, 3}, {4, 5, 6}},
			},
		},
		{
			name: "Multiple sequences",
			hashSeq: [][]Hash{
				{{1, 2, 3}, {4, 5, 6}},
				{{7, 8, 9}},
				{{10, 11, 12}, {13, 14, 15}, {16, 17, 18}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serialized := SerializeHashSequenceSequence(tc.hashSeq)
			deserialized, offset, err := DeserializeHashSequenceSequence(serialized, 0)

			assert.ErrorIs(t, err, nil)
			assert.Equal(t, offset, len(serialized))
			assert.Equal(t, tc.hashSeq, deserialized)
		})
	}
}

func TestSerializeDeserializeVarOctetSequence(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "Empty sequence",
			data: []byte{},
		},
		{
			name: "Short sequence",
			data: []byte{1, 2, 3},
		},
		{
			name: "Long sequence",
			data: bytes.Repeat([]byte{0xFF}, 1000),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serialized := SerializeVarOctetSequence(tc.data)
			deserialized, offset, err := DeserializeVarOctetSequence(serialized, 0)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if offset != len(serialized) {
				t.Errorf("Unexpected offset. Got %d, want %d", offset, len(serialized))
			}

			if !bytes.Equal(deserialized, tc.data) {
				t.Errorf("Deserialized data doesn't match original. Got %v, want %v", deserialized, tc.data)
			}
		})
	}
}

func TestDeserializeVarOctetSequenceErrors(t *testing.T) {
	testCases := []struct {
		name   string
		data   []byte
		offset int
	}{
		{
			name:   "Empty input",
			data:   []byte{},
			offset: 0,
		},
		{
			name:   "Insufficient data for length",
			data:   []byte{0xFF},
			offset: 0,
		},
		{
			name:   "Offset out of bounds",
			data:   []byte{0x04, 0x01, 0x02, 0x03, 0x04},
			offset: 5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := DeserializeVarOctetSequence(tc.data, tc.offset)
			if err == nil {
				t.Error("Expected error, got nil")
			}
		})
	}
}

func TestSerializeDeserializeWorkReport(t *testing.T) {
	report := WorkReport{
		AuthorizerHash: Hash{1, 2, 3},
		Output:         []byte{4, 5, 6},
		Context: RefinementContext{
			AnchorHash:              Hash{7, 8, 9},
			AnchorStateRoot:         Hash{10, 11, 12},
			AnchorBeefyRoot:         Hash{13, 14, 15},
			LookupAnchorHash:        Hash{16, 17, 18},
			LookupAnchorTimeSlot:    1000,
			PrerequisitePackageHash: &Hash{19, 20, 21},
		},
		PackageSpec: AvailabilitySpec{
			PackageHash:  Hash{22, 23, 24},
			BundleLength: 2000,
			ErasureRoot:  Hash{25, 26, 27},
			SegmentRoot:  Hash{28, 29, 30},
		},
		Results: []WorkResult{
			{
				ServiceIndex: 1,
				CodeHash:     Hash{31, 32, 33},
				PayloadHash:  Hash{34, 35, 36},
				GasRatio:     3000,
				Output:       []byte{37, 38, 39},
			},
		},
	}

	serialized := report.Serialize()
	deserialized, _, err := DeserializeWorkReport(serialized, 0)

	assert.ErrorIs(t, err, nil)
	assert.Equal(t, deserialized, report)
}

func createSampleState() *State {
	return &State{
		Alpha: [][]Hash{
			{Hash{1, 2, 3}, Hash{4, 5, 6}},
			{Hash{7, 8, 9}},
		},
		Beta: []struct {
			HeaderHash       Hash
			AccumulationRoot Hash
			StateRoot        Hash
			WorkReportHashes []Hash
		}{
			{
				HeaderHash:       Hash{1, 1, 1},
				AccumulationRoot: Hash{2, 2, 2},
				StateRoot:        Hash{3, 3, 3},
				WorkReportHashes: []Hash{{4, 4, 4}, {5, 5, 5}},
			},
		},
		Gamma: struct {
			ValidatorKeys     []ValidatorKey
			EpochRoot         Hash
			SlotSealers       []Ticket
			TicketAccumulator []Ticket
		}{
			ValidatorKeys: []ValidatorKey{
				{
					BandersnatchKey: [32]byte{1, 1, 1},
					Ed25519Key:      [32]byte{2, 2, 2},
					BLSKey:          [144]byte{3, 3, 3},
					Metadata:        [128]byte{4, 4, 4},
				},
			},
			EpochRoot: Hash{6, 6, 6},
			SlotSealers: []Ticket{
				{EntryIndex: 1, Proof: []byte{7, 7, 7}},
			},
			TicketAccumulator: []Ticket{
				{EntryIndex: 2, Proof: []byte{8, 8, 8}},
			},
		},
		Delta: map[uint32]ServiceAccount{
			1: {
				CodeHash:           Hash{9, 9, 9},
				Balance:            1000,
				AccumulateGasLimit: 500,
				OnTransferGasLimit: 250,
				Storage:            map[Hash][]byte{{10, 10, 10}: {11, 11, 11}},
				PreimageLookup:     map[Hash][]byte{{12, 12, 12}: {13, 13, 13}},
				PreimageMeta: map[struct {
					Hash
					Length uint32
				}][]uint32{{Hash: Hash{14, 14, 14}, Length: 3}: {15, 16, 17}},
			},
		},
		Eta:    [4]Hash{{1}, {2}, {3}, {4}},
		Iota:   []ValidatorKey{{BandersnatchKey: [32]byte{5}, Ed25519Key: [32]byte{6}, BLSKey: [144]byte{7}, Metadata: [128]byte{8}}},
		Kappa:  []ValidatorKey{{BandersnatchKey: [32]byte{9}, Ed25519Key: [32]byte{10}, BLSKey: [144]byte{11}, Metadata: [128]byte{12}}},
		Lambda: []ValidatorKey{{BandersnatchKey: [32]byte{13}, Ed25519Key: [32]byte{14}, BLSKey: [144]byte{15}, Metadata: [128]byte{16}}},
		Rho: []WorkReportState{
			{
				Report: &WorkReport{
					AuthorizerHash: Hash{17},
					Output:         []byte{18},
					Context: RefinementContext{
						AnchorHash:              Hash{19},
						AnchorStateRoot:         Hash{20},
						AnchorBeefyRoot:         Hash{21},
						LookupAnchorHash:        Hash{22},
						LookupAnchorTimeSlot:    23,
						PrerequisitePackageHash: &Hash{24},
					},
					PackageSpec: AvailabilitySpec{
						PackageHash:  Hash{25},
						BundleLength: 26,
						ErasureRoot:  Hash{27},
						SegmentRoot:  Hash{28},
					},
					Results: []WorkResult{
						{
							ServiceIndex: 29,
							CodeHash:     Hash{30},
							PayloadHash:  Hash{31},
							GasRatio:     32,
							Output:       []byte{33},
						},
					},
				},
				Guarantors: []Hash{{34}, {35}},
				Timestamp:  36,
			},
		},
		Tau: 37,
		Phi: [][]Hash{{Hash{38}, Hash{39}}, {Hash{40}}},
		Chi: struct {
			Manager    uint32
			Authorizer uint32
			Validator  uint32
		}{
			Manager:    41,
			Authorizer: 42,
			Validator:  43,
		},
		Psi: struct {
			AllowSet  map[Hash]struct{}
			BanSet    map[Hash]struct{}
			PunishSet map[Hash]struct{}
		}{
			AllowSet:  map[Hash]struct{}{{44}: {}},
			BanSet:    map[Hash]struct{}{{45}: {}},
			PunishSet: map[Hash]struct{}{{46}: {}},
		},
		Pi: [2][]struct {
			BlocksProduced      uint32
			TicketsIntroduced   uint32
			PreimagesIntroduced uint32
			PreimageBytes       uint32
			ReportsGuaranteed   uint32
			AssurancesMade      uint32
		}{
			{
				{
					BlocksProduced:      47,
					TicketsIntroduced:   48,
					PreimagesIntroduced: 49,
					PreimageBytes:       50,
					ReportsGuaranteed:   51,
					AssurancesMade:      52,
				},
			},
			{
				{
					BlocksProduced:      53,
					TicketsIntroduced:   54,
					PreimagesIntroduced: 55,
					PreimageBytes:       56,
					ReportsGuaranteed:   57,
					AssurancesMade:      58,
				},
			},
		},
	}
}
