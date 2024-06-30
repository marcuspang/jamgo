package main

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"reflect"

	"golang.org/x/crypto/blake2b"
)

const HashSize = blake2b.Size256

type Hash [HashSize]byte

func (h Hash) Serialize() []byte {
	return h[:]
}

func (s *State) Serialize() []byte {
	var buf []byte
	buf = append(buf, SerializeAlpha(s.Alpha)...)
	buf = append(buf, SerializeBeta(s.Beta)...)
	buf = append(buf, SerializeGamma(s.Gamma)...)
	buf = append(buf, SerializeDelta(s.Delta)...)
	buf = append(buf, SerializeEta(s.Eta)...)
	buf = append(buf, SerializeValidatorKeys(s.Iota)...)
	buf = append(buf, SerializeValidatorKeys(s.Kappa)...)
	buf = append(buf, SerializeValidatorKeys(s.Lambda)...)
	buf = append(buf, SerializeRho(s.Rho)...)
	buf = append(buf, SerializeTau(s.Tau)...)
	buf = append(buf, SerializePhi(s.Phi)...)
	buf = append(buf, SerializeChi(s.Chi)...)
	buf = append(buf, SerializePsi(s.Psi)...)
	buf = append(buf, SerializePi(s.Pi)...)
	return buf
}

// Deserialize deserializes the entire State struct
func DeserializeState(data []byte, offset int) (*State, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	state := &State{}
	var err error

	state.Alpha, offset, err = DeserializeAlpha(data, offset)
	if err != nil {
		return nil, err
	}

	state.Beta, offset, err = DeserializeBeta(data, offset)
	if err != nil {
		return nil, err
	}

	state.Gamma, offset, err = DeserializeGamma(data, offset)
	if err != nil {
		return nil, err
	}

	state.Delta, offset, err = DeserializeDelta(data, offset)
	if err != nil {
		return nil, err
	}

	state.Eta, offset, err = DeserializeEta(data, offset)
	if err != nil {
		return nil, err
	}

	state.Iota, offset, err = DeserializeValidatorKeys(data, offset)
	if err != nil {
		return nil, err
	}

	state.Kappa, offset, err = DeserializeValidatorKeys(data, offset)
	if err != nil {
		return nil, err
	}

	state.Lambda, offset, err = DeserializeValidatorKeys(data, offset)
	if err != nil {
		return nil, err
	}

	state.Rho, offset, err = DeserializeRho(data, offset)
	if err != nil {
		return nil, err
	}

	state.Tau, offset, err = DeserializeTau(data, offset)
	if err != nil {
		return nil, err
	}

	state.Phi, offset, err = DeserializePhi(data, offset)
	if err != nil {
		return nil, err
	}

	state.Chi, offset, err = DeserializeChi(data, offset)
	if err != nil {
		return nil, err
	}

	state.Psi, offset, err = DeserializePsi(data, offset)
	if err != nil {
		return nil, err
	}

	state.Pi, _, err = DeserializePi(data, offset)
	if err != nil {
		return nil, err
	}

	return state, nil
}

func SerializeAlpha(alpha [][]Hash) []byte {
	return SerializeHashSequenceSequence(alpha)
}

func DeserializeAlpha(data []byte, offset int) ([][]Hash, int, error) {
	return DeserializeHashSequenceSequence(data, offset)
}

func SerializeBeta(beta []struct {
	HeaderHash       Hash
	AccumulationRoot Hash
	StateRoot        Hash
	WorkReportHashes []Hash
}) []byte {
	var buf []byte
	for _, item := range beta {
		buf = append(buf, item.HeaderHash[:]...)
		buf = append(buf, item.AccumulationRoot[:]...)
		buf = append(buf, item.StateRoot[:]...)
		buf = append(buf, SerializeHashSequence(item.WorkReportHashes)...)
	}
	return SerializeVarOctetSequence(buf)
}

func DeserializeBeta(data []byte, offset int) ([]struct {
	HeaderHash       Hash
	AccumulationRoot Hash
	StateRoot        Hash
	WorkReportHashes []Hash
}, int, error) {
	betaSeq, offset, err := DeserializeVarOctetSequence(data, offset)
	if err != nil {
		return nil, offset, err
	}

	beta := []struct {
		HeaderHash       Hash
		AccumulationRoot Hash
		StateRoot        Hash
		WorkReportHashes []Hash
	}{}

	seqOffset := 0
	for seqOffset < len(betaSeq) {
		if seqOffset+32*3 > len(betaSeq) {
			return nil, offset, errors.New("insufficient data for Beta item")
		}

		item := struct {
			HeaderHash       Hash
			AccumulationRoot Hash
			StateRoot        Hash
			WorkReportHashes []Hash
		}{}

		copy(item.HeaderHash[:], betaSeq[seqOffset:seqOffset+32])
		seqOffset += 32
		copy(item.AccumulationRoot[:], betaSeq[seqOffset:seqOffset+32])
		seqOffset += 32
		copy(item.StateRoot[:], betaSeq[seqOffset:seqOffset+32])
		seqOffset += 32

		workReportHashes, newSeqOffset, err := DeserializeHashSequence(betaSeq, seqOffset)
		if err != nil {
			return nil, offset, err
		}
		item.WorkReportHashes = workReportHashes
		seqOffset = newSeqOffset

		beta = append(beta, item)
	}

	return beta, offset, nil
}

func SerializeGamma(gamma struct {
	ValidatorKeys     []ValidatorKey
	EpochRoot         Hash
	SlotSealers       []Ticket
	TicketAccumulator []Ticket
}) []byte {
	var buf []byte
	buf = append(buf, SerializeValidatorKeys(gamma.ValidatorKeys)...)
	buf = append(buf, gamma.EpochRoot[:]...)
	buf = append(buf, SerializeTickets(gamma.SlotSealers)...)
	buf = append(buf, SerializeTickets(gamma.TicketAccumulator)...)
	return buf
}

func DeserializeGamma(data []byte, offset int) (struct {
	ValidatorKeys     []ValidatorKey
	EpochRoot         Hash
	SlotSealers       []Ticket
	TicketAccumulator []Ticket
}, int, error) {
	gamma := struct {
		ValidatorKeys     []ValidatorKey
		EpochRoot         Hash
		SlotSealers       []Ticket
		TicketAccumulator []Ticket
	}{}

	var err error

	gamma.ValidatorKeys, offset, err = DeserializeValidatorKeys(data, offset)
	if err != nil {
		return gamma, offset, err
	}

	if offset+32 > len(data) {
		return gamma, offset, errors.New("insufficient data for EpochRoot")
	}
	copy(gamma.EpochRoot[:], data[offset:offset+32])
	offset += 32

	gamma.SlotSealers, offset, err = DeserializeTickets(data, offset)
	if err != nil {
		return gamma, offset, err
	}

	gamma.TicketAccumulator, offset, err = DeserializeTickets(data, offset)
	if err != nil {
		return gamma, offset, err
	}

	return gamma, offset, nil
}

func SerializeDelta(delta map[uint32]ServiceAccount) []byte {
	var buf []byte
	buf = append(buf, SerializeCompactInteger(uint64(len(delta)))...)
	for k, v := range delta {
		buf = binary.BigEndian.AppendUint32(buf, k)
		buf = append(buf, SerializeServiceAccount(v)...)
	}
	return buf
}

func DeserializeDelta(data []byte, offset int) (map[uint32]ServiceAccount, int, error) {
	count, newOffset, err := DeserializeCompactInteger(data, offset)
	if err != nil {
		return nil, offset, err
	}
	offset = newOffset

	delta := make(map[uint32]ServiceAccount)
	for i := uint64(0); i < count; i++ {
		if offset+4 > len(data) {
			return nil, offset, errors.New("insufficient data for delta key")
		}
		key := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		account, newOffset, err := DeserializeServiceAccount(data, offset)
		if err != nil {
			return nil, offset, err
		}
		offset = newOffset

		delta[key] = account
	}

	return delta, offset, nil
}

func SerializeEta(eta [4]Hash) []byte {
	var buf []byte
	for _, hash := range eta {
		buf = append(buf, hash[:]...)
	}
	return buf
}

func DeserializeEta(data []byte, offset int) ([4]Hash, int, error) {
	if offset+4*32 > len(data) {
		return [4]Hash{}, offset, errors.New("insufficient data for eta")
	}
	var eta [4]Hash
	for i := range eta {
		copy(eta[i][:], data[offset:offset+32])
		offset += 32
	}
	return eta, offset, nil
}

func SerializeValidatorKeys(keys []ValidatorKey) []byte {
	var buf []byte
	buf = append(buf, SerializeCompactInteger(uint64(len(keys)))...)
	for _, key := range keys {
		buf = append(buf, key.BandersnatchKey[:]...)
		buf = append(buf, key.Ed25519Key[:]...)
		buf = append(buf, key.BLSKey[:]...)
		buf = append(buf, key.Metadata[:]...)
	}
	return buf
}

func DeserializeValidatorKeys(data []byte, offset int) ([]ValidatorKey, int, error) {
	count, newOffset, err := DeserializeCompactInteger(data, offset)
	if err != nil {
		return nil, offset, err
	}
	offset = newOffset

	keys := make([]ValidatorKey, count)
	for i := uint64(0); i < count; i++ {
		if offset+32+32+144+128 > len(data) {
			return nil, offset, errors.New("insufficient data for validator key")
		}

		copy(keys[i].BandersnatchKey[:], data[offset:offset+32])
		offset += 32

		copy(keys[i].Ed25519Key[:], data[offset:offset+32])
		offset += 32

		copy(keys[i].BLSKey[:], data[offset:offset+144])
		offset += 144

		copy(keys[i].Metadata[:], data[offset:offset+128])
		offset += 128
	}

	return keys, offset, nil
}

func SerializeRho(rho []WorkReportState) []byte {
	var buf []byte
	buf = append(buf, SerializeCompactInteger(uint64(len(rho)))...)
	for _, state := range rho {
		if state.Report != nil {
			buf = append(buf, 1)
			buf = append(buf, state.Report.Serialize()...)
			buf = append(buf, SerializeHashSequence(state.Guarantors)...)
			buf = binary.BigEndian.AppendUint32(buf, state.Timestamp)
		} else {
			buf = append(buf, 0)
		}
	}
	return buf
}

func DeserializeRho(data []byte, offset int) ([]WorkReportState, int, error) {
	count, newOffset, err := DeserializeCompactInteger(data, offset)
	if err != nil {
		return nil, offset, err
	}
	offset = newOffset

	rho := make([]WorkReportState, count)
	for i := uint64(0); i < count; i++ {
		if offset >= len(data) {
			return nil, offset, errors.New("insufficient data for rho item")
		}

		hasReport := data[offset] != 0
		offset++

		if hasReport {
			report, newOffset, err := DeserializeWorkReport(data, offset)
			if err != nil {
				return nil, offset, err
			}
			offset = newOffset

			guarantors, newOffset, err := DeserializeHashSequence(data, offset)
			if err != nil {
				return nil, offset, err
			}
			offset = newOffset

			if offset+4 > len(data) {
				return nil, offset, errors.New("insufficient data for rho timestamp")
			}
			timestamp := binary.BigEndian.Uint32(data[offset : offset+4])
			offset += 4

			rho[i] = WorkReportState{
				Report:     &report,
				Guarantors: guarantors,
				Timestamp:  timestamp,
			}
		}
	}

	return rho, offset, nil
}

func SerializeTau(tau uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, tau)
}

func DeserializeTau(data []byte, offset int) (uint32, int, error) {
	if offset+4 > len(data) {
		return 0, offset, errors.New("insufficient data for tau")
	}
	return binary.BigEndian.Uint32(data[offset : offset+4]), offset + 4, nil
}

func SerializePhi(phi [][]Hash) []byte {
	return SerializeHashSequenceSequence(phi)
}

func DeserializePhi(data []byte, offset int) ([][]Hash, int, error) {
	return DeserializeHashSequenceSequence(data, offset)
}

func SerializeChi(chi struct {
	Manager    uint32
	Authorizer uint32
	Validator  uint32
}) []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, chi.Manager)
	buf = binary.BigEndian.AppendUint32(buf, chi.Authorizer)
	buf = binary.BigEndian.AppendUint32(buf, chi.Validator)
	return buf
}

func DeserializeChi(data []byte, offset int) (struct {
	Manager    uint32
	Authorizer uint32
	Validator  uint32
}, int, error) {
	if offset+12 > len(data) {
		return struct {
			Manager    uint32
			Authorizer uint32
			Validator  uint32
		}{}, offset, errors.New("insufficient data for chi")
	}

	chi := struct {
		Manager    uint32
		Authorizer uint32
		Validator  uint32
	}{
		Manager:    binary.BigEndian.Uint32(data[offset : offset+4]),
		Authorizer: binary.BigEndian.Uint32(data[offset+4 : offset+8]),
		Validator:  binary.BigEndian.Uint32(data[offset+8 : offset+12]),
	}
	return chi, offset + 12, nil
}

func SerializePsi(psi struct {
	AllowSet  map[Hash]struct{}
	BanSet    map[Hash]struct{}
	PunishSet map[Hash]struct{}
}) []byte {
	var buf []byte
	buf = append(buf, SerializeHashSet(psi.AllowSet)...)
	buf = append(buf, SerializeHashSet(psi.BanSet)...)
	buf = append(buf, SerializeHashSet(psi.PunishSet)...)
	return buf
}

func DeserializePsi(data []byte, offset int) (struct {
	AllowSet  map[Hash]struct{}
	BanSet    map[Hash]struct{}
	PunishSet map[Hash]struct{}
}, int, error) {
	psi := struct {
		AllowSet  map[Hash]struct{}
		BanSet    map[Hash]struct{}
		PunishSet map[Hash]struct{}
	}{}

	var err error
	psi.AllowSet, offset, err = DeserializeHashSet(data, offset)
	if err != nil {
		return psi, offset, err
	}

	psi.BanSet, offset, err = DeserializeHashSet(data, offset)
	if err != nil {
		return psi, offset, err
	}

	psi.PunishSet, offset, err = DeserializeHashSet(data, offset)
	if err != nil {
		return psi, offset, err
	}

	return psi, offset, nil
}

func SerializePi(pi [2][]struct {
	BlocksProduced      uint32
	TicketsIntroduced   uint32
	PreimagesIntroduced uint32
	PreimageBytes       uint32
	ReportsGuaranteed   uint32
	AssurancesMade      uint32
}) []byte {
	var buf []byte
	for _, epoch := range pi {
		buf = append(buf, SerializeCompactInteger(uint64(len(epoch)))...)
		for _, stats := range epoch {
			buf = binary.BigEndian.AppendUint32(buf, stats.BlocksProduced)
			buf = binary.BigEndian.AppendUint32(buf, stats.TicketsIntroduced)
			buf = binary.BigEndian.AppendUint32(buf, stats.PreimagesIntroduced)
			buf = binary.BigEndian.AppendUint32(buf, stats.PreimageBytes)
			buf = binary.BigEndian.AppendUint32(buf, stats.ReportsGuaranteed)
			buf = binary.BigEndian.AppendUint32(buf, stats.AssurancesMade)
		}
	}
	return buf
}

func DeserializePi(data []byte, offset int) ([2][]struct {
	BlocksProduced      uint32
	TicketsIntroduced   uint32
	PreimagesIntroduced uint32
	PreimageBytes       uint32
	ReportsGuaranteed   uint32
	AssurancesMade      uint32
}, int, error) {
	var pi [2][]struct {
		BlocksProduced      uint32
		TicketsIntroduced   uint32
		PreimagesIntroduced uint32
		PreimageBytes       uint32
		ReportsGuaranteed   uint32
		AssurancesMade      uint32
	}

	for i := 0; i < 2; i++ {
		count, newOffset, err := DeserializeCompactInteger(data, offset)
		if err != nil {
			return pi, offset, err
		}
		offset = newOffset

		pi[i] = make([]struct {
			BlocksProduced      uint32
			TicketsIntroduced   uint32
			PreimagesIntroduced uint32
			PreimageBytes       uint32
			ReportsGuaranteed   uint32
			AssurancesMade      uint32
		}, count)

		for j := uint64(0); j < count; j++ {
			if offset+24 > len(data) {
				return pi, offset, errors.New("insufficient data for pi stats")
			}
			pi[i][j].BlocksProduced = binary.BigEndian.Uint32(data[offset : offset+4])
			pi[i][j].TicketsIntroduced = binary.BigEndian.Uint32(data[offset+4 : offset+8])
			pi[i][j].PreimagesIntroduced = binary.BigEndian.Uint32(data[offset+8 : offset+12])
			pi[i][j].PreimageBytes = binary.BigEndian.Uint32(data[offset+12 : offset+16])
			pi[i][j].ReportsGuaranteed = binary.BigEndian.Uint32(data[offset+16 : offset+20])
			pi[i][j].AssurancesMade = binary.BigEndian.Uint32(data[offset+20 : offset+24])
			offset += 24
		}
	}

	return pi, offset, nil
}

func SerializeHashSet(set map[Hash]struct{}) []byte {
	var buf []byte
	buf = append(buf, SerializeCompactInteger(uint64(len(set)))...)
	for hash := range set {
		buf = append(buf, hash[:]...)
	}
	return buf
}

func DeserializeHashSet(data []byte, offset int) (map[Hash]struct{}, int, error) {
	count, newOffset, err := DeserializeCompactInteger(data, offset)
	if err != nil {
		return nil, offset, err
	}
	offset = newOffset

	set := make(map[Hash]struct{})
	for i := uint64(0); i < count; i++ {
		if offset+32 > len(data) {
			return nil, offset, errors.New("insufficient data for hash in set")
		}
		var hash Hash
		copy(hash[:], data[offset:offset+32])
		set[hash] = struct{}{}
		offset += 32
	}

	return set, offset, nil
}

func SerializeHashSequence(hashes []Hash) []byte {
	var buf []byte
	buf = append(buf, SerializeCompactInteger(uint64(len(hashes)))...)
	for _, hash := range hashes {
		buf = append(buf, hash[:]...)
	}
	return buf
}

func DeserializeHashSequence(data []byte, offset int) ([]Hash, int, error) {
	count, newOffset, err := DeserializeCompactInteger(data, offset)
	if err != nil {
		return nil, offset, err
	}
	offset = newOffset

	if offset+int(count)*32 > len(data) {
		return nil, offset, errors.New("insufficient data for hash sequence")
	}

	hashes := make([]Hash, count)
	for i := uint64(0); i < count; i++ {
		copy(hashes[i][:], data[offset:offset+32])
		offset += 32
	}

	return hashes, offset, nil
}

func SerializeHashSequenceSequence(hashSeq [][]Hash) []byte {
	var buf []byte
	buf = append(buf, SerializeCompactInteger(uint64(len(hashSeq)))...)
	for _, hashes := range hashSeq {
		buf = append(buf, SerializeHashSequence(hashes)...)
	}
	return buf
}

func DeserializeHashSequenceSequence(data []byte, offset int) ([][]Hash, int, error) {
	count, newOffset, err := DeserializeCompactInteger(data, offset)
	if err != nil {
		return nil, offset, err
	}
	offset = newOffset

	result := make([][]Hash, count)
	for i := uint64(0); i < count; i++ {
		hashes, newOffset, err := DeserializeHashSequence(data, offset)
		if err != nil {
			return nil, offset, err
		}
		result[i] = hashes
		offset = newOffset
	}

	return result, offset, nil
}

func SerializeServiceAccount(sa ServiceAccount) []byte {
	var buf []byte

	// CodeHash
	buf = append(buf, sa.CodeHash[:]...)

	// Balance
	buf = binary.BigEndian.AppendUint64(buf, sa.Balance)

	// AccumulateGasLimit
	buf = binary.BigEndian.AppendUint64(buf, uint64(sa.AccumulateGasLimit))

	// OnTransferGasLimit
	buf = binary.BigEndian.AppendUint64(buf, uint64(sa.OnTransferGasLimit))

	// Storage
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(sa.Storage)))
	for key, value := range sa.Storage {
		buf = append(buf, key[:]...)
		buf = append(buf, SerializeVarOctetSequence(value)...)
	}

	// PreimageLookup
	buf = append(buf, SerializeCompactInteger(uint64(len(sa.PreimageLookup)))...)
	for key, value := range sa.PreimageLookup {
		buf = append(buf, key[:]...)
		buf = append(buf, SerializeVarOctetSequence(value)...)
	}

	// PreimageMeta
	buf = append(buf, SerializeCompactInteger(uint64(len(sa.PreimageMeta)))...)
	for key, value := range sa.PreimageMeta {
		buf = append(buf, key.Hash[:]...)
		buf = binary.BigEndian.AppendUint32(buf, key.Length)

		// Convert []uint32 to []byte
		uint32Bytes := make([]byte, len(value)*4)
		for i, v := range value {
			binary.BigEndian.PutUint32(uint32Bytes[i*4:], v)
		}
		buf = append(buf, SerializeVarOctetSequence(uint32Bytes)...)
	}

	return buf
}

func DeserializeServiceAccount(data []byte, offset int) (ServiceAccount, int, error) {
	if offset+32+8+8+8+4 > len(data) {
		return ServiceAccount{}, offset, errors.New("insufficient data for ServiceAccount")
	}

	sa := ServiceAccount{}

	copy(sa.CodeHash[:], data[offset:offset+32])
	offset += 32

	sa.Balance = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	sa.AccumulateGasLimit = int64(binary.BigEndian.Uint64(data[offset : offset+8]))
	offset += 8

	sa.OnTransferGasLimit = int64(binary.BigEndian.Uint64(data[offset : offset+8]))
	offset += 8

	storageLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	sa.Storage = make(map[Hash][]byte)
	for i := uint32(0); i < storageLen; i++ {
		if offset+32 > len(data) {
			return ServiceAccount{}, offset, errors.New("insufficient data for ServiceAccount Storage key")
		}
		var key Hash
		copy(key[:], data[offset:offset+32])
		offset += 32

		value, newOffset, err := DeserializeVarOctetSequence(data, offset)
		if err != nil {
			return ServiceAccount{}, offset, err
		}
		offset = newOffset

		sa.Storage[key] = value
	}

	// Deserialize PreimageLookup
	preimagesLen, newOffset, err := DeserializeCompactInteger(data, offset)
	if err != nil {
		return ServiceAccount{}, offset, err
	}
	offset = newOffset

	sa.PreimageLookup = make(map[Hash][]byte)
	for i := uint64(0); i < preimagesLen; i++ {
		if offset+32 > len(data) {
			return ServiceAccount{}, offset, errors.New("insufficient data for ServiceAccount PreimageLookup key")
		}
		var key Hash
		copy(key[:], data[offset:offset+32])
		offset += 32

		value, newOffset, err := DeserializeVarOctetSequence(data, offset)
		if err != nil {
			return ServiceAccount{}, offset, err
		}
		offset = newOffset

		sa.PreimageLookup[key] = value
	}

	// Deserialize PreimageMeta
	metaLen, newOffset, err := DeserializeCompactInteger(data, offset)
	if err != nil {
		return ServiceAccount{}, offset, err
	}
	offset = newOffset

	sa.PreimageMeta = make(map[struct {
		Hash
		Length uint32
	}][]uint32)
	for i := uint64(0); i < metaLen; i++ {
		if offset+32+4 > len(data) {
			return ServiceAccount{}, offset, errors.New("insufficient data for ServiceAccount PreimageMeta key")
		}
		var key struct {
			Hash
			Length uint32
		}
		copy(key.Hash[:], data[offset:offset+32])
		offset += 32
		key.Length = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		value, newOffset, err := DeserializeVarOctetSequence(data, offset)
		if err != nil {
			return ServiceAccount{}, offset, err
		}
		offset = newOffset

		// Convert []byte to []uint32
		uint32Slice := make([]uint32, len(value)/4)
		for j := 0; j < len(value); j += 4 {
			uint32Slice[j/4] = binary.BigEndian.Uint32(value[j : j+4])
		}

		sa.PreimageMeta[key] = uint32Slice
	}

	return sa, offset, nil
}

func (h *Header) Serialize(includeSeal bool) []byte {
	var buf []byte
	buf = append(buf, h.ParentHash[:]...)
	buf = append(buf, h.StateRoot[:]...)
	buf = append(buf, h.ExtrinsicHash[:]...)
	buf = binary.BigEndian.AppendUint32(buf, h.TimeSlot)

	buf = append(buf, h.EpochMarker.Serialize()...)
	buf = append(buf, h.WinningTickets.Serialize()...)
	buf = append(buf, SerializeVarOctetSequence(SerializeHashSequence(h.JudgementsMarker))...)
	buf = binary.BigEndian.AppendUint32(buf, h.AuthorKey)
	buf = append(buf, h.VRFSignature.Signature[:]...)

	if includeSeal {
		buf = append(buf, h.Seal.Signature[:]...)
	}

	return buf
}

func DeserializeHeader(data []byte, offset int) (*Header, int, error) {
	h := &Header{}
	if len(data) < HashSize*3+4 {
		return nil, offset, errors.New("insufficient data for header deserialization")
	}

	copy(h.ParentHash[:], data[offset:offset+32])
	offset += 32

	copy(h.StateRoot[:], data[offset:offset+32])
	offset += 32

	copy(h.ExtrinsicHash[:], data[offset:offset+32])
	offset += 32

	h.TimeSlot = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// EpochMarker
	if data[offset] == 1 {
		h.EpochMarker = &EpochMarker{}
		copy(h.EpochMarker.EpochRandomness[:], data[offset+1:offset+33])
		validatorCount := binary.BigEndian.Uint32(data[offset+33 : offset+37])
		h.EpochMarker.ValidatorKeys = make([]BandersnatchKey, validatorCount)
		for i := uint32(0); i < validatorCount; i++ {
			copy(h.EpochMarker.ValidatorKeys[i][:], data[uint32(offset)+37+i*HashSize:uint32(offset)+69+i*HashSize])
		}
		offset += int(37 + validatorCount*HashSize)
	} else {
		offset++
	}

	// WinningTickets
	if data[offset] == 1 {
		h.WinningTickets = &WinningTickets{}
		ticketCount := binary.BigEndian.Uint32(data[offset+1 : offset+5])
		h.WinningTickets.Tickets = make([]Ticket, ticketCount)
		offset += 5
		for i := uint32(0); i < ticketCount; i++ {
			h.WinningTickets.Tickets[i].EntryIndex = binary.BigEndian.Uint32(data[offset : offset+4])
			copy(h.WinningTickets.Tickets[i].Proof, data[offset+4:offset+100])
			offset += 100
		}
	} else {
		offset++
	}

	// JudgementsMarker
	judgementCount := binary.BigEndian.Uint32(data[offset : offset+4])
	h.JudgementsMarker = make([]Hash, judgementCount)
	offset += 4
	for i := uint32(0); i < judgementCount; i++ {
		copy(h.JudgementsMarker[i][:], data[uint32(offset)+i*HashSize:uint32(offset)+(i+1)*HashSize])
	}
	offset += int(judgementCount * HashSize)

	h.AuthorKey = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	copy(h.VRFSignature.Signature[:], data[offset:offset+96])
	offset += 96

	if len(data) >= offset+96 {
		copy(h.Seal.Signature[:], data[offset:offset+96])
	}

	return h, offset, nil
}

func (em *EpochMarker) Serialize() []byte {
	var buf []byte
	buf = append(buf, em.EpochRandomness[:]...)
	buf = append(buf, SerializeVarOctetSequence(SerializeBandersnatchKeySequence(em.ValidatorKeys))...)
	return buf
}

func (b *Block) Serialize() []byte {
	headerData := b.Header.Serialize(true)
	extrinsicsData := b.Extrinsics.Serialize()

	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(headerData)))
	buf = append(buf, headerData...)
	buf = append(buf, extrinsicsData...)

	return buf
}

func DeserializeBlock(data []byte, offset int) (*Block, int, error) {
	if len(data) < 4 {
		return nil, offset, errors.New("insufficient data for block deserialization")
	}

	headerSize := binary.BigEndian.Uint32(data[offset : offset+4])
	if uint32(len(data)) < 4+headerSize {
		return nil, offset, errors.New("insufficient data for header deserialization")
	}

	header, offset, err := DeserializeHeader(data, offset)
	if err != nil {
		return nil, offset, err
	}

	extrinsics, offset, err := DeserializeExtrinsics(data, offset)
	if err != nil {
		return nil, offset, err
	}

	return &Block{
		Header:     *header,
		Extrinsics: *extrinsics,
	}, offset, nil
}

func (wt *WinningTickets) Serialize() []byte {
	return SerializeTickets(wt.Tickets)
}

func (t *Ticket) Serialize() []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, t.EntryIndex)
	buf = append(buf, SerializeVarOctetSequence(t.Proof)...)
	return buf
}

func DeserializeTicket(data []byte, offset int) (Ticket, int, error) {
	if len(data[offset:]) < 8 {
		return Ticket{}, offset, errors.New("insufficient data for ticket")
	}

	ticket := Ticket{
		EntryIndex: binary.BigEndian.Uint32(data[offset : offset+4]),
	}
	offset += 4

	proofSize := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if len(data[offset:]) < int(proofSize) {
		return Ticket{}, offset, errors.New("insufficient data for ticket proof")
	}

	ticket.Proof = make([]byte, proofSize)
	copy(ticket.Proof, data[offset:offset+int(proofSize)])
	offset += int(proofSize)

	return ticket, offset, nil
}

func (wr *WorkReport) Serialize() []byte {
	var buf []byte
	buf = append(buf, wr.AuthorizerHash[:]...)
	buf = append(buf, SerializeVarOctetSequence(wr.Output)...)
	buf = append(buf, wr.Context.Serialize()...)
	buf = append(buf, wr.PackageSpec.Serialize()...)
	buf = append(buf, SerializeCompactInteger(uint64(len(wr.Results)))...)
	for _, result := range wr.Results {
		buf = append(buf, result.Serialize()...)
	}
	return buf
}

func DeserializeWorkReport(data []byte, offset int) (WorkReport, int, error) {
	report := WorkReport{}

	if offset+32 > len(data) {
		return WorkReport{}, offset, errors.New("insufficient data for AuthorizerHash")
	}
	copy(report.AuthorizerHash[:], data[offset:offset+32])
	offset += 32

	var err error
	report.Output, offset, err = DeserializeVarOctetSequence(data, offset)
	if err != nil {
		return WorkReport{}, offset, err
	}

	report.Context, offset, err = DeserializeRefinementContext(data, offset)
	if err != nil {
		return WorkReport{}, offset, err
	}

	report.PackageSpec, offset, err = DeserializeAvailabilitySpec(data, offset)
	if err != nil {
		return WorkReport{}, offset, err
	}

	resultCount, offset, err := DeserializeCompactInteger(data, offset)
	if err != nil {
		return WorkReport{}, offset, err
	}

	report.Results = make([]WorkResult, resultCount)
	for i := uint64(0); i < resultCount; i++ {
		report.Results[i], offset, err = DeserializeWorkResult(data, offset)
		if err != nil {
			return WorkReport{}, offset, err
		}
	}

	return report, offset, nil
}

func (rc *RefinementContext) Serialize() []byte {
	var buf []byte
	buf = append(buf, rc.AnchorHash[:]...)
	buf = append(buf, rc.AnchorStateRoot[:]...)
	buf = append(buf, rc.AnchorBeefyRoot[:]...)
	buf = append(buf, rc.LookupAnchorHash[:]...)
	buf = binary.BigEndian.AppendUint32(buf, rc.LookupAnchorTimeSlot)
	buf = append(buf, SerializeMaybe(rc.PrerequisitePackageHash, func(h interface{}) []byte {
		return h.(*Hash).Serialize()
	})...)
	return buf
}

func DeserializeRefinementContext(data []byte, offset int) (RefinementContext, int, error) {
	if offset+32*3+4 > len(data) {
		return RefinementContext{}, offset, errors.New("insufficient data for RefinementContext")
	}

	rc := RefinementContext{}

	copy(rc.AnchorHash[:], data[offset:offset+32])
	offset += 32

	copy(rc.AnchorStateRoot[:], data[offset:offset+32])
	offset += 32

	copy(rc.AnchorBeefyRoot[:], data[offset:offset+32])
	offset += 32

	copy(rc.LookupAnchorHash[:], data[offset:offset+32])
	offset += 32

	rc.LookupAnchorTimeSlot = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if offset >= len(data) {
		return RefinementContext{}, offset, errors.New("insufficient data for PrerequisitePackageHash flag")
	}

	hasPrerequisite := data[offset] != 0
	offset++

	if hasPrerequisite {
		if offset+32 > len(data) {
			return RefinementContext{}, offset, errors.New("insufficient data for PrerequisitePackageHash")
		}
		rc.PrerequisitePackageHash = new(Hash)
		copy(rc.PrerequisitePackageHash[:], data[offset:offset+32])
		offset += 32
	}

	return rc, offset, nil
}

func (wr *WorkResult) Serialize() []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, wr.ServiceIndex)
	buf = append(buf, wr.CodeHash[:]...)
	buf = append(buf, wr.PayloadHash[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(wr.GasRatio))
	buf = append(buf, SerializeWorkOutput(wr.Output)...)
	return buf
}

func DeserializeWorkResult(data []byte, offset int) (WorkResult, int, error) {
	if len(data[offset:]) < 76 {
		return WorkResult{}, offset, errors.New("insufficient data for work result")
	}

	result := WorkResult{
		ServiceIndex: binary.BigEndian.Uint32(data[offset : offset+4]),
	}
	offset += 4

	copy(result.CodeHash[:], data[offset:offset+32])
	offset += 32

	copy(result.PayloadHash[:], data[offset:offset+32])
	offset += 32

	result.GasRatio = int64(binary.BigEndian.Uint64(data[offset : offset+8]))
	offset += 8

	workOutput, offset, err := DeserializeWorkOutput(data, offset)
	if err != nil {
		return WorkResult{}, offset, err
	}
	result.Output = make([]byte, len(workOutput))
	copy(result.Output, workOutput)

	return result, offset, nil
}

func SerializeWorkOutput(wo interface{}) []byte {
	switch v := wo.(type) {
	case []byte:
		return append([]byte{0}, SerializeVarOctetSequence(v)...)
	case uint32: // Assuming errors are represented as uint32
		buf := make([]byte, 5)
		buf[0] = byte(v)
		binary.BigEndian.PutUint32(buf[1:], v)
		return buf
	default:
		panic("Unknown work output type")
	}
}

func DeserializeWorkOutput(data []byte, offset int) ([]byte, int, error) {
	if len(data) < 1+offset {
		return nil, offset, errors.New("insufficient data for work output")
	}

	// Output type is the first byte
	outputType := data[offset]
	offset++

	switch outputType {
	case 0: // Successful output
		output, offset, err := DeserializeVarOctetSequence(data, offset)
		if err != nil {
			return nil, offset, err
		}
		return output, offset, nil
	case 1, 2, 3, 4: // Error outputs
		return data[offset : offset+4], offset + 4, nil
	default:
		return nil, offset, errors.New("invalid work output type")
	}
}

func SerializeVarOctetSequence(data []byte) []byte {
	var buf []byte
	buf = append(buf, SerializeCompactInteger(uint64(len(data)))...)
	buf = append(buf, data...)
	return buf
}

func DeserializeVarOctetSequence(data []byte, offset int) ([]byte, int, error) {
	if offset >= len(data) {
		return nil, offset, errors.New("insufficient data for var octet sequence")
	}

	length, newOffset, err := DeserializeCompactInteger(data, offset)
	if err != nil {
		return nil, offset, err
	}
	offset = newOffset

	if uint64(len(data)-offset) < length {
		return nil, offset, errors.New("insufficient data for var octet sequence")
	}

	result := make([]byte, length)
	copy(result, data[offset:offset+int(length)])
	offset += int(length)

	return result, offset, nil
}

func SerializeCompactInteger(n uint64) []byte {
	if n < 1<<6 {
		return []byte{byte(n) << 2}
	} else if n < 1<<14 {
		return []byte{byte(n<<2) | 0b01, byte(n >> 6)}
	} else if n < 1<<30 {
		return []byte{byte(n<<2) | 0b10, byte(n >> 6), byte(n >> 14), byte(n >> 22)}
	} else {
		numBytes := (bits.Len64(n) + 7) / 8
		buf := make([]byte, numBytes+1)
		buf[0] = byte(numBytes-4)<<2 | 0b11
		binary.LittleEndian.PutUint64(buf[1:], n)
		return buf[:1+numBytes]
	}
}

func DeserializeCompactInteger(data []byte, offset int) (uint64, int, error) {
	if offset >= len(data) {
		return 0, 0, errors.New("insufficient data for compact integer")
	}

	mode := data[offset] & 0b11
	switch mode {
	case 0b00:
		return uint64(data[offset]) >> 2, offset + 1, nil
	case 0b01:
		if offset+2 > len(data) {
			return 0, 0, errors.New("insufficient data for 2-byte compact integer")
		}
		return (uint64(data[offset]&0b11111100) | uint64(data[offset+1])<<8) >> 2, offset + 2, nil
	case 0b10:
		if offset+4 > len(data) {
			return 0, 0, errors.New("insufficient data for 4-byte compact integer")
		}
		return uint64(binary.LittleEndian.Uint32(data[offset:]) >> 2), offset + 4, nil
	case 0b11:
		bytesFollow := int(data[offset] >> 2)
		if bytesFollow == 0 || bytesFollow > 8 || offset+1+bytesFollow > len(data) {
			return 0, 0, errors.New("invalid compact integer")
		}
		return binary.LittleEndian.Uint64(data[offset+1:]), offset + 1 + bytesFollow, nil
	default:
		return 0, 0, errors.New("invalid compact integer mode")
	}
}

func SerializeMaybe(data interface{}, serializeFunc func(interface{}) []byte) []byte {
	if data == nil || reflect.ValueOf(data).IsNil() {
		return []byte{0}
	}
	serialized := serializeFunc(data)
	return append([]byte{1}, serialized...)
}

func SerializeBandersnatchKeySequence(keys []BandersnatchKey) []byte {
	var buf []byte
	for _, key := range keys {
		buf = append(buf, key[:]...)
	}
	return buf
}

func SerializeWorkResultSequence(results []WorkResult) []byte {
	var buf []byte
	for _, result := range results {
		buf = append(buf, result.Serialize()...)
	}
	return buf
}

func DeserializeWorkResultSequence(data []byte, offset int) ([]WorkResult, int, error) {
	resultSeq, offset, err := DeserializeVarOctetSequence(data, offset)
	if err != nil {
		return nil, offset, err
	}

	results := []WorkResult{}
	seqOffset := 0

	for seqOffset < len(resultSeq) {
		if seqOffset+32+32+8+1 > len(resultSeq) {
			return nil, offset, errors.New("insufficient data for WorkResult")
		}

		wr := WorkResult{}
		wr.ServiceIndex = binary.BigEndian.Uint32(resultSeq[seqOffset : seqOffset+4])
		seqOffset += 4

		copy(wr.CodeHash[:], resultSeq[seqOffset:seqOffset+32])
		seqOffset += 32

		copy(wr.PayloadHash[:], resultSeq[seqOffset:seqOffset+32])
		seqOffset += 32

		wr.GasRatio = int64(binary.BigEndian.Uint64(resultSeq[seqOffset : seqOffset+8]))
		seqOffset += 8

		outputType := resultSeq[seqOffset]
		seqOffset++

		switch outputType {
		case 0: // Successful output
			output, n, err := DeserializeVarOctetSequence(resultSeq, seqOffset)
			if err != nil {
				return nil, offset, err
			}
			wr.Output = output
			seqOffset = n
		case 1, 2, 3, 4: // Error outputs
			wr.Output = []byte{outputType}
		default:
			return nil, offset, errors.New("invalid WorkResult output type")
		}

		results = append(results, wr)
	}

	return results, offset, nil
}

func CalculateHeaderHash(h *Header) Hash {
	// Serialize the header without the seal
	serializedHeader := h.Serialize(false)

	// Use Blake2b-256 for header hashing
	return blake2b.Sum256(serializedHeader)
}

func CalculateExtrinsicHash(extrinsics *Extrinsics) Hash {
	// Serialize the extrinsics
	serializedExtrinsics := extrinsics.Serialize()

	// Use Blake2b-256 for extrinsic hashing
	return blake2b.Sum256(serializedExtrinsics)
}

func SerializeTickets(tickets []Ticket) []byte {
	var buf []byte
	buf = append(buf, SerializeCompactInteger(uint64(len(tickets)))...)
	for _, ticket := range tickets {
		buf = binary.BigEndian.AppendUint32(buf, ticket.EntryIndex)
		buf = append(buf, SerializeVarOctetSequence(ticket.Proof)...)
	}
	return buf
}

func DeserializeTickets(data []byte, offset int) ([]Ticket, int, error) {
	count, offset, err := DeserializeCompactInteger(data, offset)
	if err != nil {
		return nil, offset, err
	}

	tickets := make([]Ticket, count)
	for i := uint64(0); i < count; i++ {
		if offset+4 > len(data) {
			return nil, offset, errors.New("insufficient data for ticket entry index")
		}
		tickets[i].EntryIndex = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		tickets[i].Proof, offset, err = DeserializeVarOctetSequence(data, offset)
		if err != nil {
			return nil, offset, err
		}
	}

	return tickets, offset, nil
}

func (j *Judgement) Serialize() []byte {
	var buf []byte
	buf = append(buf, j.ReportHash[:]...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(j.Votes)))
	for _, vote := range j.Votes {
		if vote.Valid {
			buf = append(buf, 1)
		} else {
			buf = append(buf, 0)
		}
		buf = binary.BigEndian.AppendUint32(buf, vote.ValidatorIndex)
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(vote.Signature)))
		buf = append(buf, vote.Signature...)
	}
	return buf
}

func DeserializeJudgement(data []byte, offset int) (Judgement, int, error) {
	if len(data[offset:]) < 36 {
		return Judgement{}, offset, errors.New("insufficient data for judgement")
	}

	judgement := Judgement{}
	copy(judgement.ReportHash[:], data[offset:offset+32])
	offset += 32

	voteCount := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	judgement.Votes = make([]struct {
		Valid          bool
		ValidatorIndex uint32
		Signature      []byte
	}, voteCount)

	var err error
	for i := uint32(0); i < voteCount; i++ {
		judgement.Votes[i], offset, err = DeserializeVote(data, offset)
		if err != nil {
			return Judgement{}, offset, err
		}
	}

	return judgement, offset, nil
}

func SerializeJudgements(judgements []Judgement) []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(judgements)))
	for _, judgement := range judgements {
		buf = append(buf, judgement.Serialize()...)
	}
	return buf
}

func DeserializeJudgements(data []byte, offset int) ([]Judgement, int, error) {
	if len(data[offset:]) < 4 {
		return nil, offset, errors.New("insufficient data for judgement count")
	}

	count := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	judgements := make([]Judgement, count)
	var err error

	for i := uint32(0); i < count; i++ {
		judgements[i], offset, err = DeserializeJudgement(data, offset)
		if err != nil {
			return nil, offset, err
		}
	}

	return judgements, offset, nil
}

func (p *Preimage) Serialize() []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, p.ServiceIndex)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(p.Data)))
	buf = append(buf, p.Data...)
	return buf
}

func DeserializePreimage(data []byte, offset int) (Preimage, int, error) {
	if len(data[offset:]) < 8 {
		return Preimage{}, offset, errors.New("insufficient data for preimage")
	}

	preimage := Preimage{
		ServiceIndex: binary.BigEndian.Uint32(data[offset : offset+4]),
	}
	offset += 4

	dataSize := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if len(data[offset:]) < int(dataSize) {
		return Preimage{}, offset, errors.New("insufficient data for preimage data")
	}

	preimage.Data = make([]byte, dataSize)
	copy(preimage.Data, data[offset:offset+int(dataSize)])
	offset += int(dataSize)

	return preimage, offset, nil
}

func SerializePreimages(preimages []Preimage) []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(preimages)))
	for _, preimage := range preimages {
		buf = append(buf, preimage.Serialize()...)
	}
	return buf
}

func DeserializePreimages(data []byte, offset int) ([]Preimage, int, error) {
	if len(data[offset:]) < 4 {
		return nil, offset, errors.New("insufficient data for preimage count")
	}

	count := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	preimages := make([]Preimage, count)
	var err error

	for i := uint32(0); i < count; i++ {
		preimages[i], offset, err = DeserializePreimage(data, offset)
		if err != nil {
			return nil, offset, err
		}
	}

	return preimages, offset, nil
}

func (a *Assurance) Serialize() []byte {
	var buf []byte
	buf = append(buf, a.AnchorHash[:]...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(a.Flags)))
	for _, flag := range a.Flags {
		if flag {
			buf = append(buf, 1)
		} else {
			buf = append(buf, 0)
		}
	}
	buf = binary.BigEndian.AppendUint32(buf, a.ValidatorIndex)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(a.Signature)))
	buf = append(buf, a.Signature...)
	return buf
}

func DeserializeAssurance(data []byte, offset int) (Assurance, int, error) {
	if len(data[offset:]) < 36 {
		return Assurance{}, offset, errors.New("insufficient data for assurance")
	}

	assurance := Assurance{}
	copy(assurance.AnchorHash[:], data[offset:offset+32])
	offset += 32

	flagCount := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if len(data[offset:]) < int(flagCount)+8 {
		return Assurance{}, offset, errors.New("insufficient data for assurance flags and validator index")
	}

	assurance.Flags = make([]bool, flagCount)
	for i := uint32(0); i < flagCount; i++ {
		assurance.Flags[i] = data[offset+int(i)] == 1
	}
	offset += int(flagCount)

	assurance.ValidatorIndex = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	sigSize := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if len(data[offset:]) < int(sigSize) {
		return Assurance{}, offset, errors.New("insufficient data for assurance signature")
	}

	assurance.Signature = make([]byte, sigSize)
	copy(assurance.Signature, data[offset:offset+int(sigSize)])
	offset += int(sigSize)

	return assurance, offset, nil
}

func SerializeAssurances(assurances []Assurance) []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(assurances)))
	for _, assurance := range assurances {
		buf = append(buf, assurance.Serialize()...)
	}
	return buf
}

func DeserializeAssurances(data []byte, offset int) ([]Assurance, int, error) {
	if len(data[offset:]) < 4 {
		return nil, offset, errors.New("insufficient data for assurance count")
	}

	count := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	assurances := make([]Assurance, count)
	var err error

	for i := uint32(0); i < count; i++ {
		assurances[i], offset, err = DeserializeAssurance(data, offset)
		if err != nil {
			return nil, offset, err
		}
	}

	return assurances, offset, nil
}

func (g *Guarantee) Serialize() []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, g.CoreIndex)
	reportBuf := g.WorkReport.Serialize()
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(reportBuf)))
	buf = append(buf, reportBuf...)
	buf = binary.BigEndian.AppendUint32(buf, g.Timestamp)
	for _, attestation := range g.Attestations {
		if attestation != nil {
			buf = append(buf, 1)
			buf = binary.BigEndian.AppendUint32(buf, attestation.ValidatorIndex)
			buf = binary.BigEndian.AppendUint32(buf, uint32(len(attestation.Signature)))
			buf = append(buf, attestation.Signature...)
		} else {
			buf = append(buf, 0)
		}
	}
	return buf
}

func DeserializeGuarantee(data []byte, offset int) (Guarantee, int, error) {
	if len(data[offset:]) < 8 {
		return Guarantee{}, offset, errors.New("insufficient data for guarantee")
	}

	guarantee := Guarantee{
		CoreIndex: binary.BigEndian.Uint32(data[offset : offset+4]),
	}
	offset += 4

	reportSize := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if len(data[offset:]) < int(reportSize) {
		return Guarantee{}, offset, errors.New("insufficient data for work report")
	}

	var err error
	guarantee.WorkReport, offset, err = DeserializeWorkReport(data[offset:offset+int(reportSize)], offset)
	if err != nil {
		return Guarantee{}, offset, err
	}
	offset += int(reportSize)

	if len(data[offset:]) < 4 {
		return Guarantee{}, offset, errors.New("insufficient data for guarantee timestamp")
	}

	guarantee.Timestamp = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	guarantee.Attestations = [3]*struct {
		Signature      []byte
		ValidatorIndex uint32
	}{nil, nil, nil}

	for i := 0; i < 3; i++ {
		if len(data[offset:]) < 1 {
			return Guarantee{}, offset, errors.New("insufficient data for attestation presence flag")
		}

		if data[offset] == 1 {
			offset++
			if len(data[offset:]) < 8 {
				return Guarantee{}, offset, errors.New("insufficient data for attestation")
			}

			attestation := &struct {
				Signature      []byte
				ValidatorIndex uint32
			}{
				ValidatorIndex: binary.BigEndian.Uint32(data[offset : offset+4]),
			}
			offset += 4

			sigSize := binary.BigEndian.Uint32(data[offset : offset+4])
			offset += 4

			if len(data[offset:]) < int(sigSize) {
				return Guarantee{}, offset, errors.New("insufficient data for attestation signature")
			}

			attestation.Signature = make([]byte, sigSize)
			copy(attestation.Signature, data[offset:offset+int(sigSize)])
			offset += int(sigSize)

			guarantee.Attestations[i] = attestation
		} else {
			offset++
		}
	}

	return guarantee, offset, nil
}

func SerializeGuarantees(guarantees []Guarantee) []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(guarantees)))
	for _, guarantee := range guarantees {
		buf = append(buf, guarantee.Serialize()...)
	}
	return buf
}

func DeserializeGuarantees(data []byte, offset int) ([]Guarantee, int, error) {
	if len(data[offset:]) < 4 {
		return nil, offset, errors.New("insufficient data for guarantee count")
	}

	count := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	guarantees := make([]Guarantee, count)
	var err error

	for i := uint32(0); i < count; i++ {
		guarantees[i], offset, err = DeserializeGuarantee(data, offset)
		if err != nil {
			return nil, offset, err
		}
	}

	return guarantees, offset, nil
}

func (spec *AvailabilitySpec) Serialize() []byte {
	var buf []byte
	buf = append(buf, spec.PackageHash[:]...)
	buf = binary.BigEndian.AppendUint32(buf, spec.BundleLength)
	buf = append(buf, spec.ErasureRoot[:]...)
	buf = append(buf, spec.SegmentRoot[:]...)
	return buf
}

func DeserializeAvailabilitySpec(data []byte, offset int) (AvailabilitySpec, int, error) {
	if offset+32+4+32+32 > len(data) {
		return AvailabilitySpec{}, offset, errors.New("insufficient data for AvailabilitySpec")
	}

	as := AvailabilitySpec{}

	copy(as.PackageHash[:], data[offset:offset+32])
	offset += 32

	as.BundleLength = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	copy(as.ErasureRoot[:], data[offset:offset+32])
	offset += 32

	copy(as.SegmentRoot[:], data[offset:offset+32])
	offset += 32

	return as, offset, nil
}

func (e *Extrinsics) Serialize() []byte {
	var buf []byte

	ticketsBuf := SerializeTickets(e.Tickets)
	judgementsBuf := SerializeJudgements(e.Judgements)
	preimagesBuf := SerializePreimages(e.Preimages)
	assurancesBuf := SerializeAssurances(e.Assurances)
	guaranteesBuf := SerializeGuarantees(e.Guarantees)

	buf = append(buf, ticketsBuf...)
	buf = append(buf, judgementsBuf...)
	buf = append(buf, preimagesBuf...)
	buf = append(buf, assurancesBuf...)
	buf = append(buf, guaranteesBuf...)

	return buf
}

func DeserializeExtrinsics(data []byte, offset int) (*Extrinsics, int, error) {
	e := &Extrinsics{}
	var err error

	e.Tickets, offset, err = DeserializeTickets(data, offset)
	if err != nil {
		return nil, offset, err
	}

	e.Judgements, offset, err = DeserializeJudgements(data, offset)
	if err != nil {
		return nil, offset, err
	}

	e.Preimages, offset, err = DeserializePreimages(data, offset)
	if err != nil {
		return nil, offset, err
	}

	e.Assurances, offset, err = DeserializeAssurances(data, offset)
	if err != nil {
		return nil, offset, err
	}

	e.Guarantees, offset, err = DeserializeGuarantees(data, offset)
	if err != nil {
		return nil, offset, err
	}

	return e, offset, nil
}

func DeserializeVote(data []byte, offset int) (struct {
	Valid          bool
	ValidatorIndex uint32
	Signature      []byte
}, int, error) {
	if len(data[offset:]) < 9 {
		return struct {
			Valid          bool
			ValidatorIndex uint32
			Signature      []byte
		}{}, offset, errors.New("insufficient data for vote")
	}

	vote := struct {
		Valid          bool
		ValidatorIndex uint32
		Signature      []byte
	}{
		Valid:          data[offset] == 1,
		ValidatorIndex: binary.BigEndian.Uint32(data[offset+1 : offset+5]),
	}
	offset += 5

	sigSize := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if len(data[offset:]) < int(sigSize) {
		return struct {
			Valid          bool
			ValidatorIndex uint32
			Signature      []byte
		}{}, offset, errors.New("insufficient data for vote signature")
	}

	vote.Signature = make([]byte, sigSize)
	copy(vote.Signature, data[offset:offset+int(sigSize)])
	offset += int(sigSize)

	return vote, offset, nil
}
