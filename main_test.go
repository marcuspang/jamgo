package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestCase represents the structure of our JSON test cases
type TestCase struct {
	Input struct {
		Slot       uint32        `json:"slot"`
		Entropy    string        `json:"entropy"`
		Extrinsics []interface{} `json:"extrinsics"`
	} `json:"input"`
	PreState SafroleState `json:"pre_state"`
	Output   struct {
		Ok struct {
			EpochMark   interface{} `json:"epoch_mark"`
			TicketsMark interface{} `json:"tickets_mark"`
		} `json:"ok"`
	} `json:"output"`
	PostState SafroleState `json:"post_state"`
}

func (ticketsOrKeys TicketsOrKeys) UnmarshalJSON(data []byte) error {
	// Unmarshal JSON into a BandersnatchKey struct

	tmp := struct {
		Keys []string `json:"keys"`
	}{}

	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	ticketsOrKeys = TicketsOrKeys{Keys: []BandersnatchKey{}}
	for _, key := range tmp.Keys {
		ticketsOrKeys.Keys = append(ticketsOrKeys.Keys, BandersnatchKey(hexToBytes32(key)))
	}

	return nil
}

func (vk ValidatorKey) UnmarshalJSON(data []byte) error {
	// Unmarshal JSON into a ValidatorKey struct

	tmp := struct {
		Ed25519      string `json:"ed25519"`
		Bandersnatch string `json:"bandersnatch"`
		Bls          string `json:"bls"`
		Metadata     string `json:"metadata"`
	}{}

	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	vk.Ed25519Key = hexToBytes32(tmp.Ed25519)
	vk.BandersnatchKey = hexToBytes32(tmp.Bandersnatch)
	vk.BLSKey = hexToBytes144(tmp.Bls)
	vk.Metadata = hexToBytes128(tmp.Metadata)

	return nil
}

func (s *SafroleState) UnmarshalJSON(data []byte) error {
	// Unmarshal JSON into a SafroleState struct

	tmp := struct {
		Timeslot           uint32         `json:"timeslot"`
		Entropy            []string       `json:"entropy"`
		PrevValidators     []ValidatorKey `json:"prev_validators"`
		CurrValidators     []ValidatorKey `json:"curr_validators"`
		NextValidators     []ValidatorKey `json:"next_validators"`
		DesignedValidators []ValidatorKey `json:"designed_validators"`
		TicketsAccumulator []Ticket       `json:"tickets_accumulator"`
		TicketsOrKeys      TicketsOrKeys  `json:"tickets_or_keys"`
		TicketsVerifierKey string         `json:"tickets_verifier_key"`
	}{}

	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	s.Timeslot = tmp.Timeslot
	var entropy [4][32]byte
	for i, e := range tmp.Entropy {
		entropy[i] = hexToBytes32(e)
	}
	s.Entropy = entropy
	s.PrevValidators = tmp.PrevValidators
	s.CurrValidators = tmp.CurrValidators
	s.NextValidators = tmp.NextValidators
	s.DesignedValidators = tmp.DesignedValidators
	s.TicketsAccumulator = tmp.TicketsAccumulator
	s.TicketsOrKeys = tmp.TicketsOrKeys
	s.TicketsVerifierKey = hexToBytes384(tmp.TicketsVerifierKey)

	return nil
}

func TestSafroleTransitions(t *testing.T) {
	// Get all JSON files in the test directory
	files, err := filepath.Glob("jamtestvectors/safrole/*.json")
	if err != nil {
		t.Fatalf("Failed to read test files: %v", err)
	}

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			// Read the test case file
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("Failed to read test file %s: %v", file, err)
			}

			// Parse the JSON into our TestCase struct
			var testCase TestCase
			err = json.Unmarshal(data, &testCase)
			if err != nil {
				t.Fatalf("Failed to parse JSON in file %s: %v", file, err.Error())
			}

			// Create SafroleInput from the test case
			input := SafroleInput{
				Slot:    testCase.Input.Slot,
				Entropy: hexToBytes32(testCase.Input.Entropy),
				// Convert Extrinsics if needed
			}

			// Run the Safrole transition
			output, err := ProcessSafroleTransition(input, testCase.PreState)
			if err != nil {
				t.Fatalf("ProcessSafroleTransition failed: %v", err)
			}

			// Compare the output with the expected output
			if !compareOutputs(output, testCase.Output.Ok) {
				t.Errorf("Output mismatch in file %s", file)
			}

			// Compare the post-state with the expected post-state
			if ok, err := compareSafroleStates(*output.State, testCase.PostState); !ok {
				t.Errorf("Post-state mismatch in file %s: %v", file, err)
			}
		})
	}
}

func compareOutputs(actual SafroleOutput, expected struct {
	EpochMark   interface{} `json:"epoch_mark"`
	TicketsMark interface{} `json:"tickets_mark"`
}) bool {
	// Implement comparison logic
	return actual.Ok.EpochMark == expected.EpochMark &&
		actual.Ok.TicketsMark == expected.TicketsMark
}

func compareSafroleStates(actual, expected SafroleState) (bool, error) {
	if actual.Timeslot != expected.Timeslot {
		return false, errors.New("Timeslot mismatch")
	}
	if actual.Entropy != expected.Entropy {
		return false, errors.New("Entropy mismatch")
	}
	if !reflect.DeepEqual(actual.PrevValidators, expected.PrevValidators) {
		return false, errors.New("PrevValidators mismatch")
	}
	if !reflect.DeepEqual(actual.CurrValidators, expected.CurrValidators) {
		return false, errors.New("CurrValidators mismatch")
	}
	if !reflect.DeepEqual(actual.NextValidators, expected.NextValidators) {
		return false, errors.New("NextValidators mismatch")
	}
	if !reflect.DeepEqual(actual.DesignedValidators, expected.DesignedValidators) {
		return false, errors.New("DesignedValidators mismatch")
	}
	if !reflect.DeepEqual(actual.TicketsAccumulator, expected.TicketsAccumulator) {
		return false, errors.New("TicketsAccumulator mismatch")
	}
	if !reflect.DeepEqual(actual.TicketsOrKeys, expected.TicketsOrKeys) {
		return false, errors.New("TicketsOrKeys mismatch")
	}
	if actual.TicketsVerifierKey != expected.TicketsVerifierKey {
		return false, errors.New("TicketsVerifierKey mismatch")
	}
	return true, nil
}

func hexToBytes(s string) []byte {
	if len(s) < 2 {
		return []byte{}
	}
	b, _ := hex.DecodeString(s[2:])
	return b
}

func hexToBytes32(s string) [32]byte {
	var arr [32]byte
	b := hexToBytes(s)
	copy(arr[:], b)
	return arr
}

func hexToBytes144(s string) [144]byte {
	var arr [144]byte
	b := hexToBytes(s)
	copy(arr[:], b)
	return arr
}

func hexToBytes128(s string) [128]byte {
	var arr [128]byte
	b := hexToBytes(s)
	copy(arr[:], b)
	return arr
}

func hexToBytes384(s string) [384]byte {
	var arr [384]byte
	b := hexToBytes(s)
	copy(arr[:], b)
	return arr
}
