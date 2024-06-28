package main

import (
	"errors"
)

const (
	RegisterCount        = 13
	MaxInstructionLength = 16
	JumpAlignmentFactor  = 4
	MemorySize           = 1 << 32 // 4GB of memory
)

type PVM struct {
	Code      []byte
	JumpTable []uint32
	Registers [RegisterCount]uint32
	Memory    Memory
	GasLimit  uint64
	GasUsed   uint64
	PC        uint32 // Program Counter
}

type Memory struct {
	Data      []byte
	ReadMask  []bool
	WriteMask []bool
}

type ExitReason uint32

const (
	ExitHalt ExitReason = iota
	ExitPanic
	ExitOOG
	ExitFault
	ExitHost
)

func NewPVM(code []byte, jumpTable []uint32, gasLimit uint64) (*PVM, error) {
	if len(code) == 0 {
		return nil, errors.New("code cannot be empty")
	}
	if gasLimit == 0 {
		return nil, errors.New("gas limit must be greater than zero")
	}
	return &PVM{
		Code:      code,
		JumpTable: jumpTable,
		GasLimit:  gasLimit,
		Memory:    NewMemory(),
	}, nil
}

func NewMemory() Memory {
	return Memory{
		Data:      make([]byte, MemorySize),
		ReadMask:  make([]bool, MemorySize),
		WriteMask: make([]bool, MemorySize),
	}
}

func (pvm *PVM) Execute() (ExitReason, uint32, error) {
	for pvm.GasUsed < pvm.GasLimit {
		exitReason, value, err := pvm.executeInstruction()
		if err != nil {
			return ExitPanic, 0, err
		}
		if exitReason != ExitHalt {
			return exitReason, value, nil
		}
	}
	return ExitOOG, 0, nil
}

func (pvm *PVM) executeInstruction() (ExitReason, uint32, error) {
	if pvm.PC >= uint32(len(pvm.Code)) {
		return ExitPanic, 0, errors.New("program counter out of bounds")
	}

	opcode := pvm.Code[pvm.PC]
	instructionLength := pvm.skipLength() + 1

	gasCost := pvm.calculateGasCost(opcode)
	if pvm.GasUsed+gasCost > pvm.GasLimit {
		return ExitOOG, 0, nil
	}
	pvm.GasUsed += gasCost

	switch opcode {
	case 0x00: // trap
		return ExitHalt, 0, nil
	case 0x11: // fallthrough
		// No operation
	// TODO: Implement other instructions
	default:
		return ExitPanic, 0, errors.New("unknown opcode")
	}

	pvm.PC += instructionLength
	return ExitHalt, 0, nil
}

func (pvm *PVM) skipLength() uint32 {
	for i := uint32(1); i <= 24; i++ {
		if pvm.PC+i >= uint32(len(pvm.Code)) || pvm.Code[pvm.PC+i] == 1 {
			return i - 1
		}
	}
	return 24
}

func (pvm *PVM) calculateGasCost(opcode byte) uint64 {
	// TODO: Implement proper gas cost calculation
	return 10 // Placeholder
}

func (pvm *PVM) readImmediate(length uint32) uint32 {
	if length > 4 {
		length = 4
	}
	var value uint32
	for i := uint32(0); i < length; i++ {
		value |= uint32(pvm.Code[pvm.PC+1+i]) << (8 * i)
	}
	return signExtend(value, uint(length*8))
}

func signExtend(value uint32, bits uint) uint32 {
	mask := uint32(1) << (bits - 1)
	return uint32((int32(value^mask) - int32(mask)))
}

func (pvm *PVM) dynamicJump(address uint32) (ExitReason, uint32, error) {
	if address == 0xFFFF0000 {
		return ExitHalt, 0, nil
	}
	if address == 0 || address > uint32(len(pvm.JumpTable))*JumpAlignmentFactor || address%JumpAlignmentFactor != 0 {
		return ExitPanic, 0, errors.New("invalid jump address")
	}
	jumpIndex := (address / JumpAlignmentFactor) - 1
	if !pvm.isBasicBlockStart(pvm.JumpTable[jumpIndex]) {
		return ExitPanic, 0, errors.New("jump destination is not a basic block start")
	}
	pvm.PC = pvm.JumpTable[jumpIndex]
	return ExitHalt, 0, nil
}

func (pvm *PVM) isBasicBlockStart(address uint32) bool {
	// TODO: Implement logic to check if the address is the start of a basic block
	return true // Placeholder
}

// Memory operations

func (m *Memory) Read(address uint32, size uint32) ([]byte, error) {
	if address+size > uint32(len(m.Data)) {
		return nil, errors.New("memory read out of bounds")
	}
	for i := uint32(0); i < size; i++ {
		if !m.ReadMask[address+i] {
			return nil, errors.New("memory read access violation")
		}
	}
	return m.Data[address : address+size], nil
}

func (m *Memory) Write(address uint32, value []byte) error {
	if address+uint32(len(value)) > uint32(len(m.Data)) {
		return errors.New("memory write out of bounds")
	}
	for i := uint32(0); i < uint32(len(value)); i++ {
		if !m.WriteMask[address+i] {
			return errors.New("memory write access violation")
		}
	}
	copy(m.Data[address:], value)
	return nil
}

func ExecutePVM(code []byte, entryPoint uint32, args ...interface{}) (interface{}, error) {
	pvm, err := NewPVM(code, nil, 1000) // Gas limit of 1000
	if err != nil {
		return nil, err
	}
	exitReason, value, err := pvm.Execute()
	if err != nil {
		return nil, err
	}
	if exitReason != ExitHalt {
		return nil, errors.New("pvm execution failed")
	}
	return value, nil
}
