package main

import "testing"

func TestPVM(t *testing.T) { // Example code (a simple program that adds two numbers)
	code := []byte{
		0x04, 0x00, 0x0A, 0x00, 0x00, 0x00, // load_imm 10 into register 0
		0x04, 0x01, 0x14, 0x00, 0x00, 0x00, // load_imm 20 into register 1
		0x08, 0x00, 0x01, 0x02, // add register 0 and 1, store result in register 2
		0x00, // trap (halt)
	}

	// Jump table (in this simple example, we only have one basic block)
	jumpTable := []uint32{0}

	// Create a new PVM instance
	pvm, err := NewPVM(code, jumpTable, 1000) // Gas limit of 1000
	if err != nil {
		panic(err)
	}

	// Execute the PVM
	exitReason, _, err := pvm.Execute()
	if err != nil {
		panic(err)
	}

	// Check the result
	if exitReason == ExitHalt {
		result := pvm.Registers[2] // The result should be in register 2
		println("Result:", result) // Should print "Result: 30"
	} else {
		println("Execution failed with exit reason:", exitReason)
	}
}
