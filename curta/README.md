
## How to run

cargo run --bin curta -- --program fib 
Instruction { opcode: ADDI, op_a: 2, op_b: 2, op_c: 4294967216 }
Instruction { opcode: SW, op_a: 1, op_b: 2, op_c: 76 }
Instruction { opcode: SW, op_a: 10, op_b: 2, op_c: 12 }
...
Instruction { opcode: JALR, op_a: 1, op_b: 1, op_c: 4294967172 }
Instruction { opcode: UNIMP, op_a: 0, op_b: 0, op_c: 0 }
initial pc: 264
[0, 928, 8388608, 0, 0, 0, 0, 0, 0, 0, 55, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]