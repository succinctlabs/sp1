mod air;
mod columns;
mod execute;
mod trace;

use serde::{Deserialize, Serialize};

use crate::runtime::{MemoryReadRecord, MemoryWriteRecord};

pub const SHA_COMPRESS_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShaCompressEvent {
    pub lookup_id: u128,
    pub shard: u32,
    pub channel: u8,
    pub clk: u32,
    pub w_ptr: u32,
    pub h_ptr: u32,
    pub w: Vec<u32>,
    pub h: [u32; 8],
    pub h_read_records: [MemoryReadRecord; 8],
    pub w_i_read_records: Vec<MemoryReadRecord>,
    pub h_write_records: [MemoryWriteRecord; 8],
}

/// Implements the SHA compress operation which loops over 0 = [0, 63] and modifies A-H in each
/// iteration. The inputs to the syscall are a pointer to the 64 word array W and a pointer to the 8
/// word array H.
///
/// In the AIR, each SHA compress syscall takes up 80 rows. The first and last 8 rows are for
/// initialization and finalize respectively. The middle 64 rows are for compression. Each row
/// operates over a single memory word.
#[derive(Default)]
pub struct ShaCompressChip;

impl ShaCompressChip {
    pub const fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod compress_tests {

    use crate::{
        runtime::{Instruction, Opcode, Program, SyscallCode},
        stark::DefaultProver,
        utils::{run_test, setup_logger, tests::SHA_COMPRESS_ELF},
    };

    pub fn sha_compress_program() -> Program {
        let w_ptr = 100;
        let h_ptr = 1000;
        let mut instructions = vec![Instruction::new(Opcode::ADD, 29, 0, 5, false, true)];
        for i in 0..64 {
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 30, 0, w_ptr + i * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }
        for i in 0..8 {
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 30, 0, h_ptr + i * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }
        instructions.extend(vec![
            Instruction::new(
                Opcode::ADD,
                5,
                0,
                SyscallCode::SHA_COMPRESS as u32,
                false,
                true,
            ),
            Instruction::new(Opcode::ADD, 10, 0, w_ptr, false, true),
            Instruction::new(Opcode::ADD, 11, 0, h_ptr, false, true),
            Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        ]);
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn prove_babybear() {
        setup_logger();
        let program = sha_compress_program();
        run_test::<DefaultProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_sha_compress_program() {
        setup_logger();
        let program = Program::from(SHA_COMPRESS_ELF);
        run_test::<DefaultProver<_, _>>(program).unwrap();
    }
}
