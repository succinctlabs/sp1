mod air;
mod columns;
mod execute;
mod trace;

use serde::{Deserialize, Serialize};

use crate::runtime::{MemoryReadRecord, MemoryWriteRecord};

pub const SHA_COMPRESS_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShaCompressEvent {
    pub shard: u32,
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
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod compress_tests {

    use crate::{
        runtime::{Instruction, Opcode, Program, SyscallCode},
        utils::{run_test, setup_logger, tests::SHA_COMPRESS_ELF},
    };

    #[must_use]
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
        run_test(program).unwrap();
    }

    #[test]
    fn test_sha_compress_program() {
        setup_logger();
        let program = Program::from(SHA_COMPRESS_ELF);
        run_test(program).unwrap();
    }
}
