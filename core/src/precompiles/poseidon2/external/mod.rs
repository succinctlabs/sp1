use std::ops::Add;

use p3_field::Field;

use crate::cpu::{MemoryReadRecord, MemoryWriteRecord};

use self::constants::RC_16_30;

mod add_rc;
mod air;
mod columns;
mod constants;
mod execute;
mod external_linear_permute;
mod sbox;
mod trace;

/// The number of field elements in a Poseidon2 state.
pub const P2_WIDTH: usize = 16;

pub const P2_DEFAULT_ROUNDS_F: usize = 8;
pub const P2_DEFAULT_ROUNDS_P: usize = 22;
pub const P2_TOTAL_ROUNDS: usize = P2_DEFAULT_ROUNDS_F + P2_DEFAULT_ROUNDS_P;

/// The number of times to loop in the first or the last external round of Poseidon2.
pub const P2_EXTERNAL_ROUND_COUNT: usize = P2_DEFAULT_ROUNDS_F / 2;

pub const P2_SBOX_EXPONENT: usize = 7;

/// The number of bits necessary to express `P2_SBOX_EXPONENT`. Used to decide how many times
/// we need to square an element to raise it to the power of `P2_SBOX_EXPONENT` using the
/// exponentiation by squaring algorithm.
pub const P2_SBOX_EXPONENT_LOG2: usize = 3;

pub const P2_ROUND_CONSTANTS: [[u32; P2_WIDTH]; P2_TOTAL_ROUNDS] = RC_16_30;

/// An `Event` struct recording the state of the Poseidon2 permutation during either the first or
/// the second external round.
#[derive(Debug, Clone, Copy)]
pub struct Poseidon2ExternalEvent<const WIDTH: usize> {
    pub clk: u32,
    pub state_ptr: u32,
    pub state_reads: [[MemoryReadRecord; WIDTH]; P2_EXTERNAL_ROUND_COUNT],
    pub state_writes: [[MemoryWriteRecord; WIDTH]; P2_EXTERNAL_ROUND_COUNT],
}

/// The first external round of the Poseidon2 permutation.
///
/// TODO: When implementing the second external round, we should attempt to share as much code as
/// possible between the two rounds.
pub struct Poseidon2External1Chip<F: Field> {
    pub _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> Poseidon2External1Chip<F> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

/// Implements the permutation given by the matrix:
///  ```ignore
///     M4 = [[5, 7, 1, 3],
///           [4, 6, 1, 1],
///           [1, 3, 5, 7],
///           [1, 1, 4, 6]];
///   ```
fn m4_permute_mut<T>(input: &mut [T; 4])
where
    T: Add<Output = T> + Default + Clone,
{
    // Implements the permutation given by the matrix M4 with multiplications unrolled as
    // additions and doublings.
    let mut t_0 = input[0].clone();
    t_0 = t_0 + input[1].clone();
    let mut t_1 = input[2].clone();
    t_1 = t_1 + input[3].clone();
    let mut t_2 = input[1].clone();
    t_2 = t_2.clone() + t_2.clone();
    t_2 = t_2.clone() + t_1.clone();
    let mut t_3 = input[3].clone();
    t_3 = t_3.clone() + t_3.clone();
    t_3 = t_3.clone() + t_0.clone();
    let mut t_4 = t_1.clone();
    t_4 = t_4.clone() + t_4.clone();
    t_4 = t_4.clone() + t_4.clone();
    t_4 = t_4.clone() + t_3.clone();
    let mut t_5 = t_0.clone();
    t_5 = t_5.clone() + t_5.clone();
    t_5 = t_5.clone() + t_5.clone();
    t_5 = t_5.clone() + t_2.clone();
    let mut t_6 = t_3.clone();
    t_6 = t_6.clone() + t_5.clone();
    let mut t_7 = t_2.clone();
    t_7 = t_7.clone() + t_4.clone();
    input[0] = t_6;
    input[1] = t_5;
    input[2] = t_7;
    input[3] = t_4;
}

pub(crate) fn matmul_m4<T, const WIDTH: usize>(input: &mut [T; WIDTH])
where
    T: Add<Output = T> + Default + Clone,
{
    input
        .chunks_exact_mut(4)
        .for_each(|x| m4_permute_mut(x.try_into().unwrap()));
}

pub(crate) fn external_linear_permute_mut<T, const WIDTH: usize>(input: &mut [T; WIDTH])
where
    T: Add<Output = T> + Default + Clone,
{
    match WIDTH {
        16 => {
            // First, apply Diag(M4, ..., M4).
            matmul_m4(input);

            let t4 = WIDTH / 4;
            // Four 0's.
            let mut stored = [T::default(), T::default(), T::default(), T::default()];
            for l in 0..4 {
                stored[l] = input[l].clone();
                for j in 1..t4 {
                    stored[l] = stored[l].clone() + input[j * 4 + l].clone();
                }
            }
            for i in 0..WIDTH {
                input[i] = input[i].clone() + stored[i % 4].clone();
            }
        }
        _ => unimplemented!(),
    }
}

#[cfg(test)]
pub mod external_tests {

    use crate::{
        runtime::{Instruction, Opcode, Program, Syscall},
        utils::{prove, setup_logger, tests::POSEIDON2_EXTERNAL_1_ELF},
    };

    use super::P2_WIDTH;

    pub fn poseidon2_external_1_program() -> Program {
        let w_ptr = 100;
        let mut instructions = vec![];
        for i in 0..P2_WIDTH {
            // Store 100 + i in memory for the i-th word of the state. 100 + i is an arbitrary
            // number that is easy to spot while debugging.
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 29, 0, 100 + i as u32, false, true),
                Instruction::new(Opcode::ADD, 30, 0, w_ptr + i as u32 * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }
        instructions.extend(vec![
            Instruction::new(
                Opcode::ADD,
                5,
                0,
                Syscall::POSEIDON2_EXTERNAL_1 as u32,
                false,
                true,
            ),
            Instruction::new(Opcode::ADD, 10, 0, w_ptr, false, true),
            Instruction::new(Opcode::ECALL, 10, 5, 0, false, true),
        ]);
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn prove_babybear() {
        setup_logger();
        let program = poseidon2_external_1_program();
        prove(program);
    }

    #[test]
    fn test_poseidon2_external_1_simple() {
        setup_logger();
        let program = Program::from(POSEIDON2_EXTERNAL_1_ELF);
        prove(program);
    }
}
