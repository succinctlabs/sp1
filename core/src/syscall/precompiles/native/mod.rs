use std::fmt::{Display, Formatter};

use crate::runtime::{ExecutionRecord, SyscallCode};
use crate::syscall::precompiles::{MemoryReadRecord, MemoryWriteRecord};

mod air;
mod syscall;
mod trace;

pub use air::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BinaryOpcode {
    Add = SyscallCode::FADD as isize,
    Mul = SyscallCode::FMUL as isize,
    Sub = SyscallCode::FSUB as isize,
    Div = SyscallCode::FDIV as isize,
}

/// An arithmetic binary operation in the air native field.
///
/// The event descrives a request for `Op(a, b) -> a` where `Op` is an arithmetic binary operation,
/// `b` and `c` are the input operands, and `a` is the output. The supported operations are:
/// `add`, `mul`, `sub`, `div`.
#[derive(Clone, Debug)]
pub struct NativeEvent {
    pub clk: u32,
    pub shard: u32,

    a_record: MemoryWriteRecord,
    b_record: MemoryReadRecord,
}

impl BinaryOpcode {
    pub(crate) fn events<'b>(&self, input: &'b ExecutionRecord) -> &'b [NativeEvent] {
        match self {
            Self::Add => &input.native_add_events,
            Self::Mul => &input.native_mul_events,
            Self::Sub => &input.native_sub_events,
            Self::Div => &input.native_div_events,
        }
    }

    pub(crate) fn events_mut<'b>(
        &self,
        input: &'b mut ExecutionRecord,
    ) -> &'b mut Vec<NativeEvent> {
        match self {
            Self::Add => &mut input.native_add_events,
            Self::Mul => &mut input.native_mul_events,
            Self::Sub => &mut input.native_sub_events,
            Self::Div => &mut input.native_div_events,
        }
    }
}

impl Display for BinaryOpcode {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        match self {
            Self::Add => write!(f, "add"),
            Self::Mul => write!(f, "mul"),
            Self::Sub => write!(f, "sub"),
            Self::Div => write!(f, "div"),
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;
    use rand::Rng;

    use crate::{
        runtime::{Instruction, Opcode, Program, Runtime, SyscallCode, A0, A1, T0, ZERO},
        utils::{run_test, setup_logger},
    };

    #[test]
    fn test_add_native_execute() {
        type F = BabyBear;
        let num_tests = 10;
        let mut rng = rand::thread_rng();
        for _ in 0..num_tests {
            let a = rng.gen::<F>();
            let b = rng.gen::<F>();
            // main:
            //     addi a0, x0, a
            //     addi a1, x0, b
            //     FADD
            let instructions = vec![
                Instruction::new(
                    Opcode::ADD,
                    A0 as u32,
                    ZERO as u32,
                    a.as_canonical_u32(),
                    false,
                    true,
                ),
                Instruction::new(
                    Opcode::ADD,
                    A1 as u32,
                    ZERO as u32,
                    b.as_canonical_u32(),
                    false,
                    true,
                ),
                Instruction::new(
                    Opcode::ADD,
                    T0 as u32,
                    0,
                    SyscallCode::FADD as u32,
                    false,
                    true,
                ),
                Instruction::new(Opcode::ECALL, A0 as u32, T0 as u32, 0, false, true),
            ];
            let program = Program::new(instructions, 0, 0);

            let mut runtime = Runtime::<BabyBear>::new(program);
            runtime.run();
            assert_eq!(runtime.register(A0), (a + b).as_canonical_u32());
        }
    }

    #[test]
    fn test_native_add_prove() {
        type F = BabyBear;
        setup_logger();
        let num_tests = 3;

        let mut rng = rand::thread_rng();
        for _ in 0..num_tests {
            let a = rng.gen::<F>();
            let b = rng.gen::<F>();
            // main:
            //     addi a0, x0, a
            //     addi a1, x0, b
            //     FADD
            let instructions = vec![
                Instruction::new(
                    Opcode::ADD,
                    A0 as u32,
                    ZERO as u32,
                    a.as_canonical_u32(),
                    false,
                    true,
                ),
                Instruction::new(
                    Opcode::ADD,
                    A1 as u32,
                    ZERO as u32,
                    b.as_canonical_u32(),
                    false,
                    true,
                ),
                Instruction::new(
                    Opcode::ADD,
                    T0 as u32,
                    0,
                    SyscallCode::FADD as u32,
                    false,
                    true,
                ),
                Instruction::new(Opcode::ECALL, A0 as u32, T0 as u32, 0, false, true),
            ];
            let program = Program::new(instructions, 0, 0);
            run_test(program).unwrap();
        }
    }

    #[test]
    fn test_mul_native_execute() {
        type F = BabyBear;
        let num_tests = 10;
        let mut rng = rand::thread_rng();
        for _ in 0..num_tests {
            let a = rng.gen::<F>();
            let b = rng.gen::<F>();
            // main:
            //     addi a0, x0, a
            //     addi a1, x0, b
            //     FMUL
            let instructions = vec![
                Instruction::new(
                    Opcode::ADD,
                    A0 as u32,
                    ZERO as u32,
                    a.as_canonical_u32(),
                    false,
                    true,
                ),
                Instruction::new(
                    Opcode::ADD,
                    A1 as u32,
                    ZERO as u32,
                    b.as_canonical_u32(),
                    false,
                    true,
                ),
                Instruction::new(
                    Opcode::ADD,
                    T0 as u32,
                    0,
                    SyscallCode::FMUL as u32,
                    false,
                    true,
                ),
                Instruction::new(Opcode::ECALL, A0 as u32, T0 as u32, 0, false, true),
            ];
            let program = Program::new(instructions, 0, 0);

            let mut runtime = Runtime::<BabyBear>::new(program);
            runtime.run();
            assert_eq!(runtime.register(A0), (a * b).as_canonical_u32());
        }
    }

    #[test]
    fn test_native_mul_prove() {
        type F = BabyBear;
        setup_logger();
        let num_tests = 3;

        let mut rng = rand::thread_rng();
        for _ in 0..num_tests {
            let a = rng.gen::<F>();
            let b = rng.gen::<F>();
            // main:
            //     addi a0, x0, a
            //     addi a1, x0, b
            //     FMUL
            let instructions = vec![
                Instruction::new(
                    Opcode::ADD,
                    A0 as u32,
                    ZERO as u32,
                    a.as_canonical_u32(),
                    false,
                    true,
                ),
                Instruction::new(
                    Opcode::ADD,
                    A1 as u32,
                    ZERO as u32,
                    b.as_canonical_u32(),
                    false,
                    true,
                ),
                Instruction::new(
                    Opcode::ADD,
                    T0 as u32,
                    0,
                    SyscallCode::FMUL as u32,
                    false,
                    true,
                ),
                Instruction::new(Opcode::ECALL, A0 as u32, T0 as u32, 0, false, true),
            ];
            let program = Program::new(instructions, 0, 0);
            run_test(program).unwrap();
        }
    }

    #[test]
    fn test_native_sub_execute() {
        type F = BabyBear;
        let num_tests = 10;
        let mut rng = rand::thread_rng();
        for _ in 0..num_tests {
            let a = rng.gen::<F>();
            let b = rng.gen::<F>();
            // main:
            //     addi a0, x0, a
            //     addi a1, x0, b
            //     FSUB
            let instructions = vec![
                Instruction::new(
                    Opcode::ADD,
                    A0 as u32,
                    ZERO as u32,
                    a.as_canonical_u32(),
                    false,
                    true,
                ),
                Instruction::new(
                    Opcode::ADD,
                    A1 as u32,
                    ZERO as u32,
                    b.as_canonical_u32(),
                    false,
                    true,
                ),
                Instruction::new(
                    Opcode::ADD,
                    T0 as u32,
                    0,
                    SyscallCode::FSUB as u32,
                    false,
                    true,
                ),
                Instruction::new(Opcode::ECALL, A0 as u32, T0 as u32, 0, false, true),
            ];
            let program = Program::new(instructions, 0, 0);

            let mut runtime = Runtime::<BabyBear>::new(program);
            runtime.run();
            assert_eq!(runtime.register(A0), (a - b).as_canonical_u32());
        }
    }

    #[test]
    fn test_native_sub_prove() {
        type F = BabyBear;
        setup_logger();
        let num_tests = 3;

        let mut rng = rand::thread_rng();
        for _ in 0..num_tests {
            let a = rng.gen::<F>();
            let b = rng.gen::<F>();
            // main:
            //     addi a0, x0, a
            //     addi a1, x0, b
            //     FSUB
            let instructions = vec![
                Instruction::new(
                    Opcode::ADD,
                    A0 as u32,
                    ZERO as u32,
                    a.as_canonical_u32(),
                    false,
                    true,
                ),
                Instruction::new(
                    Opcode::ADD,
                    A1 as u32,
                    ZERO as u32,
                    b.as_canonical_u32(),
                    false,
                    true,
                ),
                Instruction::new(
                    Opcode::ADD,
                    T0 as u32,
                    0,
                    SyscallCode::FSUB as u32,
                    false,
                    true,
                ),
                Instruction::new(Opcode::ECALL, A0 as u32, T0 as u32, 0, false, true),
            ];
            let program = Program::new(instructions, 0, 0);
            run_test(program).unwrap();
        }
    }

    #[test]
    fn test_native_div_execute() {
        type F = BabyBear;
        let num_tests = 10;
        let mut rng = rand::thread_rng();
        for _ in 0..num_tests {
            let a = rng.gen::<F>();
            let b = rng.gen::<F>();
            // main:
            //     addi a0, x0, a
            //     addi a1, x0, b
            //     FDIV
            let instructions = vec![
                Instruction::new(
                    Opcode::ADD,
                    A0 as u32,
                    ZERO as u32,
                    a.as_canonical_u32(),
                    false,
                    true,
                ),
                Instruction::new(
                    Opcode::ADD,
                    A1 as u32,
                    ZERO as u32,
                    b.as_canonical_u32(),
                    false,
                    true,
                ),
                Instruction::new(
                    Opcode::ADD,
                    T0 as u32,
                    0,
                    SyscallCode::FDIV as u32,
                    false,
                    true,
                ),
                Instruction::new(Opcode::ECALL, A0 as u32, T0 as u32, 0, false, true),
            ];
            let program = Program::new(instructions, 0, 0);

            let mut runtime = Runtime::<BabyBear>::new(program);
            runtime.run();
            assert_eq!(runtime.register(A0), (a / b).as_canonical_u32());
        }
    }

    #[test]
    fn test_native_div_prove() {
        type F = BabyBear;
        setup_logger();
        let num_tests = 3;

        let mut rng = rand::thread_rng();
        for _ in 0..num_tests {
            let a = rng.gen::<F>();
            let b = rng.gen::<F>();
            // main:
            //     addi a0, x0, a
            //     addi a1, x0, b
            //     FDIV
            let instructions = vec![
                Instruction::new(
                    Opcode::ADD,
                    A0 as u32,
                    ZERO as u32,
                    a.as_canonical_u32(),
                    false,
                    true,
                ),
                Instruction::new(
                    Opcode::ADD,
                    A1 as u32,
                    ZERO as u32,
                    b.as_canonical_u32(),
                    false,
                    true,
                ),
                Instruction::new(
                    Opcode::ADD,
                    T0 as u32,
                    0,
                    SyscallCode::FDIV as u32,
                    false,
                    true,
                ),
                Instruction::new(Opcode::ECALL, A0 as u32, T0 as u32, 0, false, true),
            ];
            let program = Program::new(instructions, 0, 0);
            run_test(program).unwrap();
        }
    }
}
