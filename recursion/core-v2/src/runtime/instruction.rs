use p3_field::{AbstractExtensionField, AbstractField};
use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Instruction<F> {
    BaseAlu(BaseAluInstr<F>),
    ExtAlu(ExtAluInstr<F>),
    Mem(MemInstr<F>),
    Poseidon2Wide(Poseidon2WideInstr<F>),
}

pub fn base_alu<F: AbstractField>(
    opcode: BaseAluOpcode,
    mult: u32,
    out: u32,
    in1: u32,
    in2: u32,
) -> Instruction<F> {
    Instruction::BaseAlu(BaseAluInstr {
        opcode,
        mult: F::from_canonical_u32(mult),
        addrs: BaseAluIo {
            out: Address(F::from_canonical_u32(out)),
            in1: Address(F::from_canonical_u32(in1)),
            in2: Address(F::from_canonical_u32(in2)),
        },
    })
}

pub fn ext_alu<F: AbstractField>(
    opcode: ExtAluOpcode,
    mult: u32,
    out: u32,
    in1: u32,
    in2: u32,
) -> Instruction<F> {
    Instruction::ExtAlu(ExtAluInstr {
        opcode,
        mult: F::from_canonical_u32(mult),
        addrs: ExtAluIo {
            out: Address(F::from_canonical_u32(out)),
            in1: Address(F::from_canonical_u32(in1)),
            in2: Address(F::from_canonical_u32(in2)),
        },
    })
}

pub fn mem<F: AbstractField>(
    kind: MemAccessKind,
    mult: u32,
    addr: u32,
    val: u32,
) -> Instruction<F> {
    mem_single(kind, mult, addr, F::from_canonical_u32(val))
}

pub fn mem_single<F: AbstractField>(
    kind: MemAccessKind,
    mult: u32,
    addr: u32,
    val: F,
) -> Instruction<F> {
    mem_block(kind, mult, addr, Block::from(val))
}

pub fn mem_ext<F: AbstractField + Copy, EF: AbstractExtensionField<F>>(
    kind: MemAccessKind,
    mult: u32,
    addr: u32,
    val: EF,
) -> Instruction<F> {
    mem_block(kind, mult, addr, val.as_base_slice().into())
}

pub fn mem_block<F: AbstractField>(
    kind: MemAccessKind,
    mult: u32,
    addr: u32,
    val: Block<F>,
) -> Instruction<F> {
    Instruction::Mem(MemInstr {
        addrs: MemIo {
            inner: Address(F::from_canonical_u32(addr)),
        },
        vals: MemIo { inner: val },
        mult: F::from_canonical_u32(mult),
        kind,
    })
}

pub fn poseidon2_wide<F: AbstractField>(
    mult: u32,
    output: [u32; WIDTH],
    input: [u32; WIDTH],
) -> Instruction<F> {
    Instruction::Poseidon2Wide(Poseidon2WideInstr {
        mult: F::from_canonical_u32(mult),
        addrs: Poseidon2Io {
            output: output.map(F::from_canonical_u32).map(Address),
            input: input.map(F::from_canonical_u32).map(Address),
        },
    })
}
