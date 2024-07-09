use core::fmt::Debug;
use p3_field::ExtensionField;
use p3_field::PrimeField;
use p3_field::TwoAdicField;
use sp1_recursion_core::air::Block;
use sp1_recursion_core_v2::BaseAluInstr;
use sp1_recursion_core_v2::Opcode;
use std::collections::hash_map::Entry;
use std::collections::HashMap;

use sp1_recursion_core_v2::*;

use crate::asm::AsmConfig;
use crate::ir::DslIr;
use crate::prelude::TracedVec;

/// The backend for the constraint compiler.
#[derive(Debug, Clone, Default)]
pub struct AsmCompiler<F, EF> {
    pub next_addr: F,
    /// Map the frame pointers of the variables to the "physical" addresses.
    pub fp_to_addr: HashMap<i32, Address<F>>,
    /// Map base field constants to "physical" addresses and mults.
    pub consts_f: HashMap<F, (Address<F>, F)>,
    /// Map extension field constants to "physical" addresses and mults.
    pub consts_ef: HashMap<EF, (Address<F>, F)>,
    /// Map each "physical" address to its read count.
    pub addr_to_mult: HashMap<Address<F>, F>,
}

impl<F, EF> AsmCompiler<F, EF>
where
    F: PrimeField + TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
{
    /// Allocate a fresh address. Checks that the address space is not full.
    pub fn alloc(next_addr: &mut F) -> Address<F> {
        let id = Address(*next_addr);
        *next_addr += F::one();
        if next_addr.is_zero() {
            panic!("out of address space");
        }
        id
    }

    /// Map `fp` to a fresh address and initialize the mult to 0.
    /// Ensures that `fp` has not already been written to.
    pub fn write_fp(&mut self, fp: i32) -> Address<F> {
        match self.fp_to_addr.entry(fp) {
            Entry::Vacant(entry) => {
                let addr = Self::alloc(&mut self.next_addr);
                // This is a write, so we set the mult to zero.
                if let Some(x) = self.addr_to_mult.insert(addr, F::zero()) {
                    panic!("unexpected entry in addr_to_mult: {x:?}");
                }
                *entry.insert(addr)
            }
            Entry::Occupied(entry) => panic!("unexpected entry in fp_to_addr: {entry:?}"),
        }
    }

    /// Map `fp` to its existing address and increment its mult.
    /// Ensures that `fp` has already been assigned an address.
    pub fn read_fp(&mut self, fp: i32) -> Address<F> {
        match self.fp_to_addr.entry(fp) {
            Entry::Vacant(entry) => panic!("expected entry in fp_to_addr: {entry:?}"),
            Entry::Occupied(entry) => {
                // This is a read, so we increment the mult.
                match self.addr_to_mult.get_mut(entry.get()) {
                    Some(mult) => *mult += F::one(),
                    None => panic!("expected entry in addr_mult: {entry:?}"),
                }
                *entry.into_mut()
            }
        }
    }

    /// Read the base field constant.
    /// Increments the mult, first creating an entry if it does not yet exist.
    pub fn read_const_f(&mut self, f: F) -> Address<F> {
        self.consts_f
            .entry(f)
            .and_modify(|(_, x)| *x += F::one())
            .or_insert_with(|| (Self::alloc(&mut self.next_addr), F::one()))
            .0
    }

    /// Read the base field constant.
    /// Increments the mult, first creating an entry if it does not yet exist.
    pub fn read_const_ef(&mut self, ef: EF) -> Address<F> {
        self.consts_ef
            .entry(ef)
            .and_modify(|(_, x)| *x += F::one())
            .or_insert_with(|| (Self::alloc(&mut self.next_addr), F::one()))
            .0
    }

    // ---------------------------------------------------------------------------------------------
    // INSTRUCTION HELPERS

    pub fn init_at_f(&mut self, fp: i32, f: F) -> Instruction<F> {
        self.init_at(fp, Block::from(f))
    }

    pub fn init_at_ef(&mut self, fp: i32, ef: EF) -> Instruction<F> {
        self.init_at(fp, ef.as_base_slice().into())
    }

    pub fn init_at(&mut self, fp: i32, block: Block<F>) -> Instruction<F> {
        let addr = self.write_fp(fp);
        Self::init_at_addr(addr, block)
    }

    pub fn init_at_addr(addr: Address<F>, block: Block<F>) -> Instruction<F> {
        Instruction::Mem(MemInstr {
            addrs: MemIo { inner: addr },
            vals: MemIo { inner: block },
            mult: F::zero(),
            kind: MemAccessKind::Write,
        })
    }

    // ---------------------------------------------------------------------------------------------
    // COMPILATION

    pub fn compile_one(&mut self, ir_instr: DslIr<AsmConfig<F, EF>>) -> Instruction<F> {
        match ir_instr {
            DslIr::ImmV(dst, src) => self.init_at_f(dst.fp(), src),
            DslIr::ImmF(dst, src) => self.init_at_f(dst.fp(), src),
            DslIr::ImmE(dst, src) => self.init_at_ef(dst.fp(), src),

            DslIr::AddV(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::AddF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::AddVI(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::AddF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_const_f(rhs),
                },
            }),
            DslIr::AddF(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::AddF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::AddFI(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::AddF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_const_f(rhs),
                },
            }),
            DslIr::AddE(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::AddE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::AddEI(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::AddE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_const_ef(rhs),
                },
            }),
            DslIr::AddEF(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::AddE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::AddEFI(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::AddE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_const_f(rhs),
                },
            }),
            DslIr::AddEFFI(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::AddE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_const_ef(rhs),
                },
            }),

            DslIr::SubV(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::SubF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::SubVI(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::SubF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_const_f(rhs),
                },
            }),
            DslIr::SubVIN(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::SubF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_const_f(lhs),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::SubF(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::SubF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::SubFI(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::SubF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_const_f(rhs),
                },
            }),
            DslIr::SubFIN(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::SubF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_const_f(lhs),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::SubE(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::SubE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::SubEI(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::SubE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_const_ef(rhs),
                },
            }),
            DslIr::SubEIN(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::SubE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_const_ef(lhs),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::SubEFI(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::SubE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_const_f(rhs),
                },
            }),
            DslIr::SubEF(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::SubE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_fp(rhs.fp()),
                },
            }),

            DslIr::MulV(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::MulF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::MulVI(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::MulF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_const_f(rhs),
                },
            }),
            DslIr::MulF(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::MulF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::MulFI(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::MulF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_const_f(rhs),
                },
            }),
            DslIr::MulE(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::MulE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::MulEI(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::MulE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_const_ef(rhs),
                },
            }),
            DslIr::MulEFI(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::MulE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_const_f(rhs),
                },
            }),
            DslIr::MulEF(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::MulE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_fp(rhs.fp()),
                },
            }),

            DslIr::DivF(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::DivF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::DivFI(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::DivF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_const_f(rhs),
                },
            }),
            DslIr::DivFIN(dst, lhs, rhs) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::DivF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_const_f(lhs),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::DivE(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::DivE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::DivEI(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::DivE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_const_ef(rhs),
                },
            }),
            DslIr::DivEIN(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::DivE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_const_ef(lhs),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::DivEFI(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::DivE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_const_f(rhs),
                },
            }),
            DslIr::DivEFIN(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::DivE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_const_f(lhs),
                    in2: self.read_fp(rhs.fp()),
                },
            }),
            DslIr::DivEF(dst, lhs, rhs) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::DivE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_fp(lhs.fp()),
                    in2: self.read_fp(rhs.fp()),
                },
            }),

            DslIr::NegV(dst, src) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::SubF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_const_f(F::zero()),
                    in2: self.read_fp(src.fp()),
                },
            }),
            DslIr::NegF(dst, src) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::SubF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_const_f(F::zero()),
                    in2: self.read_fp(src.fp()),
                },
            }),
            DslIr::NegE(dst, src) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::SubE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_const_f(F::zero()),
                    in2: self.read_fp(src.fp()),
                },
            }),
            DslIr::InvV(dst, src) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::DivF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_const_f(F::one()),
                    in2: self.read_fp(src.fp()),
                },
            }),
            DslIr::InvF(dst, src) => Instruction::BaseAlu(BaseAluInstr {
                opcode: Opcode::DivF,
                mult: F::zero(),
                addrs: BaseAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_const_f(F::one()),
                    in2: self.read_fp(src.fp()),
                },
            }),
            DslIr::InvE(dst, src) => Instruction::ExtAlu(ExtAluInstr {
                opcode: Opcode::DivE,
                mult: F::zero(),
                addrs: ExtAluIo {
                    out: self.write_fp(dst.fp()),
                    in1: self.read_const_f(F::one()),
                    in2: self.read_fp(src.fp()),
                },
            }),

            // DslIr::AssertEqV(dst, src) => todo!(),

            // DslIr::AssertEqF(dst, src) => todo!(),

            // DslIr::AssertEqE(dst, src) => todo!(),

            // DslIr::AssertEqVI(dst, src) => todo!(),

            // DslIr::AssertEqFI(dst, src) => todo!(),

            // DslIr::AssertEqEI(dst, src) => todo!(),

            // DslIr::For(_, _, _, _, _) => todo!(),
            // DslIr::IfEq(_, _, _, _) => todo!(),
            // DslIr::IfNe(_, _, _, _) => todo!(),
            // DslIr::IfEqI(_, _, _, _) => todo!(),
            // DslIr::IfNeI(_, _, _, _) => todo!(),
            // DslIr::Break => todo!(),
            // DslIr::AssertNeV(_, _) => todo!(),
            // DslIr::AssertNeF(_, _) => todo!(),
            // DslIr::AssertNeE(_, _) => todo!(),
            // DslIr::AssertNeVI(_, _) => todo!(),
            // DslIr::AssertNeFI(_, _) => todo!(),
            // DslIr::AssertNeEI(_, _) => todo!(),
            // DslIr::Alloc(_, _, _) => todo!(),
            // DslIr::LoadV(_, _, _) => todo!(),
            // DslIr::LoadF(_, _, _) => todo!(),
            // DslIr::LoadE(_, _, _) => todo!(),
            // DslIr::StoreV(_, _, _) => todo!(),
            // DslIr::StoreF(_, _, _) => todo!(),
            // DslIr::StoreE(_, _, _) => todo!(),
            // DslIr::CircuitNum2BitsV(_, _, _) => todo!(),
            // DslIr::CircuitNum2BitsF(_, _) => todo!(),
            // DslIr::Poseidon2PermuteBabyBear(_, _) => todo!(),
            // DslIr::Poseidon2CompressBabyBear(_, _, _) => todo!(),
            // DslIr::Poseidon2AbsorbBabyBear(_, _) => todo!(),
            // DslIr::Poseidon2FinalizeBabyBear(_, _) => todo!(),
            // DslIr::CircuitPoseidon2Permute(_) => todo!(),
            // DslIr::CircuitPoseidon2PermuteBabyBear(_) => todo!(),
            // DslIr::HintBitsU(_, _) => todo!(),
            // DslIr::HintBitsV(_, _) => todo!(),
            // DslIr::HintBitsF(_, _) => todo!(),
            // DslIr::PrintV(_) => todo!(),
            // DslIr::PrintF(_) => todo!(),
            // DslIr::PrintE(_) => todo!(),
            // DslIr::Error() => todo!(),
            // DslIr::HintExt2Felt(_, _) => todo!(),
            // DslIr::HintLen(_) => todo!(),
            // DslIr::HintVars(_) => todo!(),
            // DslIr::HintFelts(_) => todo!(),
            // DslIr::HintExts(_) => todo!(),
            // DslIr::WitnessVar(_, _) => todo!(),
            // DslIr::WitnessFelt(_, _) => todo!(),
            // DslIr::WitnessExt(_, _) => todo!(),
            // DslIr::Commit(_, _) => todo!(),
            // DslIr::RegisterPublicValue(_) => todo!(),
            // DslIr::Halt => todo!(),
            // DslIr::CircuitCommitVkeyHash(_) => todo!(),
            // DslIr::CircuitCommitCommitedValuesDigest(_) => todo!(),
            // DslIr::FriFold(_, _) => todo!(),
            // DslIr::CircuitSelectV(_, _, _, _) => todo!(),
            // DslIr::CircuitSelectF(_, _, _, _) => todo!(),
            // DslIr::CircuitSelectE(_, _, _, _) => todo!(),
            // DslIr::CircuitExt2Felt(_, _) => todo!(),
            // DslIr::CircuitFelts2Ext(_, _) => todo!(),
            // DslIr::LessThan(_, _, _) => todo!(),
            // DslIr::CycleTracker(_) => todo!(),
            // DslIr::ExpReverseBitsLen(_, _, _) => todo!(),
            instr => panic!("unsupported instruction: {instr:?}"),
        }
    }

    /// Emit the instructions from a list of operations in the DSL.
    pub fn compile(
        &mut self,
        operations: TracedVec<DslIr<AsmConfig<F, EF>>>,
    ) -> Vec<Instruction<F>> {
        // First, preprocess.
        // Each immediate must be assigned to an address and written to that address.
        // Each fp must be assigned to an address.
        // Reads of each address must be counted.
        // Mults will be set to zero and then filled back in later.

        let mut instrs = operations
            .into_iter()
            .map(|(ir_instr, _)| self.compile_one(ir_instr))
            .collect::<Vec<_>>();
        // Replace the mults.
        for asm_instr in instrs.iter_mut() {
            match asm_instr {
                Instruction::BaseAlu(BaseAluInstr {
                    mult,
                    addrs: BaseAluIo { out, .. },
                    ..
                }) => *mult = self.addr_to_mult.remove(out).unwrap(),
                Instruction::ExtAlu(ExtAluInstr {
                    mult,
                    addrs: ExtAluIo { out, .. },
                    ..
                }) => *mult = self.addr_to_mult.remove(out).unwrap(),
                Instruction::Mem(MemInstr {
                    addrs: MemIo { inner: out },
                    mult,
                    kind: MemAccessKind::Write,
                    ..
                }) => *mult = self.addr_to_mult.remove(out).unwrap(),
                _ => (),
                // _ => panic!("unsupported {:?}", instruction),
            }
        }
        debug_assert!(self.addr_to_mult.is_empty());
        // Initialize constants.
        let instrs_consts_f = self.consts_f.drain().map(|(f, (addr, mult))| {
            Instruction::Mem(MemInstr {
                addrs: MemIo { inner: addr },
                vals: MemIo {
                    inner: Block::from(f),
                },
                mult,
                kind: MemAccessKind::Write,
            })
        });
        let instrs_consts_ef = self.consts_ef.drain().map(|(ef, (addr, mult))| {
            Instruction::Mem(MemInstr {
                addrs: MemIo { inner: addr },
                vals: MemIo {
                    inner: ef.as_base_slice().into(),
                },
                mult,
                kind: MemAccessKind::Write,
            })
        });
        // Reset the other fields.
        self.next_addr = Default::default();
        self.fp_to_addr.clear();
        // Place constant-initializing instructions at the top.
        instrs_consts_f
            .chain(instrs_consts_ef)
            .chain(instrs)
            .collect()
    }
}

#[cfg(test)]
#[cfg(ignore)] // TODO make test work
mod tests {
    use p3_baby_bear::DiffusionMatrixBabyBear;
    use sp1_core::{stark::StarkGenericConfig, utils::run_test_machine};
    use sp1_recursion_core::stark::config::BabyBearPoseidon2Outer;
    use sp1_recursion_core_v2::{machine::RecursionAir, RecursionProgram, Runtime};

    use p3_field::AbstractField;

    use crate::{asm::AsmBuilder, prelude::*};

    #[test]
    fn arithmetic() {
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type A = RecursionAir<F>;

        // let n_val = 10;
        let mut builder = AsmBuilder::<F, EF>::default();
        let a: Felt<_> = builder.eval(F::one());
        let b: Felt<_> = builder.eval(F::one());

        let temp: Felt<_> = builder.eval(F::one());
        builder.assign(temp, a + b);
        builder.assign(b, a + temp);
        builder.assign(a, temp);
        // let expected_value = F::from_canonical_u32(0);
        // builder.assert_felt_eq(a, expected_value);

        let mut compiler = super::AsmCompiler::default();
        let instructions = compiler.compile(builder.operations);

        println!("Program size = {}", instructions.len());

        let program = RecursionProgram { instructions };
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new(&program);
        runtime.run();

        let config = SC::new();
        let machine = A::machine(config);
        let (pk, vk) = machine.setup(&program);
        let result = run_test_machine(runtime.record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }
}
