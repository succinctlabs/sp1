use core::fmt::Debug;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::ExtensionField;
use p3_field::PrimeField;
use p3_field::TwoAdicField;
use sp1_recursion_core::air::Block;
use sp1_recursion_core_v2::BaseAluInstr;
use sp1_recursion_core_v2::BaseAluOpcode;
use std::collections::hash_map::Entry;
use std::collections::HashMap;

use sp1_recursion_core_v2::*;

use crate::asm::AsmConfig;
use crate::prelude::*;

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

    /// Associate a `mult` of zero with `addr`.
    /// Ensures that `addr` has not already been written to.
    pub fn write_addr(&mut self, addr: Address<F>) -> F {
        match self.addr_to_mult.entry(addr) {
            Entry::Vacant(entry) => *entry.insert(F::zero()),
            Entry::Occupied(entry) => panic!("unexpected entry in addr_to_mult: {entry:?}"),
        }
    }

    /// Increment the existing `mult` associated with `addr`.
    /// Ensures that `addr` has already been assigned a `mult`.
    pub fn read_addr(&mut self, addr: Address<F>) -> F {
        match self.addr_to_mult.entry(addr) {
            Entry::Vacant(entry) => panic!("expected entry in addr_to_mult: {entry:?}"),
            Entry::Occupied(entry) => {
                // This is a read, so we increment the mult.
                let mult = entry.into_mut();
                *mult += F::one();
                *mult
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

    fn mem_write_const(&mut self, dst: impl Reg<F, EF>, src: Imm<F, EF>) -> Instruction<F> {
        Instruction::Mem(MemInstr {
            addrs: MemIo {
                inner: dst.write(self),
            },
            vals: MemIo {
                inner: src.as_block(),
            },
            mult: F::zero(),
            kind: MemAccessKind::Write,
        })
    }

    fn base_alu(
        &mut self,
        opcode: BaseAluOpcode,
        dst: impl Reg<F, EF>,
        lhs: impl Reg<F, EF>,
        rhs: impl Reg<F, EF>,
    ) -> Instruction<F> {
        Instruction::BaseAlu(BaseAluInstr {
            opcode,
            mult: F::zero(),
            addrs: BaseAluIo {
                out: dst.write(self),
                in1: lhs.read(self),
                in2: rhs.read(self),
            },
        })
    }

    fn ext_alu(
        &mut self,
        opcode: ExtAluOpcode,
        dst: impl Reg<F, EF>,
        lhs: impl Reg<F, EF>,
        rhs: impl Reg<F, EF>,
    ) -> Instruction<F> {
        Instruction::ExtAlu(ExtAluInstr {
            opcode,
            mult: F::zero(),
            addrs: ExtAluIo {
                out: dst.write(self),
                in1: lhs.read(self),
                in2: rhs.read(self),
            },
        })
    }

    fn base_assert_eq(
        &mut self,
        lhs: impl Reg<F, EF>,
        rhs: impl Reg<F, EF>,
    ) -> Vec<Instruction<F>> {
        use BaseAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));
        vec![
            self.base_alu(SubF, diff, lhs, rhs),
            self.base_alu(DivF, out, diff, Imm::F(F::zero())),
        ]
    }

    fn base_assert_ne(
        &mut self,
        lhs: impl Reg<F, EF>,
        rhs: impl Reg<F, EF>,
    ) -> Vec<Instruction<F>> {
        use BaseAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));
        vec![
            self.base_alu(SubF, diff, lhs, rhs),
            self.base_alu(DivF, out, Imm::F(F::one()), diff),
        ]
    }

    fn ext_assert_eq(&mut self, lhs: impl Reg<F, EF>, rhs: impl Reg<F, EF>) -> Vec<Instruction<F>> {
        use ExtAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));
        vec![
            self.ext_alu(SubE, diff, lhs, rhs),
            self.ext_alu(DivE, out, diff, Imm::EF(EF::zero())),
        ]
    }

    fn ext_assert_ne(&mut self, lhs: impl Reg<F, EF>, rhs: impl Reg<F, EF>) -> Vec<Instruction<F>> {
        use ExtAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));
        vec![
            self.ext_alu(SubE, diff, lhs, rhs),
            self.ext_alu(DivE, out, Imm::EF(EF::one()), diff),
        ]
    }

    // ---------------------------------------------------------------------------------------------
    // COMPILATION

    pub fn compile_one(&mut self, ir_instr: DslIr<AsmConfig<F, EF>>) -> Vec<Instruction<F>> {
        // For readability. Avoids polluting outer scope.
        use BaseAluOpcode::*;
        use ExtAluOpcode::*;

        match ir_instr {
            DslIr::ImmV(dst, src) => vec![self.mem_write_const(dst, Imm::F(src))],
            DslIr::ImmF(dst, src) => vec![self.mem_write_const(dst, Imm::F(src))],
            DslIr::ImmE(dst, src) => vec![self.mem_write_const(dst, Imm::EF(src))],

            DslIr::AddV(dst, lhs, rhs) => vec![self.base_alu(AddF, dst, lhs, rhs)],
            DslIr::AddVI(dst, lhs, rhs) => vec![self.base_alu(AddF, dst, lhs, Imm::F(rhs))],
            DslIr::AddF(dst, lhs, rhs) => vec![self.base_alu(AddF, dst, lhs, rhs)],
            DslIr::AddFI(dst, lhs, rhs) => vec![self.base_alu(AddF, dst, lhs, Imm::F(rhs))],
            DslIr::AddE(dst, lhs, rhs) => vec![self.ext_alu(AddE, dst, lhs, rhs)],
            DslIr::AddEI(dst, lhs, rhs) => vec![self.ext_alu(AddE, dst, lhs, Imm::EF(rhs))],
            DslIr::AddEF(dst, lhs, rhs) => vec![self.ext_alu(AddE, dst, lhs, rhs)],
            DslIr::AddEFI(dst, lhs, rhs) => vec![self.ext_alu(AddE, dst, lhs, Imm::F(rhs))],
            DslIr::AddEFFI(dst, lhs, rhs) => vec![self.ext_alu(AddE, dst, lhs, Imm::EF(rhs))],

            DslIr::SubV(dst, lhs, rhs) => vec![self.base_alu(SubF, dst, lhs, rhs)],
            DslIr::SubVI(dst, lhs, rhs) => vec![self.base_alu(SubF, dst, lhs, Imm::F(rhs))],
            DslIr::SubVIN(dst, lhs, rhs) => vec![self.base_alu(SubF, dst, Imm::F(lhs), rhs)],
            DslIr::SubF(dst, lhs, rhs) => vec![self.base_alu(SubF, dst, lhs, rhs)],
            DslIr::SubFI(dst, lhs, rhs) => vec![self.base_alu(SubF, dst, lhs, Imm::F(rhs))],
            DslIr::SubFIN(dst, lhs, rhs) => vec![self.base_alu(SubF, dst, Imm::F(lhs), rhs)],
            DslIr::SubE(dst, lhs, rhs) => vec![self.ext_alu(SubE, dst, lhs, rhs)],
            DslIr::SubEI(dst, lhs, rhs) => vec![self.ext_alu(SubE, dst, lhs, Imm::EF(rhs))],
            DslIr::SubEIN(dst, lhs, rhs) => vec![self.ext_alu(SubE, dst, Imm::EF(lhs), rhs)],
            DslIr::SubEFI(dst, lhs, rhs) => vec![self.ext_alu(SubE, dst, lhs, Imm::F(rhs))],
            DslIr::SubEF(dst, lhs, rhs) => vec![self.ext_alu(SubE, dst, lhs, rhs)],

            DslIr::MulV(dst, lhs, rhs) => vec![self.base_alu(MulF, dst, lhs, rhs)],
            DslIr::MulVI(dst, lhs, rhs) => vec![self.base_alu(MulF, dst, lhs, Imm::F(rhs))],
            DslIr::MulF(dst, lhs, rhs) => vec![self.base_alu(MulF, dst, lhs, rhs)],
            DslIr::MulFI(dst, lhs, rhs) => vec![self.base_alu(MulF, dst, lhs, Imm::F(rhs))],
            DslIr::MulE(dst, lhs, rhs) => vec![self.ext_alu(MulE, dst, lhs, rhs)],
            DslIr::MulEI(dst, lhs, rhs) => vec![self.ext_alu(MulE, dst, lhs, Imm::EF(rhs))],
            DslIr::MulEFI(dst, lhs, rhs) => vec![self.ext_alu(MulE, dst, lhs, Imm::F(rhs))],
            DslIr::MulEF(dst, lhs, rhs) => vec![self.ext_alu(MulE, dst, lhs, rhs)],

            DslIr::DivF(dst, lhs, rhs) => vec![self.base_alu(DivF, dst, lhs, rhs)],
            DslIr::DivFI(dst, lhs, rhs) => vec![self.base_alu(DivF, dst, lhs, Imm::F(rhs))],
            DslIr::DivFIN(dst, lhs, rhs) => vec![self.base_alu(DivF, dst, Imm::F(lhs), rhs)],
            DslIr::DivE(dst, lhs, rhs) => vec![self.ext_alu(DivE, dst, lhs, rhs)],
            DslIr::DivEI(dst, lhs, rhs) => vec![self.ext_alu(DivE, dst, lhs, Imm::EF(rhs))],
            DslIr::DivEIN(dst, lhs, rhs) => vec![self.ext_alu(DivE, dst, Imm::EF(lhs), rhs)],
            DslIr::DivEFI(dst, lhs, rhs) => vec![self.ext_alu(DivE, dst, lhs, Imm::F(rhs))],
            DslIr::DivEFIN(dst, lhs, rhs) => vec![self.ext_alu(DivE, dst, Imm::F(lhs), rhs)],
            DslIr::DivEF(dst, lhs, rhs) => vec![self.ext_alu(DivE, dst, lhs, rhs)],

            DslIr::NegV(dst, src) => vec![self.base_alu(SubF, dst, Imm::F(F::zero()), src)],
            DslIr::NegF(dst, src) => vec![self.base_alu(SubF, dst, Imm::F(F::zero()), src)],
            DslIr::NegE(dst, src) => vec![self.ext_alu(SubE, dst, Imm::EF(EF::zero()), src)],
            DslIr::InvV(dst, src) => vec![self.base_alu(DivF, dst, Imm::F(F::one()), src)],
            DslIr::InvF(dst, src) => vec![self.base_alu(DivF, dst, Imm::F(F::one()), src)],
            DslIr::InvE(dst, src) => vec![self.ext_alu(DivE, dst, Imm::F(F::one()), src)],

            DslIr::AssertEqV(lhs, rhs) => self.base_assert_eq(lhs, rhs),
            DslIr::AssertEqF(lhs, rhs) => self.base_assert_eq(lhs, rhs),
            DslIr::AssertEqE(lhs, rhs) => self.ext_assert_eq(lhs, rhs),
            DslIr::AssertEqVI(lhs, rhs) => self.base_assert_eq(lhs, Imm::F(rhs)),
            DslIr::AssertEqFI(lhs, rhs) => self.base_assert_eq(lhs, Imm::F(rhs)),
            DslIr::AssertEqEI(lhs, rhs) => self.ext_assert_eq(lhs, Imm::EF(rhs)),

            DslIr::AssertNeV(lhs, rhs) => self.base_assert_ne(lhs, rhs),
            DslIr::AssertNeF(lhs, rhs) => self.base_assert_ne(lhs, rhs),
            DslIr::AssertNeE(lhs, rhs) => self.ext_assert_ne(lhs, rhs),
            DslIr::AssertNeVI(lhs, rhs) => self.base_assert_ne(lhs, Imm::F(rhs)),
            DslIr::AssertNeFI(lhs, rhs) => self.base_assert_ne(lhs, Imm::F(rhs)),
            DslIr::AssertNeEI(lhs, rhs) => self.ext_assert_ne(lhs, Imm::EF(rhs)),

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
            .flat_map(|(ir_instr, _)| self.compile_one(ir_instr))
            .collect::<Vec<_>>();
        // Replace the mults.
        instrs
            .iter_mut()
            .filter_map(|asm_instr| match asm_instr {
                Instruction::BaseAlu(BaseAluInstr {
                    mult,
                    addrs: BaseAluIo { out, .. },
                    ..
                }) => Some((mult, out)),
                Instruction::ExtAlu(ExtAluInstr {
                    mult,
                    addrs: ExtAluIo { out, .. },
                    ..
                }) => Some((mult, out)),
                Instruction::Mem(MemInstr {
                    addrs: MemIo { inner },
                    mult,
                    kind: MemAccessKind::Write,
                    ..
                }) => Some((mult, inner)),
                _ => None,
            })
            .for_each(|(mult, addr)| *mult = self.addr_to_mult.remove(addr).unwrap());
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

/// Immediate (i.e. constant) field element.
///
/// Required to distinguish a base and extension field element at the type level,
/// since the IR's instructions do not provide this information.
#[derive(Debug, Clone, Copy)]
enum Imm<F, EF> {
    /// Element of the base field `F`.
    F(F),
    /// Element of the extension field `EF`.
    EF(EF),
}

impl<F, EF> Imm<F, EF>
where
    F: AbstractField + Copy,
    EF: AbstractExtensionField<F>,
{
    // Get a `Block` of memory representing this immediate.
    fn as_block(&self) -> Block<F> {
        match self {
            Imm::F(f) => Block::from(*f),
            Imm::EF(ef) => ef.as_base_slice().into(),
        }
    }
}

/// Utility functions for various register types.
trait Reg<F, EF> {
    /// Mark the register as to be read from, returning the "physical" address.
    fn read(&self, compiler: &mut AsmCompiler<F, EF>) -> Address<F>;

    /// Mark the register as to be written to, returning the "physical" address.
    fn write(&self, _compiler: &mut AsmCompiler<F, EF>) -> Address<F>;
}

macro_rules! impl_reg_fp {
    ($a:ty) => {
        impl<F, EF> Reg<F, EF> for $a
        where
            F: PrimeField + TwoAdicField,
            EF: ExtensionField<F> + TwoAdicField,
        {
            fn read(&self, compiler: &mut AsmCompiler<F, EF>) -> Address<F> {
                compiler.read_fp(self.fp())
            }
            fn write(&self, compiler: &mut AsmCompiler<F, EF>) -> Address<F> {
                compiler.write_fp(self.fp())
            }
        }
    };
}

// These three types have `.fp()` but they don't share a trait.
impl_reg_fp!(Var<F>);
impl_reg_fp!(Felt<F>);
impl_reg_fp!(Ext<F, EF>);

impl<F, EF> Reg<F, EF> for Imm<F, EF>
where
    F: PrimeField + TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
{
    fn read(&self, compiler: &mut AsmCompiler<F, EF>) -> Address<F> {
        match self {
            Imm::F(f) => compiler.read_const_f(*f),
            Imm::EF(ef) => compiler.read_const_ef(*ef),
        }
    }

    fn write(&self, _compiler: &mut AsmCompiler<F, EF>) -> Address<F> {
        panic!("cannot write to immediate in register: {self:?}")
    }
}

impl<F, EF> Reg<F, EF> for Address<F>
where
    F: PrimeField + TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
{
    fn read(&self, compiler: &mut AsmCompiler<F, EF>) -> Address<F> {
        compiler.read_addr(*self);
        *self
    }

    fn write(&self, compiler: &mut AsmCompiler<F, EF>) -> Address<F> {
        compiler.write_addr(*self);
        *self
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::DiffusionMatrixBabyBear;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_core::{stark::StarkGenericConfig, utils::run_test_machine};
    use sp1_recursion_core::stark::config::BabyBearPoseidon2Outer;
    use sp1_recursion_core_v2::{machine::RecursionAir, RecursionProgram, Runtime};

    use p3_field::Field;

    use crate::asm::AsmBuilder;

    use super::*;

    type SC = BabyBearPoseidon2Outer;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    type A = RecursionAir<F>;

    fn test_operations(operations: TracedVec<DslIr<AsmConfig<F, EF>>>) {
        let mut compiler = super::AsmCompiler::default();
        let instructions = compiler.compile(operations);
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

    macro_rules! test_assert_fixture {
        ($assert_felt:ident, $assert_ext:ident, $should_offset:literal) => {
            let mut builder = AsmBuilder::<F, EF>::default();

            let mut base_elts = StdRng::seed_from_u64(0xDEADBEEF)
                .sample_iter::<F, _>(rand::distributions::Standard);
            for _ in 0..100 {
                let a = base_elts.next().unwrap();
                let b = base_elts.next().unwrap();
                let c = a + b;
                let ar: Felt<_> = builder.eval(a);
                let br: Felt<_> = builder.eval(b);
                let cr: Felt<_> = builder.eval(ar + br);
                let cm = if $should_offset {
                    c + base_elts.find(|x| !x.is_zero()).unwrap()
                } else {
                    c
                };
                builder.$assert_felt(cr, cm);
            }

            let mut ext_elts = StdRng::seed_from_u64(0xABADCAFE)
                .sample_iter::<EF, _>(rand::distributions::Standard);
            for _ in 0..100 {
                let a = ext_elts.next().unwrap();
                let b = ext_elts.next().unwrap();
                let c = a + b;
                let ar: Ext<_, _> = builder.eval(a.cons());
                let br: Ext<_, _> = builder.eval(b.cons());
                let cr: Ext<_, _> = builder.eval(ar + br);
                let cm = if $should_offset {
                    c + ext_elts.find(|x| !x.is_zero()).unwrap()
                } else {
                    c
                };
                builder.$assert_ext(cr, cm.cons());
            }

            test_operations(builder.operations);
        };
    }

    #[test]
    fn test_assert_eq_noop() {
        test_assert_fixture!(assert_felt_eq, assert_ext_eq, false);
    }

    #[test]
    #[should_panic]
    fn test_assert_eq_panics() {
        test_assert_fixture!(assert_felt_eq, assert_ext_eq, true);
    }

    #[test]
    fn test_assert_ne_noop() {
        test_assert_fixture!(assert_felt_ne, assert_ext_ne, true);
    }

    #[test]
    #[should_panic]
    fn test_assert_ne_panics() {
        test_assert_fixture!(assert_felt_ne, assert_ext_ne, false);
    }
}
