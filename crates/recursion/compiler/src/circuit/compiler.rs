use chips::poseidon2_skinny::WIDTH;
use core::fmt::Debug;
use instruction::{
    FieldEltType, HintAddCurveInstr, HintBitsInstr, HintExt2FeltsInstr, HintInstr, PrintInstr,
};
use itertools::Itertools;
use p3_field::{AbstractExtensionField, AbstractField, Field, PrimeField64, TwoAdicField};
use sp1_recursion_core::{
    air::{Block, RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS},
    BaseAluInstr, BaseAluOpcode,
};
use sp1_stark::septic_curve::SepticCurve;
use std::{
    borrow::{Borrow, Cow},
    collections::HashMap,
    mem::transmute,
};
use vec_map::VecMap;

use sp1_recursion_core::*;

use crate::prelude::*;

/// The backend for the circuit compiler.
#[derive(Debug, Clone, Default)]
pub struct AsmCompiler<C: Config> {
    pub next_addr: C::F,
    /// Map the frame pointers of the variables to the "physical" addresses.
    pub virtual_to_physical: VecMap<Address<C::F>>,
    /// Map base or extension field constants to "physical" addresses and mults.
    pub consts: HashMap<Imm<C::F, C::EF>, (Address<C::F>, C::F)>,
    /// Map each "physical" address to its read count.
    pub addr_to_mult: VecMap<C::F>,
}

impl<C: Config> AsmCompiler<C>
where
    C::F: PrimeField64,
{
    /// Allocate a fresh address. Checks that the address space is not full.
    pub fn alloc(next_addr: &mut C::F) -> Address<C::F> {
        let id = Address(*next_addr);
        *next_addr += C::F::one();
        if next_addr.is_zero() {
            panic!("out of address space");
        }
        id
    }

    /// Map `fp` to its existing address without changing its mult.
    ///
    /// Ensures that `fp` has already been assigned an address.
    pub fn read_ghost_vaddr(&mut self, vaddr: usize) -> Address<C::F> {
        self.read_vaddr_internal(vaddr, false)
    }

    /// Map `fp` to its existing address and increment its mult.
    ///
    /// Ensures that `fp` has already been assigned an address.
    pub fn read_vaddr(&mut self, vaddr: usize) -> Address<C::F> {
        self.read_vaddr_internal(vaddr, true)
    }

    pub fn read_vaddr_internal(&mut self, vaddr: usize, increment_mult: bool) -> Address<C::F> {
        use vec_map::Entry;
        match self.virtual_to_physical.entry(vaddr) {
            Entry::Vacant(_) => panic!("expected entry: virtual_physical[{vaddr:?}]"),
            Entry::Occupied(entry) => {
                if increment_mult {
                    // This is a read, so we increment the mult.
                    match self.addr_to_mult.get_mut(entry.get().as_usize()) {
                        Some(mult) => *mult += C::F::one(),
                        None => panic!("expected entry: virtual_physical[{vaddr:?}]"),
                    }
                }
                *entry.into_mut()
            }
        }
    }

    /// Map `fp` to a fresh address and initialize the mult to 0.
    ///
    /// Ensures that `fp` has not already been written to.
    pub fn write_fp(&mut self, vaddr: usize) -> Address<C::F> {
        use vec_map::Entry;
        match self.virtual_to_physical.entry(vaddr) {
            Entry::Vacant(entry) => {
                let addr = Self::alloc(&mut self.next_addr);
                // This is a write, so we set the mult to zero.
                if let Some(x) = self.addr_to_mult.insert(addr.as_usize(), C::F::zero()) {
                    panic!("unexpected entry in addr_to_mult: {x:?}");
                }
                *entry.insert(addr)
            }
            Entry::Occupied(entry) => {
                panic!("unexpected entry: virtual_to_physical[{:?}] = {:?}", vaddr, entry.get())
            }
        }
    }

    /// Increment the existing `mult` associated with `addr`.
    ///
    /// Ensures that `addr` has already been assigned a `mult`.
    pub fn read_addr(&mut self, addr: Address<C::F>) -> &mut C::F {
        self.read_addr_internal(addr, true)
    }

    /// Retrieves `mult` associated with `addr`.
    ///
    /// Ensures that `addr` has already been assigned a `mult`.
    pub fn read_ghost_addr(&mut self, addr: Address<C::F>) -> &mut C::F {
        self.read_addr_internal(addr, true)
    }

    fn read_addr_internal(&mut self, addr: Address<C::F>, increment_mult: bool) -> &mut C::F {
        use vec_map::Entry;
        match self.addr_to_mult.entry(addr.as_usize()) {
            Entry::Vacant(_) => panic!("expected entry: addr_to_mult[{:?}]", addr.as_usize()),
            Entry::Occupied(entry) => {
                // This is a read, so we increment the mult.
                let mult = entry.into_mut();
                if increment_mult {
                    *mult += C::F::one();
                }
                mult
            }
        }
    }

    /// Associate a `mult` of zero with `addr`.
    ///
    /// Ensures that `addr` has not already been written to.
    pub fn write_addr(&mut self, addr: Address<C::F>) -> &mut C::F {
        use vec_map::Entry;
        match self.addr_to_mult.entry(addr.as_usize()) {
            Entry::Vacant(entry) => entry.insert(C::F::zero()),
            Entry::Occupied(entry) => {
                panic!("unexpected entry: addr_to_mult[{:?}] = {:?}", addr.as_usize(), entry.get())
            }
        }
    }

    /// Read a constant (a.k.a. immediate).
    ///
    /// Increments the mult, first creating an entry if it does not yet exist.
    pub fn read_const(&mut self, imm: Imm<C::F, C::EF>) -> Address<C::F> {
        self.consts
            .entry(imm)
            .and_modify(|(_, x)| *x += C::F::one())
            .or_insert_with(|| (Self::alloc(&mut self.next_addr), C::F::one()))
            .0
    }

    /// Read a constant (a.k.a. immediate).
    ///    
    /// Does not increment the mult. Creates an entry if it does not yet exist.
    pub fn read_ghost_const(&mut self, imm: Imm<C::F, C::EF>) -> Address<C::F> {
        self.consts.entry(imm).or_insert_with(|| (Self::alloc(&mut self.next_addr), C::F::zero())).0
    }

    fn mem_write_const(&mut self, dst: impl Reg<C>, src: Imm<C::F, C::EF>) -> Instruction<C::F> {
        Instruction::Mem(MemInstr {
            addrs: MemIo { inner: dst.write(self) },
            vals: MemIo { inner: src.as_block() },
            mult: C::F::zero(),
            kind: MemAccessKind::Write,
        })
    }

    fn base_alu(
        &mut self,
        opcode: BaseAluOpcode,
        dst: impl Reg<C>,
        lhs: impl Reg<C>,
        rhs: impl Reg<C>,
    ) -> Instruction<C::F> {
        Instruction::BaseAlu(BaseAluInstr {
            opcode,
            mult: C::F::zero(),
            addrs: BaseAluIo { out: dst.write(self), in1: lhs.read(self), in2: rhs.read(self) },
        })
    }

    fn ext_alu(
        &mut self,
        opcode: ExtAluOpcode,
        dst: impl Reg<C>,
        lhs: impl Reg<C>,
        rhs: impl Reg<C>,
    ) -> Instruction<C::F> {
        Instruction::ExtAlu(ExtAluInstr {
            opcode,
            mult: C::F::zero(),
            addrs: ExtAluIo { out: dst.write(self), in1: lhs.read(self), in2: rhs.read(self) },
        })
    }

    fn base_assert_eq(
        &mut self,
        lhs: impl Reg<C>,
        rhs: impl Reg<C>,
        mut f: impl FnMut(Instruction<C::F>),
    ) {
        use BaseAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));
        f(self.base_alu(SubF, diff, lhs, rhs));
        f(self.base_alu(DivF, out, diff, Imm::F(C::F::zero())));
    }

    fn base_assert_ne(
        &mut self,
        lhs: impl Reg<C>,
        rhs: impl Reg<C>,
        mut f: impl FnMut(Instruction<C::F>),
    ) {
        use BaseAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));

        f(self.base_alu(SubF, diff, lhs, rhs));
        f(self.base_alu(DivF, out, Imm::F(C::F::one()), diff));
    }

    fn ext_assert_eq(
        &mut self,
        lhs: impl Reg<C>,
        rhs: impl Reg<C>,
        mut f: impl FnMut(Instruction<C::F>),
    ) {
        use ExtAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));

        f(self.ext_alu(SubE, diff, lhs, rhs));
        f(self.ext_alu(DivE, out, diff, Imm::EF(C::EF::zero())));
    }

    fn ext_assert_ne(
        &mut self,
        lhs: impl Reg<C>,
        rhs: impl Reg<C>,
        mut f: impl FnMut(Instruction<C::F>),
    ) {
        use ExtAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));

        f(self.ext_alu(SubE, diff, lhs, rhs));
        f(self.ext_alu(DivE, out, Imm::EF(C::EF::one()), diff));
    }

    #[inline(always)]
    fn poseidon2_permute(
        &mut self,
        dst: [impl Reg<C>; WIDTH],
        src: [impl Reg<C>; WIDTH],
    ) -> Instruction<C::F> {
        Instruction::Poseidon2(Box::new(Poseidon2Instr {
            addrs: Poseidon2Io {
                input: src.map(|r| r.read(self)),
                output: dst.map(|r| r.write(self)),
            },
            mults: [C::F::zero(); WIDTH],
        }))
    }

    #[inline(always)]
    fn select(
        &mut self,
        bit: impl Reg<C>,
        dst1: impl Reg<C>,
        dst2: impl Reg<C>,
        lhs: impl Reg<C>,
        rhs: impl Reg<C>,
    ) -> Instruction<C::F> {
        Instruction::Select(SelectInstr {
            addrs: SelectIo {
                bit: bit.read(self),
                out1: dst1.write(self),
                out2: dst2.write(self),
                in1: lhs.read(self),
                in2: rhs.read(self),
            },
            mult1: C::F::zero(),
            mult2: C::F::zero(),
        })
    }

    fn exp_reverse_bits(
        &mut self,
        dst: impl Reg<C>,
        base: impl Reg<C>,
        exp: impl IntoIterator<Item = impl Reg<C>>,
    ) -> Instruction<C::F> {
        Instruction::ExpReverseBitsLen(ExpReverseBitsInstr {
            addrs: ExpReverseBitsIo {
                result: dst.write(self),
                base: base.read(self),
                exp: exp.into_iter().map(|r| r.read(self)).collect(),
            },
            mult: C::F::zero(),
        })
    }

    fn hint_bit_decomposition(
        &mut self,
        value: impl Reg<C>,
        output: impl IntoIterator<Item = impl Reg<C>>,
    ) -> Instruction<C::F> {
        Instruction::HintBits(HintBitsInstr {
            output_addrs_mults: output.into_iter().map(|r| (r.write(self), C::F::zero())).collect(),
            input_addr: value.read_ghost(self),
        })
    }

    fn add_curve(
        &mut self,
        output: SepticCurve<Felt<C::F>>,
        input1: SepticCurve<Felt<C::F>>,
        input2: SepticCurve<Felt<C::F>>,
    ) -> Instruction<C::F> {
        Instruction::HintAddCurve(Box::new(HintAddCurveInstr {
            output_x_addrs_mults: output
                .x
                .0
                .into_iter()
                .map(|r| (r.write(self), C::F::zero()))
                .collect(),
            output_y_addrs_mults: output
                .y
                .0
                .into_iter()
                .map(|r| (r.write(self), C::F::zero()))
                .collect(),
            input1_x_addrs: input1.x.0.into_iter().map(|value| value.read_ghost(self)).collect(),
            input1_y_addrs: input1.y.0.into_iter().map(|value| value.read_ghost(self)).collect(),
            input2_x_addrs: input2.x.0.into_iter().map(|value| value.read_ghost(self)).collect(),
            input2_y_addrs: input2.y.0.into_iter().map(|value| value.read_ghost(self)).collect(),
        }))
    }

    fn fri_fold(
        &mut self,
        CircuitV2FriFoldOutput { alpha_pow_output, ro_output }: CircuitV2FriFoldOutput<C>,
        CircuitV2FriFoldInput {
            z,
            alpha,
            x,
            mat_opening,
            ps_at_z,
            alpha_pow_input,
            ro_input,
        }: CircuitV2FriFoldInput<C>,
    ) -> Instruction<C::F> {
        Instruction::FriFold(Box::new(FriFoldInstr {
            // Calculate before moving the vecs.
            alpha_pow_mults: vec![C::F::zero(); alpha_pow_output.len()],
            ro_mults: vec![C::F::zero(); ro_output.len()],

            base_single_addrs: FriFoldBaseIo { x: x.read(self) },
            ext_single_addrs: FriFoldExtSingleIo { z: z.read(self), alpha: alpha.read(self) },
            ext_vec_addrs: FriFoldExtVecIo {
                mat_opening: mat_opening.into_iter().map(|e| e.read(self)).collect(),
                ps_at_z: ps_at_z.into_iter().map(|e| e.read(self)).collect(),
                alpha_pow_input: alpha_pow_input.into_iter().map(|e| e.read(self)).collect(),
                ro_input: ro_input.into_iter().map(|e| e.read(self)).collect(),
                alpha_pow_output: alpha_pow_output.into_iter().map(|e| e.write(self)).collect(),
                ro_output: ro_output.into_iter().map(|e| e.write(self)).collect(),
            },
        }))
    }

    fn batch_fri(
        &mut self,
        acc: Ext<C::F, C::EF>,
        alpha_pows: Vec<Ext<C::F, C::EF>>,
        p_at_zs: Vec<Ext<C::F, C::EF>>,
        p_at_xs: Vec<Felt<C::F>>,
    ) -> Instruction<C::F> {
        Instruction::BatchFRI(Box::new(BatchFRIInstr {
            base_vec_addrs: BatchFRIBaseVecIo {
                p_at_x: p_at_xs.into_iter().map(|e| e.read(self)).collect(),
            },
            ext_single_addrs: BatchFRIExtSingleIo { acc: acc.write(self) },
            ext_vec_addrs: BatchFRIExtVecIo {
                p_at_z: p_at_zs.into_iter().map(|e| e.read(self)).collect(),
                alpha_pow: alpha_pows.into_iter().map(|e| e.read(self)).collect(),
            },
            acc_mult: C::F::zero(),
        }))
    }

    fn commit_public_values(
        &mut self,
        public_values: &RecursionPublicValues<Felt<C::F>>,
    ) -> Instruction<C::F> {
        public_values.digest.iter().for_each(|x| {
            let _ = x.read(self);
        });
        let pv_addrs =
            unsafe {
                transmute::<
                    RecursionPublicValues<Felt<C::F>>,
                    [Felt<C::F>; RECURSIVE_PROOF_NUM_PV_ELTS],
                >(*public_values)
            }
            .map(|pv| pv.read_ghost(self));

        let public_values_a: &RecursionPublicValues<Address<C::F>> = pv_addrs.as_slice().borrow();
        Instruction::CommitPublicValues(Box::new(CommitPublicValuesInstr {
            pv_addrs: *public_values_a,
        }))
    }

    fn print_f(&mut self, addr: impl Reg<C>) -> Instruction<C::F> {
        Instruction::Print(PrintInstr {
            field_elt_type: FieldEltType::Base,
            addr: addr.read_ghost(self),
        })
    }

    fn print_e(&mut self, addr: impl Reg<C>) -> Instruction<C::F> {
        Instruction::Print(PrintInstr {
            field_elt_type: FieldEltType::Extension,
            addr: addr.read_ghost(self),
        })
    }

    fn ext2felts(&mut self, felts: [impl Reg<C>; D], ext: impl Reg<C>) -> Instruction<C::F> {
        Instruction::HintExt2Felts(HintExt2FeltsInstr {
            output_addrs_mults: felts.map(|r| (r.write(self), C::F::zero())),
            input_addr: ext.read_ghost(self),
        })
    }

    fn hint(&mut self, output: impl Reg<C>, len: usize) -> Instruction<C::F> {
        let zero = C::F::zero();
        Instruction::Hint(HintInstr {
            output_addrs_mults: output
                .write_many(self, len)
                .into_iter()
                .map(|a| (a, zero))
                .collect(),
        })
    }
}

impl<C> AsmCompiler<C>
where
    C: Config<N = <C as Config>::F> + Debug,
    C::F: PrimeField64 + TwoAdicField,
{
    /// Compiles one instruction, passing one or more instructions to `consumer`.
    ///
    /// We do not simply return a `Vec` for performance reasons --- results would be immediately fed
    /// to `flat_map`, so we employ fusion/deforestation to eliminate intermediate data structures.
    pub fn compile_one(
        &mut self,
        ir_instr: DslIr<C>,
        mut consumer: impl FnMut(Result<Instruction<C::F>, CompileOneErr<C>>),
    ) {
        // For readability. Avoids polluting outer scope.
        use BaseAluOpcode::*;
        use ExtAluOpcode::*;

        let mut f = |instr| consumer(Ok(instr));
        match ir_instr {
            DslIr::ImmV(dst, src) => f(self.mem_write_const(dst, Imm::F(src))),
            DslIr::ImmF(dst, src) => f(self.mem_write_const(dst, Imm::F(src))),
            DslIr::ImmE(dst, src) => f(self.mem_write_const(dst, Imm::EF(src))),

            DslIr::AddV(dst, lhs, rhs) => f(self.base_alu(AddF, dst, lhs, rhs)),
            DslIr::AddVI(dst, lhs, rhs) => f(self.base_alu(AddF, dst, lhs, Imm::F(rhs))),
            DslIr::AddF(dst, lhs, rhs) => f(self.base_alu(AddF, dst, lhs, rhs)),
            DslIr::AddFI(dst, lhs, rhs) => f(self.base_alu(AddF, dst, lhs, Imm::F(rhs))),
            DslIr::AddE(dst, lhs, rhs) => f(self.ext_alu(AddE, dst, lhs, rhs)),
            DslIr::AddEI(dst, lhs, rhs) => f(self.ext_alu(AddE, dst, lhs, Imm::EF(rhs))),
            DslIr::AddEF(dst, lhs, rhs) => f(self.ext_alu(AddE, dst, lhs, rhs)),
            DslIr::AddEFI(dst, lhs, rhs) => f(self.ext_alu(AddE, dst, lhs, Imm::F(rhs))),
            DslIr::AddEFFI(dst, lhs, rhs) => f(self.ext_alu(AddE, dst, lhs, Imm::EF(rhs))),

            DslIr::SubV(dst, lhs, rhs) => f(self.base_alu(SubF, dst, lhs, rhs)),
            DslIr::SubVI(dst, lhs, rhs) => f(self.base_alu(SubF, dst, lhs, Imm::F(rhs))),
            DslIr::SubVIN(dst, lhs, rhs) => f(self.base_alu(SubF, dst, Imm::F(lhs), rhs)),
            DslIr::SubF(dst, lhs, rhs) => f(self.base_alu(SubF, dst, lhs, rhs)),
            DslIr::SubFI(dst, lhs, rhs) => f(self.base_alu(SubF, dst, lhs, Imm::F(rhs))),
            DslIr::SubFIN(dst, lhs, rhs) => f(self.base_alu(SubF, dst, Imm::F(lhs), rhs)),
            DslIr::SubE(dst, lhs, rhs) => f(self.ext_alu(SubE, dst, lhs, rhs)),
            DslIr::SubEI(dst, lhs, rhs) => f(self.ext_alu(SubE, dst, lhs, Imm::EF(rhs))),
            DslIr::SubEIN(dst, lhs, rhs) => f(self.ext_alu(SubE, dst, Imm::EF(lhs), rhs)),
            DslIr::SubEFI(dst, lhs, rhs) => f(self.ext_alu(SubE, dst, lhs, Imm::F(rhs))),
            DslIr::SubEF(dst, lhs, rhs) => f(self.ext_alu(SubE, dst, lhs, rhs)),

            DslIr::MulV(dst, lhs, rhs) => f(self.base_alu(MulF, dst, lhs, rhs)),
            DslIr::MulVI(dst, lhs, rhs) => f(self.base_alu(MulF, dst, lhs, Imm::F(rhs))),
            DslIr::MulF(dst, lhs, rhs) => f(self.base_alu(MulF, dst, lhs, rhs)),
            DslIr::MulFI(dst, lhs, rhs) => f(self.base_alu(MulF, dst, lhs, Imm::F(rhs))),
            DslIr::MulE(dst, lhs, rhs) => f(self.ext_alu(MulE, dst, lhs, rhs)),
            DslIr::MulEI(dst, lhs, rhs) => f(self.ext_alu(MulE, dst, lhs, Imm::EF(rhs))),
            DslIr::MulEFI(dst, lhs, rhs) => f(self.ext_alu(MulE, dst, lhs, Imm::F(rhs))),
            DslIr::MulEF(dst, lhs, rhs) => f(self.ext_alu(MulE, dst, lhs, rhs)),

            DslIr::DivF(dst, lhs, rhs) => f(self.base_alu(DivF, dst, lhs, rhs)),
            DslIr::DivFI(dst, lhs, rhs) => f(self.base_alu(DivF, dst, lhs, Imm::F(rhs))),
            DslIr::DivFIN(dst, lhs, rhs) => f(self.base_alu(DivF, dst, Imm::F(lhs), rhs)),
            DslIr::DivE(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, lhs, rhs)),
            DslIr::DivEI(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, lhs, Imm::EF(rhs))),
            DslIr::DivEIN(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, Imm::EF(lhs), rhs)),
            DslIr::DivEFI(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, lhs, Imm::F(rhs))),
            DslIr::DivEFIN(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, Imm::F(lhs), rhs)),
            DslIr::DivEF(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, lhs, rhs)),

            DslIr::NegV(dst, src) => f(self.base_alu(SubF, dst, Imm::F(C::F::zero()), src)),
            DslIr::NegF(dst, src) => f(self.base_alu(SubF, dst, Imm::F(C::F::zero()), src)),
            DslIr::NegE(dst, src) => f(self.ext_alu(SubE, dst, Imm::EF(C::EF::zero()), src)),
            DslIr::InvV(dst, src) => f(self.base_alu(DivF, dst, Imm::F(C::F::one()), src)),
            DslIr::InvF(dst, src) => f(self.base_alu(DivF, dst, Imm::F(C::F::one()), src)),
            DslIr::InvE(dst, src) => f(self.ext_alu(DivE, dst, Imm::F(C::F::one()), src)),

            DslIr::Select(bit, dst1, dst2, lhs, rhs) => f(self.select(bit, dst1, dst2, lhs, rhs)),

            DslIr::AssertEqV(lhs, rhs) => self.base_assert_eq(lhs, rhs, f),
            DslIr::AssertEqF(lhs, rhs) => self.base_assert_eq(lhs, rhs, f),
            DslIr::AssertEqE(lhs, rhs) => self.ext_assert_eq(lhs, rhs, f),
            DslIr::AssertEqVI(lhs, rhs) => self.base_assert_eq(lhs, Imm::F(rhs), f),
            DslIr::AssertEqFI(lhs, rhs) => self.base_assert_eq(lhs, Imm::F(rhs), f),
            DslIr::AssertEqEI(lhs, rhs) => self.ext_assert_eq(lhs, Imm::EF(rhs), f),

            DslIr::AssertNeV(lhs, rhs) => self.base_assert_ne(lhs, rhs, f),
            DslIr::AssertNeF(lhs, rhs) => self.base_assert_ne(lhs, rhs, f),
            DslIr::AssertNeE(lhs, rhs) => self.ext_assert_ne(lhs, rhs, f),
            DslIr::AssertNeVI(lhs, rhs) => self.base_assert_ne(lhs, Imm::F(rhs), f),
            DslIr::AssertNeFI(lhs, rhs) => self.base_assert_ne(lhs, Imm::F(rhs), f),
            DslIr::AssertNeEI(lhs, rhs) => self.ext_assert_ne(lhs, Imm::EF(rhs), f),

            DslIr::CircuitV2Poseidon2PermuteBabyBear(data) => {
                f(self.poseidon2_permute(data.0, data.1))
            }
            DslIr::CircuitV2ExpReverseBits(dst, base, exp) => {
                f(self.exp_reverse_bits(dst, base, exp))
            }
            DslIr::CircuitV2HintBitsF(output, value) => {
                f(self.hint_bit_decomposition(value, output))
            }
            DslIr::CircuitV2FriFold(data) => f(self.fri_fold(data.0, data.1)),
            DslIr::CircuitV2BatchFRI(data) => f(self.batch_fri(data.0, data.1, data.2, data.3)),
            DslIr::CircuitV2CommitPublicValues(public_values) => {
                f(self.commit_public_values(&public_values))
            }
            DslIr::CircuitV2HintAddCurve(data) => f(self.add_curve(data.0, data.1, data.2)),

            DslIr::Parallel(_) => {
                unreachable!("parallel case should have been handled by compile_raw_program")
            }

            DslIr::PrintV(dst) => f(self.print_f(dst)),
            DslIr::PrintF(dst) => f(self.print_f(dst)),
            DslIr::PrintE(dst) => f(self.print_e(dst)),
            #[cfg(feature = "debug")]
            DslIr::DebugBacktrace(trace) => f(Instruction::DebugBacktrace(trace)),
            DslIr::CircuitV2HintFelts(output, len) => f(self.hint(output, len)),
            DslIr::CircuitV2HintExts(output, len) => f(self.hint(output, len)),
            DslIr::CircuitExt2Felt(felts, ext) => f(self.ext2felts(felts, ext)),
            DslIr::CycleTrackerV2Enter(name) => {
                consumer(Err(CompileOneErr::CycleTrackerEnter(name)))
            }
            DslIr::CycleTrackerV2Exit => consumer(Err(CompileOneErr::CycleTrackerExit)),
            DslIr::ReduceE(_) => {}
            instr => consumer(Err(CompileOneErr::Unsupported(instr))),
        }
    }

    /// A raw program (algebraic data type of instructions), not yet backfilled.
    fn compile_raw_program(
        &mut self,
        block: DslIrBlock<C>,
        instrs_prefix: Vec<SeqBlock<Instruction<C::F>>>,
    ) -> RawProgram<Instruction<C::F>> {
        // Consider refactoring the builder to use an AST instead of a list of operations.
        // Possible to remove address translation at this step.
        let mut seq_blocks = instrs_prefix;
        let mut maybe_bb: Option<BasicBlock<Instruction<C::F>>> = None;

        for op in block.ops {
            match op {
                DslIr::Parallel(par_blocks) => {
                    seq_blocks.extend(maybe_bb.take().map(SeqBlock::Basic));
                    seq_blocks.push(SeqBlock::Parallel(
                        par_blocks
                            .into_iter()
                            .map(|b| self.compile_raw_program(b, vec![]))
                            .collect(),
                    ))
                }
                op => {
                    let bb = maybe_bb.get_or_insert_with(Default::default);
                    self.compile_one(op, |item| match item {
                        Ok(instr) => bb.instrs.push(instr),
                        Err(
                            CompileOneErr::CycleTrackerEnter(_) | CompileOneErr::CycleTrackerExit,
                        ) => (),
                        Err(CompileOneErr::Unsupported(instr)) => {
                            panic!("unsupported instruction: {instr:?}")
                        }
                    });
                }
            }
        }

        seq_blocks.extend(maybe_bb.map(SeqBlock::Basic));

        RawProgram { seq_blocks }
    }

    fn backfill_all<'a>(
        &mut self,
        instrs: impl Iterator<Item = &'a mut Instruction<<C as Config>::F>>,
    ) {
        let mut backfill = |(mult, addr): (&mut C::F, &Address<C::F>)| {
            *mult = self.addr_to_mult.remove(addr.as_usize()).unwrap()
        };

        for asm_instr in instrs {
            // Exhaustive match for refactoring purposes.
            match asm_instr {
                Instruction::BaseAlu(BaseAluInstr {
                    mult,
                    addrs: BaseAluIo { out: ref addr, .. },
                    ..
                }) => backfill((mult, addr)),
                Instruction::ExtAlu(ExtAluInstr {
                    mult,
                    addrs: ExtAluIo { out: ref addr, .. },
                    ..
                }) => backfill((mult, addr)),
                Instruction::Mem(MemInstr {
                    addrs: MemIo { inner: ref addr },
                    mult,
                    kind: MemAccessKind::Write,
                    ..
                }) => backfill((mult, addr)),
                Instruction::Poseidon2(instr) => {
                    let Poseidon2SkinnyInstr {
                        addrs: Poseidon2Io { output: ref addrs, .. },
                        mults,
                    } = instr.as_mut();
                    mults.iter_mut().zip(addrs).for_each(&mut backfill);
                }
                Instruction::Select(SelectInstr {
                    addrs: SelectIo { out1: ref addr1, out2: ref addr2, .. },
                    mult1,
                    mult2,
                }) => {
                    backfill((mult1, addr1));
                    backfill((mult2, addr2));
                }
                Instruction::ExpReverseBitsLen(ExpReverseBitsInstr {
                    addrs: ExpReverseBitsIo { result: ref addr, .. },
                    mult,
                }) => backfill((mult, addr)),
                Instruction::HintBits(HintBitsInstr { output_addrs_mults, .. }) |
                Instruction::Hint(HintInstr { output_addrs_mults, .. }) => {
                    output_addrs_mults.iter_mut().for_each(|(addr, mult)| backfill((mult, addr)));
                }
                Instruction::FriFold(instr) => {
                    let FriFoldInstr {
                        ext_vec_addrs: FriFoldExtVecIo { ref alpha_pow_output, ref ro_output, .. },
                        alpha_pow_mults,
                        ro_mults,
                        ..
                    } = instr.as_mut();
                    // Using `.chain` seems to be less performant.
                    alpha_pow_mults.iter_mut().zip(alpha_pow_output).for_each(&mut backfill);
                    ro_mults.iter_mut().zip(ro_output).for_each(&mut backfill);
                }
                Instruction::BatchFRI(instr) => {
                    let BatchFRIInstr {
                        ext_single_addrs: BatchFRIExtSingleIo { ref acc },
                        acc_mult,
                        ..
                    } = instr.as_mut();
                    backfill((acc_mult, acc));
                }
                Instruction::HintExt2Felts(HintExt2FeltsInstr { output_addrs_mults, .. }) => {
                    output_addrs_mults.iter_mut().for_each(|(addr, mult)| backfill((mult, addr)));
                }
                Instruction::HintAddCurve(instr) => {
                    let HintAddCurveInstr { output_x_addrs_mults, output_y_addrs_mults, .. } =
                        instr.as_mut();
                    output_x_addrs_mults.iter_mut().for_each(|(addr, mult)| backfill((mult, addr)));
                    output_y_addrs_mults.iter_mut().for_each(|(addr, mult)| backfill((mult, addr)));
                }
                // Instructions that do not write to memory.
                Instruction::Mem(MemInstr { kind: MemAccessKind::Read, .. }) |
                Instruction::CommitPublicValues(_) |
                Instruction::Print(_) => (),
                #[cfg(feature = "debug")]
                Instruction::DebugBacktrace(_) => (),
            }
        }

        debug_assert!(self.addr_to_mult.is_empty());
    }

    /// Compile a `DslIrProgram` that is definitionally assumed to be well-formed.
    ///
    /// Returns a well-formed program.
    pub fn compile(&mut self, program: DslIrProgram<C>) -> RecursionProgram<C::F> {
        // SAFETY: The compiler produces well-formed programs given a well-formed DSL input.
        // This is also a cryptographic requirement.
        unsafe { RecursionProgram::new_unchecked(self.compile_inner(program.into_inner())) }
    }

    /// Compile a root `DslIrBlock` that has not necessarily been validated.
    ///
    /// Returns a program that may be ill-formed.
    pub fn compile_inner(&mut self, root_block: DslIrBlock<C>) -> RootProgram<C::F> {
        // Prefix an empty basic block to be later filled in by constants.
        let mut program = tracing::debug_span!("compile raw program").in_scope(|| {
            self.compile_raw_program(root_block, vec![SeqBlock::Basic(BasicBlock::default())])
        });
        let total_memory = self.addr_to_mult.len() + self.consts.len();
        tracing::debug_span!("backfill mult").in_scope(|| self.backfill_all(program.iter_mut()));

        // Put in the constants.
        tracing::debug_span!("prepend constants").in_scope(|| {
            let Some(SeqBlock::Basic(BasicBlock { instrs: instrs_consts })) =
                program.seq_blocks.first_mut()
            else {
                unreachable!()
            };
            instrs_consts.extend(self.consts.drain().sorted_by_key(|x| x.1 .0 .0).map(
                |(imm, (addr, mult))| {
                    Instruction::Mem(MemInstr {
                        addrs: MemIo { inner: addr },
                        vals: MemIo { inner: imm.as_block() },
                        mult,
                        kind: MemAccessKind::Write,
                    })
                },
            ));
        });

        RootProgram { inner: program, total_memory, shape: None }
    }
}

#[derive(Debug, Clone)]
pub enum CompileOneErr<C: Config> {
    Unsupported(DslIr<C>),
    CycleTrackerEnter(Cow<'static, str>),
    CycleTrackerExit,
}

/// Immediate (i.e. constant) field element.
///
/// Required to distinguish a base and extension field element at the type level,
/// since the IR's instructions do not provide this information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Imm<F, EF> {
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
    pub fn as_block(&self) -> Block<F> {
        match self {
            Imm::F(f) => Block::from(*f),
            Imm::EF(ef) => ef.as_base_slice().into(),
        }
    }
}

/// Utility functions for various register types.
trait Reg<C: Config> {
    /// Mark the register as to be read from, returning the "physical" address.
    fn read(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F>;

    /// Get the "physical" address of the register, assigning a new address if necessary.
    fn read_ghost(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F>;

    /// Mark the register as to be written to, returning the "physical" address.
    fn write(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F>;

    fn write_many(&self, compiler: &mut AsmCompiler<C>, len: usize) -> Vec<Address<C::F>>;
}

macro_rules! impl_reg_borrowed {
    ($a:ty) => {
        impl<C, T> Reg<C> for $a
        where
            C: Config,
            T: Reg<C> + ?Sized,
        {
            fn read(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
                (**self).read(compiler)
            }

            fn read_ghost(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
                (**self).read_ghost(compiler)
            }

            fn write(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
                (**self).write(compiler)
            }

            fn write_many(&self, compiler: &mut AsmCompiler<C>, len: usize) -> Vec<Address<C::F>> {
                (**self).write_many(compiler, len)
            }
        }
    };
}

// Allow for more flexibility in arguments.
impl_reg_borrowed!(&T);
impl_reg_borrowed!(&mut T);
impl_reg_borrowed!(Box<T>);

macro_rules! impl_reg_vaddr {
    ($a:ty) => {
        impl<C: Config<F: PrimeField64>> Reg<C> for $a {
            fn read(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
                compiler.read_vaddr(self.idx as usize)
            }
            fn read_ghost(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
                compiler.read_ghost_vaddr(self.idx as usize)
            }
            fn write(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
                compiler.write_fp(self.idx as usize)
            }

            fn write_many(&self, compiler: &mut AsmCompiler<C>, len: usize) -> Vec<Address<C::F>> {
                (0..len).map(|i| compiler.write_fp((self.idx + i as u32) as usize)).collect()
            }
        }
    };
}

// These three types wrap a `u32` but they don't share a trait.
impl_reg_vaddr!(Var<C::F>);
impl_reg_vaddr!(Felt<C::F>);
impl_reg_vaddr!(Ext<C::F, C::EF>);

impl<C: Config<F: PrimeField64>> Reg<C> for Imm<C::F, C::EF> {
    fn read(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
        compiler.read_const(*self)
    }

    fn read_ghost(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
        compiler.read_ghost_const(*self)
    }

    fn write(&self, _compiler: &mut AsmCompiler<C>) -> Address<C::F> {
        panic!("cannot write to immediate in register: {self:?}")
    }

    fn write_many(&self, _compiler: &mut AsmCompiler<C>, _len: usize) -> Vec<Address<C::F>> {
        panic!("cannot write to immediate in register: {self:?}")
    }
}

impl<C: Config<F: PrimeField64>> Reg<C> for Address<C::F> {
    fn read(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
        compiler.read_addr(*self);
        *self
    }

    fn read_ghost(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
        compiler.read_ghost_addr(*self);
        *self
    }

    fn write(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
        compiler.write_addr(*self);
        *self
    }

    fn write_many(&self, _compiler: &mut AsmCompiler<C>, _len: usize) -> Vec<Address<C::F>> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use std::{collections::VecDeque, io::BufRead, iter::zip, sync::Arc};

    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_field::{Field, PrimeField32};
    use p3_symmetric::{CryptographicHasher, Permutation};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use sp1_core_machine::utils::{run_test_machine, setup_logger};
    use sp1_recursion_core::{machine::RecursionAir, Runtime};
    use sp1_stark::{
        baby_bear_poseidon2::BabyBearPoseidon2, inner_perm, BabyBearPoseidon2Inner, InnerHash,
        StarkGenericConfig,
    };

    use crate::circuit::{AsmBuilder, AsmConfig, CircuitV2Builder};

    use super::*;

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    fn test_block(block: DslIrBlock<AsmConfig<F, EF>>) {
        test_block_with_runner(block, |program| {
            let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new(
                program,
                BabyBearPoseidon2Inner::new().perm,
            );
            runtime.run().unwrap();
            runtime.record
        });
    }

    fn test_block_with_runner(
        block: DslIrBlock<AsmConfig<F, EF>>,
        run: impl FnOnce(Arc<RecursionProgram<F>>) -> ExecutionRecord<F>,
    ) {
        let mut compiler = super::AsmCompiler::<AsmConfig<F, EF>>::default();
        let program = Arc::new(compiler.compile_inner(block).validate().unwrap());
        let record = run(program.clone());

        // Run with the poseidon2 wide chip.
        let wide_machine =
            RecursionAir::<_, 3>::machine_wide_with_all_chips(BabyBearPoseidon2::default());
        let (pk, vk) = wide_machine.setup(&program);
        let result = run_test_machine(vec![record.clone()], wide_machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {e:?}");
        }

        // Run with the poseidon2 skinny chip.
        let skinny_machine = RecursionAir::<_, 9>::machine_skinny_with_all_chips(
            BabyBearPoseidon2::ultra_compressed(),
        );
        let (pk, vk) = skinny_machine.setup(&program);
        let result = run_test_machine(vec![record.clone()], skinny_machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {e:?}");
        }
    }

    #[test]
    fn test_poseidon2() {
        setup_logger();

        let mut builder = AsmBuilder::<F, EF>::default();
        let mut rng = StdRng::seed_from_u64(0xCAFEDA7E)
            .sample_iter::<[F; WIDTH], _>(rand::distributions::Standard);
        for _ in 0..100 {
            let input_1: [F; WIDTH] = rng.next().unwrap();
            let output_1 = inner_perm().permute(input_1);

            let input_1_felts = input_1.map(|x| builder.eval(x));
            let output_1_felts = builder.poseidon2_permute_v2(input_1_felts);
            let expected: [Felt<_>; WIDTH] = output_1.map(|x| builder.eval(x));
            for (lhs, rhs) in output_1_felts.into_iter().zip(expected) {
                builder.assert_felt_eq(lhs, rhs);
            }
        }

        test_block(builder.into_root_block());
    }

    #[test]
    fn test_poseidon2_hash() {
        let perm = inner_perm();
        let hasher = InnerHash::new(perm.clone());

        let input: [F; 26] = [
            F::from_canonical_u32(0),
            F::from_canonical_u32(1),
            F::from_canonical_u32(2),
            F::from_canonical_u32(2),
            F::from_canonical_u32(2),
            F::from_canonical_u32(2),
            F::from_canonical_u32(2),
            F::from_canonical_u32(2),
            F::from_canonical_u32(2),
            F::from_canonical_u32(2),
            F::from_canonical_u32(2),
            F::from_canonical_u32(2),
            F::from_canonical_u32(2),
            F::from_canonical_u32(2),
            F::from_canonical_u32(2),
            F::from_canonical_u32(3),
            F::from_canonical_u32(3),
            F::from_canonical_u32(3),
            F::from_canonical_u32(3),
            F::from_canonical_u32(3),
            F::from_canonical_u32(3),
            F::from_canonical_u32(3),
            F::from_canonical_u32(3),
            F::from_canonical_u32(3),
            F::from_canonical_u32(3),
            F::from_canonical_u32(3),
        ];
        let expected = hasher.hash_iter(input);
        println!("{expected:?}");

        let mut builder = AsmBuilder::<F, EF>::default();
        let input_felts: [Felt<_>; 26] = input.map(|x| builder.eval(x));
        let result = builder.poseidon2_hash_v2(&input_felts);

        for (actual_f, expected_f) in zip(result, expected) {
            builder.assert_felt_eq(actual_f, expected_f);
        }
    }

    #[test]
    fn test_exp_reverse_bits() {
        setup_logger();

        let mut builder = AsmBuilder::<F, EF>::default();
        let mut rng =
            StdRng::seed_from_u64(0xEC0BEEF).sample_iter::<F, _>(rand::distributions::Standard);
        for _ in 0..100 {
            let power_f = rng.next().unwrap();
            let power = power_f.as_canonical_u32();
            let power_bits = (0..NUM_BITS).map(|i| (power >> i) & 1).collect::<Vec<_>>();

            let input_felt = builder.eval(power_f);
            let power_bits_felt = builder.num2bits_v2_f(input_felt, NUM_BITS);

            let base = rng.next().unwrap();
            let base_felt = builder.eval(base);
            let result_felt = builder.exp_reverse_bits_v2(base_felt, power_bits_felt);

            let expected = power_bits
                .into_iter()
                .rev()
                .zip(std::iter::successors(Some(base), |x| Some(x.square())))
                .map(|(bit, base_pow)| match bit {
                    0 => F::one(),
                    1 => base_pow,
                    _ => panic!("not a bit: {bit}"),
                })
                .product::<F>();
            let expected_felt: Felt<_> = builder.eval(expected);
            builder.assert_felt_eq(result_felt, expected_felt);
        }
        test_block(builder.into_root_block());
    }

    #[test]
    fn test_fri_fold() {
        setup_logger();

        let mut builder = AsmBuilder::<F, EF>::default();

        let mut rng = StdRng::seed_from_u64(0xFEB29).sample_iter(rand::distributions::Standard);
        let mut random_felt = move || -> F { rng.next().unwrap() };
        let mut rng =
            StdRng::seed_from_u64(0x0451).sample_iter::<[F; 4], _>(rand::distributions::Standard);
        let mut random_ext = move || EF::from_base_slice(&rng.next().unwrap());

        for i in 2..17 {
            // Generate random values for the inputs.
            let x = random_felt();
            let z = random_ext();
            let alpha = random_ext();

            let alpha_pow_input = (0..i).map(|_| random_ext()).collect::<Vec<_>>();
            let ro_input = (0..i).map(|_| random_ext()).collect::<Vec<_>>();

            let ps_at_z = (0..i).map(|_| random_ext()).collect::<Vec<_>>();
            let mat_opening = (0..i).map(|_| random_ext()).collect::<Vec<_>>();

            // Compute the outputs from the inputs.
            let alpha_pow_output = (0..i).map(|i| alpha_pow_input[i] * alpha).collect::<Vec<EF>>();
            let ro_output = (0..i)
                .map(|i| {
                    ro_input[i] + alpha_pow_input[i] * (-ps_at_z[i] + mat_opening[i]) / (-z + x)
                })
                .collect::<Vec<EF>>();

            // Compute inputs and outputs through the builder.
            let input_vars = CircuitV2FriFoldInput {
                z: builder.eval(z.cons()),
                alpha: builder.eval(alpha.cons()),
                x: builder.eval(x),
                mat_opening: mat_opening.iter().map(|e| builder.eval(e.cons())).collect(),
                ps_at_z: ps_at_z.iter().map(|e| builder.eval(e.cons())).collect(),
                alpha_pow_input: alpha_pow_input.iter().map(|e| builder.eval(e.cons())).collect(),
                ro_input: ro_input.iter().map(|e| builder.eval(e.cons())).collect(),
            };

            let output_vars = builder.fri_fold_v2(input_vars);
            for (lhs, rhs) in std::iter::zip(output_vars.alpha_pow_output, alpha_pow_output) {
                builder.assert_ext_eq(lhs, rhs.cons());
            }
            for (lhs, rhs) in std::iter::zip(output_vars.ro_output, ro_output) {
                builder.assert_ext_eq(lhs, rhs.cons());
            }
        }

        test_block(builder.into_root_block());
    }

    #[test]
    fn test_hint_bit_decomposition() {
        setup_logger();

        let mut builder = AsmBuilder::<F, EF>::default();
        let mut rng =
            StdRng::seed_from_u64(0xC0FFEE7AB1E).sample_iter::<F, _>(rand::distributions::Standard);
        for _ in 0..100 {
            let input_f = rng.next().unwrap();
            let input = input_f.as_canonical_u32();
            let output = (0..NUM_BITS).map(|i| (input >> i) & 1).collect::<Vec<_>>();

            let input_felt = builder.eval(input_f);
            let output_felts = builder.num2bits_v2_f(input_felt, NUM_BITS);
            let expected: Vec<Felt<_>> =
                output.into_iter().map(|x| builder.eval(F::from_canonical_u32(x))).collect();
            for (lhs, rhs) in output_felts.into_iter().zip(expected) {
                builder.assert_felt_eq(lhs, rhs);
            }
        }
        test_block(builder.into_root_block());
    }

    #[test]
    fn test_print_and_cycle_tracker() {
        const ITERS: usize = 5;

        setup_logger();

        let mut builder = AsmBuilder::<F, EF>::default();

        let input_fs = StdRng::seed_from_u64(0xC0FFEE7AB1E)
            .sample_iter::<F, _>(rand::distributions::Standard)
            .take(ITERS)
            .collect::<Vec<_>>();

        let input_efs = StdRng::seed_from_u64(0x7EA7AB1E)
            .sample_iter::<[F; 4], _>(rand::distributions::Standard)
            .take(ITERS)
            .collect::<Vec<_>>();

        let mut buf = VecDeque::<u8>::new();

        builder.cycle_tracker_v2_enter("printing felts");
        for (i, &input_f) in input_fs.iter().enumerate() {
            builder.cycle_tracker_v2_enter(format!("printing felt {i}"));
            let input_felt = builder.eval(input_f);
            builder.print_f(input_felt);
            builder.cycle_tracker_v2_exit();
        }
        builder.cycle_tracker_v2_exit();

        builder.cycle_tracker_v2_enter("printing exts");
        for (i, input_block) in input_efs.iter().enumerate() {
            builder.cycle_tracker_v2_enter(format!("printing ext {i}"));
            let input_ext = builder.eval(EF::from_base_slice(input_block).cons());
            builder.print_e(input_ext);
            builder.cycle_tracker_v2_exit();
        }
        builder.cycle_tracker_v2_exit();

        test_block_with_runner(builder.into_root_block(), |program| {
            let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new(
                program,
                BabyBearPoseidon2Inner::new().perm,
            );
            runtime.debug_stdout = Box::new(&mut buf);
            runtime.run().unwrap();
            runtime.record
        });

        let input_str_fs = input_fs.into_iter().map(|elt| format!("{elt}"));
        let input_str_efs = input_efs.into_iter().map(|elt| format!("{elt:?}"));
        let input_strs = input_str_fs.chain(input_str_efs);

        for (input_str, line) in zip(input_strs, buf.lines()) {
            let line = line.unwrap();
            assert!(line.contains(&input_str));
        }
    }

    #[test]
    fn test_ext2felts() {
        setup_logger();

        let mut builder = AsmBuilder::<F, EF>::default();
        let mut rng =
            StdRng::seed_from_u64(0x3264).sample_iter::<[F; 4], _>(rand::distributions::Standard);
        let mut random_ext = move || EF::from_base_slice(&rng.next().unwrap());
        for _ in 0..100 {
            let input = random_ext();
            let output: &[F] = input.as_base_slice();

            let input_ext = builder.eval(input.cons());
            let output_felts = builder.ext2felt_v2(input_ext);
            let expected: Vec<Felt<_>> = output.iter().map(|&x| builder.eval(x)).collect();
            for (lhs, rhs) in output_felts.into_iter().zip(expected) {
                builder.assert_felt_eq(lhs, rhs);
            }
        }
        test_block(builder.into_root_block());
    }

    macro_rules! test_assert_fixture {
        ($assert_felt:ident, $assert_ext:ident, $should_offset:literal) => {
            {
                use std::convert::identity;
                let mut builder = AsmBuilder::<F, EF>::default();
                test_assert_fixture!(builder, identity, F, Felt<_>, 0xDEADBEEF, $assert_felt, $should_offset);
                test_assert_fixture!(builder, EF::cons, EF, Ext<_, _>, 0xABADCAFE, $assert_ext, $should_offset);
                test_block(builder.into_root_block());
            }
        };
        ($builder:ident, $wrap:path, $t:ty, $u:ty, $seed:expr, $assert:ident, $should_offset:expr) => {
            {
                let mut elts = StdRng::seed_from_u64($seed)
                    .sample_iter::<$t, _>(rand::distributions::Standard);
                for _ in 0..100 {
                    let a = elts.next().unwrap();
                    let b = elts.next().unwrap();
                    let c = a + b;
                    let ar: $u = $builder.eval($wrap(a));
                    let br: $u = $builder.eval($wrap(b));
                    let cr: $u = $builder.eval(ar + br);
                    let cm = if $should_offset {
                        c + elts.find(|x| !x.is_zero()).unwrap()
                    } else {
                        c
                    };
                    $builder.$assert(cr, $wrap(cm));
                }
            }
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
