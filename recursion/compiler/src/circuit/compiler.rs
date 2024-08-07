use chips::poseidon2_skinny::WIDTH;
use core::fmt::Debug;
use instruction::{FieldEltType, HintBitsInstr, HintExt2FeltsInstr, HintInstr, PrintInstr};
use p3_field::{AbstractExtensionField, AbstractField, Field, PrimeField, TwoAdicField};
use sp1_core::utils::SpanBuilder;
use sp1_recursion_core::air::{Block, RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS};
use sp1_recursion_core_v2::{BaseAluInstr, BaseAluOpcode};
use std::{
    borrow::Borrow,
    collections::{hash_map::Entry, HashMap},
    iter::{repeat, zip},
    mem::transmute,
};

use sp1_recursion_core_v2::*;

use crate::prelude::*;

/// The backend for the circuit compiler.
#[derive(Debug, Clone, Default)]
pub struct AsmCompiler<C: Config> {
    pub next_addr: C::F,
    /// Map the frame pointers of the variables to the "physical" addresses.
    pub fp_to_addr: HashMap<i32, Address<C::F>>,
    /// Map base or extension field constants to "physical" addresses and mults.
    pub consts: HashMap<Imm<C::F, C::EF>, (Address<C::F>, C::F)>,
    /// Map each "physical" address to its read count.
    pub addr_to_mult: HashMap<Address<C::F>, C::F>,
}

impl<C: Config> AsmCompiler<C> {
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
    pub fn read_ghost_fp(&mut self, fp: i32) -> Address<C::F> {
        self.read_fp_internal(fp, false)
    }

    /// Map `fp` to its existing address and increment its mult.
    ///
    /// Ensures that `fp` has already been assigned an address.
    pub fn read_fp(&mut self, fp: i32) -> Address<C::F> {
        self.read_fp_internal(fp, true)
    }

    pub fn read_fp_internal(&mut self, fp: i32, increment_mult: bool) -> Address<C::F> {
        match self.fp_to_addr.entry(fp) {
            Entry::Vacant(entry) => panic!("expected entry in fp_to_addr: {entry:?}"),
            Entry::Occupied(entry) => {
                if increment_mult {
                    // This is a read, so we increment the mult.
                    match self.addr_to_mult.get_mut(entry.get()) {
                        Some(mult) => *mult += C::F::one(),
                        None => panic!("expected entry in addr_mult: {entry:?}"),
                    }
                }
                *entry.into_mut()
            }
        }
    }

    /// Map `fp` to a fresh address and initialize the mult to 0.
    ///
    /// Ensures that `fp` has not already been written to.
    pub fn write_fp(&mut self, fp: i32) -> Address<C::F> {
        match self.fp_to_addr.entry(fp) {
            Entry::Vacant(entry) => {
                let addr = Self::alloc(&mut self.next_addr);
                // This is a write, so we set the mult to zero.
                if let Some(x) = self.addr_to_mult.insert(addr, C::F::zero()) {
                    panic!("unexpected entry in addr_to_mult: {x:?}");
                }
                *entry.insert(addr)
            }
            Entry::Occupied(entry) => panic!("unexpected entry in fp_to_addr: {entry:?}"),
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
        match self.addr_to_mult.entry(addr) {
            Entry::Vacant(entry) => panic!("expected entry in addr_to_mult: {entry:?}"),
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
        match self.addr_to_mult.entry(addr) {
            Entry::Vacant(entry) => entry.insert(C::F::zero()),
            Entry::Occupied(entry) => panic!("unexpected entry in addr_to_mult: {entry:?}"),
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
        self.consts
            .entry(imm)
            .or_insert_with(|| (Self::alloc(&mut self.next_addr), C::F::zero()))
            .0
    }

    fn mem_write_const(&mut self, dst: impl Reg<C>, src: Imm<C::F, C::EF>) -> CompileOneItem<C::F> {
        Instruction::Mem(MemInstr {
            addrs: MemIo {
                inner: dst.write(self),
            },
            vals: MemIo {
                inner: src.as_block(),
            },
            mult: C::F::zero(),
            kind: MemAccessKind::Write,
        })
        .into()
    }

    fn base_alu(
        &mut self,
        opcode: BaseAluOpcode,
        dst: impl Reg<C>,
        lhs: impl Reg<C>,
        rhs: impl Reg<C>,
    ) -> CompileOneItem<C::F> {
        Instruction::BaseAlu(BaseAluInstr {
            opcode,
            mult: C::F::zero(),
            addrs: BaseAluIo {
                out: dst.write(self),
                in1: lhs.read(self),
                in2: rhs.read(self),
            },
        })
        .into()
    }

    fn ext_alu(
        &mut self,
        opcode: ExtAluOpcode,
        dst: impl Reg<C>,
        lhs: impl Reg<C>,
        rhs: impl Reg<C>,
    ) -> CompileOneItem<C::F> {
        Instruction::ExtAlu(ExtAluInstr {
            opcode,
            mult: C::F::zero(),
            addrs: ExtAluIo {
                out: dst.write(self),
                in1: lhs.read(self),
                in2: rhs.read(self),
            },
        })
        .into()
    }

    fn base_assert_eq(&mut self, lhs: impl Reg<C>, rhs: impl Reg<C>) -> Vec<CompileOneItem<C::F>> {
        use BaseAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));
        vec![
            self.base_alu(SubF, diff, lhs, rhs),
            self.base_alu(DivF, out, diff, Imm::F(C::F::zero())),
        ]
    }

    fn base_assert_ne(&mut self, lhs: impl Reg<C>, rhs: impl Reg<C>) -> Vec<CompileOneItem<C::F>> {
        use BaseAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));
        vec![
            self.base_alu(SubF, diff, lhs, rhs),
            self.base_alu(DivF, out, Imm::F(C::F::one()), diff),
        ]
    }

    fn ext_assert_eq(&mut self, lhs: impl Reg<C>, rhs: impl Reg<C>) -> Vec<CompileOneItem<C::F>> {
        use ExtAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));
        vec![
            self.ext_alu(SubE, diff, lhs, rhs),
            self.ext_alu(DivE, out, diff, Imm::EF(C::EF::zero())),
        ]
    }

    fn ext_assert_ne(&mut self, lhs: impl Reg<C>, rhs: impl Reg<C>) -> Vec<CompileOneItem<C::F>> {
        use ExtAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));
        vec![
            self.ext_alu(SubE, diff, lhs, rhs),
            self.ext_alu(DivE, out, Imm::EF(C::EF::one()), diff),
        ]
    }

    fn poseidon2_permute_skinny(
        &mut self,
        dst: [impl Reg<C>; WIDTH],
        src: [impl Reg<C>; WIDTH],
    ) -> CompileOneItem<C::F> {
        Instruction::Poseidon2Skinny(Poseidon2WideInstr {
            addrs: Poseidon2Io {
                input: src.map(|r| r.read(self)),
                output: dst.map(|r| r.write(self)),
            },
            mults: [C::F::zero(); WIDTH],
        })
        .into()
    }

    fn poseidon2_permute_wide(
        &mut self,
        dst: [impl Reg<C>; WIDTH],
        src: [impl Reg<C>; WIDTH],
    ) -> CompileOneItem<C::F> {
        Instruction::Poseidon2Wide(Poseidon2WideInstr {
            addrs: Poseidon2Io {
                input: src.map(|r| r.read(self)),
                output: dst.map(|r| r.write(self)),
            },
            mults: [C::F::zero(); WIDTH],
        })
        .into()
    }

    fn exp_reverse_bits(
        &mut self,
        dst: impl Reg<C>,
        base: impl Reg<C>,
        exp: impl IntoIterator<Item = impl Reg<C>>,
    ) -> CompileOneItem<C::F> {
        Instruction::ExpReverseBitsLen(ExpReverseBitsInstr {
            addrs: ExpReverseBitsIo {
                result: dst.write(self),
                base: base.read(self),
                exp: exp.into_iter().map(|r| r.read(self)).collect(),
            },
            mult: C::F::zero(),
        })
        .into()
    }

    fn hint_bit_decomposition(
        &mut self,
        value: impl Reg<C>,
        output: impl IntoIterator<Item = impl Reg<C>>,
    ) -> CompileOneItem<C::F> {
        Instruction::HintBits(HintBitsInstr {
            output_addrs_mults: output
                .into_iter()
                .map(|r| (r.write(self), C::F::zero()))
                .collect(),
            input_addr: value.read_ghost(self),
        })
        .into()
    }

    fn fri_fold(
        &mut self,
        CircuitV2FriFoldOutput {
            alpha_pow_output,
            ro_output,
        }: CircuitV2FriFoldOutput<C>,
        CircuitV2FriFoldInput {
            z,
            alpha,
            x,
            mat_opening,
            ps_at_z,
            alpha_pow_input,
            ro_input,
        }: CircuitV2FriFoldInput<C>,
    ) -> CompileOneItem<C::F> {
        Instruction::FriFold(FriFoldInstr {
            // Calculate before moving the vecs.
            alpha_pow_mults: vec![C::F::zero(); alpha_pow_output.len()],
            ro_mults: vec![C::F::zero(); ro_output.len()],

            base_single_addrs: FriFoldBaseIo { x: x.read(self) },
            ext_single_addrs: FriFoldExtSingleIo {
                z: z.read(self),
                alpha: alpha.read(self),
            },
            ext_vec_addrs: FriFoldExtVecIo {
                mat_opening: mat_opening.into_iter().map(|e| e.read(self)).collect(),
                ps_at_z: ps_at_z.into_iter().map(|e| e.read(self)).collect(),
                alpha_pow_input: alpha_pow_input.into_iter().map(|e| e.read(self)).collect(),
                ro_input: ro_input.into_iter().map(|e| e.read(self)).collect(),
                alpha_pow_output: alpha_pow_output
                    .into_iter()
                    .map(|e| e.write(self))
                    .collect(),
                ro_output: ro_output.into_iter().map(|e| e.write(self)).collect(),
            },
        })
        .into()
    }

    fn commit_public_values(
        &mut self,
        public_values: &RecursionPublicValues<Felt<C::F>>,
    ) -> CompileOneItem<C::F> {
        let pv_addrs =
            unsafe {
                transmute::<
                    RecursionPublicValues<Felt<C::F>>,
                    [Felt<C::F>; RECURSIVE_PROOF_NUM_PV_ELTS],
                >(*public_values)
            }
            .map(|pv| pv.read(self));

        let public_values_a: &RecursionPublicValues<Address<C::F>> = pv_addrs.as_slice().borrow();
        Instruction::CommitPublicValues(CommitPublicValuesInstr {
            pv_addrs: *public_values_a,
        })
        .into()
    }

    fn print_f(&mut self, addr: impl Reg<C>) -> CompileOneItem<C::F> {
        Instruction::Print(PrintInstr {
            field_elt_type: FieldEltType::Base,
            addr: addr.read_ghost(self),
        })
        .into()
    }

    fn print_e(&mut self, addr: impl Reg<C>) -> CompileOneItem<C::F> {
        Instruction::Print(PrintInstr {
            field_elt_type: FieldEltType::Extension,
            addr: addr.read_ghost(self),
        })
        .into()
    }

    fn ext2felts(&mut self, felts: [impl Reg<C>; D], ext: impl Reg<C>) -> CompileOneItem<C::F> {
        Instruction::HintExt2Felts(HintExt2FeltsInstr {
            output_addrs_mults: felts.map(|r| (r.write(self), C::F::zero())),
            input_addr: ext.read_ghost(self),
        })
        .into()
    }

    fn hint(&mut self, output: &[impl Reg<C>]) -> CompileOneItem<C::F> {
        Instruction::Hint(HintInstr {
            output_addrs_mults: output
                .iter()
                .map(|r| (r.write(self), C::F::zero()))
                .collect(),
        })
        .into()
    }

    pub fn compile_one<F>(&mut self, ir_instr: DslIr<C>) -> Vec<CompileOneItem<C::F>>
    where
        F: PrimeField + TwoAdicField,
        C: Config<N = F, F = F> + Debug,
    {
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

            DslIr::NegV(dst, src) => vec![self.base_alu(SubF, dst, Imm::F(C::F::zero()), src)],
            DslIr::NegF(dst, src) => vec![self.base_alu(SubF, dst, Imm::F(C::F::zero()), src)],
            DslIr::NegE(dst, src) => vec![self.ext_alu(SubE, dst, Imm::EF(C::EF::zero()), src)],
            DslIr::InvV(dst, src) => vec![self.base_alu(DivF, dst, Imm::F(C::F::one()), src)],
            DslIr::InvF(dst, src) => vec![self.base_alu(DivF, dst, Imm::F(C::F::one()), src)],
            DslIr::InvE(dst, src) => vec![self.ext_alu(DivE, dst, Imm::F(C::F::one()), src)],

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

            DslIr::CircuitV2Poseidon2PermuteBabyBearSkinny(dst, src) => {
                vec![self.poseidon2_permute_skinny(dst, src)]
            }
            DslIr::CircuitV2Poseidon2PermuteBabyBearWide(dst, src) => {
                vec![self.poseidon2_permute_wide(dst, src)]
            }
            DslIr::CircuitV2ExpReverseBits(dst, base, exp) => {
                vec![self.exp_reverse_bits(dst, base, exp)]
            }
            DslIr::CircuitV2HintBitsF(output, value) => {
                vec![self.hint_bit_decomposition(value, output)]
            }
            DslIr::CircuitV2FriFold(output, input) => vec![self.fri_fold(output, input)],
            DslIr::CircuitV2CommitPublicValues(public_values) => {
                vec![self.commit_public_values(&public_values)]
            }

            DslIr::PrintV(dst) => vec![self.print_f(dst)],
            DslIr::PrintF(dst) => vec![self.print_f(dst)],
            DslIr::PrintE(dst) => vec![self.print_e(dst)],
            DslIr::CircuitV2HintFelts(output) => vec![self.hint(&output)],
            DslIr::CircuitV2HintExts(output) => vec![self.hint(&output)],
            DslIr::CircuitExt2Felt(felts, ext) => vec![self.ext2felts(felts, ext)],
            DslIr::CycleTrackerV2Enter(name) => vec![CompileOneItem::CycleTrackerEnter(name)],
            DslIr::CycleTrackerV2Exit => vec![CompileOneItem::CycleTrackerExit],
            instr => panic!("unsupported instruction: {instr:?}"),
        }
    }

    /// Emit the instructions from a list of operations in the DSL.
    pub fn compile<F>(&mut self, operations: TracedVec<DslIr<C>>) -> RecursionProgram<C::F>
    where
        F: PrimeField + TwoAdicField,
        C: Config<N = F, F = F> + Debug,
    {
        // Compile each IR instruction into a list of ASM instructions, then combine them.
        // This step also counts the number of times each address is read from.
        let annotated_instrs = operations
            .into_iter()
            .flat_map(|(ir_instr, trace)| zip(self.compile_one(ir_instr), repeat(trace)))
            .collect::<Vec<_>>();

        // Cycle tracking logic.
        let (mut instrs, cycle_tracker_root_span) = {
            let mut span_builder = SpanBuilder::<_, &'static str>::new("cycle_tracker".to_string());
            let instrs = annotated_instrs
                .into_iter()
                .filter_map(|(item, trace)| match item {
                    CompileOneItem::Instr(instr) => {
                        span_builder.item(instr_name(&instr));
                        Some((instr, trace))
                    }
                    CompileOneItem::CycleTrackerEnter(name) => {
                        span_builder.enter(name);
                        None
                    }
                    CompileOneItem::CycleTrackerExit => {
                        span_builder.exit().unwrap();
                        None
                    }
                })
                .collect::<Vec<_>>();
            (instrs, span_builder.finish().unwrap())
        };
        for line in cycle_tracker_root_span.lines() {
            tracing::info!("{}", line);
        }

        // Replace the mults using the address count data gathered in this previous.
        // Exhaustive match for refactoring purposes.
        instrs
            .iter_mut()
            .flat_map(|(asm_instr, _)| match asm_instr {
                Instruction::BaseAlu(BaseAluInstr {
                    mult,
                    addrs: BaseAluIo { ref out, .. },
                    ..
                }) => vec![(mult, out)],
                Instruction::ExtAlu(ExtAluInstr {
                    mult,
                    addrs: ExtAluIo { ref out, .. },
                    ..
                }) => vec![(mult, out)],
                Instruction::Mem(MemInstr {
                    addrs: MemIo { ref inner },
                    mult,
                    kind: MemAccessKind::Write,
                    ..
                }) => vec![(mult, inner)],
                Instruction::Poseidon2Skinny(Poseidon2SkinnyInstr {
                    addrs: Poseidon2Io { ref output, .. },
                    mults,
                }) => mults.iter_mut().zip(output).collect(),
                Instruction::Poseidon2Wide(Poseidon2WideInstr {
                    addrs: Poseidon2Io { ref output, .. },
                    mults,
                }) => mults.iter_mut().zip(output).collect(),
                Instruction::ExpReverseBitsLen(ExpReverseBitsInstr {
                    addrs: ExpReverseBitsIo { ref result, .. },
                    mult,
                }) => vec![(mult, result)],
                Instruction::HintBits(HintBitsInstr {
                    output_addrs_mults, ..
                })
                | Instruction::Hint(HintInstr {
                    output_addrs_mults, ..
                }) => output_addrs_mults
                    .iter_mut()
                    .map(|(ref addr, mult)| (mult, addr))
                    .collect(),
                Instruction::FriFold(FriFoldInstr {
                    ext_vec_addrs:
                        FriFoldExtVecIo {
                            ref alpha_pow_output,
                            ref ro_output,
                            ..
                        },
                    alpha_pow_mults,
                    ro_mults,
                    ..
                }) => alpha_pow_mults
                    .iter_mut()
                    .zip(alpha_pow_output)
                    .chain(ro_mults.iter_mut().zip(ro_output))
                    .collect(),
                Instruction::HintExt2Felts(HintExt2FeltsInstr {
                    output_addrs_mults, ..
                }) => output_addrs_mults
                    .iter_mut()
                    .map(|(ref addr, mult)| (mult, addr))
                    .collect(),
                // Instructions that do not write to memory.
                Instruction::Mem(MemInstr {
                    kind: MemAccessKind::Read,
                    ..
                })
                | Instruction::CommitPublicValues(_)
                | Instruction::Print(_) => vec![],
            })
            .for_each(|(mult, addr): (&mut C::F, &Address<C::F>)| {
                *mult = self.addr_to_mult.remove(addr).unwrap()
            });
        debug_assert!(self.addr_to_mult.is_empty());
        // Initialize constants.
        let instrs_consts = self.consts.drain().map(|(imm, (addr, mult))| {
            Instruction::Mem(MemInstr {
                addrs: MemIo { inner: addr },
                vals: MemIo {
                    inner: imm.as_block(),
                },
                mult,
                kind: MemAccessKind::Write,
            })
        });
        // Reset the other fields.
        self.next_addr = Default::default();
        self.fp_to_addr.clear();
        // Place constant-initializing instructions at the top.
        let (instructions, traces) = zip(instrs_consts, repeat(None)).chain(instrs).unzip();
        RecursionProgram {
            instructions,
            traces,
        }
    }
}

/// Used for cycle tracking.
const fn instr_name<F>(instr: &Instruction<F>) -> &'static str {
    match instr {
        Instruction::BaseAlu(_) => "BaseAlu",
        Instruction::ExtAlu(_) => "ExtAlu",
        Instruction::Mem(_) => "Mem",
        Instruction::Poseidon2Skinny(_) => "Poseidon2Skinny",
        Instruction::Poseidon2Wide(_) => "Poseidon2Wide",
        Instruction::ExpReverseBitsLen(_) => "ExpReverseBitsLen",
        Instruction::HintBits(_) => "HintBits",
        Instruction::FriFold(_) => "FriFold",
        Instruction::Print(_) => "Print",
        Instruction::HintExt2Felts(_) => "HintExt2Felts",
        Instruction::Hint(_) => "Hint",
        Instruction::CommitPublicValues(_) => "CommitPublicValues",
    }
}

/// Instruction or annotation. Result of compiling one `DslIr` item.
#[derive(Debug, Clone)]
pub enum CompileOneItem<F> {
    Instr(Instruction<F>),
    CycleTrackerEnter(String),
    CycleTrackerExit,
}

impl<F> From<Instruction<F>> for CompileOneItem<F> {
    fn from(value: Instruction<F>) -> Self {
        CompileOneItem::Instr(value)
    }
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
        }
    };
}

// Allow for more flexibility in arguments.
impl_reg_borrowed!(&T);
impl_reg_borrowed!(&mut T);
impl_reg_borrowed!(Box<T>);

macro_rules! impl_reg_fp {
    ($a:ty) => {
        impl<C: Config> Reg<C> for $a {
            fn read(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
                compiler.read_fp(self.fp())
            }
            fn read_ghost(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
                compiler.read_ghost_fp(self.fp())
            }
            fn write(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
                compiler.write_fp(self.fp())
            }
        }
    };
}

// These three types have `.fp()` but they don't share a trait.
impl_reg_fp!(Var<C::F>);
impl_reg_fp!(Felt<C::F>);
impl_reg_fp!(Ext<C::F, C::EF>);

impl<C: Config> Reg<C> for Imm<C::F, C::EF> {
    fn read(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
        compiler.read_const(*self)
    }

    fn read_ghost(&self, compiler: &mut AsmCompiler<C>) -> Address<C::F> {
        compiler.read_ghost_const(*self)
    }

    fn write(&self, _compiler: &mut AsmCompiler<C>) -> Address<C::F> {
        panic!("cannot write to immediate in register: {self:?}")
    }
}

impl<C: Config> Reg<C> for Address<C::F> {
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
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, io::BufRead, iter::zip};

    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_field::{Field, PrimeField32};
    use p3_symmetric::{CryptographicHasher, Permutation};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_core::{
        stark::StarkGenericConfig,
        utils::{
            inner_perm, run_test_machine, setup_logger, BabyBearPoseidon2, BabyBearPoseidon2Inner,
            InnerHash,
        },
    };
    use sp1_recursion_core_v2::{machine::RecursionAir, RecursionProgram, Runtime};

    use crate::{
        asm::{AsmBuilder, AsmConfig},
        circuit::CircuitV2Builder,
    };

    use super::*;

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    type A = RecursionAir<F, 3, 1>;
    fn test_operations(operations: TracedVec<DslIr<AsmConfig<F, EF>>>) {
        test_operations_with_runner(operations, |program| {
            let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new(
                program,
                BabyBearPoseidon2Inner::new().perm,
            );
            runtime.run().unwrap();
            runtime.record
        });
    }

    fn test_operations_with_runner(
        operations: TracedVec<DslIr<AsmConfig<F, EF>>>,
        run: impl FnOnce(&RecursionProgram<F>) -> ExecutionRecord<F>,
    ) {
        let mut compiler = super::AsmCompiler::<AsmConfig<F, EF>>::default();
        let program = compiler.compile(operations);
        let record = run(&program);

        let config = SC::new();
        let machine = A::machine_with_all_chips(config);
        let (pk, vk) = machine.setup(&program);
        let result = run_test_machine(vec![record], machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }

    #[test]
    fn test_poseidon2_skinny() {
        setup_logger();

        let mut builder = AsmBuilder::<F, EF>::default();
        let mut rng = StdRng::seed_from_u64(0xCAFEDA7E)
            .sample_iter::<[F; WIDTH], _>(rand::distributions::Standard);
        for _ in 0..100 {
            let input_1: [F; WIDTH] = rng.next().unwrap();
            let output_1 = inner_perm().permute(input_1);

            let input_1_felts = input_1.map(|x| builder.eval(x));
            let output_1_felts = builder.poseidon2_permute_v2_skinny(input_1_felts);
            let expected: [Felt<_>; WIDTH] = output_1.map(|x| builder.eval(x));
            for (lhs, rhs) in output_1_felts.into_iter().zip(expected) {
                builder.assert_felt_eq(lhs, rhs);
            }
        }

        test_operations(builder.operations);
    }

    #[test]
    fn test_poseidon2_wide() {
        setup_logger();

        let mut builder = AsmBuilder::<F, EF>::default();
        let mut rng = StdRng::seed_from_u64(0xCAFEDA7E)
            .sample_iter::<[F; WIDTH], _>(rand::distributions::Standard);
        for _ in 0..100 {
            let input_1: [F; WIDTH] = rng.next().unwrap();
            let output_1 = inner_perm().permute(input_1);

            let input_1_felts = input_1.map(|x| builder.eval(x));
            let output_1_felts = builder.poseidon2_permute_v2_wide(input_1_felts);
            let expected: [Felt<_>; WIDTH] = output_1.map(|x| builder.eval(x));
            for (lhs, rhs) in output_1_felts.into_iter().zip(expected) {
                builder.assert_felt_eq(lhs, rhs);
            }
        }

        test_operations(builder.operations);
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
        println!("{:?}", expected);

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
        test_operations(builder.operations);
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
            let alpha_pow_output = (0..i)
                .map(|i| alpha_pow_input[i] * alpha)
                .collect::<Vec<EF>>();
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
                alpha_pow_input: alpha_pow_input
                    .iter()
                    .map(|e| builder.eval(e.cons()))
                    .collect(),
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

        test_operations(builder.operations);
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
            let expected: Vec<Felt<_>> = output
                .into_iter()
                .map(|x| builder.eval(F::from_canonical_u32(x)))
                .collect();
            for (lhs, rhs) in output_felts.into_iter().zip(expected) {
                builder.assert_felt_eq(lhs, rhs);
            }
        }
        test_operations(builder.operations);
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

        builder.cycle_tracker_v2_enter("printing felts".to_string());
        for (i, &input_f) in input_fs.iter().enumerate() {
            builder.cycle_tracker_v2_enter(format!("printing felt {i}"));
            let input_felt = builder.eval(input_f);
            builder.print_f(input_felt);
            builder.cycle_tracker_v2_exit();
        }
        builder.cycle_tracker_v2_exit();

        builder.cycle_tracker_v2_enter("printing exts".to_string());
        for (i, input_block) in input_efs.iter().enumerate() {
            builder.cycle_tracker_v2_enter(format!("printing ext {i}"));
            let input_ext = builder.eval(EF::from_base_slice(input_block).cons());
            builder.print_e(input_ext);
            builder.cycle_tracker_v2_exit();
        }
        builder.cycle_tracker_v2_exit();

        test_operations_with_runner(builder.operations, |program| {
            let mut runtime = Runtime::<F, EF, DiffusionMatrixBabyBear>::new(
                program,
                BabyBearPoseidon2Inner::new().perm,
            );
            runtime.debug_stdout = Box::new(&mut buf);
            runtime.run().unwrap();
            runtime.record
        });

        let input_str_fs = input_fs.into_iter().map(|elt| format!("{}", elt));
        let input_str_efs = input_efs.into_iter().map(|elt| format!("{:?}", elt));
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
        test_operations(builder.operations);
    }

    macro_rules! test_assert_fixture {
        ($assert_felt:ident, $assert_ext:ident, $should_offset:literal) => {
            {
                use std::convert::identity;
                let mut builder = AsmBuilder::<F, EF>::default();
                test_assert_fixture!(builder, identity, F, Felt<_>, 0xDEADBEEF, $assert_felt, $should_offset);
                test_assert_fixture!(builder, EF::cons, EF, Ext<_, _>, 0xABADCAFE, $assert_ext, $should_offset);
                test_operations(builder.operations);
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
