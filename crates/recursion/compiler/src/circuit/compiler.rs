// use chips::poseidon2_skinny::WIDTH;
use cfg_if::cfg_if;
use core::fmt::Debug;
use instruction::{
    FieldEltType, HintAddCurveInstr, HintBitsInstr, HintExt2FeltsInstr, HintInstr, PrintInstr,
};
use itertools::Itertools;
use slop_algebra::{AbstractExtensionField, AbstractField, Field, PrimeField64};
#[cfg(feature = "debug")]
use sp1_core_machine::utils::SpanBuilder;
use sp1_hypercube::septic_curve::SepticCurve;
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_executor::{
    BaseAluInstr, BaseAluOpcode, Block, RecursionPublicValues, PERMUTATION_WIDTH,
    RECURSIVE_PROOF_NUM_PV_ELTS,
};
use std::{
    borrow::{Borrow, Cow},
    collections::HashMap,
    mem::transmute,
};
use vec_map::VecMap;

use sp1_recursion_executor::*;

use crate::prelude::*;

/// A fast, deterministic hasher for the compiler's const-interning map.
///
/// The keys are one or four field-element limbs, so hashing itself is a large fraction of
/// each map operation under the default SipHash hasher. The map is not exposed to untrusted
/// input, so an FxHash-style multiply-mix suffices.
#[derive(Debug, Clone, Copy, Default)]
struct FxHasher(u64);

impl FxHasher {
    #[inline]
    fn add(&mut self, v: u64) {
        const SEED: u64 = 0x517cc1b727220a95;
        self.0 = (self.0.rotate_left(5) ^ v).wrapping_mul(SEED);
    }
}

impl std::hash::Hasher for FxHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.add(b as u64);
        }
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add(i as u64);
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.add(i as u64);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add(i as u64);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add(i);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add(i as u64);
    }
}

type ConstsMap = HashMap<
    Imm<SP1Field, SP1ExtensionField>,
    (Address<SP1Field>, SP1Field),
    std::hash::BuildHasherDefault<FxHasher>,
>;

/// The backend for the circuit compiler.
#[derive(Debug, Clone, Default)]
pub struct AsmCompiler {
    next_addr: SP1Field,
    /// Map the frame pointers of the variables to the "physical" addresses.
    virtual_to_physical: VecMap<Address<SP1Field>>,
    /// Map base or extension field constants to "physical" addresses and mults.
    consts: ConstsMap,
    /// Map each "physical" address to its read count.
    addr_to_mult: VecMap<SP1Field>,
}

impl AsmCompiler
where
    SP1Field: PrimeField64,
{
    /// Allocate a fresh address. Checks that the address space is not full.
    pub fn alloc(next_addr: &mut SP1Field) -> Address<SP1Field> {
        let id = Address(*next_addr);
        *next_addr += SP1Field::one();
        if next_addr.is_zero() {
            panic!("out of address space");
        }
        id
    }

    /// Map `fp` to its existing address without changing its mult.
    ///
    /// Ensures that `fp` has already been assigned an address.
    pub fn read_ghost_vaddr(&mut self, vaddr: usize) -> Address<SP1Field> {
        self.read_vaddr_internal(vaddr, false)
    }

    /// Map `fp` to its existing address and increment its mult.
    ///
    /// Ensures that `fp` has already been assigned an address.
    pub fn read_vaddr(&mut self, vaddr: usize) -> Address<SP1Field> {
        self.read_vaddr_internal(vaddr, true)
    }

    #[allow(clippy::uninlined_format_args)]
    pub fn read_vaddr_internal(&mut self, vaddr: usize, increment_mult: bool) -> Address<SP1Field> {
        use vec_map::Entry;
        match self.virtual_to_physical.entry(vaddr) {
            Entry::Vacant(_) => panic!("expected entry: virtual_physical[{vaddr:?}]"),
            Entry::Occupied(entry) => {
                if increment_mult {
                    // This is a read, so we increment the mult.
                    match self.addr_to_mult.get_mut(entry.get().as_usize()) {
                        Some(mult) => *mult += SP1Field::one(),
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
    pub fn write_fp(&mut self, vaddr: usize) -> Address<SP1Field> {
        use vec_map::Entry;
        match self.virtual_to_physical.entry(vaddr) {
            Entry::Vacant(entry) => {
                let addr = Self::alloc(&mut self.next_addr);
                // This is a write, so we set the mult to zero.
                if let Some(x) = self.addr_to_mult.insert(addr.as_usize(), SP1Field::zero()) {
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
    pub fn read_addr(&mut self, addr: Address<SP1Field>) -> &mut SP1Field {
        self.read_addr_internal(addr, true)
    }

    /// Retrieves `mult` associated with `addr`.
    ///
    /// Ensures that `addr` has already been assigned a `mult`.
    pub fn read_ghost_addr(&mut self, addr: Address<SP1Field>) -> &mut SP1Field {
        self.read_addr_internal(addr, true)
    }

    fn read_addr_internal(
        &mut self,
        addr: Address<SP1Field>,
        increment_mult: bool,
    ) -> &mut SP1Field {
        use vec_map::Entry;
        match self.addr_to_mult.entry(addr.as_usize()) {
            Entry::Vacant(_) => panic!("expected entry: addr_to_mult[{:?}]", addr.as_usize()),
            Entry::Occupied(entry) => {
                // This is a read, so we increment the mult.
                let mult = entry.into_mut();
                if increment_mult {
                    *mult += SP1Field::one();
                }
                mult
            }
        }
    }

    /// Associate a `mult` of zero with `addr`.
    ///
    /// Ensures that `addr` has not already been written to.
    pub fn write_addr(&mut self, addr: Address<SP1Field>) -> &mut SP1Field {
        use vec_map::Entry;
        match self.addr_to_mult.entry(addr.as_usize()) {
            Entry::Vacant(entry) => entry.insert(SP1Field::zero()),
            Entry::Occupied(entry) => {
                panic!("unexpected entry: addr_to_mult[{:?}] = {:?}", addr.as_usize(), entry.get())
            }
        }
    }

    /// Read a constant (a.k.a. immediate).
    ///
    /// Increments the mult, first creating an entry if it does not yet exist.
    pub fn read_const(&mut self, imm: Imm<SP1Field, SP1ExtensionField>) -> Address<SP1Field> {
        self.consts
            .entry(imm)
            .and_modify(|(_, x)| *x += SP1Field::one())
            .or_insert_with(|| (Self::alloc(&mut self.next_addr), SP1Field::one()))
            .0
    }

    /// Read a constant (a.k.a. immediate).
    ///    
    /// Does not increment the mult. Creates an entry if it does not yet exist.
    pub fn read_ghost_const(&mut self, imm: Imm<SP1Field, SP1ExtensionField>) -> Address<SP1Field> {
        self.consts
            .entry(imm)
            .or_insert_with(|| (Self::alloc(&mut self.next_addr), SP1Field::zero()))
            .0
    }

    fn mem_write_const(
        &mut self,
        dst: impl Reg,
        src: Imm<SP1Field, SP1ExtensionField>,
    ) -> Instruction<SP1Field> {
        Instruction::Mem(MemInstr {
            addrs: MemIo { inner: dst.write(self) },
            vals: MemIo { inner: src.as_block() },
            mult: SP1Field::zero(),
            kind: MemAccessKind::Write,
        })
    }

    fn base_alu(
        &mut self,
        opcode: BaseAluOpcode,
        dst: impl Reg,
        lhs: impl Reg,
        rhs: impl Reg,
    ) -> Instruction<SP1Field> {
        Instruction::BaseAlu(BaseAluInstr {
            opcode,
            mult: SP1Field::zero(),
            addrs: BaseAluIo { out: dst.write(self), in1: lhs.read(self), in2: rhs.read(self) },
        })
    }

    fn ext_alu(
        &mut self,
        opcode: ExtAluOpcode,
        dst: impl Reg,
        lhs: impl Reg,
        rhs: impl Reg,
    ) -> Instruction<SP1Field> {
        Instruction::ExtAlu(ExtAluInstr {
            opcode,
            mult: SP1Field::zero(),
            addrs: ExtAluIo { out: dst.write(self), in1: lhs.read(self), in2: rhs.read(self) },
        })
    }

    fn base_assert_eq(
        &mut self,
        lhs: impl Reg,
        rhs: impl Reg,
        mut f: impl FnMut(Instruction<SP1Field>),
    ) {
        use BaseAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));
        f(self.base_alu(SubF, diff, lhs, rhs));
        f(self.base_alu(DivF, out, diff, Imm::F(SP1Field::zero())));
    }

    fn base_assert_ne(
        &mut self,
        lhs: impl Reg,
        rhs: impl Reg,
        mut f: impl FnMut(Instruction<SP1Field>),
    ) {
        use BaseAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));

        f(self.base_alu(SubF, diff, lhs, rhs));
        f(self.base_alu(DivF, out, Imm::F(SP1Field::one()), diff));
    }

    fn ext_assert_eq(
        &mut self,
        lhs: impl Reg,
        rhs: impl Reg,
        mut f: impl FnMut(Instruction<SP1Field>),
    ) {
        use ExtAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));

        f(self.ext_alu(SubE, diff, lhs, rhs));
        f(self.ext_alu(DivE, out, diff, Imm::EF(SP1ExtensionField::zero())));
    }

    fn ext_assert_ne(
        &mut self,
        lhs: impl Reg,
        rhs: impl Reg,
        mut f: impl FnMut(Instruction<SP1Field>),
    ) {
        use ExtAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));

        f(self.ext_alu(SubE, diff, lhs, rhs));
        f(self.ext_alu(DivE, out, Imm::EF(SP1ExtensionField::one()), diff));
    }

    #[inline(always)]
    fn ext2felt_chip(&mut self, dst: [impl Reg; D], src: impl Reg) -> Instruction<SP1Field> {
        Instruction::ExtFelt(ExtFeltInstr {
            addrs: [
                src.read(self),
                dst[0].write(self),
                dst[1].write(self),
                dst[2].write(self),
                dst[3].write(self),
            ],
            mults: [SP1Field::zero(); D + 1],
            ext2felt: true,
        })
    }

    #[inline(always)]
    fn felt2ext_chip(&mut self, dst: impl Reg, src: [impl Reg; D]) -> Instruction<SP1Field> {
        Instruction::ExtFelt(ExtFeltInstr {
            addrs: [
                dst.write(self),
                src[0].read(self),
                src[1].read(self),
                src[2].read(self),
                src[3].read(self),
            ],
            mults: [SP1Field::zero(); D + 1],
            ext2felt: false,
        })
    }

    #[inline(always)]
    fn poseidon2_permute(
        &mut self,
        dst: [impl Reg; PERMUTATION_WIDTH],
        src: [impl Reg; PERMUTATION_WIDTH],
    ) -> Instruction<SP1Field> {
        Instruction::Poseidon2(Box::new(Poseidon2Instr {
            addrs: Poseidon2Io {
                input: src.map(|r| r.read(self)),
                output: dst.map(|r| r.write(self)),
            },
            mults: [SP1Field::zero(); PERMUTATION_WIDTH],
        }))
    }

    #[inline(always)]
    fn poseidon2_external_linear_layer(
        &mut self,
        dst: [impl Reg; PERMUTATION_WIDTH / D],
        src: [impl Reg; PERMUTATION_WIDTH / D],
    ) -> Instruction<SP1Field> {
        Instruction::Poseidon2LinearLayer(Box::new(Poseidon2LinearLayerInstr {
            addrs: Poseidon2LinearLayerIo {
                input: src.map(|r| r.read(self)),
                output: dst.map(|r| r.write(self)),
            },
            mults: [SP1Field::zero(); PERMUTATION_WIDTH / D],
            external: true,
        }))
    }

    #[inline(always)]
    fn poseidon2_internal_linear_layer(
        &mut self,
        dst: [impl Reg; PERMUTATION_WIDTH / D],
        src: [impl Reg; PERMUTATION_WIDTH / D],
    ) -> Instruction<SP1Field> {
        Instruction::Poseidon2LinearLayer(Box::new(Poseidon2LinearLayerInstr {
            addrs: Poseidon2LinearLayerIo {
                input: src.map(|r| r.read(self)),
                output: dst.map(|r| r.write(self)),
            },
            mults: [SP1Field::zero(); PERMUTATION_WIDTH / D],
            external: false,
        }))
    }

    #[inline(always)]
    fn poseidon2_external_sbox(&mut self, dst: impl Reg, src: impl Reg) -> Instruction<SP1Field> {
        Instruction::Poseidon2SBox(Poseidon2SBoxInstr {
            addrs: Poseidon2SBoxIo { input: src.read(self), output: dst.write(self) },
            mults: SP1Field::zero(),
            external: true,
        })
    }

    #[inline(always)]
    fn poseidon2_internal_sbox(&mut self, dst: impl Reg, src: impl Reg) -> Instruction<SP1Field> {
        Instruction::Poseidon2SBox(Poseidon2SBoxInstr {
            addrs: Poseidon2SBoxIo { input: src.read(self), output: dst.write(self) },
            mults: SP1Field::zero(),
            external: false,
        })
    }

    #[inline(always)]
    fn select(
        &mut self,
        bit: impl Reg,
        dst1: impl Reg,
        dst2: impl Reg,
        lhs: impl Reg,
        rhs: impl Reg,
    ) -> Instruction<SP1Field> {
        Instruction::Select(SelectInstr {
            addrs: SelectIo {
                bit: bit.read(self),
                out1: dst1.write(self),
                out2: dst2.write(self),
                in1: lhs.read(self),
                in2: rhs.read(self),
            },
            mult1: SP1Field::zero(),
            mult2: SP1Field::zero(),
        })
    }

    fn hint_bit_decomposition(
        &mut self,
        value: impl Reg,
        output: impl IntoIterator<Item = impl Reg>,
    ) -> Instruction<SP1Field> {
        Instruction::HintBits(HintBitsInstr {
            output_addrs_mults: output
                .into_iter()
                .map(|r| (r.write(self), SP1Field::zero()))
                .collect(),
            input_addr: value.read_ghost(self),
        })
    }

    fn add_curve(
        &mut self,
        output: SepticCurve<Felt<SP1Field>>,
        input1: SepticCurve<Felt<SP1Field>>,
        input2: SepticCurve<Felt<SP1Field>>,
    ) -> Instruction<SP1Field> {
        Instruction::HintAddCurve(Box::new(HintAddCurveInstr {
            output_x_addrs_mults: output
                .x
                .0
                .into_iter()
                .map(|r| (r.write(self), SP1Field::zero()))
                .collect(),
            output_y_addrs_mults: output
                .y
                .0
                .into_iter()
                .map(|r| (r.write(self), SP1Field::zero()))
                .collect(),
            input1_x_addrs: input1.x.0.into_iter().map(|value| value.read_ghost(self)).collect(),
            input1_y_addrs: input1.y.0.into_iter().map(|value| value.read_ghost(self)).collect(),
            input2_x_addrs: input2.x.0.into_iter().map(|value| value.read_ghost(self)).collect(),
            input2_y_addrs: input2.y.0.into_iter().map(|value| value.read_ghost(self)).collect(),
        }))
    }

    fn prefix_sum_checks(
        &mut self,
        zero: Felt<SP1Field>,
        one: Ext<SP1Field, SP1ExtensionField>,
        accs: Vec<Ext<SP1Field, SP1ExtensionField>>,
        field_accs: Vec<Felt<SP1Field>>,
        x1: Vec<Felt<SP1Field>>,
        x2: Vec<Ext<SP1Field, SP1ExtensionField>>,
    ) -> Instruction<SP1Field> {
        // First, write to the addresses in `accs`.
        let acc_write_addrs: Vec<_> = accs.clone().into_iter().map(|r| r.write(self)).collect();
        let field_acc_write_addrs = field_accs.clone().into_iter().map(|r| r.write(self)).collect();
        // Then, read from the addresses in `accs`.
        let _: Vec<_> = accs.iter().take(accs.len() - 1).map(|r| r.read(self)).collect();
        let _: Vec<_> =
            field_accs.iter().take(field_accs.len() - 1).map(|r| r.read(self)).collect();
        Instruction::PrefixSumChecks(Box::new(PrefixSumChecksInstr {
            addrs: PrefixSumChecksIo {
                zero: zero.read(self),
                one: one.read(self),
                x1: x1.into_iter().map(|r| r.read(self)).collect(),
                x2: x2.into_iter().map(|r| r.read(self)).collect(),
                accs: acc_write_addrs,
                field_accs: field_acc_write_addrs,
            },
            acc_mults: vec![SP1Field::zero(); accs.len()],
            field_acc_mults: vec![SP1Field::zero(); field_accs.len()],
        }))
    }

    fn commit_public_values(
        &mut self,
        public_values: &RecursionPublicValues<Felt<SP1Field>>,
    ) -> Instruction<SP1Field> {
        public_values.digest.iter().for_each(|x| {
            let _ = x.read(self);
        });
        let pv_addrs = unsafe {
            transmute::<
                RecursionPublicValues<Felt<SP1Field>>,
                [Felt<SP1Field>; RECURSIVE_PROOF_NUM_PV_ELTS],
            >(*public_values)
        }
        .map(|pv| pv.read_ghost(self));

        let public_values_a: &RecursionPublicValues<Address<SP1Field>> =
            pv_addrs.as_slice().borrow();
        Instruction::CommitPublicValues(Box::new(CommitPublicValuesInstr {
            pv_addrs: *public_values_a,
        }))
    }

    fn print_f(&mut self, addr: impl Reg) -> Instruction<SP1Field> {
        Instruction::Print(PrintInstr {
            field_elt_type: FieldEltType::Base,
            addr: addr.read_ghost(self),
        })
    }

    fn print_e(&mut self, addr: impl Reg) -> Instruction<SP1Field> {
        Instruction::Print(PrintInstr {
            field_elt_type: FieldEltType::Extension,
            addr: addr.read_ghost(self),
        })
    }

    fn ext2felts(&mut self, felts: [impl Reg; D], ext: impl Reg) -> Instruction<SP1Field> {
        Instruction::HintExt2Felts(HintExt2FeltsInstr {
            output_addrs_mults: felts.map(|r| (r.write(self), SP1Field::zero())),
            input_addr: ext.read_ghost(self),
        })
    }

    fn hint(&mut self, output: impl Reg, len: usize) -> Instruction<SP1Field> {
        let zero = SP1Field::zero();
        Instruction::Hint(HintInstr {
            output_addrs_mults: output
                .write_many(self, len)
                .into_iter()
                .map(|a| (a, zero))
                .collect(),
        })
    }
    /// Compiles one instruction, passing one or more instructions to `consumer`.
    ///
    /// We do not simply return a `Vec` for performance reasons --- results would be immediately fed
    /// to `flat_map`, so we employ fusion/deforestation to eliminate intermediate data structures.
    pub fn compile_one<C: Config<N = SP1Field>>(
        &mut self,
        ir_instr: DslIr<C>,
        mut consumer: impl FnMut(Result<Instruction<SP1Field>, CompileOneErr<C>>),
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
            DslIr::SubEF(dst, lhs, rhs) => f(self.ext_alu(SubE, dst, lhs, rhs)),

            DslIr::MulV(dst, lhs, rhs) => f(self.base_alu(MulF, dst, lhs, rhs)),
            DslIr::MulVI(dst, lhs, rhs) => f(self.base_alu(MulF, dst, lhs, Imm::F(rhs))),
            DslIr::MulF(dst, lhs, rhs) => f(self.base_alu(MulF, dst, lhs, rhs)),
            DslIr::MulFI(dst, lhs, rhs) => f(self.base_alu(MulF, dst, lhs, Imm::F(rhs))),
            DslIr::MulE(dst, lhs, rhs) => f(self.ext_alu(MulE, dst, lhs, rhs)),
            DslIr::MulEI(dst, lhs, rhs) => f(self.ext_alu(MulE, dst, lhs, Imm::EF(rhs))),
            DslIr::MulEF(dst, lhs, rhs) => f(self.ext_alu(MulE, dst, lhs, rhs)),

            DslIr::DivF(dst, lhs, rhs) => f(self.base_alu(DivF, dst, lhs, rhs)),
            DslIr::DivFI(dst, lhs, rhs) => f(self.base_alu(DivF, dst, lhs, Imm::F(rhs))),
            DslIr::DivFIN(dst, lhs, rhs) => f(self.base_alu(DivF, dst, Imm::F(lhs), rhs)),
            DslIr::DivE(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, lhs, rhs)),
            DslIr::DivEI(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, lhs, Imm::EF(rhs))),
            DslIr::DivEIN(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, Imm::EF(lhs), rhs)),
            DslIr::DivEF(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, lhs, rhs)),

            DslIr::NegV(dst, src) => f(self.base_alu(SubF, dst, Imm::F(SP1Field::zero()), src)),
            DslIr::NegF(dst, src) => f(self.base_alu(SubF, dst, Imm::F(SP1Field::zero()), src)),
            DslIr::NegE(dst, src) => {
                f(self.ext_alu(SubE, dst, Imm::EF(SP1ExtensionField::zero()), src))
            }
            DslIr::InvV(dst, src) => f(self.base_alu(DivF, dst, Imm::F(SP1Field::one()), src)),
            DslIr::InvF(dst, src) => f(self.base_alu(DivF, dst, Imm::F(SP1Field::one()), src)),
            DslIr::InvE(dst, src) => f(self.ext_alu(DivE, dst, Imm::F(SP1Field::one()), src)),

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

            DslIr::CircuitChipExt2Felt(dst, src) => f(self.ext2felt_chip(dst, src)),
            DslIr::CircuitChipFelt2Ext(dst, src) => f(self.felt2ext_chip(dst, src)),
            DslIr::Poseidon2ExternalLinearLayer(data) => {
                f(self.poseidon2_external_linear_layer(data.0, data.1))
            }
            DslIr::Poseidon2InternalLinearLayer(data) => {
                f(self.poseidon2_internal_linear_layer(data.0, data.1))
            }
            DslIr::Poseidon2ExternalSBOX(dst, src) => f(self.poseidon2_external_sbox(dst, src)),
            DslIr::Poseidon2InternalSBOX(dst, src) => f(self.poseidon2_internal_sbox(dst, src)),

            DslIr::CircuitV2Poseidon2PermuteKoalaBear(data) => {
                f(self.poseidon2_permute(data.0, data.1))
            }
            DslIr::CircuitV2HintBitsF(output, value) => {
                f(self.hint_bit_decomposition(value, output))
            }
            DslIr::CircuitV2PrefixSumChecks(data) => {
                f(self.prefix_sum_checks(data.0, data.1, data.2, data.3, data.4, data.5))
            }
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
    ///
    /// Event-vector offsets (see [`AnalyzedInstruction`]) are assigned as instructions are
    /// emitted, in emission order, which coincides with the traversal order of
    /// [`RawProgram::analyze`]. `Mem` instructions are assigned offsets starting from zero and
    /// are shifted up by the number of interned constants in [`Self::backfill_all`], once that
    /// number is known; the constants themselves occupy the first offsets (as if they were
    /// analyzed first, matching their position at the start of the program).
    ///
    /// The parameter `cycle_tracker` is enabled with the `debug` feature.
    /// The cycle tracker cannot be a field of `self` because of the consumer
    /// passed to `compile_one`, which exclusively borrows `self`.
    fn compile_raw_program<C: Config<N = SP1Field>>(
        &mut self,
        block: DslIrBlock<C>,
        instrs_prefix: Vec<SeqBlock<AnalyzedInstruction<SP1Field>>>,
        event_counts: &mut RecursionAirEventCount,
        #[cfg(feature = "debug")] cycle_tracker: &mut SpanBuilder<Cow<'static, str>, &'static str>,
    ) -> RawProgram<AnalyzedInstruction<SP1Field>> {
        // Consider refactoring the builder to use an AST instead of a list of operations.
        // Possible to remove address translation at this step.
        let mut seq_blocks = instrs_prefix;
        let mut maybe_bb: Option<BasicBlock<AnalyzedInstruction<SP1Field>>> = None;

        for op in block.ops {
            match op {
                DslIr::Parallel(par_blocks) => {
                    seq_blocks.extend(maybe_bb.take().map(SeqBlock::Basic));
                    seq_blocks.push(SeqBlock::Parallel(
                        par_blocks
                            .into_iter()
                            .map(|b| {
                                cfg_if! {
                                    if #[cfg(feature = "debug")] {
                                        self.compile_raw_program(b, vec![], event_counts, cycle_tracker)
                                    } else {
                                        self.compile_raw_program(b, vec![], event_counts)
                                    }
                                }
                            })
                            .collect(),
                    ))
                }
                op => {
                    let bb = maybe_bb.get_or_insert_with(Default::default);
                    self.compile_one(op, |item| match item {
                        Ok(instr) => {
                            #[cfg(feature = "debug")]
                            {
                                cycle_tracker.item(instr_name(&instr));
                            }
                            let offset = event_counts.claim_offset(&instr);
                            bb.instrs.push(AnalyzedInstruction::new(instr, offset))
                        }
                        #[cfg(not(feature = "debug"))]
                        Err(
                            CompileOneErr::CycleTrackerEnter(_) | CompileOneErr::CycleTrackerExit,
                        ) => (),
                        #[cfg(feature = "debug")]
                        Err(CompileOneErr::CycleTrackerEnter(name)) => {
                            cycle_tracker.enter(name);
                        }
                        #[cfg(feature = "debug")]
                        Err(CompileOneErr::CycleTrackerExit) => {
                            cycle_tracker.exit().unwrap();
                        }
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

    /// Backfills the multiplicities of all instructions, and relocates `Mem` event offsets
    /// after the interned constants (see [`Self::compile_raw_program`]).
    fn backfill_all<'a>(
        &mut self,
        instrs: impl Iterator<Item = &'a mut AnalyzedInstruction<SP1Field>>,
        num_consts: usize,
    ) {
        let mut backfill = |(mult, addr): (&mut SP1Field, &Address<SP1Field>)| {
            *mult = self.addr_to_mult.remove(addr.as_usize()).unwrap()
        };

        for analyzed_instr in instrs {
            if matches!(analyzed_instr.inner(), Instruction::Mem(_)) {
                analyzed_instr.shift_offset(num_consts);
            }
            let asm_instr = analyzed_instr.inner_mut();
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
                Instruction::ExtFelt(ExtFeltInstr { addrs, mults, ext2felt }) => {
                    if *ext2felt {
                        backfill((&mut mults[1], &addrs[1]));
                        backfill((&mut mults[2], &addrs[2]));
                        backfill((&mut mults[3], &addrs[3]));
                        backfill((&mut mults[4], &addrs[4]));
                    } else {
                        backfill((&mut mults[0], &addrs[0]));
                    }
                }
                Instruction::Poseidon2(instr) => {
                    let Poseidon2Instr { addrs: Poseidon2Io { output: ref addrs, .. }, mults } =
                        instr.as_mut();
                    mults.iter_mut().zip(addrs).for_each(&mut backfill);
                }
                Instruction::Poseidon2LinearLayer(instr) => {
                    let Poseidon2LinearLayerInstr {
                        addrs: Poseidon2LinearLayerIo { output: ref addrs, .. },
                        mults,
                        ..
                    } = instr.as_mut();
                    mults.iter_mut().zip(addrs).for_each(&mut backfill);
                }
                Instruction::Poseidon2SBox(Poseidon2SBoxInstr {
                    addrs: Poseidon2SBoxIo { output: ref addr, .. },
                    mults,
                    ..
                }) => {
                    backfill((mults, addr));
                }
                Instruction::Select(SelectInstr {
                    addrs: SelectIo { out1: ref addr1, out2: ref addr2, .. },
                    mult1,
                    mult2,
                }) => {
                    backfill((mult1, addr1));
                    backfill((mult2, addr2));
                }
                Instruction::HintBits(HintBitsInstr { output_addrs_mults, .. })
                | Instruction::Hint(HintInstr { output_addrs_mults, .. }) => {
                    output_addrs_mults.iter_mut().for_each(|(addr, mult)| backfill((mult, addr)));
                }
                Instruction::PrefixSumChecks(instr) => {
                    let PrefixSumChecksInstr {
                        addrs: PrefixSumChecksIo { accs, field_accs, .. },
                        acc_mults,
                        field_acc_mults,
                    } = instr.as_mut();
                    acc_mults.iter_mut().zip(accs).for_each(|(mult, addr)| backfill((mult, addr)));
                    field_acc_mults
                        .iter_mut()
                        .zip(field_accs)
                        .for_each(|(mult, addr)| backfill((mult, addr)));
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
                Instruction::Mem(MemInstr { kind: MemAccessKind::Read, .. })
                | Instruction::CommitPublicValues(_)
                | Instruction::Print(_)
                | Instruction::DebugBacktrace(_) => (),
            }
        }

        debug_assert!(self.addr_to_mult.is_empty());
    }

    /// Compile a `DslIrProgram` that is definitionally assumed to be well-formed.
    ///
    /// Returns a well-formed program.
    pub fn compile<C: Config<N = SP1Field>>(
        &mut self,
        program: DslIrProgram<C>,
    ) -> RecursionProgram<SP1Field> {
        let inner = self.compile_inner(program.into_inner());
        // SAFETY: The compiler produces well-formed programs given a well-formed DSL input.
        // This is also a cryptographic requirement.
        unsafe { RecursionProgram::new_unchecked(inner) }
    }

    /// Compile a root `DslIrBlock` that has not necessarily been validated.
    ///
    /// Returns a program that may be ill-formed.
    pub fn compile_inner<C: Config<N = SP1Field>>(
        &mut self,
        root_block: DslIrBlock<C>,
    ) -> RootProgram<SP1Field> {
        let mut event_counts = RecursionAirEventCount::default();
        let mut program = tracing::debug_span!("compile raw program").in_scope(|| {
            // Prefix an empty basic block in the argument to `compile_raw_program`.
            // Later, we will fill it with constants.
            // When the debug feature is enabled, perform cycle tracking.
            cfg_if! {
                if #[cfg(feature = "debug")] {
                    let mut cycle_tracker = SpanBuilder::new(Cow::Borrowed("cycle_tracker"));
                    let program = self.compile_raw_program(
                        root_block,
                        vec![SeqBlock::Basic(BasicBlock::default())],
                        &mut event_counts,
                        &mut cycle_tracker,
                    );
                    let cycle_tracker_root_span = cycle_tracker.finish().unwrap();
                    for line in cycle_tracker_root_span.lines() {
                        tracing::info!("{}", line);
                    }
                    program
                } else {
                    self.compile_raw_program(
                        root_block,
                        vec![SeqBlock::Basic(BasicBlock::default())],
                        &mut event_counts,
                    )
                }
            }
        });
        let total_memory = self.addr_to_mult.len() + self.consts.len();
        let num_consts = self.consts.len();
        tracing::debug_span!("backfill mult")
            .in_scope(|| self.backfill_all(program.iter_mut(), num_consts));

        // Put in the constants. They occupy the first `Mem` event offsets, ahead of the
        // program body's `Mem` instructions, whose offsets were shifted in `backfill_all`.
        tracing::debug_span!("prepend constants").in_scope(|| {
            let Some(SeqBlock::Basic(BasicBlock { instrs: instrs_consts })) =
                program.seq_blocks.first_mut()
            else {
                unreachable!()
            };
            instrs_consts.extend(self.consts.drain().sorted_by_key(|x| x.1 .0 .0).enumerate().map(
                |(offset, (imm, (addr, mult)))| {
                    AnalyzedInstruction::new(
                        Instruction::Mem(MemInstr {
                            addrs: MemIo { inner: addr },
                            vals: MemIo { inner: imm.as_block() },
                            mult,
                            kind: MemAccessKind::Write,
                        }),
                        offset,
                    )
                },
            ));
            event_counts.mem_const_events += num_consts;
        });

        RootProgram { inner: program, total_memory, shape: None, event_counts }
    }
}

/// Used for cycle tracking.
#[cfg(feature = "debug")]
const fn instr_name<F>(instr: &Instruction<F>) -> &'static str {
    match instr {
        Instruction::BaseAlu(_) => "BaseAlu",
        Instruction::ExtAlu(_) => "ExtAlu",
        Instruction::Mem(_) => "Mem",
        Instruction::ExtFelt(_) => "ExtFelt",
        Instruction::Poseidon2(_) => "Poseidon2",
        Instruction::Poseidon2LinearLayer(_) => "Poseidon2LinearLayer",
        Instruction::Poseidon2SBox(_) => "Poseidon2SBox",
        Instruction::Select(_) => "Select",
        Instruction::HintBits(_) => "HintBits",
        Instruction::PrefixSumChecks(_) => "PrefixSumChecks",
        Instruction::Print(_) => "Print",
        Instruction::HintExt2Felts(_) => "HintExt2Felts",
        Instruction::Hint(_) => "Hint",
        Instruction::HintAddCurve(_) => "HintAddCurve",
        Instruction::CommitPublicValues(_) => "CommitPublicValues",
        Instruction::DebugBacktrace(_) => "DebugBacktrace",
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
trait Reg {
    /// Mark the register as to be read from, returning the "physical" address.
    fn read(&self, compiler: &mut AsmCompiler) -> Address<SP1Field>;

    /// Get the "physical" address of the register, assigning a new address if necessary.
    fn read_ghost(&self, compiler: &mut AsmCompiler) -> Address<SP1Field>;

    /// Mark the register as to be written to, returning the "physical" address.
    fn write(&self, compiler: &mut AsmCompiler) -> Address<SP1Field>;

    fn write_many(&self, compiler: &mut AsmCompiler, len: usize) -> Vec<Address<SP1Field>>;
}

macro_rules! impl_reg_vaddr {
    ($a:ty) => {
        impl Reg for $a {
            fn read(&self, compiler: &mut AsmCompiler) -> Address<SP1Field> {
                compiler.read_vaddr(self.idx as usize)
            }
            fn read_ghost(&self, compiler: &mut AsmCompiler) -> Address<SP1Field> {
                compiler.read_ghost_vaddr(self.idx as usize)
            }
            fn write(&self, compiler: &mut AsmCompiler) -> Address<SP1Field> {
                compiler.write_fp(self.idx as usize)
            }

            fn write_many(&self, compiler: &mut AsmCompiler, len: usize) -> Vec<Address<SP1Field>> {
                (0..len).map(|i| compiler.write_fp((self.idx + i as u32) as usize)).collect()
            }
        }
    };
}

// These three types wrap a `u32` but they don't share a trait.
impl_reg_vaddr!(Var<SP1Field>);
impl_reg_vaddr!(Felt<SP1Field>);
impl_reg_vaddr!(Ext<SP1Field, SP1ExtensionField>);

impl Reg for Imm<SP1Field, SP1ExtensionField> {
    fn read(&self, compiler: &mut AsmCompiler) -> Address<SP1Field> {
        compiler.read_const(*self)
    }

    fn read_ghost(&self, compiler: &mut AsmCompiler) -> Address<SP1Field> {
        compiler.read_ghost_const(*self)
    }

    fn write(&self, _compiler: &mut AsmCompiler) -> Address<SP1Field> {
        panic!("cannot write to immediate in register: {self:?}")
    }

    fn write_many(&self, _compiler: &mut AsmCompiler, _len: usize) -> Vec<Address<SP1Field>> {
        panic!("cannot write to immediate in register: {self:?}")
    }
}

impl Reg for Address<SP1Field> {
    fn read(&self, compiler: &mut AsmCompiler) -> Address<SP1Field> {
        compiler.read_addr(*self);
        *self
    }

    fn read_ghost(&self, compiler: &mut AsmCompiler) -> Address<SP1Field> {
        compiler.read_ghost_addr(*self);
        *self
    }

    fn write(&self, compiler: &mut AsmCompiler) -> Address<SP1Field> {
        compiler.write_addr(*self);
        *self
    }

    fn write_many(&self, _compiler: &mut AsmCompiler, _len: usize) -> Vec<Address<SP1Field>> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use std::{collections::VecDeque, io::BufRead, iter::zip, sync::Arc};

    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_algebra::extension::BinomialExtensionField;
    use slop_symmetric::Permutation;
    use sp1_hypercube::inner_perm;
    use sp1_primitives::{SP1DiffusionMatrix, SP1Field};

    // use sp1_core_machine::utils::{run_test_machine};
    use slop_algebra::PrimeField32;
    use sp1_core_machine::utils::setup_logger;
    use sp1_recursion_executor::Executor;

    use crate::circuit::{AsmBuilder, AsmConfig, CircuitV2Builder};

    use super::*;

    type F = SP1Field;
    type EF = BinomialExtensionField<SP1Field, 4>;
    fn test_block(block: DslIrBlock<AsmConfig>) {
        test_block_with_runner(block, |program| {
            let mut executor = Executor::<F, EF, SP1DiffusionMatrix>::new(program, inner_perm());
            executor.run().unwrap();
            executor.record
        });
    }

    fn test_block_with_runner(
        block: DslIrBlock<AsmConfig>,
        run: impl FnOnce(Arc<RecursionProgram<F>>) -> ExecutionRecord<F>,
    ) {
        let mut compiler = super::AsmCompiler::default();
        let program = Arc::new(compiler.compile_inner(block).validate().unwrap());
        let _ = run(program.clone());

        // Run with the poseidon2 wide chip.
        // let wide_machine =
        //     RecursionAir::<_, 3>::machine_wide_with_all_chips(SP1InnerPcs::default());
        // let (pk, vk) = wide_machine.setup(&program);
        // let result = run_test_machine(vec![record.clone()], wide_machine, pk, vk);
        // if let Err(e) = result {
        //     panic!("Verification failed: {:?}", e);
        // }

        // Run with the poseidon2 skinny chip.
        // let skinny_machine = RecursionAir::<_, 9>::machine_skinny_with_all_chips(
        //     SP1InnerPcs::ultra_compressed(),
        // );
        // let (pk, vk) = skinny_machine.setup(&program);
        // let result = run_test_machine(vec![record.clone()], skinny_machine, pk, vk);
        // if let Err(e) = result {
        //     panic!("Verification failed: {:?}", e);
        // }
    }

    #[test]
    fn test_poseidon2() {
        setup_logger();

        let mut builder = AsmBuilder::default();
        let mut rng = StdRng::seed_from_u64(0xCAFEDA7E)
            .sample_iter::<[F; PERMUTATION_WIDTH], _>(rand::distributions::Standard);
        for _ in 0..100 {
            let input_1: [F; PERMUTATION_WIDTH] = rng.next().unwrap();
            let output_1 = inner_perm().permute(input_1);

            let input_1_felts = input_1.map(|x| builder.eval(x));
            let output_1_felts = builder.poseidon2_permute_v2(input_1_felts);
            let expected: [Felt<_>; PERMUTATION_WIDTH] = output_1.map(|x| builder.eval(x));
            for (lhs, rhs) in output_1_felts.into_iter().zip(expected) {
                builder.assert_felt_eq(lhs, rhs);
            }
        }

        test_block(builder.into_root_block());
    }

    #[test]
    fn test_hint_bit_decomposition() {
        setup_logger();

        let mut builder = AsmBuilder::default();
        let mut rng =
            StdRng::seed_from_u64(0xC0FFEE7AB1E).sample_iter::<F, _>(rand::distributions::Standard);
        for _ in 0..100 {
            let input_f = rng.next().unwrap();
            let input = input_f.as_canonical_u32();
            let output = (0..NUM_BITS).map(|i| (input >> i) & 1).collect::<Vec<_>>();

            let input_felt: Felt<_> = builder.eval(input_f);
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
    #[allow(clippy::uninlined_format_args)]
    fn test_print_and_cycle_tracker() {
        const ITERS: usize = 5;

        setup_logger();

        let mut builder = AsmBuilder::default();

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
            let mut executor = Executor::<F, EF, SP1DiffusionMatrix>::new(program, inner_perm());
            executor.debug_stdout = Box::new(&mut buf);
            executor.run().unwrap();
            executor.record
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

        let mut builder = AsmBuilder::default();
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
                let mut builder = AsmBuilder::default();
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
