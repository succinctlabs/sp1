use p3_air::PermutationAirBuilder;
use p3_air::{AirBuilder, FilteredAirBuilder};
use p3_uni_stark::{ProverConstraintFolder, SymbolicAirBuilder, VerifierConstraintFolder};

use super::interaction::AirInteraction;
use super::word::Word;
use super::BinomialExtension;
use crate::cpu::columns::InstructionCols;
use crate::cpu::columns::OpcodeSelectorCols;
use crate::lookup::InteractionKind;
use crate::memory::MemoryAccessCols;
use crate::{bytes::ByteOpcode, memory::MemoryCols};
use p3_field::{AbstractField, Field};

use p3_uni_stark::StarkGenericConfig;
use std::iter::once;

/// A Builder with the ability to encode the existance of interactions with other AIRs by sending
/// and receiving messages.
pub trait MessageBuilder<M> {
    fn send(&mut self, message: M);

    fn receive(&mut self, message: M);
}

impl<AB: EmptyMessageBuilder, M> MessageBuilder<M> for AB {
    fn send(&mut self, _message: M) {}

    fn receive(&mut self, _message: M) {}
}

/// A message builder for which sending and receiving messages is a no-op.
pub trait EmptyMessageBuilder: AirBuilder {}

/// A trait which contains basic methods for building an AIR.
pub trait BaseAirBuilder: AirBuilder + MessageBuilder<AirInteraction<Self::Expr>> {
    /// Returns a sub-builder whose constraints are enforced only when `condition` is not one.
    fn when_not<I: Into<Self::Expr>>(&mut self, condition: I) -> FilteredAirBuilder<Self> {
        self.when_ne(condition, Self::F::one())
    }

    /// Asserts that an iterator of expressions are all equal.
    fn assert_all_eq<
        I1: Into<Self::Expr>,
        I2: Into<Self::Expr>,
        I1I: IntoIterator<Item = I1> + Copy,
        I2I: IntoIterator<Item = I2> + Copy,
    >(
        &mut self,
        left: I1I,
        right: I2I,
    ) {
        debug_assert_eq!(left.into_iter().count(), right.into_iter().count());
        for (left, right) in left.into_iter().zip(right) {
            self.assert_eq(left, right);
        }
    }
}

/// A trait which contains methods for byte interactions in an AIR.
pub trait ByteAirBuilder: BaseAirBuilder {
    /// Sends a byte operation to be processed.
    fn send_byte<EOp, Ea, Eb, Ec, EMult>(
        &mut self,
        opcode: EOp,
        a: Ea,
        b: Eb,
        c: Ec,
        multiplicity: EMult,
    ) where
        EOp: Into<Self::Expr>,
        Ea: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        Ec: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        self.send_byte_pair(opcode, a, Self::Expr::zero(), b, c, multiplicity)
    }

    /// Sends a byte operation with two outputs to be processed.
    fn send_byte_pair<EOp, Ea1, Ea2, Eb, Ec, EMult>(
        &mut self,
        opcode: EOp,
        a1: Ea1,
        a2: Ea2,
        b: Eb,
        c: Ec,
        multiplicity: EMult,
    ) where
        EOp: Into<Self::Expr>,
        Ea1: Into<Self::Expr>,
        Ea2: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        Ec: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        self.send(AirInteraction::new(
            vec![opcode.into(), a1.into(), a2.into(), b.into(), c.into()],
            multiplicity.into(),
            InteractionKind::Byte,
        ));
    }

    /// Receives a byte operation to be processed.
    fn receive_byte<EOp, Ea, Eb, Ec, EMult>(
        &mut self,
        opcode: EOp,
        a: Ea,
        b: Eb,
        c: Ec,
        multiplicity: EMult,
    ) where
        EOp: Into<Self::Expr>,
        Ea: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        Ec: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        self.receive_byte_pair(opcode, a, Self::Expr::zero(), b, c, multiplicity)
    }

    /// Receives a byte operation with two outputs to be processed.
    fn receive_byte_pair<EOp, Ea1, Ea2, Eb, Ec, EMult>(
        &mut self,
        opcode: EOp,
        a1: Ea1,
        a2: Ea2,
        b: Eb,
        c: Ec,
        multiplicity: EMult,
    ) where
        EOp: Into<Self::Expr>,
        Ea1: Into<Self::Expr>,
        Ea2: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        Ec: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        self.receive(AirInteraction::new(
            vec![opcode.into(), a1.into(), a2.into(), b.into(), c.into()],
            multiplicity.into(),
            InteractionKind::Byte,
        ));
    }
}

/// A trait which contains methods related to words in an AIR.
pub trait WordAirBuilder: ByteAirBuilder {
    /// Asserts that the two words are equal.
    fn assert_word_eq<I: Into<Self::Expr>>(&mut self, left: Word<I>, right: Word<I>) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }

    /// Check that each limb of the given slice is a u8.
    fn slice_range_check_u8<EWord: Into<Self::Expr> + Copy, EMult: Into<Self::Expr> + Clone>(
        &mut self,
        input: &[EWord],
        mult: EMult,
    ) {
        let mut index = 0;
        while index + 1 < input.len() {
            self.send_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                Self::Expr::zero(),
                input[index],
                input[index + 1],
                mult.clone(),
            );
            index += 2;
        }
        if index < input.len() {
            self.send_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                Self::Expr::zero(),
                input[index],
                Self::Expr::zero(),
                mult.clone(),
            );
        }
    }

    /// Check that each limb of the given slice is a u16.
    fn slice_range_check_u16<EWord: Into<Self::Expr> + Copy, EMult: Into<Self::Expr> + Clone>(
        &mut self,
        input: &[EWord],
        mult: EMult,
    ) {
        input.iter().for_each(|limb| {
            self.send_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
                *limb,
                Self::Expr::zero(),
                Self::Expr::zero(),
                mult.clone(),
            );
        });
    }
}

/// A trait which contains methods related to ALU interactions in an AIR.
pub trait AluAirBuilder: BaseAirBuilder {
    /// Sends an ALU operation to be processed.
    fn send_alu<EOp, Ea, Eb, Ec, EMult>(
        &mut self,
        opcode: EOp,
        a: Word<Ea>,
        b: Word<Eb>,
        c: Word<Ec>,
        multiplicity: EMult,
    ) where
        EOp: Into<Self::Expr>,
        Ea: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        Ec: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        let values = once(opcode.into())
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .collect();

        self.send(AirInteraction::new(
            values,
            multiplicity.into(),
            InteractionKind::Alu,
        ));
    }

    /// Receives an ALU operation to be processed.
    fn receive_alu<EOp, Ea, Eb, Ec, EMult>(
        &mut self,
        opcode: EOp,
        a: Word<Ea>,
        b: Word<Eb>,
        c: Word<Ec>,
        multiplicity: EMult,
    ) where
        EOp: Into<Self::Expr>,
        Ea: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        Ec: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        let values = once(opcode.into())
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .collect();

        self.receive(AirInteraction::new(
            values,
            multiplicity.into(),
            InteractionKind::Alu,
        ));
    }

    /// Sends an syscall operation to be processed (with "ECALL" opcode).
    fn send_syscall<EShard, EClk, Ea, Eb, Ec, EMult>(
        &mut self,
        shard: EShard,
        clk: EClk,
        syscall_id: Ea,
        arg1: Eb,
        arg2: Ec,
        multiplicity: EMult,
    ) where
        EShard: Into<Self::Expr> + Clone,
        EClk: Into<Self::Expr> + Clone,
        Ea: Into<Self::Expr> + Clone,
        Eb: Into<Self::Expr> + Clone,
        Ec: Into<Self::Expr> + Clone,
        EMult: Into<Self::Expr>,
    {
        self.send(AirInteraction::new(
            vec![
                shard.clone().into(),
                clk.clone().into(),
                syscall_id.clone().into(),
                arg1.clone().into(),
                arg2.clone().into(),
            ],
            multiplicity.into(),
            InteractionKind::Syscall,
        ));
    }

    /// Receives a syscall operation to be processed.
    fn receive_syscall<EShard, EClk, Ea, Eb, Ec, EMult>(
        &mut self,
        shard: EShard,
        clk: EClk,
        syscall_id: Ea,
        arg1: Eb,
        arg2: Ec,
        multiplicity: EMult,
    ) where
        EShard: Into<Self::Expr> + Clone,
        EClk: Into<Self::Expr> + Clone,
        Ea: Into<Self::Expr> + Clone,
        Eb: Into<Self::Expr> + Clone,
        Ec: Into<Self::Expr> + Clone,
        EMult: Into<Self::Expr>,
    {
        self.receive(AirInteraction::new(
            vec![
                shard.clone().into(),
                clk.clone().into(),
                syscall_id.clone().into(),
                arg1.clone().into(),
                arg2.clone().into(),
            ],
            multiplicity.into(),
            InteractionKind::Syscall,
        ));
    }
}

/// A trait which contains methods related to memory interactions in an AIR.
pub trait MemoryAirBuilder: BaseAirBuilder {
    /// Constraints a memory read or write.
    ///
    /// This method verifies that a memory access ts is greater than the previous ts.  It will also
    /// add to the memory argument.
    fn constraint_memory_access<EClk, EShard, Ea, Eb, EVerify, M>(
        &mut self,
        shard: EShard,
        clk: EClk,
        addr: Ea,
        memory_access: &M,
        do_check: EVerify,
    ) where
        EShard: Into<Self::Expr>,
        EClk: Into<Self::Expr>,
        Ea: Into<Self::Expr>,
        Eb: Into<Self::Expr> + Clone,
        EVerify: Into<Self::Expr>,
        M: MemoryCols<Eb>,
    {
        let do_check: Self::Expr = do_check.into();
        let shard: Self::Expr = shard.into();
        let clk: Self::Expr = clk.into();

        self.assert_bool(do_check.clone());

        // Verify all the materialized memory access columns.
        let mem_access = memory_access.access();
        mem_access.verify_materialized_columns(self, clk.clone(), shard.clone(), do_check.clone());

        // Verify that the current memory access time is greater than the previous's.
        self.verify_mem_access_ts(mem_access, do_check.clone());

        // Add to the memory argument.
        let addr = addr.into();
        let prev_shard = mem_access.prev_shard.clone().into();
        let prev_clk = mem_access.prev_clk.clone().into();
        let prev_values = once(prev_shard)
            .chain(once(prev_clk))
            .chain(once(addr.clone()))
            .chain(memory_access.prev_value().clone().map(Into::into))
            .collect();
        let current_values = once(shard)
            .chain(once(clk))
            .chain(once(addr.clone()))
            .chain(memory_access.value().clone().map(Into::into))
            .collect();

        // The previous values get sent with multiplicity * 1, for "read".
        self.send(AirInteraction::new(
            prev_values,
            do_check.clone(),
            InteractionKind::Memory,
        ));

        // The current values get "received", i.e. multiplicity = -1
        self.receive(AirInteraction::new(
            current_values,
            do_check.clone(),
            InteractionKind::Memory,
        ));
    }

    /// Verifies the memory access timestamp.
    ///
    /// This method verifies that the diff between the current and previous memory access ts is
    /// valid.  Specifically it will ensure the following.
    /// If the previous memory access is within the same shard, then the current_mem_clk_ts -
    /// prev_mem_clk_ts is within [1, MAX_SHARD_SIZE - 1].
    /// If the previous memory access is in a different shard, then the current_mem_shard_ts -
    /// prev_mem_shard_ts is within [1, MAX_SHARD_SIZE - 1].
    fn verify_mem_access_ts<Eb, Everify>(
        &mut self,
        mem_access: &MemoryAccessCols<Eb>,
        do_check: Everify,
    ) where
        Eb: Into<Self::Expr> + Clone,
        Everify: Into<Self::Expr>,
    {
        // current_comp_val is the clk value at the current memory access if the previous memory access
        // is within the same shard.  Otherwise, it is the shard value at the current memory access.
        let current_comp_val: Self::Expr = mem_access.current_comp_val.clone().into();
        // prev_comp_val is the clk value at the previous memory access if the current memory access
        // is within the same shard.  Otherwise, it is the shard value at the previous memory access.
        let prev_comp_val: Self::Expr = mem_access.prev_comp_val.clone().into();
        let do_check: Self::Expr = do_check.into();

        // Assert `current_comp_val > prev_comp_val`. We check this by asserting that `0 <= current_comp_val-prev_comp_val-1 < 2^24`. The equivalence of these statements comes from the fact that if `current_comp_val <= prev_comp_val`, then `current_comp_val-prev_comp_val-1 < 0` and will underflow in the prime field, resulting in a value that is `>= 2^24` as long as both `current_comp_val, prev_comp_val` are range-checked to be `<2^24`, as long as we're working in a field larger than `2 * 2^24` (which is true of the BabyBear and Mersenne31 prime).
        //
        // We know that diff_minus_one will have the possible values of [-MAX_SHARD_SIZE, MAX_SHARD_SIZE - 2]
        // (in other words [BABYBEAR_P - 1 - MAX_SHARD_SIZE, BABYBEAR_P - 1] union [0, MAX_SHARD_SIZE - 2]),
        // since we do a range check for all clk values to be within [0, MAX_SHARD_SIZE - 1].
        // We want to ensure that diff_minus_one is within [0, MAX_SHARD_SIZE - 2], so we do a 24 bit
        // range check on it.
        let diff_minus_one = current_comp_val - prev_comp_val - Self::Expr::one();

        // Verify that mem_access.ts_diff = mem_access.ts_diff_16bit_limb + mem_access.ts_diff_8bit_limb * 2^16.
        self.when(do_check.clone()).assert_eq(
            diff_minus_one,
            mem_access.diff_16bit_limb.clone().into()
                + mem_access.diff_8bit_limb.clone().into()
                    * Self::Expr::from_canonical_u32(1 << 16),
        );

        // Send the range checks for the limbs.
        self.send_byte(
            Self::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            mem_access.diff_16bit_limb.clone(),
            Self::Expr::zero(),
            Self::Expr::zero(),
            do_check.clone(),
        );

        self.send_byte(
            Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
            Self::Expr::zero(),
            Self::Expr::zero(),
            mem_access.diff_8bit_limb.clone(),
            do_check,
        )
    }

    /// Constraints a memory read or write to a slice of `MemoryAccessCols`.
    fn constraint_memory_access_slice<EShard, Ea, Eb, EVerify, M>(
        &mut self,
        shard: EShard,
        clk: Self::Expr,
        initial_addr: Ea,
        memory_access_slice: &[M],
        verify_memory_access: EVerify,
    ) where
        EShard: Into<Self::Expr> + std::marker::Copy,
        Ea: Into<Self::Expr> + std::marker::Copy,
        Eb: Into<Self::Expr> + std::marker::Copy,
        EVerify: Into<Self::Expr> + std::marker::Copy,
        M: MemoryCols<Eb>,
    {
        for (i, access_slice) in memory_access_slice.iter().enumerate() {
            self.constraint_memory_access(
                shard,
                clk.clone(),
                initial_addr.into() + Self::Expr::from_canonical_usize(i * 4),
                access_slice,
                verify_memory_access,
            );
        }
    }
}

/// A trait which contains methods related to program interactions in an AIR.
pub trait ProgramAirBuilder: BaseAirBuilder {
    /// Sends an instruction.
    fn send_program<EPc, EInst, ESel, EMult>(
        &mut self,
        pc: EPc,
        instruction: InstructionCols<EInst>,
        selectors: OpcodeSelectorCols<ESel>,
        multiplicity: EMult,
    ) where
        EPc: Into<Self::Expr>,
        EInst: Into<Self::Expr> + Copy,
        ESel: Into<Self::Expr> + Copy,
        EMult: Into<Self::Expr>,
    {
        let values = once(pc.into())
            .chain(once(instruction.opcode.into()))
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(selectors.into_iter().map(|x| x.into()))
            .collect();

        self.send(AirInteraction::new(
            values,
            multiplicity.into(),
            InteractionKind::Program,
        ));
    }

    /// Receives an instruction.
    fn receive_program<EPc, EInst, ESel, EMult>(
        &mut self,
        pc: EPc,
        instruction: InstructionCols<EInst>,
        selectors: OpcodeSelectorCols<ESel>,
        multiplicity: EMult,
    ) where
        EPc: Into<Self::Expr>,
        EInst: Into<Self::Expr> + Copy,
        ESel: Into<Self::Expr> + Copy,
        EMult: Into<Self::Expr>,
    {
        let values: Vec<<Self as AirBuilder>::Expr> = once(pc.into())
            .chain(once(instruction.opcode.into()))
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(selectors.into_iter().map(|x| x.into()))
            .collect();

        self.receive(AirInteraction::new(
            values,
            multiplicity.into(),
            InteractionKind::Program,
        ));
    }
}

pub trait ExtensionAirBuilder: BaseAirBuilder {
    /// Asserts that the two field extensions are equal.
    fn assert_ext_eq<I: Into<Self::Expr>>(
        &mut self,
        left: BinomialExtension<I>,
        right: BinomialExtension<I>,
    ) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }
}

pub trait MultiTableAirBuilder: PermutationAirBuilder {
    type Sum: Into<Self::ExprEF>;

    fn cumulative_sum(&self) -> Self::Sum;
}

/// A trait which contains all helper methods for building an AIR.
pub trait SP1AirBuilder:
    BaseAirBuilder
    + ByteAirBuilder
    + WordAirBuilder
    + AluAirBuilder
    + MemoryAirBuilder
    + ProgramAirBuilder
    + ExtensionAirBuilder
{
}

impl<'a, AB: AirBuilder + MessageBuilder<M>, M> MessageBuilder<M> for FilteredAirBuilder<'a, AB> {
    fn send(&mut self, message: M) {
        self.inner.send(message);
    }

    fn receive(&mut self, message: M) {
        self.inner.receive(message);
    }
}

impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> BaseAirBuilder for AB {}
impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> ByteAirBuilder for AB {}
impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> WordAirBuilder for AB {}
impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> AluAirBuilder for AB {}
impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> MemoryAirBuilder for AB {}
impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> ProgramAirBuilder for AB {}
impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> ExtensionAirBuilder for AB {}
impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> SP1AirBuilder for AB {}

impl<'a, SC: StarkGenericConfig> EmptyMessageBuilder for ProverConstraintFolder<'a, SC> {}
impl<'a, SC: StarkGenericConfig> EmptyMessageBuilder for VerifierConstraintFolder<'a, SC> {}
impl<F: Field> EmptyMessageBuilder for SymbolicAirBuilder<F> {}

#[cfg(debug_assertions)]
impl<'a, F: Field> EmptyMessageBuilder for p3_uni_stark::DebugConstraintBuilder<'a, F> {}
