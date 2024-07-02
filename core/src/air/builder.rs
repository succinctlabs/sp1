use std::array;
use std::iter::once;

use itertools::Itertools;
use p3_air::{AirBuilder, FilteredAirBuilder};
use p3_air::{AirBuilderWithPublicValues, PermutationAirBuilder};
use p3_field::{AbstractField, Field};
use p3_uni_stark::StarkGenericConfig;
use p3_uni_stark::{ProverConstraintFolder, SymbolicAirBuilder, VerifierConstraintFolder};

use super::interaction::AirInteraction;
use super::word::Word;
use super::{BinomialExtension, WORD_SIZE};
use crate::cpu::columns::InstructionCols;
use crate::cpu::columns::OpcodeSelectorCols;
use crate::lookup::InteractionKind;
use crate::memory::MemoryAccessCols;
use crate::{bytes::ByteOpcode, memory::MemoryCols};

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
    fn assert_all_eq<I1: Into<Self::Expr>, I2: Into<Self::Expr>>(
        &mut self,
        left: impl IntoIterator<Item = I1>,
        right: impl IntoIterator<Item = I2>,
    ) {
        for (left, right) in left.into_iter().zip_eq(right) {
            self.assert_eq(left, right);
        }
    }

    /// Asserts that an iterator of expressions are all zero.
    fn assert_all_zero<I: Into<Self::Expr>>(&mut self, iter: impl IntoIterator<Item = I>) {
        iter.into_iter().for_each(|expr| self.assert_zero(expr));
    }

    /// Will return `a` if `condition` is 1, else `b`.  This assumes that `condition` is already
    /// checked to be a boolean.
    #[inline]
    fn if_else(
        &mut self,
        condition: impl Into<Self::Expr> + Clone,
        a: impl Into<Self::Expr> + Clone,
        b: impl Into<Self::Expr> + Clone,
    ) -> Self::Expr {
        condition.clone().into() * a.into() + (Self::Expr::one() - condition.into()) * b.into()
    }

    /// Index an array of expressions using an index bitmap.  This function assumes that the EIndex
    /// type is a boolean and that index_bitmap's entries sum to 1.
    fn index_array(
        &mut self,
        array: &[impl Into<Self::Expr> + Clone],
        index_bitmap: &[impl Into<Self::Expr> + Clone],
    ) -> Self::Expr {
        let mut result = Self::Expr::zero();

        for (value, i) in array.iter().zip_eq(index_bitmap) {
            result += value.clone().into() * i.clone().into();
        }

        result
    }
}

/// A trait which contains methods for byte interactions in an AIR.
pub trait ByteAirBuilder: BaseAirBuilder {
    /// Sends a byte operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn send_byte(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        shard: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.send_byte_pair(
            opcode,
            a,
            Self::Expr::zero(),
            b,
            c,
            shard,
            channel,
            multiplicity,
        )
    }

    /// Sends a byte operation with two outputs to be processed.
    #[allow(clippy::too_many_arguments)]
    fn send_byte_pair(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a1: impl Into<Self::Expr>,
        a2: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        shard: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.send(AirInteraction::new(
            vec![
                opcode.into(),
                a1.into(),
                a2.into(),
                b.into(),
                c.into(),
                shard.into(),
                channel.into(),
            ],
            multiplicity.into(),
            InteractionKind::Byte,
        ));
    }

    /// Receives a byte operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn receive_byte(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        shard: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.receive_byte_pair(
            opcode,
            a,
            Self::Expr::zero(),
            b,
            c,
            shard,
            channel,
            multiplicity,
        )
    }

    /// Receives a byte operation with two outputs to be processed.
    #[allow(clippy::too_many_arguments)]
    fn receive_byte_pair(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a1: impl Into<Self::Expr>,
        a2: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        shard: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.receive(AirInteraction::new(
            vec![
                opcode.into(),
                a1.into(),
                a2.into(),
                b.into(),
                c.into(),
                shard.into(),
                channel.into(),
            ],
            multiplicity.into(),
            InteractionKind::Byte,
        ));
    }
}

/// A trait which contains methods related to words in an AIR.
pub trait WordAirBuilder: ByteAirBuilder {
    /// Asserts that the two words are equal.
    fn assert_word_eq(
        &mut self,
        left: Word<impl Into<Self::Expr>>,
        right: Word<impl Into<Self::Expr>>,
    ) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }

    /// Asserts that the word is zero.
    fn assert_word_zero(&mut self, word: Word<impl Into<Self::Expr>>) {
        for limb in word.0 {
            self.assert_zero(limb);
        }
    }

    /// Index an array of words using an index bitmap.
    fn index_word_array(
        &mut self,
        array: &[Word<impl Into<Self::Expr> + Clone>],
        index_bitmap: &[impl Into<Self::Expr> + Clone],
    ) -> Word<Self::Expr> {
        let mut result = Word::default();
        for i in 0..WORD_SIZE {
            result[i] = self.index_array(
                array
                    .iter()
                    .map(|word| word[i].clone())
                    .collect_vec()
                    .as_slice(),
                index_bitmap,
            );
        }
        result
    }

    /// Same as `if_else` above, but arguments are `Word` instead of individual expressions.
    fn select_word(
        &mut self,
        condition: impl Into<Self::Expr> + Clone,
        a: Word<impl Into<Self::Expr> + Clone>,
        b: Word<impl Into<Self::Expr> + Clone>,
    ) -> Word<Self::Expr> {
        Word(array::from_fn(|i| {
            self.if_else(condition.clone(), a[i].clone(), b[i].clone())
        }))
    }

    /// Check that each limb of the given slice is a u8.
    fn slice_range_check_u8(
        &mut self,
        input: &[impl Into<Self::Expr> + Clone],
        shard: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        mult: impl Into<Self::Expr> + Clone,
    ) {
        let mut index = 0;
        while index + 1 < input.len() {
            self.send_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                Self::Expr::zero(),
                input[index].clone(),
                input[index + 1].clone(),
                shard.clone(),
                channel.clone(),
                mult.clone(),
            );
            index += 2;
        }
        if index < input.len() {
            self.send_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                Self::Expr::zero(),
                input[index].clone(),
                Self::Expr::zero(),
                shard.clone(),
                channel.clone(),
                mult.clone(),
            );
        }
    }

    /// Check that each limb of the given slice is a u16.
    fn slice_range_check_u16(
        &mut self,
        input: &[impl Into<Self::Expr> + Copy],
        shard: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        mult: impl Into<Self::Expr> + Clone,
    ) {
        input.iter().for_each(|limb| {
            self.send_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
                *limb,
                Self::Expr::zero(),
                Self::Expr::zero(),
                shard.clone(),
                channel.clone(),
                mult.clone(),
            );
        });
    }
}

/// A trait which contains methods related to ALU interactions in an AIR.
pub trait AluAirBuilder: BaseAirBuilder {
    /// Sends an ALU operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn send_alu(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: Word<impl Into<Self::Expr>>,
        b: Word<impl Into<Self::Expr>>,
        c: Word<impl Into<Self::Expr>>,
        shard: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        nonce: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(opcode.into())
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .chain(once(shard.into()))
            .chain(once(channel.into()))
            .chain(once(nonce.into()))
            .collect();

        self.send(AirInteraction::new(
            values,
            multiplicity.into(),
            InteractionKind::Alu,
        ));
    }

    /// Receives an ALU operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn receive_alu(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: Word<impl Into<Self::Expr>>,
        b: Word<impl Into<Self::Expr>>,
        c: Word<impl Into<Self::Expr>>,
        shard: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        nonce: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(opcode.into())
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .chain(once(shard.into()))
            .chain(once(channel.into()))
            .chain(once(nonce.into()))
            .collect();

        self.receive(AirInteraction::new(
            values,
            multiplicity.into(),
            InteractionKind::Alu,
        ));
    }

    /// Sends an syscall operation to be processed (with "ECALL" opcode).
    #[allow(clippy::too_many_arguments)]
    fn send_syscall(
        &mut self,
        shard: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        clk: impl Into<Self::Expr> + Clone,
        nonce: impl Into<Self::Expr> + Clone,
        syscall_id: impl Into<Self::Expr> + Clone,
        arg1: impl Into<Self::Expr> + Clone,
        arg2: impl Into<Self::Expr> + Clone,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.send(AirInteraction::new(
            vec![
                shard.clone().into(),
                channel.clone().into(),
                clk.clone().into(),
                nonce.clone().into(),
                syscall_id.clone().into(),
                arg1.clone().into(),
                arg2.clone().into(),
            ],
            multiplicity.into(),
            InteractionKind::Syscall,
        ));
    }

    /// Receives a syscall operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn receive_syscall(
        &mut self,
        shard: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        clk: impl Into<Self::Expr> + Clone,
        nonce: impl Into<Self::Expr> + Clone,
        syscall_id: impl Into<Self::Expr> + Clone,
        arg1: impl Into<Self::Expr> + Clone,
        arg2: impl Into<Self::Expr> + Clone,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.receive(AirInteraction::new(
            vec![
                shard.clone().into(),
                channel.clone().into(),
                clk.clone().into(),
                nonce.clone().into(),
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
    /// Constrain a memory read or write.
    ///
    /// This method verifies that a memory access timestamp (shard, clk) is greater than the
    /// previous access's timestamp.  It will also add to the memory argument.
    fn eval_memory_access<E: Into<Self::Expr> + Clone>(
        &mut self,
        shard: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        clk: impl Into<Self::Expr>,
        addr: impl Into<Self::Expr>,
        memory_access: &impl MemoryCols<E>,
        do_check: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        let shard: Self::Expr = shard.into();
        let channel: Self::Expr = channel.into();
        let clk: Self::Expr = clk.into();
        let mem_access = memory_access.access();

        self.assert_bool(do_check.clone());

        // Verify that the current memory access time is greater than the previous's.
        self.eval_memory_access_timestamp(
            mem_access,
            do_check.clone(),
            shard.clone(),
            channel,
            clk.clone(),
        );

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

        // The previous values get sent with multiplicity = 1, for "read".
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

    /// Constraints a memory read or write to a slice of `MemoryAccessCols`.
    fn eval_memory_access_slice<E: Into<Self::Expr> + Copy>(
        &mut self,
        shard: impl Into<Self::Expr> + Copy,
        channel: impl Into<Self::Expr> + Clone,
        clk: impl Into<Self::Expr> + Clone,
        initial_addr: impl Into<Self::Expr> + Clone,
        memory_access_slice: &[impl MemoryCols<E>],
        verify_memory_access: impl Into<Self::Expr> + Copy,
    ) {
        for (i, access_slice) in memory_access_slice.iter().enumerate() {
            self.eval_memory_access(
                shard,
                channel.clone(),
                clk.clone(),
                initial_addr.clone().into() + Self::Expr::from_canonical_usize(i * 4),
                access_slice,
                verify_memory_access,
            );
        }
    }

    /// Verifies the memory access timestamp.
    ///
    /// This method verifies that the current memory access happened after the previous one's.
    /// Specifically it will ensure that if the current and previous access are in the same shard,
    /// then the current's clk val is greater than the previous's.  If they are not in the same
    /// shard, then it will ensure that the current's shard val is greater than the previous's.
    fn eval_memory_access_timestamp(
        &mut self,
        mem_access: &MemoryAccessCols<impl Into<Self::Expr> + Clone>,
        do_check: impl Into<Self::Expr>,
        shard: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        clk: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        let compare_clk: Self::Expr = mem_access.compare_clk.clone().into();
        let shard: Self::Expr = shard.clone().into();
        let prev_shard: Self::Expr = mem_access.prev_shard.clone().into();

        // First verify that compare_clk's value is correct.
        self.when(do_check.clone()).assert_bool(compare_clk.clone());
        self.when(do_check.clone())
            .when(compare_clk.clone())
            .assert_eq(shard.clone(), prev_shard);

        // Get the comparison timestamp values for the current and previous memory access.
        let prev_comp_value = self.if_else(
            mem_access.compare_clk.clone(),
            mem_access.prev_clk.clone(),
            mem_access.prev_shard.clone(),
        );

        let current_comp_val = self.if_else(compare_clk.clone(), clk.into(), shard.clone());

        // Assert `current_comp_val > prev_comp_val`. We check this by asserting that
        // `0 <= current_comp_val-prev_comp_val-1 < 2^24`.
        //
        // The equivalence of these statements comes from the fact that if
        // `current_comp_val <= prev_comp_val`, then `current_comp_val-prev_comp_val-1 < 0` and will
        // underflow in the prime field, resulting in a value that is `>= 2^24` as long as both
        // `current_comp_val, prev_comp_val` are range-checked to be `<2^24` and as long as we're
        // working in a field larger than `2 * 2^24` (which is true of the BabyBear and Mersenne31
        // prime).
        let diff_minus_one = current_comp_val - prev_comp_value - Self::Expr::one();

        // Verify that mem_access.ts_diff = mem_access.ts_diff_16bit_limb
        // + mem_access.ts_diff_8bit_limb * 2^16.
        self.eval_range_check_24bits(
            diff_minus_one,
            mem_access.diff_16bit_limb.clone(),
            mem_access.diff_8bit_limb.clone(),
            shard.clone(),
            channel.clone(),
            do_check,
        );
    }

    /// Verifies the inputted value is within 24 bits.
    ///
    /// This method verifies that the inputted is less than 2^24 by doing a 16 bit and 8 bit range
    /// check on it's limbs.  It will also verify that the limbs are correct.  This method is needed
    /// since the memory access timestamp check (see [Self::verify_mem_access_ts]) needs to assume
    /// the clk is within 24 bits.
    fn eval_range_check_24bits(
        &mut self,
        value: impl Into<Self::Expr>,
        limb_16: impl Into<Self::Expr> + Clone,
        limb_8: impl Into<Self::Expr> + Clone,
        shard: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        do_check: impl Into<Self::Expr> + Clone,
    ) {
        // Verify that value = limb_16 + limb_8 * 2^16.
        self.when(do_check.clone()).assert_eq(
            value,
            limb_16.clone().into()
                + limb_8.clone().into() * Self::Expr::from_canonical_u32(1 << 16),
        );

        // Send the range checks for the limbs.
        self.send_byte(
            Self::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            limb_16,
            Self::Expr::zero(),
            Self::Expr::zero(),
            shard.clone(),
            channel.clone(),
            do_check.clone(),
        );

        self.send_byte(
            Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
            Self::Expr::zero(),
            Self::Expr::zero(),
            limb_8,
            shard.clone(),
            channel.clone(),
            do_check,
        )
    }
}

/// A trait which contains methods related to program interactions in an AIR.
pub trait ProgramAirBuilder: BaseAirBuilder {
    /// Sends an instruction.
    fn send_program(
        &mut self,
        pc: impl Into<Self::Expr>,
        instruction: InstructionCols<impl Into<Self::Expr> + Copy>,
        selectors: OpcodeSelectorCols<impl Into<Self::Expr> + Copy>,
        shard: impl Into<Self::Expr> + Copy,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(pc.into())
            .chain(once(instruction.opcode.into()))
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(selectors.into_iter().map(|x| x.into()))
            .chain(once(shard.into()))
            .collect();

        self.send(AirInteraction::new(
            values,
            multiplicity.into(),
            InteractionKind::Program,
        ));
    }

    /// Receives an instruction.
    fn receive_program(
        &mut self,
        pc: impl Into<Self::Expr>,
        instruction: InstructionCols<impl Into<Self::Expr> + Copy>,
        selectors: OpcodeSelectorCols<impl Into<Self::Expr> + Copy>,
        shard: impl Into<Self::Expr> + Copy,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values: Vec<<Self as AirBuilder>::Expr> = once(pc.into())
            .chain(once(instruction.opcode.into()))
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(selectors.into_iter().map(|x| x.into()))
            .chain(once(shard.into()))
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

    /// Checks if an extension element is a base element.
    fn assert_is_base_element<I: Into<Self::Expr> + Clone>(
        &mut self,
        element: BinomialExtension<I>,
    ) {
        let base_slice = element.as_base_slice();
        let degree = base_slice.len();
        base_slice[1..degree].iter().for_each(|coeff| {
            self.assert_zero(coeff.clone().into());
        });
    }

    /// Performs an if else on extension elements.
    fn if_else_ext(
        &mut self,
        condition: impl Into<Self::Expr> + Clone,
        a: BinomialExtension<impl Into<Self::Expr> + Clone>,
        b: BinomialExtension<impl Into<Self::Expr> + Clone>,
    ) -> BinomialExtension<Self::Expr> {
        BinomialExtension(array::from_fn(|i| {
            self.if_else(condition.clone(), a.0[i].clone(), b.0[i].clone())
        }))
    }
}

pub trait MultiTableAirBuilder: PermutationAirBuilder {
    type Sum: Into<Self::ExprEF>;

    fn cumulative_sum(&self) -> Self::Sum;
}

/// A trait that contains the common helper methods for building `SP1 recursion` and SP1 machine AIRs.
pub trait MachineAirBuilder:
    BaseAirBuilder + ExtensionAirBuilder + AirBuilderWithPublicValues
{
}

/// A trait which contains all helper methods for building SP1 machine AIRs.
pub trait SP1AirBuilder:
    MachineAirBuilder
    + ByteAirBuilder
    + WordAirBuilder
    + AluAirBuilder
    + MemoryAirBuilder
    + ProgramAirBuilder
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
impl<AB: BaseAirBuilder> ByteAirBuilder for AB {}
impl<AB: BaseAirBuilder> WordAirBuilder for AB {}
impl<AB: BaseAirBuilder> AluAirBuilder for AB {}
impl<AB: BaseAirBuilder> MemoryAirBuilder for AB {}
impl<AB: BaseAirBuilder> ProgramAirBuilder for AB {}
impl<AB: BaseAirBuilder> ExtensionAirBuilder for AB {}
impl<AB: BaseAirBuilder + AirBuilderWithPublicValues> MachineAirBuilder for AB {}
impl<AB: BaseAirBuilder + AirBuilderWithPublicValues> SP1AirBuilder for AB {}

impl<'a, SC: StarkGenericConfig> EmptyMessageBuilder for ProverConstraintFolder<'a, SC> {}
impl<'a, SC: StarkGenericConfig> EmptyMessageBuilder for VerifierConstraintFolder<'a, SC> {}
impl<F: Field> EmptyMessageBuilder for SymbolicAirBuilder<F> {}

#[cfg(debug_assertions)]
#[cfg(not(doctest))]
impl<'a, F: Field> EmptyMessageBuilder for p3_uni_stark::DebugConstraintBuilder<'a, F> {}
