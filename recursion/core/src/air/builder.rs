use core::iter::{once, repeat};
use p3_air::{AirBuilder, AirBuilderWithPublicValues};
use p3_field::AbstractField;
use sp1_core::{
    air::{AirInteraction, BaseAirBuilder, MachineAirBuilder},
    lookup::InteractionKind,
};

use crate::memory::{MemoryAccessTimestampCols, MemoryCols};
use crate::range_check::RangeCheckOpcode;

use super::Block;
/// A trait which contains all helper methods for building SP1 recursion machine AIRs.
pub trait SP1RecursionAirBuilder:
    MachineAirBuilder + RecursionMemoryAirBuilder + RangeCheckAirBuilder
{
}

impl<AB: AirBuilderWithPublicValues + RecursionMemoryAirBuilder> SP1RecursionAirBuilder for AB {}
impl<AB: BaseAirBuilder + AirBuilderWithPublicValues> RecursionMemoryAirBuilder for AB {}
impl<AB: BaseAirBuilder + AirBuilderWithPublicValues> RangeCheckAirBuilder for AB {}

pub trait RecursionMemoryAirBuilder: RangeCheckAirBuilder {
    fn recursion_eval_memory_access<E: Into<Self::Expr> + Clone>(
        &mut self,
        timestamp: impl Into<Self::Expr>,
        addr: impl Into<Self::Expr>,
        memory_access: &impl MemoryCols<E, Block<E>>,
        is_real: impl Into<Self::Expr>,
    ) {
        let is_real: Self::Expr = is_real.into();
        let timestamp: Self::Expr = timestamp.into();
        let mem_access = memory_access.access();

        self.eval_memory_access_timestamp(timestamp.clone(), mem_access, is_real.clone());

        let addr = addr.into();
        let prev_timestamp = mem_access.prev_timestamp.clone().into();
        let prev_values = once(prev_timestamp)
            .chain(once(addr.clone()))
            .chain(memory_access.prev_value().clone().map(Into::into))
            .collect();
        let current_values = once(timestamp)
            .chain(once(addr.clone()))
            .chain(memory_access.value().clone().map(Into::into))
            .collect();

        self.receive(AirInteraction::new(
            prev_values,
            is_real.clone(),
            InteractionKind::Memory,
        ));
        self.send(AirInteraction::new(
            current_values,
            is_real,
            InteractionKind::Memory,
        ));
    }

    fn recursion_eval_memory_access_single<E: Into<Self::Expr> + Clone>(
        &mut self,
        timestamp: impl Into<Self::Expr>,
        addr: impl Into<Self::Expr>,
        memory_access: &impl MemoryCols<E, E>,
        is_real: impl Into<Self::Expr>,
    ) {
        let is_real: Self::Expr = is_real.into();
        let timestamp: Self::Expr = timestamp.into();
        let mem_access = memory_access.access();

        // self.eval_memory_access_timestamp(timestamp.clone(), mem_access, is_real.clone());

        let addr = addr.into();
        let prev_timestamp = mem_access.prev_timestamp.clone().into();
        let prev_values = once(prev_timestamp)
            .chain(once(addr.clone()))
            .chain(once(memory_access.prev_value().clone().into()))
            .chain(repeat(Self::Expr::zero()).take(3))
            .collect();
        let current_values = once(timestamp)
            .chain(once(addr.clone()))
            .chain(once(memory_access.value().clone().into()))
            .chain(repeat(Self::Expr::zero()).take(3))
            .collect();

        self.receive(AirInteraction::new(
            prev_values,
            is_real.clone(),
            InteractionKind::Memory,
        ));
        self.send(AirInteraction::new(
            current_values,
            is_real,
            InteractionKind::Memory,
        ));
    }

    fn eval_memory_access_timestamp<E: Into<Self::Expr> + Clone>(
        &mut self,
        timestamp: impl Into<Self::Expr>,
        mem_access: &impl MemoryAccessTimestampCols<E>,
        is_real: impl Into<Self::Expr> + Clone,
    ) {
        let diff_minus_one: Self::Expr =
            timestamp.into() - mem_access.prev_timestamp().clone().into() - Self::Expr::one();

        // Verify that mem_access.ts_diff = mem_access.ts_diff_16bit_limb
        // + mem_access.ts_diff_8bit_limb * 2^16.
        self.eval_range_check_28bits(
            diff_minus_one,
            mem_access.diff_16bit_limb().clone(),
            mem_access.diff_12bit_limb().clone(),
            is_real.clone(),
        );
    }

    /// Verifies the inputted value is within 24 bits.
    ///
    /// This method verifies that the inputted is less than 2^24 by doing a 16 bit and 8 bit range
    /// check on it's limbs.  It will also verify that the limbs are correct.  This method is needed
    /// since the memory access timestamp check (see [Self::verify_mem_access_ts]) needs to assume
    /// the clk is within 24 bits.
    fn eval_range_check_28bits(
        &mut self,
        value: impl Into<Self::Expr>,
        limb_16: impl Into<Self::Expr> + Clone,
        limb_12: impl Into<Self::Expr> + Clone,
        is_real: impl Into<Self::Expr> + Clone,
    ) {
        // Verify that value = limb_16 + limb_8 * 2^16.
        self.when(is_real.clone()).assert_eq(
            value,
            limb_16.clone().into()
                + limb_12.clone().into() * Self::Expr::from_canonical_u32(1 << 16),
        );

        // Send the range checks for the limbs.
        self.send_range_check(
            Self::Expr::from_canonical_u8(RangeCheckOpcode::U16 as u8),
            limb_16,
            is_real.clone(),
        );

        self.send_range_check(
            Self::Expr::from_canonical_u8(RangeCheckOpcode::U12 as u8),
            limb_12,
            is_real,
        )
    }
}

pub trait RangeCheckAirBuilder: BaseAirBuilder {
    /// Sends a range check operation to be processed.
    fn send_range_check(
        &mut self,
        range_check_opcode: impl Into<Self::Expr>,
        val: impl Into<Self::Expr>,
        is_real: impl Into<Self::Expr>,
    ) {
        let values = vec![range_check_opcode.into(), val.into()];
        self.send(AirInteraction::new(
            values,
            is_real.into(),
            InteractionKind::Range,
        ));
    }

    /// Receives a range check operation to be processed.
    fn receive_range_check(
        &mut self,
        range_check_opcode: impl Into<Self::Expr>,
        val: impl Into<Self::Expr>,
        is_real: impl Into<Self::Expr>,
    ) {
        let values = vec![range_check_opcode.into(), val.into()];
        self.receive(AirInteraction::new(
            values,
            is_real.into(),
            InteractionKind::Range,
        ));
    }
}
