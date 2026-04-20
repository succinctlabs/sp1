use std::iter::once;

use itertools::Itertools;
use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field};
use sp1_core_executor::ByteOpcode;
use sp1_hypercube::{
    air::{AirInteraction, BaseAirBuilder, ByteAirBuilder, InteractionScope},
    InteractionKind, Word,
};

use crate::memory::{
    MemoryAccessCols, MemoryAccessTimestamp, PageProtAccessCols, RegisterAccessCols,
    RegisterAccessTimestamp,
};

pub trait MemoryAirBuilder: BaseAirBuilder {
    /// Constrain a memory read, by using the read value as the write value.
    /// The constraints enforce that the new timestamp is greater than the previous one.
    fn eval_memory_access_read<E: Into<Self::Expr> + Clone>(
        &mut self,
        clk_high: impl Into<Self::Expr>,
        clk_low: impl Into<Self::Expr>,
        addr: &[Self::Expr; 3],
        mem_access: MemoryAccessCols<E>,
        do_check: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        let clk_high: Self::Expr = clk_high.into();
        let clk_low: Self::Expr = clk_low.into();

        self.assert_bool(do_check.clone());
        // Verify that the current memory access time is greater than the previous's.
        self.eval_memory_access_timestamp(
            &mem_access.access_timestamp,
            do_check.clone(),
            clk_high.clone(),
            clk_low.clone(),
        );

        // Add to the memory argument.
        let prev_high = mem_access.access_timestamp.prev_high.clone().into();
        let prev_low = mem_access.access_timestamp.prev_low.clone().into();
        let prev_values = once(prev_high)
            .chain(once(prev_low))
            .chain(addr.clone())
            .chain(mem_access.prev_value.clone().map(Into::into))
            .collect();
        let current_values = once(clk_high)
            .chain(once(clk_low))
            .chain(addr.clone())
            .chain(mem_access.prev_value.clone().map(Into::into))
            .collect();

        // The previous values get sent with multiplicity = 1, for "read".
        self.send(
            AirInteraction::new(prev_values, do_check.clone(), InteractionKind::Memory),
            InteractionScope::Local,
        );

        // The current values get "received", i.e. multiplicity = -1
        self.receive(
            AirInteraction::new(current_values, do_check.clone(), InteractionKind::Memory),
            InteractionScope::Local,
        );
    }

    /// Constrain a memory write, given the write value.
    /// The constraints enforce that the new timestamp is greater than the previous one.
    fn eval_memory_access_write<E: Into<Self::Expr> + Clone>(
        &mut self,
        clk_high: impl Into<Self::Expr>,
        clk_low: impl Into<Self::Expr>,
        addr: &[Self::Expr; 3],
        mem_access: MemoryAccessCols<E>,
        write_value: Word<impl Into<Self::Expr>>,
        do_check: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        let clk_high: Self::Expr = clk_high.into();
        let clk_low: Self::Expr = clk_low.into();

        self.assert_bool(do_check.clone());
        // Verify that the current memory access time is greater than the previous's.
        self.eval_memory_access_timestamp(
            &mem_access.access_timestamp,
            do_check.clone(),
            clk_high.clone(),
            clk_low.clone(),
        );

        // Add to the memory argument.
        let prev_high = mem_access.access_timestamp.prev_high.clone().into();
        let prev_low = mem_access.access_timestamp.prev_low.clone().into();
        let prev_values = once(prev_high)
            .chain(once(prev_low.clone()))
            .chain(addr.clone())
            .chain(mem_access.prev_value.clone().map(Into::into))
            .collect();
        let current_values = once(clk_high.clone())
            .chain(once(clk_low.clone()))
            .chain(addr.clone())
            .chain(write_value.map(Into::into))
            .collect();

        // The previous values get sent with multiplicity = 1, for "read".
        self.send(
            AirInteraction::new(prev_values, do_check.clone(), InteractionKind::Memory),
            InteractionScope::Local,
        );

        // The current values get "received", i.e. multiplicity = -1
        self.receive(
            AirInteraction::new(current_values, do_check.clone(), InteractionKind::Memory),
            InteractionScope::Local,
        );
    }

    /// Constrain a register read, by using the read value as the write value.
    /// The constraints enforce that the new timestamp is greater than the previous one.
    /// For register reads, the top limb of the timestamp is equal to the previous one.
    fn eval_register_access_read<E: Into<Self::Expr> + Clone>(
        &mut self,
        clk_high: impl Into<Self::Expr>,
        clk_low: impl Into<Self::Expr>,
        addr: [Self::Expr; 3],
        reg_access: RegisterAccessCols<E>,
        do_check: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        let clk_high: Self::Expr = clk_high.into();
        let clk_low: Self::Expr = clk_low.into();

        self.assert_bool(do_check.clone());
        // Verify that the current memory access time is greater than the previous's.
        self.eval_register_access_timestamp(
            &reg_access.access_timestamp,
            do_check.clone(),
            clk_low.clone(),
        );

        // Add to the memory argument.
        let prev_low = reg_access.access_timestamp.prev_low.clone().into();
        let prev_values = once(clk_high.clone())
            .chain(once(prev_low))
            .chain(addr.clone())
            .chain(reg_access.prev_value.clone().map(Into::into))
            .collect();
        let current_values = once(clk_high)
            .chain(once(clk_low))
            .chain(addr.clone())
            .chain(reg_access.prev_value.clone().map(Into::into))
            .collect();

        // The previous values get sent with multiplicity = 1, for "read".
        self.send(
            AirInteraction::new(prev_values, do_check.clone(), InteractionKind::Memory),
            InteractionScope::Local,
        );

        // The current values get "received", i.e. multiplicity = -1
        self.receive(
            AirInteraction::new(current_values, do_check.clone(), InteractionKind::Memory),
            InteractionScope::Local,
        );
    }

    /// Constrain a register write, given the write value.
    /// The constraints enforce that the new timestamp is greater than the previous one.
    /// For register reads, the top limb of the timestamp is equal to the previous one.
    fn eval_register_access_write<E: Into<Self::Expr> + Clone>(
        &mut self,
        clk_high: impl Into<Self::Expr>,
        clk_low: impl Into<Self::Expr>,
        addr: [Self::Expr; 3],
        reg_access: RegisterAccessCols<E>,
        write_value: Word<impl Into<Self::Expr>>,
        do_check: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        let clk_high: Self::Expr = clk_high.into();
        let clk_low: Self::Expr = clk_low.into();

        self.assert_bool(do_check.clone());
        // Verify that the current memory access time is greater than the previous's.
        self.eval_register_access_timestamp(
            &reg_access.access_timestamp,
            do_check.clone(),
            clk_low.clone(),
        );

        // Add to the memory argument.
        let prev_low = reg_access.access_timestamp.prev_low.clone().into();
        let prev_values = once(clk_high.clone())
            .chain(once(prev_low.clone()))
            .chain(addr.clone())
            .chain(reg_access.prev_value.clone().map(Into::into))
            .collect();
        let current_values = once(clk_high.clone())
            .chain(once(clk_low.clone()))
            .chain(addr.clone())
            .chain(write_value.map(Into::into))
            .collect();

        // The previous values get sent with multiplicity = 1, for "read".
        self.send(
            AirInteraction::new(prev_values, do_check.clone(), InteractionKind::Memory),
            InteractionScope::Local,
        );

        // The current values get "received", i.e. multiplicity = -1
        self.receive(
            AirInteraction::new(current_values, do_check.clone(), InteractionKind::Memory),
            InteractionScope::Local,
        );
    }

    /// Constraints a memory read to a slice of `MemoryAccessCols`.
    fn eval_memory_access_slice_read<E: Into<Self::Expr> + Copy>(
        &mut self,
        clk_high: impl Into<Self::Expr> + Clone,
        clk_low: impl Into<Self::Expr> + Clone,
        addr_slice: &[[Self::Expr; 3]],
        memory_access_slice: &[MemoryAccessCols<E>],
        verify_memory_access: impl Into<Self::Expr> + Clone,
    ) {
        for (access_slice, addr) in memory_access_slice.iter().zip(addr_slice) {
            self.eval_memory_access_read(
                clk_high.clone(),
                clk_low.clone(),
                addr,
                *access_slice,
                verify_memory_access.clone(),
            );
        }
    }

    /// Constraints a memory write to a slice of `MemoryAccessCols`.
    fn eval_memory_access_slice_write<E: Into<Self::Expr> + Copy>(
        &mut self,
        clk_high: impl Into<Self::Expr> + Clone,
        clk_low: impl Into<Self::Expr> + Clone,
        addr_slice: &[[Self::Expr; 3]],
        memory_access_slice: &[MemoryAccessCols<E>],
        write_values: Vec<Word<impl Into<Self::Expr>>>,
        verify_memory_access: impl Into<Self::Expr> + Clone,
    ) {
        for ((access_slice, addr), write_value) in
            memory_access_slice.iter().zip_eq(addr_slice).zip_eq(write_values)
        {
            self.eval_memory_access_write(
                clk_high.clone(),
                clk_low.clone(),
                addr,
                *access_slice,
                write_value,
                verify_memory_access.clone(),
            );
        }
    }

    /// Verifies the memory access timestamp.
    ///
    /// This method verifies that the current memory access happened after the previous one's.
    fn eval_memory_access_timestamp(
        &mut self,
        mem_access: &MemoryAccessTimestamp<impl Into<Self::Expr> + Clone>,
        do_check: impl Into<Self::Expr>,
        clk_high: impl Into<Self::Expr> + Clone,
        clk_low: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        let compare_low: Self::Expr = mem_access.compare_low.clone().into();
        let clk_high: Self::Expr = clk_high.clone().into();
        let prev_high: Self::Expr = mem_access.prev_high.clone().into();

        // First verify that compare_clk's value is correct.
        self.when(do_check.clone()).assert_bool(compare_low.clone());
        self.when(do_check.clone())
            .when(compare_low.clone())
            .assert_eq(clk_high.clone(), prev_high);

        // Get the comparison timestamp values for the current and previous memory access.
        let prev_comp_value = self.if_else(
            compare_low.clone(),
            mem_access.prev_low.clone(),
            mem_access.prev_high.clone(),
        );

        let current_comp_val = self.if_else(compare_low.clone(), clk_low.into(), clk_high.clone());

        // Assert `current_comp_val > prev_comp_val`. We check this by asserting that
        // `0 <= current_comp_val-prev_comp_val-1 < 2^24`.
        //
        // The equivalence of these statements comes from the fact that if
        // `current_comp_val <= prev_comp_val`, then `current_comp_val-prev_comp_val-1 < 0` and will
        // underflow in the prime field, resulting in a value that is `>= 2^24` as long as both
        // `current_comp_val, prev_comp_val` are range-checked to be `< 2^24` and as long as we're
        // working in a field larger than `2 * 2^24` (which is true of the SP1Field).
        let diff_minus_one = current_comp_val - prev_comp_value - Self::Expr::one();

        // Verify that value = limb_low + limb_high * 2^16.
        self.when(do_check.clone()).assert_eq(
            diff_minus_one,
            mem_access.diff_low_limb.clone().into()
                + mem_access.diff_high_limb.clone().into()
                    * Self::Expr::from_canonical_u32(1 << 16),
        );

        // Send the range checks for the limbs.
        self.send_byte(
            Self::Expr::from_canonical_u8(ByteOpcode::Range as u8),
            mem_access.diff_low_limb.clone(),
            Self::Expr::from_canonical_u32(16),
            Self::Expr::zero(),
            do_check.clone(),
        );

        self.send_byte(
            Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
            Self::Expr::zero(),
            mem_access.diff_high_limb.clone(),
            Self::Expr::zero(),
            do_check,
        )
    }

    /// Verifies the register access timestamp, where the high limb of the timestamp is equal.
    ///
    /// This method verifies that the current memory access happened after the previous one's.
    /// Specifically it will ensure that the current's clk val is greater than the previous's.
    fn eval_register_access_timestamp(
        &mut self,
        reg_access: &RegisterAccessTimestamp<impl Into<Self::Expr> + Clone>,
        do_check: impl Into<Self::Expr>,
        clk: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();

        let diff_minus_one = clk.into() - reg_access.prev_low.clone().into() - Self::Expr::one();
        let diff_high_limb = (diff_minus_one.clone() - reg_access.diff_low_limb.clone().into())
            * Self::F::from_canonical_u32(1 << 16).inverse();

        // Send the range checks for the limbs.
        self.send_byte(
            Self::Expr::from_canonical_u8(ByteOpcode::Range as u8),
            reg_access.diff_low_limb.clone(),
            Self::Expr::from_canonical_u32(16),
            Self::Expr::zero(),
            do_check.clone(),
        );

        self.send_byte(
            Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
            Self::Expr::zero(),
            diff_high_limb,
            Self::Expr::zero(),
            do_check,
        )
    }

    /// This function is used to send to the a request to check an address's permissions.
    #[allow(clippy::too_many_arguments)]
    fn send_page_prot(
        &mut self,
        clk_high: impl Into<Self::Expr>,
        clk_low: impl Into<Self::Expr>,
        addr: &[Self::Expr; 3],
        permissions: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(clk_high.into())
            .chain(once(clk_low.into()))
            .chain(addr.clone())
            .chain(once(permissions.into()))
            .collect();

        self.send(
            AirInteraction::new(values, multiplicity.into(), InteractionKind::PageProt),
            InteractionScope::Local,
        );
    }

    /// This function is used to receive a response to a request to check an address's permissions.
    #[allow(clippy::too_many_arguments)]
    fn receive_page_prot(
        &mut self,
        clk_high: impl Into<Self::Expr>,
        clk_low: impl Into<Self::Expr>,
        addr: &[Self::Expr; 3],
        permissions: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(clk_high.into())
            .chain(once(clk_low.into()))
            .chain(addr.clone())
            .chain(once(permissions.into()))
            .collect();

        self.receive(
            AirInteraction::new(values, multiplicity.into(), InteractionKind::PageProt),
            InteractionScope::Local,
        );
    }

    /// Constrain a page prot read, by using the read value as the write value.
    /// The constraints enforce that the new clk is greater than the previous one.
    fn eval_page_prot_access_read<E: Into<Self::Expr> + Clone>(
        &mut self,
        clk_high: impl Into<Self::Expr>,
        clk_low: impl Into<Self::Expr>,
        prot_page_idx: &[impl Into<Self::Expr> + Clone; 3],
        page_prot_access: PageProtAccessCols<E>,
        do_check: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        let clk_high: Self::Expr = clk_high.into();
        let clk_low: Self::Expr = clk_low.into();

        self.assert_bool(do_check.clone());
        // Verify that the current memory access time is greater than the previous's.
        self.eval_memory_access_timestamp(
            &page_prot_access.access_timestamp,
            do_check.clone(),
            clk_high.clone(),
            clk_low.clone(),
        );

        // Add to the memory argument.
        let prev_high = page_prot_access.access_timestamp.prev_high.clone().into();
        let prev_low = page_prot_access.access_timestamp.prev_low.clone().into();
        let prev_values = once(prev_high)
            .chain(once(prev_low))
            .chain(prot_page_idx.clone().map(Into::into))
            .chain(once(page_prot_access.prev_prot_bitmap.clone().into()))
            .collect();
        let current_values = once(clk_high)
            .chain(once(clk_low))
            .chain(prot_page_idx.clone().map(Into::into))
            .chain(once(page_prot_access.prev_prot_bitmap.into()))
            .collect();

        // The previous values get sent with multiplicity = 1, for "read".
        self.send(
            AirInteraction::new(prev_values, do_check.clone(), InteractionKind::PageProtAccess),
            InteractionScope::Local,
        );

        // The current values get "received", i.e. multiplicity = -1
        self.receive(
            AirInteraction::new(current_values, do_check.clone(), InteractionKind::PageProtAccess),
            InteractionScope::Local,
        );
    }

    /// Constrain a page prot write, updating the protection bitmap.
    /// The constraints enforce that the new clk is greater than the previous one.
    fn eval_page_prot_access_write<E: Into<Self::Expr> + Clone>(
        &mut self,
        clk_high: impl Into<Self::Expr>,
        clk_low: impl Into<Self::Expr>,
        prot_page_idx: &[impl Into<Self::Expr> + Clone; 3],
        page_prot_access: PageProtAccessCols<E>,
        new_prot_bitmap: impl Into<Self::Expr>,
        do_check: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        let clk_high: Self::Expr = clk_high.into();
        let clk_low: Self::Expr = clk_low.into();
        let new_prot_bitmap: Self::Expr = new_prot_bitmap.into();

        self.assert_bool(do_check.clone());

        // Verify that the current memory access time is greater than the previous's.
        self.eval_memory_access_timestamp(
            &page_prot_access.access_timestamp,
            do_check.clone(),
            clk_high.clone(),
            clk_low.clone(),
        );

        // Read the previous state
        let prev_high = page_prot_access.access_timestamp.prev_high.clone().into();
        let prev_low = page_prot_access.access_timestamp.prev_low.clone().into();
        let prev_values = once(prev_high)
            .chain(once(prev_low))
            .chain(prot_page_idx.clone().map(Into::into))
            .chain(once(page_prot_access.prev_prot_bitmap.clone().into()))
            .collect();

        // Write the new state with updated protection bitmap
        let current_values = once(clk_high)
            .chain(once(clk_low))
            .chain(prot_page_idx.clone().map(Into::into))
            .chain(once(new_prot_bitmap))
            .collect();

        // The previous values get sent with multiplicity = 1, for "read".
        self.send(
            AirInteraction::new(prev_values, do_check.clone(), InteractionKind::PageProtAccess),
            InteractionScope::Local,
        );

        // The current values get "received", i.e. multiplicity = -1
        self.receive(
            AirInteraction::new(current_values, do_check.clone(), InteractionKind::PageProtAccess),
            InteractionScope::Local,
        );
    }
}
