use p3_air::AirBuilder;
use p3_field::AbstractField;
use sp1_derive::AlignedBorrow;

use crate::air::{SP1AirBuilder, Word};

/// Memory read access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryReadCols<T> {
    pub access: MemoryAccessCols<T>,
}

/// Memory write access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryWriteCols<T> {
    pub prev_value: Word<T>,
    pub access: MemoryAccessCols<T>,
}

/// Memory read-write access.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryReadWriteCols<T> {
    pub prev_value: Word<T>,
    pub access: MemoryAccessCols<T>,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryAccessCols<T> {
    pub value: Word<T>,

    // The previous shard and timestamp that this memory access is being read from.
    pub prev_shard: T,
    pub prev_clk: T,

    // The three columns below are helper/materialized columns used to verify that this memory access is
    // after the last one.  Specifically, it is used to verify that the current clk value > timestsamp (if
    // this access's shard == prev_access's shard) or that the current shard > shard.
    // These materialized columns' value will need to be verified in the air.

    // This will be true if the current shard == prev_access's shard, else false.
    pub compare_clk: T,
    // This materialized column is equal to compare_clk ? prev_clk : prev_shard
    pub prev_comp_val: T,
    // This materialized column is equal to compare_clk ? current_clk : current_shard.
    pub current_comp_val: T,

    // This column is the least significant 16 bit limb of current_comp_val - prev_comp_val.
    pub diff_16bit_limb: T,

    // This column is the most signficant 8 bit limb of current_comp_val - prev_comp_val.
    pub diff_8bit_limb: T,
}

impl<T> MemoryAccessCols<T> {
    /// This method verifies that all of the materialized columns' values are correct.
    pub fn verify_materialized_columns<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        current_clk: AB::Expr,
        current_shard: AB::Expr,
        do_check: AB::Expr,
    ) where
        T: Into<AB::Expr> + Clone,
    {
        let compare_clk: AB::Expr = self.compare_clk.clone().into();
        let prev_clk: AB::Expr = self.prev_clk.clone().into();
        let prev_shard: AB::Expr = self.prev_shard.clone().into();
        let one = AB::Expr::one();

        // Verify self.compare_clk's value.
        builder
            .when(do_check.clone())
            .assert_bool(compare_clk.clone());
        builder
            .when(do_check.clone())
            .when(compare_clk.clone())
            .assert_eq(current_shard.clone(), prev_shard.clone());

        // Verify self.prev_time_value's value.
        let expected_prev_time_value = compare_clk.clone() * prev_clk.clone()
            + (one.clone() - compare_clk.clone()) * prev_shard.clone();
        builder
            .when(do_check.clone())
            .assert_eq(self.prev_comp_val.clone(), expected_prev_time_value);

        // Verify self.current_time_value's value.
        let expected_current_time_value =
            compare_clk.clone() * current_clk + (one - compare_clk) * current_shard;
        builder
            .when(do_check)
            .assert_eq(self.current_comp_val.clone(), expected_current_time_value);
    }
}

/// The common columns for all memory access types.
pub trait MemoryCols<T> {
    fn access(&self) -> &MemoryAccessCols<T>;

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T>;

    fn prev_value(&self) -> &Word<T>;

    fn prev_value_mut(&mut self) -> &mut Word<T>;

    fn value(&self) -> &Word<T>;

    fn value_mut(&mut self) -> &mut Word<T>;
}

impl<T> MemoryCols<T> for MemoryReadCols<T> {
    fn access(&self) -> &MemoryAccessCols<T> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T> {
        &mut self.access
    }

    fn prev_value(&self) -> &Word<T> {
        &self.access.value
    }

    fn prev_value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }

    fn value(&self) -> &Word<T> {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }
}

impl<T> MemoryCols<T> for MemoryWriteCols<T> {
    fn access(&self) -> &MemoryAccessCols<T> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T> {
        &mut self.access
    }

    fn prev_value(&self) -> &Word<T> {
        &self.prev_value
    }

    fn prev_value_mut(&mut self) -> &mut Word<T> {
        &mut self.prev_value
    }

    fn value(&self) -> &Word<T> {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }
}

impl<T> MemoryCols<T> for MemoryReadWriteCols<T> {
    fn access(&self) -> &MemoryAccessCols<T> {
        &self.access
    }

    fn access_mut(&mut self) -> &mut MemoryAccessCols<T> {
        &mut self.access
    }

    fn prev_value(&self) -> &Word<T> {
        &self.prev_value
    }

    fn prev_value_mut(&mut self) -> &mut Word<T> {
        &mut self.prev_value
    }

    fn value(&self) -> &Word<T> {
        &self.access.value
    }

    fn value_mut(&mut self) -> &mut Word<T> {
        &mut self.access.value
    }
}
