use p3_field::AbstractField;
use sp1_core::operations::IsZeroOperation;
use sp1_derive::AlignedBorrow;

use crate::{
    air::SP1RecursionAirBuilder,
    memory::MemoryReadWriteSingleCols,
    poseidon2_wide::{RATE, WIDTH},
};

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub union OpcodeWorkspace<T: Copy> {
    compress: CompressWorkspace<T>,
    absorb: AbsorbWorkspace<T>,
    finalize: FinalizeWorkspace<T>,
}

impl<T: Copy> OpcodeWorkspace<T> {
    pub fn compress(&self) -> &CompressWorkspace<T> {
        unsafe { &self.compress }
    }

    pub fn compress_mut(&mut self) -> &mut CompressWorkspace<T> {
        unsafe { &mut self.compress }
    }

    pub fn absorb(&self) -> &AbsorbWorkspace<T> {
        unsafe { &self.absorb }
    }

    pub fn absorb_mut(&mut self) -> &mut AbsorbWorkspace<T> {
        unsafe { &mut self.absorb }
    }

    pub fn finalize(&self) -> &FinalizeWorkspace<T> {
        unsafe { &self.finalize }
    }

    pub fn finalize_mut(&mut self) -> &mut FinalizeWorkspace<T> {
        unsafe { &mut self.finalize }
    }
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct CompressWorkspace<T: Copy> {
    pub start_addr: T,
    pub memory_accesses: [MemoryReadWriteSingleCols<T>; WIDTH / 2],
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct AbsorbWorkspace<T: Copy> {
    /// State related columns.
    pub previous_state: [T; WIDTH],
    pub state: [T; WIDTH],
    pub state_cursor: T,

    /// Control flow columns.
    pub is_first_hash_row: T,
    pub num_remaining_rows: T,
    pub num_remaining_rows_is_zero: IsZeroOperation<T>,

    /// This is the state index of that last element consumed by the absorb syscall.
    pub last_row_ending_cursor: T,
    pub last_row_ending_cursor_is_seven: IsZeroOperation<T>, // Needed when doing the (last_row_ending_cursor_is_seven + 1) % 8 calculation.
    pub last_row_ending_cursor_bitmap: [T; 3],

    /// Only used for non syscall absorb rows.
    /// read_ptr' = read_ptr + num_consumed
    pub read_ptr: T,

    /// Materialized control flow flags to deal with max contraint degree.
    pub is_syscall_not_last_row: T, // expected num_consumed == RATE - start_cursor, expected cursor == start_cursor
    pub is_syscall_is_last_row: T, // expected num_consumed == len, expected cursor == start_cursor
    pub not_syscall_not_last_row: T, // expected num_consumed == 8, expected cursor == 0;
    pub not_syscall_is_last_row: T, // expected num_consuemd == last_row_num_consumed, expected_corsor == 0
    pub is_last_row_ending_cursor_is_seven: T,
    pub is_last_row_ending_cursor_not_seven: T,
}

impl<T: Copy> AbsorbWorkspace<T> {
    pub(crate) fn is_last_row<AB: SP1RecursionAirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.num_remaining_rows_is_zero.result.into()
    }

    pub(crate) fn do_perm<AB: SP1RecursionAirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.is_syscall_not_last_row.into()
            + self.not_syscall_not_last_row.into()
            + self.is_last_row_ending_cursor_is_seven.into()
    }

    pub(crate) fn num_consumed<AB: SP1RecursionAirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.is_syscall_not_last_row.into()
            * (AB::Expr::from_canonical_usize(RATE) - self.state_cursor.into())
            + self.is_syscall_is_last_row.into()
                * (self.last_row_ending_cursor.into() - self.state_cursor.into() + AB::Expr::one())
            + self.not_syscall_not_last_row.into() * AB::Expr::from_canonical_usize(RATE)
            + self.not_syscall_is_last_row.into()
                * (self.last_row_ending_cursor.into() + AB::Expr::one())
    }
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct FinalizeWorkspace<T: Copy> {
    /// State related columns.
    pub previous_state: [T; WIDTH],
    pub state: [T; WIDTH],
    pub state_cursor: T,
    pub state_cursor_is_zero: IsZeroOperation<T>,
}

impl<T: Copy> FinalizeWorkspace<T> {
    pub(crate) fn do_perm<AB: SP1RecursionAirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        AB::Expr::one() - self.state_cursor_is_zero.result.into()
    }
}
