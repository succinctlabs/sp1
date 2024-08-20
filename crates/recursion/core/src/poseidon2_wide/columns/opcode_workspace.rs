use p3_field::AbstractField;
use sp1_core_machine::operations::IsZeroOperation;
use sp1_derive::AlignedBorrow;

use crate::{
    air::SP1RecursionAirBuilder,
    memory::MemoryReadWriteSingleCols,
    poseidon2_wide::{RATE, WIDTH},
};

/// Workspace columns.  They are different for each opcode.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub union OpcodeWorkspace<T: Copy> {
    compress: CompressWorkspace<T>,
    absorb: AbsorbWorkspace<T>,
    finalize: FinalizeWorkspace<T>,
}
/// Getter and setter functions for the opcode workspace.
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

/// Workspace columns for compress. This is used memory read/writes for the 2nd half of the
/// compress permutation state.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct CompressWorkspace<T: Copy> {
    pub start_addr: T,
    pub memory_accesses: [MemoryReadWriteSingleCols<T>; WIDTH / 2],
}

/// Workspace columns for absorb.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct AbsorbWorkspace<T: Copy> {
    /// State related columns.
    pub previous_state: [T; WIDTH],
    pub state: [T; WIDTH],
    pub state_cursor: T,

    /// Control flow columns.
    pub hash_num: T,
    pub absorb_num: T,
    pub is_first_hash_row: T,
    pub num_remaining_rows: T,
    pub num_remaining_rows_is_zero: IsZeroOperation<T>,

    /// Memory columns.
    pub start_mem_idx_bitmap: [T; WIDTH / 2],
    pub end_mem_idx_bitmap: [T; WIDTH / 2],

    /// This is the state index of that last element consumed by the absorb syscall.
    pub last_row_ending_cursor: T,
    pub last_row_ending_cursor_is_seven: IsZeroOperation<T>, /* Needed when doing the
                                                              * (last_row_ending_cursor_is_seven
                                                              * + 1) % 8 calculation. */
    pub last_row_ending_cursor_bitmap: [T; 3],

    /// Materialized control flow flags to deal with max contraint degree.
    /// Is an absorb syscall row which is not the last row for that absorb.
    pub is_syscall_not_last_row: T,
    /// Is an absorb syscall row that is the last row for that absorb.
    pub is_syscall_is_last_row: T,
    /// Is not an absorb syscall row and is not the last row for that absorb.
    pub not_syscall_not_last_row: T,
    /// Is not an absorb syscall row and is last row for that absorb.
    pub not_syscall_is_last_row: T,
    /// Is the last of an absorb and the state is filled up (e.g. it's ending cursor is 7).
    pub is_last_row_ending_cursor_is_seven: T,
    /// Is the last of an absorb and the state is not filled up (e.g. it's ending cursor is not 7).
    pub is_last_row_ending_cursor_not_seven: T,
}

/// Methods that are "virtual" columns (e.g. will return expressions).
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

/// Workspace columns for finalize.
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
