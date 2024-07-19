use sp1_derive::AlignedBorrow;

/// Columns related to control flow.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct ControlFlow<T> {
    /// Specifies if this row is for compress.
    pub is_compress: T,
    /// Specifies if this row is for the compress output.
    pub is_compress_output: T,

    /// Specifies if this row is for absorb.
    pub is_absorb: T,
    /// Specifies if this row is for absorb with no permutation.
    pub is_absorb_no_perm: T,
    /// Specifies if this row is for an absorb that is not the last row.
    pub is_absorb_not_last_row: T,
    /// Specifies if this row is for an absorb that is the last row.
    pub is_absorb_last_row: T,

    /// Specifies if this row is for finalize.
    pub is_finalize: T,

    /// Specifies if this row needs to recieve a syscall interaction.
    pub is_syscall_row: T,
}
