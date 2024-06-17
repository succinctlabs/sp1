use sp1_derive::AlignedBorrow;

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct ControlFlow<T> {
    pub is_compress: T,
    pub is_compress_output: T, // is equal to is_compress * is_output
    pub is_absorb: T,
    pub is_absorb_no_perm: T,
    pub is_finalize: T,

    pub is_syscall_row: T,
}
