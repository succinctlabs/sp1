use sp1_derive::AlignedBorrow;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct HeapExpandCols<T> {
    pub diff_16bit_limb: T,
    pub diff_12bit_limb: T,
}
