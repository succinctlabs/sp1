use serde::{Deserialize, Serialize};
use sp1_derive::{AlignedBorrow, IntoShape};
use sp1_hypercube::Word;

use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::operations::U16toU8Operation;

/// Memory Access Timestamp
#[derive(AlignedBorrow, StructReflection, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryAccessTimestamp<T> {
    /// The previous timestamp's high 24 bits that this memory access is being read from.
    pub prev_high: T,
    /// The previous timestamp's low 24 bits that this memory access is being read from.
    pub prev_low: T,
    /// This will be true if the top 24 bits do not match.
    pub compare_low: T,
    /// The following columns are decomposed limbs for the difference between the current access's
    /// timestamp and the previous access's timestamp.  Note the actual value of the timestamp
    /// is either the accesses' high or low 24 bits depending on the value of compare_low.
    ///
    /// This column is the least significant 16 bit limb of the difference.
    pub diff_low_limb: T,
    /// This column is the most significant 8 bit limb of the difference.
    pub diff_high_limb: T,
}

/// Memory Access Columns
#[derive(AlignedBorrow, StructReflection, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryAccessCols<T> {
    pub prev_value: Word<T>,
    pub access_timestamp: MemoryAccessTimestamp<T>,
}

/// Memory Access Columns for u8 limbs
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryAccessColsU8<T> {
    pub memory_access: MemoryAccessCols<T>,
    pub prev_value_u8: U16toU8Operation<T>,
}

/// Register Access Timestamp. The register accesses use the same argument as the memory accesses,
/// and shares the same space as the memory. This structure is used for register accesses in RISC-V.
/// For optimization, we ensure that all register accesses have the high limb of the timestamp and
/// previous timestamp to be equal. This is done through adding in a "shadow" read, through the
/// `MemoryBump` chip. Therefore, only the columns for low limb comparison is needed here.
#[derive(
    AlignedBorrow, StructReflection, Default, Debug, Clone, Copy, Serialize, Deserialize, IntoShape,
)]
#[repr(C)]
pub struct RegisterAccessTimestamp<T> {
    /// The previous timestamp that this memory access is being read from.
    pub prev_low: T,
    /// The difference in timestamp's least significant 16 bit limb.
    pub diff_low_limb: T,
}

/// Register Access Columns
#[derive(
    AlignedBorrow, StructReflection, Default, Debug, Clone, Copy, Serialize, Deserialize, IntoShape,
)]
pub struct RegisterAccessCols<T> {
    pub prev_value: Word<T>,
    pub access_timestamp: RegisterAccessTimestamp<T>,
}

/// Page Permission Access Columns, when the shard and previous shard are known to be equal
#[derive(AlignedBorrow, StructReflection, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct PageProtAccessCols<T> {
    pub prev_prot_bitmap: T,
    pub access_timestamp: MemoryAccessTimestamp<T>,
}
