use crate::{
    alu::{AddSubCols, BitwiseCols, LtCols, MulCols, ShiftLeftCols, ShiftRightCols},
    memory::MemoryInitCols,
    memory::SingleMemoryLocal,
    syscall::chip::SyscallCols,
};
use p3_baby_bear::BabyBear;

use sp1_core_executor::events::{
    AluEvent, MemoryInitializeFinalizeEvent, MemoryLocalEvent, MemoryReadRecord, MemoryRecordEnum,
    MemoryWriteRecord, SyscallEvent,
};

#[link(name = "sp1-core-machine-sys", kind = "static")]
extern "C-unwind" {
    pub fn add_sub_event_to_row_babybear(event: &AluEvent, cols: &mut AddSubCols<BabyBear>);
    pub fn mul_event_to_row_babybear(event: &AluEvent, cols: &mut MulCols<BabyBear>);
    pub fn bitwise_event_to_row_babybear(event: &AluEvent, cols: &mut BitwiseCols<BabyBear>);
    pub fn lt_event_to_row_babybear(event: &AluEvent, cols: &mut LtCols<BabyBear>);
    pub fn sll_event_to_row_babybear(event: &AluEvent, cols: &mut ShiftLeftCols<BabyBear>);
    pub fn sr_event_to_row_babybear(event: &AluEvent, cols: &mut ShiftRightCols<BabyBear>);
    pub fn memory_local_event_to_row_babybear(
        event: &MemoryLocalEvent,
        cols: &mut SingleMemoryLocal<BabyBear>,
    );
    pub fn memory_global_event_to_row_babybear(
        event: &MemoryInitializeFinalizeEvent,
        is_receive: bool,
        cols: &mut MemoryInitCols<BabyBear>,
    );
    pub fn syscall_event_to_row_babybear(
        event: &SyscallEvent,
        is_receive: bool,
        cols: &mut SyscallCols<BabyBear>,
    );
}

/// An alternative to `Option<MemoryRecordEnum>` that is FFI-safe.
///
/// See [`MemoryRecordEnum`].
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum OptionMemoryRecordEnum {
    /// Read.
    Read(MemoryReadRecord),
    /// Write.
    Write(MemoryWriteRecord),
    None,
}

impl From<Option<MemoryRecordEnum>> for OptionMemoryRecordEnum {
    fn from(value: Option<MemoryRecordEnum>) -> Self {
        match value {
            Some(MemoryRecordEnum::Read(r)) => Self::Read(r),
            Some(MemoryRecordEnum::Write(r)) => Self::Write(r),
            None => Self::None,
        }
    }
}

impl From<OptionMemoryRecordEnum> for Option<MemoryRecordEnum> {
    fn from(value: OptionMemoryRecordEnum) -> Self {
        match value {
            OptionMemoryRecordEnum::Read(r) => Some(MemoryRecordEnum::Read(r)),
            OptionMemoryRecordEnum::Write(r) => Some(MemoryRecordEnum::Write(r)),
            OptionMemoryRecordEnum::None => None,
        }
    }
}
