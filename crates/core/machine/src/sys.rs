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

// /// An FFI-safe version of [`CpuEvent`] that also looks up nonces ahead of time.
// #[derive(Debug, Clone, Copy)]
// #[repr(C)]
// pub struct CpuEventFfi {
//     /// The clock cycle.
//     pub clk: u32,
//     /// The program counter.
//     pub pc: u32,
//     /// The next program counter.
//     pub next_pc: u32,
//     /// The first operand.
//     pub a: u32,
//     /// The first operand memory record.
//     pub a_record: OptionMemoryRecordEnum,
//     /// The second operand.
//     pub b: u32,
//     /// The second operand memory record.
//     pub b_record: OptionMemoryRecordEnum,
//     /// The third operand.
//     pub c: u32,
//     /// The third operand memory record.
//     pub c_record: OptionMemoryRecordEnum,
//     // Seems to be vestigial. Verify before completely removing this.
//     // /// The memory value.
//     // pub memory: Option<&'a u32>,
//     /// The memory record.
//     pub memory_record: OptionMemoryRecordEnum,
//     /// The exit code.
//     pub exit_code: u32,

//     pub alu_nonce: u32,
//     pub syscall_nonce: u32,
//     pub memory_add_nonce: u32,
//     pub memory_sub_nonce: u32,
//     pub branch_gt_nonce: u32,
//     pub branch_lt_nonce: u32,
//     pub branch_add_nonce: u32,
//     pub jump_jal_nonce: u32,
//     pub jump_jalr_nonce: u32,
//     pub auipc_nonce: u32,
// }

// impl CpuEventFfi {
//     pub fn new(event: &CpuEvent, nonce_lookup: &HashMap<LookupId, u32>) -> Self {
//         let &CpuEvent {
//             clk,
//             pc,
//             next_pc,
//             a,
//             a_record,
//             b,
//             b_record,
//             c,
//             c_record,
//             memory_record,
//             exit_code,
//             ref alu_lookup_id,
//             ref syscall_lookup_id,
//             ref memory_add_lookup_id,
//             ref memory_sub_lookup_id,
//             ref branch_gt_lookup_id,
//             ref branch_lt_lookup_id,
//             ref branch_add_lookup_id,
//             ref jump_jal_lookup_id,
//             ref jump_jalr_lookup_id,
//             ref auipc_lookup_id,
//         } = event;
//         Self {
//             clk,
//             pc,
//             next_pc,
//             a,
//             a_record: a_record.into(),
//             b,
//             b_record: b_record.into(),
//             c,
//             c_record: c_record.into(),
//             memory_record: memory_record.into(),
//             exit_code,
//             alu_nonce: nonce_lookup.get(alu_lookup_id).copied().unwrap_or_default(),
//             syscall_nonce: nonce_lookup.get(syscall_lookup_id).copied().unwrap_or_default(),
//             memory_add_nonce: nonce_lookup.get(memory_add_lookup_id).copied().unwrap_or_default(),
//             memory_sub_nonce: nonce_lookup.get(memory_sub_lookup_id).copied().unwrap_or_default(),
//             branch_gt_nonce: nonce_lookup.get(branch_gt_lookup_id).copied().unwrap_or_default(),
//             branch_lt_nonce: nonce_lookup.get(branch_lt_lookup_id).copied().unwrap_or_default(),
//             branch_add_nonce: nonce_lookup.get(branch_add_lookup_id).copied().unwrap_or_default(),
//             jump_jal_nonce: nonce_lookup.get(jump_jal_lookup_id).copied().unwrap_or_default(),
//             jump_jalr_nonce: nonce_lookup.get(jump_jalr_lookup_id).copied().unwrap_or_default(),
//             auipc_nonce: nonce_lookup.get(auipc_lookup_id).copied().unwrap_or_default(),
//         }
//     }
// }
