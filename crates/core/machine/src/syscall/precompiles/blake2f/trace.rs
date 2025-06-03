use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use sp1_stark::{air::MachineAir, Word};
use sp1_core_executor::{
    events::{ByteLookupEvent, KeccakPermuteEvent, PrecompileEvent, SyscallEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};

use super::Blake2fCompressChip;

impl<F: PrimeField32> MachineAir<F> for Blake2fCompressChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Blake2fCompress".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let rows: Vec<[F; 64]> = Vec::new();

        // Blake2f todo: Properly generate matrix
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), 0)
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        
    }
    
    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::BLAKE2F_COMPRESS).is_empty()
        }
    }
}