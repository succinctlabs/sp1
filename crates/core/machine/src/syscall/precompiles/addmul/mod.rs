mod addmul;
pub use addmul::*;


#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::Rng;
    use sp1_core_executor::events::AddMulEvent;
    use crate::{
        io::SP1Stdin,
        utils::{
            self,
            run_test_io,
            uni_stark_prove as prove,
            uni_stark_verify as verify
        },
    };
    use sp1_stark::{
        air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, CpuProver, StarkGenericConfig,
    };
    use test_artifacts::ADD_MUL_ELF;
    use sp1_core_executor::{
        events::{
            LookupId, MemoryReadRecord, MemoryWriteRecord, PrecompileEvent, SyscallEvent
        },
        syscalls::SyscallCode,
        ExecutionRecord, Program,
    };
    use crate::syscall::precompiles::addmul::AddMulChip;

    #[test]
    fn test_add_mul() {
        utils::setup_logger();
        println!("This test is running!");
        let program = Program::from(ADD_MUL_ELF).unwrap();
        run_test_io::<CpuProver<_, _>>(program, SP1Stdin::new()).unwrap();
    }

    fn generate_test_execution_record(pass: bool) -> ExecutionRecord {
          let mut execution_record = ExecutionRecord::default();

        let rng = &mut rand::thread_rng();
        let a_ptr: u32 = 0u32;
        let b_ptr: u32 = 4u32;
        let c_ptr: u32 = 8u32;
        let d_ptr: u32 = 12u32;

        let a = 1u32;
        let b = 2u32;
        let c = 3u32;
        let d = 4u32;

        let lookup_id = LookupId(rng.gen());

        let event = PrecompileEvent::ADDMul(AddMulEvent {
            lookup_id,
            shard: 0u32,
            clk: 1u32,
            a,
            b,
            c,
            d,
            a_ptr,
            b_ptr,
            c_ptr,
            d_ptr,
            result: 14u32,
            local_mem_access: Vec::new(),
        });

        let syscall_code = SyscallCode::ADDMUL;
        let syscall_event = SyscallEvent {
            shard: 0u32,
            clk:1u32,
            lookup_id,
            syscall_id: syscall_code as u32,
            arg1: a_ptr,
            arg2: b_ptr,
            nonce: 0u32,
        };

        execution_record.precompile_events.add_event(syscall_code, syscall_event, event);

        execution_record
    }

    #[test]
    fn test_add_mul_pass() {
        let config = BabyBearPoseidon2::new();
        let execution_record = generate_test_execution_record(true);
        let chip = AddMulChip::new();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&execution_record, &mut ExecutionRecord::default());
        let proof = prove::<BabyBearPoseidon2, _>(&config, &chip, &mut config.challenger(), trace);
        verify(&config, &chip, &mut config.challenger(), &proof).unwrap();
    }

}