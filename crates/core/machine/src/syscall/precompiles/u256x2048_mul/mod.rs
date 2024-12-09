mod air;

pub use air::*;

#[cfg(test)]
mod tests {
    use num::{BigUint, Integer, One};
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::Rng;
    use sp1_core_executor::{
        events::{
            MemoryReadRecord, MemoryWriteRecord, PrecompileEvent, SyscallEvent, U256xU2048MulEvent,
        },
        syscalls::SyscallCode,
        ExecutionRecord, Program,
    };
    use sp1_primitives::consts::bytes_to_words_le;
    use sp1_stark::{
        air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, CpuProver, StarkGenericConfig,
    };
    use test_artifacts::U256XU2048_MUL_ELF;

    use crate::{
        io::SP1Stdin,
        utils::{
            self, run_test,
            uni_stark::{uni_stark_prove, uni_stark_verify},
        },
    };
    use crate::{
        syscall::precompiles::u256x2048_mul::air::U256x2048MulChip, utils::words_to_bytes_le_vec,
    };

    fn generate_test_execution_record(pass: bool) -> ExecutionRecord {
        let mut execution_record = ExecutionRecord::default();

        let rng = &mut rand::thread_rng();
        let a_ptr: u32 = 0u32;
        let b_ptr: u32 = 1u32;
        let lo_ptr: u32 = 2u32;
        let hi_ptr: u32 = 3u32;

        let lo_ts = 1u32;
        let hi_ts = lo_ts + 1;

        let a: Vec<u32> = (0..8).map(|_| rng.gen()).collect();
        let b: Vec<u32> = (0..64).map(|_| rng.gen()).collect();

        let uint256_a = BigUint::from_bytes_le(&words_to_bytes_le_vec(&a));
        let uint2048_b = BigUint::from_bytes_le(&words_to_bytes_le_vec(&b));

        let result = uint256_a * uint2048_b;

        let two_to_2048 = BigUint::one() << 2048;

        let (hi_big, lo_big) = result.div_rem(&two_to_2048);

        let mut a_memory_records = Vec::new();
        for i in 0..8 {
            a_memory_records.push(MemoryReadRecord {
                value: a[i],
                shard: 0u32,
                timestamp: hi_ts,
                prev_shard: 0u32,
                prev_timestamp: lo_ts,
            });
        }
        let mut b_memory_records = Vec::new();
        for i in 0..64 {
            b_memory_records.push(MemoryReadRecord {
                value: b[i],
                shard: 0u32,
                timestamp: hi_ts,
                prev_shard: 0u32,
                prev_timestamp: lo_ts,
            });
        }
        let lo_ptr_memory = MemoryReadRecord {
            value: lo_ptr,
            shard: 0u32,
            timestamp: hi_ts,
            prev_shard: 0u32,
            prev_timestamp: lo_ts,
        };
        let hi_ptr_memory = MemoryReadRecord {
            value: hi_ptr,
            shard: 0u32,
            timestamp: hi_ts,
            prev_shard: 0u32,
            prev_timestamp: lo_ts,
        };

        let (lo, hi) = if pass {
            let mut lo_bytes = lo_big.to_bytes_le();
            lo_bytes.resize(256, 0u8);
            let lo_words = bytes_to_words_le::<64>(&lo_bytes);

            let mut hi_bytes = hi_big.to_bytes_le();
            hi_bytes.resize(32, 0u8);
            let hi_words = bytes_to_words_le::<8>(&hi_bytes);
            (lo_words.to_vec(), hi_words.to_vec())
        } else {
            let lo: Vec<u32> = (0..64).map(|_| rng.gen()).collect();
            let hi: Vec<u32> = (0..8).map(|_| rng.gen()).collect();
            (lo, hi)
        };
        let mut lo_memory_records = Vec::new();
        for i in 0..64 {
            lo_memory_records.push(MemoryWriteRecord {
                value: lo[i],
                shard: 0u32,
                timestamp: hi_ts + 1,
                prev_value: 0u32,
                prev_shard: 0u32,
                prev_timestamp: hi_ts,
            });
        }
        let mut hi_memory_records = Vec::new();
        for i in 0..8 {
            hi_memory_records.push(MemoryWriteRecord {
                value: hi[i],
                shard: 0u32,
                timestamp: hi_ts + 1,
                prev_value: 0u32,
                prev_shard: 0u32,
                prev_timestamp: hi_ts,
            });
        }

        let event = PrecompileEvent::U256xU2048Mul(U256xU2048MulEvent {
            shard: 0u32,
            clk: hi_ts,
            a_ptr,
            a,
            b_ptr,
            b,
            lo_ptr,
            lo,
            hi_ptr,
            hi,
            lo_ptr_memory,
            hi_ptr_memory,
            a_memory_records,
            b_memory_records,
            lo_memory_records,
            hi_memory_records,
            local_mem_access: Vec::new(),
        });

        let syscall_code = SyscallCode::U256XU2048_MUL;
        let syscall_event = SyscallEvent {
            pc: 32,
            next_pc: 36,
            shard: 0u32,
            clk: hi_ts,
            a_record: MemoryWriteRecord::default(),
            a_record_is_real: false,
            op_a_0: false,
            syscall_code,
            syscall_id: syscall_code.syscall_id(),
            arg1: a_ptr,
            arg2: b_ptr,
        };

        execution_record.precompile_events.add_event(syscall_code, syscall_event, event);

        execution_record
    }

    #[test]
    fn test_uint256_mul() {
        utils::setup_logger();
        let program = Program::from(U256XU2048_MUL_ELF).unwrap();
        run_test::<CpuProver<_, _>>(program, SP1Stdin::new()).unwrap();
    }

    #[test]
    fn test_u256x2048_mul_pass() {
        let config = BabyBearPoseidon2::new();
        let execution_record = generate_test_execution_record(true);
        let chip = U256x2048MulChip::new();
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&execution_record, &mut ExecutionRecord::default());
        let proof = uni_stark_prove::<BabyBearPoseidon2, _>(
            &config,
            &chip,
            &mut config.challenger(),
            trace,
        );
        uni_stark_verify(&config, &chip, &mut config.challenger(), &proof).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_u256x2048_mul_failure() {
        for _ in 0..10 {
            let config = BabyBearPoseidon2::new();
            let execution_record = generate_test_execution_record(false);
            let chip = U256x2048MulChip::new();
            let trace: RowMajorMatrix<BabyBear> =
                chip.generate_trace(&execution_record, &mut ExecutionRecord::default());
            let proof = uni_stark_prove::<BabyBearPoseidon2, _>(
                &config,
                &chip,
                &mut config.challenger(),
                trace,
            );
            let result = uni_stark_verify(&config, &chip, &mut config.challenger(), &proof);
            assert!(result.is_ok());
        }
    }
}
