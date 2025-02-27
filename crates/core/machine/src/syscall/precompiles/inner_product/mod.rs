mod inner_product;
pub use inner_product::*;

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::Rng;
    use sp1_core_executor::{
        events::{
            InnerProductEvent, MemoryReadRecord, MemoryWriteRecord, PrecompileEvent, SyscallEvent,
        },
        syscalls::SyscallCode,
        ExecutionRecord, Program,
    };
    use sp1_stark::{air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig};

    use crate::{
        syscall::precompiles::inner_product::InnerProductChip,
        utils::uni_stark::{uni_stark_prove, uni_stark_verify},
    };

    fn generate_test_execution_record(pass: bool) -> ExecutionRecord {
        let mut execution_record = ExecutionRecord::default();

        let rng = &mut rand::thread_rng();
        let a_ptr: u32 = 0u32;
        let b_ptr: u32 = 100u32;

        let clk: u32 = 10u32;
        let shard: u32 = 0u32;

        // Length of vectors (must be <= MAX_VECTOR_LEN)
        let len: usize = 32;

        // Generate random vectors
        let a: Vec<u32> = (0..len).map(|_| rng.gen_range(1..=255)).collect();
        let b: Vec<u32> = (0..len).map(|_| rng.gen_range(1..=255)).collect();

        // Calculate the correct inner product
        let mut correct_sum = 0u32;
        for i in 0..len {
            correct_sum += a[i] * b[i];
        }

        // Use either the correct sum or a random value based on the 'pass' flag
        let result = if pass { correct_sum } else { rng.gen() };

        // Generate memory read records for vector lengths
        let a_len_memory = MemoryReadRecord {
            value: len as u32,
            shard,
            timestamp: clk,
            prev_shard: shard,
            prev_timestamp: clk - 1,
        };

        let b_len_memory = MemoryReadRecord {
            value: len as u32,
            shard,
            timestamp: clk,
            prev_shard: shard,
            prev_timestamp: clk - 1,
        };

        // Generate memory read records for vector elements
        let mut a_memory_records = Vec::new();
        let mut b_memory_records = Vec::new();

        for i in 0..len {
            a_memory_records.push(MemoryReadRecord {
                value: a[i],
                shard,
                timestamp: clk,
                prev_shard: shard,
                prev_timestamp: clk - 1,
            });

            b_memory_records.push(MemoryReadRecord {
                value: b[i],
                shard,
                timestamp: clk,
                prev_shard: shard,
                prev_timestamp: clk - 1,
            });
        }

        // Generate memory write record for the result
        let result_memory_records = MemoryWriteRecord {
            value: result,
            shard,
            timestamp: clk + 1,
            prev_value: 0,
            prev_shard: shard,
            prev_timestamp: clk,
        };

        // Create the inner product event
        let event = PrecompileEvent::InnerProduct(InnerProductEvent {
            shard,
            clk,
            a_ptr,
            b_ptr,
            a,
            b,
            a_len_memory,
            b_len_memory,
            a_memory_records,
            b_memory_records,
            result,
            result_memory_records,
            local_mem_access: Vec::new(),
        });

        // Create the syscall event
        let syscall_code = SyscallCode::INNER_PRODUCT;
        let syscall_event = SyscallEvent {
            pc: 32,
            next_pc: 36,
            shard,
            clk,
            a_record: MemoryWriteRecord::default(),
            a_record_is_real: false,
            op_a_0: false,
            syscall_code,
            syscall_id: syscall_code.syscall_id(),
            arg1: a_ptr,
            arg2: b_ptr,
        };

        // Add the events to the execution record
        execution_record.precompile_events.add_event(syscall_code, syscall_event, event);

        execution_record
    }

    #[test]
    fn test_inner_product_pass() {
        let config = BabyBearPoseidon2::new();
        let execution_record = generate_test_execution_record(true);
        let chip = InnerProductChip::new();
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
    fn test_inner_product_failure() {
        for _ in 0..5 {
            let config = BabyBearPoseidon2::new();
            let execution_record = generate_test_execution_record(false);
            let chip = InnerProductChip::new();
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
