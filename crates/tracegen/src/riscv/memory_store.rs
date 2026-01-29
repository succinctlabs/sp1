//! GPU tracegen for memory store chips.

use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_machine::memory::store::{
    store_byte::{StoreByteChip, NUM_STORE_BYTE_COLUMNS},
    store_double::{StoreDoubleChip, NUM_STORE_DOUBLE_COLUMNS},
    store_half::{StoreHalfChip, NUM_STORE_HALF_COLUMNS},
    store_word::{StoreWordChip, NUM_STORE_WORD_COLUMNS},
};
use sp1_gpu_cudart::sys::StoreGpuEvent;
use sp1_gpu_cudart::{
    args, DeviceMle, TaskScope, TracegenRiscvStoreByteKernel, TracegenRiscvStoreDoubleKernel,
    TracegenRiscvStoreHalfKernel, TracegenRiscvStoreWordKernel,
};
use sp1_hypercube::air::MachineAir;

use crate::riscv::alu::memory_record_to_gpu;
use crate::{CudaTracegenAir, F};

/// Convert a MemInstrEvent + ITypeRecord pair into a StoreGpuEvent.
fn to_store_gpu_event(
    event: &sp1_core_executor::events::MemInstrEvent,
    record: &sp1_core_executor::ITypeRecord,
) -> StoreGpuEvent {
    StoreGpuEvent {
        clk: event.clk,
        pc: event.pc,
        b: event.b,
        c: event.c,
        a: event.a,
        mem_access_prev_value: event.mem_access.prev_value(),
        mem_access_new_value: event.mem_access.value(),
        mem_access_prev_timestamp: event.mem_access.previous_record().timestamp,
        mem_access_current_timestamp: event.mem_access.current_record().timestamp,
        op_a: record.op_a,
        op_b: record.op_b,
        op_c: record.op_c,
        op_a_0: event.op_a_0,
        mem_a: memory_record_to_gpu(&record.a),
        mem_b: memory_record_to_gpu(&record.b),
    }
}

/// Macro to implement CudaTracegenAir for store chips with common structure.
macro_rules! impl_store_chip_tracegen {
    ($chip:ty, $events_field:ident, $num_cols:expr, $kernel_fn:ident) => {
        impl CudaTracegenAir<F> for $chip {
            fn supports_device_main_tracegen(&self) -> bool {
                true
            }

            async fn generate_trace_device(
                &self,
                input: &Self::Record,
                _output: &mut Self::Record,
                scope: &TaskScope,
            ) -> Result<DeviceMle<F>, CopyError> {
                let events = &input.$events_field;
                let events_len = events.len();

                let gpu_events: Vec<StoreGpuEvent> = events
                    .iter()
                    .map(|(mem_event, i_type_record)| to_store_gpu_event(mem_event, i_type_record))
                    .collect();

                let events_device = {
                    let mut buf =
                        Buffer::try_with_capacity_in(gpu_events.len(), scope.clone()).unwrap();
                    buf.extend_from_host_slice(&gpu_events)?;
                    buf
                };

                let height = <Self as MachineAir<F>>::num_rows(self, input)
                    .expect("num_rows(...) should be Some(_)");

                let mut trace =
                    Tensor::<F, TaskScope>::zeros_in([$num_cols, height], scope.clone());

                unsafe {
                    const BLOCK_DIM: usize = 256;
                    let grid_dim = height.div_ceil(BLOCK_DIM);

                    let kernel_args =
                        args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

                    scope
                        .launch_kernel(
                            TaskScope::$kernel_fn(),
                            grid_dim,
                            BLOCK_DIM,
                            &kernel_args,
                            0,
                        )
                        .unwrap();
                }

                Ok(DeviceMle::from(trace))
            }
        }
    };
}

impl_store_chip_tracegen!(
    StoreByteChip,
    memory_store_byte_events,
    NUM_STORE_BYTE_COLUMNS,
    tracegen_riscv_store_byte_kernel
);

impl_store_chip_tracegen!(
    StoreHalfChip,
    memory_store_half_events,
    NUM_STORE_HALF_COLUMNS,
    tracegen_riscv_store_half_kernel
);

impl_store_chip_tracegen!(
    StoreWordChip,
    memory_store_word_events,
    NUM_STORE_WORD_COLUMNS,
    tracegen_riscv_store_word_kernel
);

impl_store_chip_tracegen!(
    StoreDoubleChip,
    memory_store_double_events,
    NUM_STORE_DOUBLE_COLUMNS,
    tracegen_riscv_store_double_kernel
);

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::events::{
        MemInstrEvent, MemoryRecordEnum, MemoryWriteRecord, MemoryReadRecord,
    };
    use sp1_core_executor::{ExecutionRecord, ITypeRecord, Opcode};
    use sp1_core_machine::memory::store::{
        store_byte::StoreByteChip, store_double::StoreDoubleChip, store_half::StoreHalfChip,
        store_word::StoreWordChip,
    };
    use sp1_gpu_cudart::TaskScope;
    use sp1_hypercube::air::MachineAir;

    use crate::CudaTracegenAir;
    use crate::F;

    fn random_read_record(rng: &mut StdRng, value: u64, timestamp: u64) -> MemoryRecordEnum {
        let prev_timestamp = rng.gen_range(0..timestamp);
        MemoryRecordEnum::Read(MemoryReadRecord {
            value,
            timestamp,
            prev_timestamp,
            prev_page_prot_record: None,
        })
    }

    fn random_write_record(rng: &mut StdRng, value: u64, timestamp: u64) -> MemoryRecordEnum {
        let prev_timestamp = rng.gen_range(0..timestamp);
        MemoryRecordEnum::Write(MemoryWriteRecord {
            prev_value: rng.gen(),
            prev_timestamp,
            prev_page_prot_record: None,
            timestamp,
            value,
        })
    }

    /// Generate random store byte events for testing.
    fn generate_store_byte_events(count: usize) -> Vec<(MemInstrEvent, ITypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0x5B17EFACE);
        let mut events = Vec::with_capacity(count);
        let base_timestamp: u64 = 0x1_0000_1000;
        let base_pc: u64 = 0x8000_4000_2000;

        for i in 0..count {
            let clk = base_timestamp + (i as u64) * 8;
            let pc = base_pc + (i as u64) * 4;
            let opcode = Opcode::SB;

            let base_addr: u64 = rng.gen_range(0x1000..0x1_0000_0000u64);
            let offset: u64 = rng.gen_range(0..256);
            let b = base_addr;
            let c = offset;
            let memory_addr = b.wrapping_add(c);

            // Value to store (register a value)
            let a: u64 = rng.gen();

            // Previous memory value (what was there before the store)
            let prev_mem_value: u64 = rng.gen();

            // Compute new memory value: replace one byte in prev_mem_value
            let byte_offset = (memory_addr & 7) as usize;
            let store_byte = (a & 0xFF) as u8;
            let mut new_mem_value = prev_mem_value;
            // Clear the target byte and set the new one
            new_mem_value &= !(0xFFu64 << (byte_offset * 8));
            new_mem_value |= (store_byte as u64) << (byte_offset * 8);

            let op_a: u8 = rng.gen_range(1..32);
            let mem_curr_ts = clk + 3;
            let mem_prev_ts = rng.gen_range(0..mem_curr_ts);

            let mem_access = MemoryRecordEnum::Write(MemoryWriteRecord {
                prev_value: prev_mem_value,
                prev_timestamp: mem_prev_ts,
                prev_page_prot_record: None,
                timestamp: mem_curr_ts,
                value: new_mem_value,
            });

            let event = MemInstrEvent::new(clk, pc, opcode, a, b, c, false, mem_access);

            let record = ITypeRecord {
                op_a,
                a: random_write_record(&mut rng, a, clk + 4),
                op_b: rng.gen_range(0..32),
                b: random_read_record(&mut rng, b, clk + 1),
                op_c: c,
                is_untrusted: false,
            };

            events.push((event, record));
        }

        events
    }

    /// Generate random store half events for testing.
    fn generate_store_half_events(count: usize) -> Vec<(MemInstrEvent, ITypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0x5A1FFACE);
        let mut events = Vec::with_capacity(count);
        let base_timestamp: u64 = 0x1_0000_1000;
        let base_pc: u64 = 0x8000_4000_2000;

        for i in 0..count {
            let clk = base_timestamp + (i as u64) * 8;
            let pc = base_pc + (i as u64) * 4;
            let opcode = Opcode::SH;

            let base_addr: u64 = (rng.gen_range(0x1000..0x1_0000_0000u64)) & !1;
            let offset: u64 = (rng.gen_range(0..256u64)) & !1;
            let b = base_addr;
            let c = offset;
            let memory_addr = b.wrapping_add(c);

            let a: u64 = rng.gen();
            let prev_mem_value: u64 = rng.gen();

            // Compute new memory value: replace one u16 limb
            let half_offset = ((memory_addr >> 1) & 3) as usize;
            let store_half = (a & 0xFFFF) as u16;
            let mut new_mem_value = prev_mem_value;
            new_mem_value &= !(0xFFFFu64 << (half_offset * 16));
            new_mem_value |= (store_half as u64) << (half_offset * 16);

            let op_a: u8 = rng.gen_range(1..32);
            let mem_curr_ts = clk + 3;
            let mem_prev_ts = rng.gen_range(0..mem_curr_ts);

            let mem_access = MemoryRecordEnum::Write(MemoryWriteRecord {
                prev_value: prev_mem_value,
                prev_timestamp: mem_prev_ts,
                prev_page_prot_record: None,
                timestamp: mem_curr_ts,
                value: new_mem_value,
            });

            let event = MemInstrEvent::new(clk, pc, opcode, a, b, c, false, mem_access);

            let record = ITypeRecord {
                op_a,
                a: random_write_record(&mut rng, a, clk + 4),
                op_b: rng.gen_range(0..32),
                b: random_read_record(&mut rng, b, clk + 1),
                op_c: c,
                is_untrusted: false,
            };

            events.push((event, record));
        }

        events
    }

    /// Generate random store word events for testing.
    fn generate_store_word_events(count: usize) -> Vec<(MemInstrEvent, ITypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0x5EDFACE);
        let mut events = Vec::with_capacity(count);
        let base_timestamp: u64 = 0x1_0000_1000;
        let base_pc: u64 = 0x8000_4000_2000;

        for i in 0..count {
            let clk = base_timestamp + (i as u64) * 8;
            let pc = base_pc + (i as u64) * 4;
            let opcode = Opcode::SW;

            let base_addr: u64 = (rng.gen_range(0x1000..0x1_0000_0000u64)) & !3;
            let offset: u64 = (rng.gen_range(0..256u64)) & !3;
            let b = base_addr;
            let c = offset;
            let memory_addr = b.wrapping_add(c);

            let a: u64 = rng.gen();
            let prev_mem_value: u64 = rng.gen();

            // Compute new memory value: replace one u32 word
            let word_offset = ((memory_addr >> 2) & 1) as usize;
            let store_word = (a & 0xFFFFFFFF) as u32;
            let mut new_mem_value = prev_mem_value;
            new_mem_value &= !(0xFFFFFFFFu64 << (word_offset * 32));
            new_mem_value |= (store_word as u64) << (word_offset * 32);

            let op_a: u8 = rng.gen_range(1..32);
            let mem_curr_ts = clk + 3;
            let mem_prev_ts = rng.gen_range(0..mem_curr_ts);

            let mem_access = MemoryRecordEnum::Write(MemoryWriteRecord {
                prev_value: prev_mem_value,
                prev_timestamp: mem_prev_ts,
                prev_page_prot_record: None,
                timestamp: mem_curr_ts,
                value: new_mem_value,
            });

            let event = MemInstrEvent::new(clk, pc, opcode, a, b, c, false, mem_access);

            let record = ITypeRecord {
                op_a,
                a: random_write_record(&mut rng, a, clk + 4),
                op_b: rng.gen_range(0..32),
                b: random_read_record(&mut rng, b, clk + 1),
                op_c: c,
                is_untrusted: false,
            };

            events.push((event, record));
        }

        events
    }

    /// Generate random store double events for testing.
    fn generate_store_double_events(count: usize) -> Vec<(MemInstrEvent, ITypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0x5DB1EFACE);
        let mut events = Vec::with_capacity(count);
        let base_timestamp: u64 = 0x1_0000_1000;
        let base_pc: u64 = 0x8000_4000_2000;

        for i in 0..count {
            let clk = base_timestamp + (i as u64) * 8;
            let pc = base_pc + (i as u64) * 4;
            let opcode = Opcode::SD;

            let base_addr: u64 = (rng.gen_range(0x1000..0x1_0000_0000u64)) & !7;
            let offset: u64 = (rng.gen_range(0..256u64)) & !7;
            let b = base_addr;
            let c = offset;

            let a: u64 = rng.gen();
            let prev_mem_value: u64 = rng.gen();
            // SD writes the full 64-bit register value
            let new_mem_value = a;

            let op_a: u8 = rng.gen_range(1..32);
            let mem_curr_ts = clk + 3;
            let mem_prev_ts = rng.gen_range(0..mem_curr_ts);

            let mem_access = MemoryRecordEnum::Write(MemoryWriteRecord {
                prev_value: prev_mem_value,
                prev_timestamp: mem_prev_ts,
                prev_page_prot_record: None,
                timestamp: mem_curr_ts,
                value: new_mem_value,
            });

            let event = MemInstrEvent::new(clk, pc, opcode, a, b, c, false, mem_access);

            let record = ITypeRecord {
                op_a,
                a: random_write_record(&mut rng, a, clk + 4),
                op_b: rng.gen_range(0..32),
                b: random_read_record(&mut rng, b, clk + 1),
                op_c: c,
                is_untrusted: false,
            };

            events.push((event, record));
        }

        events
    }

    macro_rules! test_store_chip {
        ($test_name:ident, $inner_name:ident, $chip:expr, $events_fn:ident, $events_field:ident, $label:expr) => {
            #[tokio::test]
            async fn $test_name() {
                sp1_gpu_cudart::spawn($inner_name).await.unwrap();
            }

            async fn $inner_name(scope: TaskScope) {
                let events = $events_fn(1000);

                let [shard, gpu_shard] = core::array::from_fn(|_| {
                    let mut record = ExecutionRecord::default();
                    record.$events_field = events.clone();
                    record
                });

                let chip = $chip;

                let cpu_start = Instant::now();
                let trace =
                    Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
                let cpu_duration = cpu_start.elapsed();

                let gpu_start = Instant::now();
                let gpu_trace = chip
                    .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
                    .await
                    .expect("should copy events to device successfully")
                    .to_host()
                    .expect("should copy trace to host successfully")
                    .into_guts();
                let gpu_duration = gpu_start.elapsed();

                println!("{} Tracegen timing (1000 events):", $label);
                println!("  CPU: {:?}", cpu_duration);
                println!("  GPU: {:?}", gpu_duration);
                println!(
                    "  Speedup: {:.2}x",
                    cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64()
                );

                crate::tests::test_traces_eq(&trace, &gpu_trace, &events);
            }
        };
    }

    test_store_chip!(
        test_store_byte_generate_trace,
        inner_test_store_byte,
        StoreByteChip,
        generate_store_byte_events,
        memory_store_byte_events,
        "StoreByte"
    );

    test_store_chip!(
        test_store_half_generate_trace,
        inner_test_store_half,
        StoreHalfChip,
        generate_store_half_events,
        memory_store_half_events,
        "StoreHalf"
    );

    test_store_chip!(
        test_store_word_generate_trace,
        inner_test_store_word,
        StoreWordChip,
        generate_store_word_events,
        memory_store_word_events,
        "StoreWord"
    );

    test_store_chip!(
        test_store_double_generate_trace,
        inner_test_store_double,
        StoreDoubleChip,
        generate_store_double_events,
        memory_store_double_events,
        "StoreDouble"
    );
}
