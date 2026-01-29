//! GPU tracegen for memory load chips.

use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::Opcode;
use sp1_core_machine::memory::load::{
    load_byte::{LoadByteChip, NUM_LOAD_BYTE_COLUMNS},
    load_double::{LoadDoubleChip, NUM_LOAD_DOUBLE_COLUMNS},
    load_half::{LoadHalfChip, NUM_LOAD_HALF_COLUMNS},
    load_word::{LoadWordChip, NUM_LOAD_WORD_COLUMNS},
    load_x0::{LoadX0Chip, NUM_LOAD_X0_COLUMNS},
};
use sp1_gpu_cudart::sys::LoadGpuEvent;
use sp1_gpu_cudart::{
    args, DeviceMle, TaskScope, TracegenRiscvLoadByteKernel, TracegenRiscvLoadDoubleKernel,
    TracegenRiscvLoadHalfKernel, TracegenRiscvLoadWordKernel, TracegenRiscvLoadX0Kernel,
};
use sp1_hypercube::air::MachineAir;

use crate::riscv::alu::memory_record_to_gpu;
use crate::{CudaTracegenAir, F};

/// Convert Opcode to GPU opcode value for load instructions.
/// GPU uses: LB=0, LBU=1, LH=2, LHU=3, LW=4, LWU=5, LD=6.
fn opcode_to_gpu_load_variant(opcode: Opcode) -> u8 {
    match opcode {
        Opcode::LB => 0,
        Opcode::LBU => 1,
        Opcode::LH => 2,
        Opcode::LHU => 3,
        Opcode::LW => 4,
        Opcode::LWU => 5,
        Opcode::LD => 6,
        _ => 0,
    }
}

/// Convert a MemInstrEvent + ITypeRecord pair into a LoadGpuEvent.
fn to_load_gpu_event(
    event: &sp1_core_executor::events::MemInstrEvent,
    record: &sp1_core_executor::ITypeRecord,
) -> LoadGpuEvent {
    let mem_prev = event.mem_access.previous_record();
    let mem_curr = event.mem_access.current_record();
    LoadGpuEvent {
        clk: event.clk,
        pc: event.pc,
        b: event.b,
        c: event.c,
        a: event.a,
        opcode: opcode_to_gpu_load_variant(event.opcode),
        mem_access_value: mem_prev.value,
        mem_access_prev_timestamp: mem_prev.timestamp,
        mem_access_current_timestamp: mem_curr.timestamp,
        op_a: record.op_a,
        op_b: record.op_b,
        op_c: record.op_c,
        op_a_0: event.op_a_0,
        mem_a: memory_record_to_gpu(&record.a),
        mem_b: memory_record_to_gpu(&record.b),
    }
}

/// Macro to implement CudaTracegenAir for load chips with common structure.
macro_rules! impl_load_chip_tracegen {
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

                let gpu_events: Vec<LoadGpuEvent> = events
                    .iter()
                    .map(|(mem_event, i_type_record)| to_load_gpu_event(mem_event, i_type_record))
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

impl_load_chip_tracegen!(
    LoadByteChip,
    memory_load_byte_events,
    NUM_LOAD_BYTE_COLUMNS,
    tracegen_riscv_load_byte_kernel
);

impl_load_chip_tracegen!(
    LoadHalfChip,
    memory_load_half_events,
    NUM_LOAD_HALF_COLUMNS,
    tracegen_riscv_load_half_kernel
);

impl_load_chip_tracegen!(
    LoadWordChip,
    memory_load_word_events,
    NUM_LOAD_WORD_COLUMNS,
    tracegen_riscv_load_word_kernel
);

impl_load_chip_tracegen!(
    LoadDoubleChip,
    memory_load_double_events,
    NUM_LOAD_DOUBLE_COLUMNS,
    tracegen_riscv_load_double_kernel
);

impl_load_chip_tracegen!(
    LoadX0Chip,
    memory_load_x0_events,
    NUM_LOAD_X0_COLUMNS,
    tracegen_riscv_load_x0_kernel
);

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::events::{
        MemInstrEvent, MemoryReadRecord, MemoryRecordEnum, MemoryWriteRecord,
    };
    use sp1_core_executor::{ExecutionRecord, ITypeRecord, Opcode};
    use sp1_core_machine::memory::load::{
        load_byte::LoadByteChip, load_double::LoadDoubleChip, load_half::LoadHalfChip,
        load_word::LoadWordChip, load_x0::LoadX0Chip,
    };
    use sp1_gpu_cudart::TaskScope;
    use sp1_hypercube::air::MachineAir;

    use crate::CudaTracegenAir;
    use crate::F;

    fn random_read_record(
        rng: &mut StdRng,
        value: u64,
        timestamp: u64,
    ) -> MemoryRecordEnum {
        let prev_timestamp = rng.gen_range(0..timestamp);
        MemoryRecordEnum::Read(MemoryReadRecord {
            value,
            timestamp,
            prev_timestamp,
            prev_page_prot_record: None,
        })
    }

    fn random_write_record(
        rng: &mut StdRng,
        value: u64,
        timestamp: u64,
    ) -> MemoryRecordEnum {
        let prev_timestamp = rng.gen_range(0..timestamp);
        MemoryRecordEnum::Write(MemoryWriteRecord {
            prev_value: rng.gen(),
            prev_timestamp,
            prev_page_prot_record: None,
            timestamp,
            value,
        })
    }

    /// Generate random load byte events for testing.
    fn generate_load_byte_events(count: usize) -> Vec<(MemInstrEvent, ITypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0x10ADB17E);
        let mut events = Vec::with_capacity(count);
        let base_timestamp: u64 = 0x1_0000_1000;
        let base_pc: u64 = 0x8000_4000_2000;

        for i in 0..count {
            let clk = base_timestamp + (i as u64) * 8;
            let pc = base_pc + (i as u64) * 4;
            let is_signed = (i % 2) == 0;
            let opcode = if is_signed { Opcode::LB } else { Opcode::LBU };

            let base_addr: u64 = rng.gen_range(0x1000..0x1_0000_0000u64);
            let offset: u64 = rng.gen_range(0..256);
            let b = base_addr;
            let c = offset;
            let memory_addr = b.wrapping_add(c);

            let mem_value: u64 = rng.gen();
            let byte_offset = (memory_addr & 7) as usize;
            let byte = ((mem_value >> (byte_offset * 8)) & 0xFF) as u8;

            let a = if is_signed {
                (byte as i8) as i64 as u64
            } else {
                byte as u64
            };

            let op_a: u8 = rng.gen_range(1..32);

            let mem_curr_ts = clk + 3;
            let mem_prev_ts = rng.gen_range(0..mem_curr_ts);

            let mem_access = MemoryRecordEnum::Read(MemoryReadRecord {
                value: mem_value,
                timestamp: mem_curr_ts,
                prev_timestamp: mem_prev_ts,
                prev_page_prot_record: None,
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

    /// Generate random load half events for testing.
    fn generate_load_half_events(count: usize) -> Vec<(MemInstrEvent, ITypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0xA1FFACE);
        let mut events = Vec::with_capacity(count);
        let base_timestamp: u64 = 0x1_0000_1000;
        let base_pc: u64 = 0x8000_4000_2000;

        for i in 0..count {
            let clk = base_timestamp + (i as u64) * 8;
            let pc = base_pc + (i as u64) * 4;
            let is_signed = (i % 2) == 0;
            let opcode = if is_signed { Opcode::LH } else { Opcode::LHU };

            let base_addr: u64 = (rng.gen_range(0x1000..0x1_0000_0000u64)) & !1;
            let offset: u64 = (rng.gen_range(0..256u64)) & !1;
            let b = base_addr;
            let c = offset;
            let memory_addr = b.wrapping_add(c);

            let mem_value: u64 = rng.gen();
            let half_offset = ((memory_addr >> 1) & 3) as usize;
            let half = ((mem_value >> (half_offset * 16)) & 0xFFFF) as u16;

            let a = if is_signed {
                (half as i16) as i64 as u64
            } else {
                half as u64
            };

            let op_a: u8 = rng.gen_range(1..32);
            let mem_curr_ts = clk + 3;
            let mem_prev_ts = rng.gen_range(0..mem_curr_ts);

            let mem_access = MemoryRecordEnum::Read(MemoryReadRecord {
                value: mem_value,
                timestamp: mem_curr_ts,
                prev_timestamp: mem_prev_ts,
                prev_page_prot_record: None,
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

    /// Generate random load word events for testing.
    fn generate_load_word_events(count: usize) -> Vec<(MemInstrEvent, ITypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0xF0EDFACE);
        let mut events = Vec::with_capacity(count);
        let base_timestamp: u64 = 0x1_0000_1000;
        let base_pc: u64 = 0x8000_4000_2000;

        for i in 0..count {
            let clk = base_timestamp + (i as u64) * 8;
            let pc = base_pc + (i as u64) * 4;
            let is_signed = (i % 2) == 0;
            let opcode = if is_signed { Opcode::LW } else { Opcode::LWU };

            let base_addr: u64 = (rng.gen_range(0x1000..0x1_0000_0000u64)) & !3;
            let offset: u64 = (rng.gen_range(0..256u64)) & !3;
            let b = base_addr;
            let c = offset;
            let memory_addr = b.wrapping_add(c);

            let mem_value: u64 = rng.gen();
            let word_offset = ((memory_addr >> 2) & 1) as usize;
            let word = ((mem_value >> (word_offset * 32)) & 0xFFFFFFFF) as u32;

            let a = if is_signed {
                (word as i32) as i64 as u64
            } else {
                word as u64
            };

            let op_a: u8 = rng.gen_range(1..32);
            let mem_curr_ts = clk + 3;
            let mem_prev_ts = rng.gen_range(0..mem_curr_ts);

            let mem_access = MemoryRecordEnum::Read(MemoryReadRecord {
                value: mem_value,
                timestamp: mem_curr_ts,
                prev_timestamp: mem_prev_ts,
                prev_page_prot_record: None,
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

    /// Generate random load double events for testing.
    fn generate_load_double_events(count: usize) -> Vec<(MemInstrEvent, ITypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0xDB1EFACE);
        let mut events = Vec::with_capacity(count);
        let base_timestamp: u64 = 0x1_0000_1000;
        let base_pc: u64 = 0x8000_4000_2000;

        for i in 0..count {
            let clk = base_timestamp + (i as u64) * 8;
            let pc = base_pc + (i as u64) * 4;
            let opcode = Opcode::LD;

            let base_addr: u64 = (rng.gen_range(0x1000..0x1_0000_0000u64)) & !7;
            let offset: u64 = (rng.gen_range(0..256u64)) & !7;
            let b = base_addr;
            let c = offset;

            let mem_value: u64 = rng.gen();
            let a = mem_value;

            let op_a: u8 = rng.gen_range(1..32);
            let mem_curr_ts = clk + 3;
            let mem_prev_ts = rng.gen_range(0..mem_curr_ts);

            let mem_access = MemoryRecordEnum::Read(MemoryReadRecord {
                value: mem_value,
                timestamp: mem_curr_ts,
                prev_timestamp: mem_prev_ts,
                prev_page_prot_record: None,
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

    /// Generate random load x0 events for testing (all load opcodes with op_a = x0).
    fn generate_load_x0_events(count: usize) -> Vec<(MemInstrEvent, ITypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0xA0FACE);
        let mut events = Vec::with_capacity(count);
        let base_timestamp: u64 = 0x1_0000_1000;
        let base_pc: u64 = 0x8000_4000_2000;

        let opcodes = [
            Opcode::LB,
            Opcode::LBU,
            Opcode::LH,
            Opcode::LHU,
            Opcode::LW,
            Opcode::LWU,
            Opcode::LD,
        ];

        for i in 0..count {
            let clk = base_timestamp + (i as u64) * 8;
            let pc = base_pc + (i as u64) * 4;
            let opcode = opcodes[i % opcodes.len()];

            let align_mask: u64 = match opcode {
                Opcode::LB | Opcode::LBU => !0,
                Opcode::LH | Opcode::LHU => !1,
                Opcode::LW | Opcode::LWU => !3,
                Opcode::LD => !7,
                _ => !0,
            };

            let base_addr: u64 = (rng.gen_range(0x1000..0x1_0000_0000u64)) & align_mask;
            let offset: u64 = (rng.gen_range(0..256u64)) & align_mask;
            let b = base_addr;
            let c = offset;

            let mem_value: u64 = rng.gen();
            let a: u64 = 0; // x0 always reads as 0

            let op_a: u8 = 0; // x0
            let mem_curr_ts = clk + 3;
            let mem_prev_ts = rng.gen_range(0..mem_curr_ts);

            let mem_access = MemoryRecordEnum::Read(MemoryReadRecord {
                value: mem_value,
                timestamp: mem_curr_ts,
                prev_timestamp: mem_prev_ts,
                prev_page_prot_record: None,
            });

            let event = MemInstrEvent::new(clk, pc, opcode, a, b, c, true, mem_access);

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

    macro_rules! test_load_chip {
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

    test_load_chip!(
        test_load_byte_generate_trace,
        inner_test_load_byte,
        LoadByteChip,
        generate_load_byte_events,
        memory_load_byte_events,
        "LoadByte"
    );

    test_load_chip!(
        test_load_half_generate_trace,
        inner_test_load_half,
        LoadHalfChip,
        generate_load_half_events,
        memory_load_half_events,
        "LoadHalf"
    );

    test_load_chip!(
        test_load_word_generate_trace,
        inner_test_load_word,
        LoadWordChip,
        generate_load_word_events,
        memory_load_word_events,
        "LoadWord"
    );

    test_load_chip!(
        test_load_double_generate_trace,
        inner_test_load_double,
        LoadDoubleChip,
        generate_load_double_events,
        memory_load_double_events,
        "LoadDouble"
    );

    test_load_chip!(
        test_load_x0_generate_trace,
        inner_test_load_x0,
        LoadX0Chip,
        generate_load_x0_events,
        memory_load_x0_events,
        "LoadX0"
    );
}
