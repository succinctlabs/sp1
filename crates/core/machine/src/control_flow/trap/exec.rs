use hashbrown::HashMap;
use itertools::Itertools;
use rayon::iter::{ParallelBridge, ParallelIterator};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode, ExecutionRecord, Program, CLK_INC,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::MachineAir;
use sp1_primitives::consts::{PROT_EXEC, PROT_FAILURE_EXEC, PROT_FAILURE_READ, PROT_READ};
use std::borrow::{Borrow, BorrowMut};
use std::mem::{size_of, MaybeUninit};

use crate::{
    adapter::state::{CPUState, CPUStateInput},
    air::{SP1CoreAirBuilder, SP1Operation},
    operations::{PageProtOperation, TrapOperation},
    utils::next_multiple_of_32,
};
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
#[cfg(feature = "mprotect")]
use sp1_hypercube::addr_to_limbs;

/// The number of main trace columns for `TrapExecChip`.
pub const NUM_TRAP_EXEC_COLS: usize = size_of::<TrapExecColumns<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct TrapExecColumns<T> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The operation to get the page permission.
    pub page_prot_operation: PageProtOperation<T>,

    /// The operation to handle the trap.
    pub trap_operation: TrapOperation<T>,

    /// Addresses for the trap context. Should be removed after GKR supports public values.
    pub addresses: [[T; 3]; 3],

    /// Whether or not `PROT_EXEC` failed.
    pub prot_exec_fail: T,

    /// Whether or not `PROT_READ` failed.
    pub prot_read_fail: T,

    /// The trap code.
    pub trap_code: T,

    /// Whether or not the current row is a real row.
    pub is_real: T,
}

#[derive(Default)]
pub struct TrapExecChip;

impl<F> BaseAir<F> for TrapExecChip {
    fn width(&self) -> usize {
        NUM_TRAP_EXEC_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for TrapExecChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "TrapExec"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows =
            next_multiple_of_32(input.trap_exec_events.len(), input.fixed_log2_rows::<F, _>(self));
        Some(nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let chunk_size = std::cmp::max((input.trap_exec_events.len()) / num_cpus::get(), 1);
        let padded_nb_rows = <TrapExecChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let width = <TrapExecChip as BaseAir<F>>::width(self);
        let num_event_rows = input.trap_exec_events.len();

        unsafe {
            let padding_start = num_event_rows * width;
            let padding_size = (padded_nb_rows - num_event_rows) * width;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe { core::slice::from_raw_parts_mut(buffer_ptr, padded_nb_rows * width) };

        let blu_events = values
            .chunks_mut(chunk_size * width)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(width).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut TrapExecColumns<F> = row.borrow_mut();

                    if idx < input.trap_exec_events.len() {
                        let event = &input.trap_exec_events[idx];
                        cols.state.populate(&mut blu, event.clk, event.pc);
                        cols.page_prot_operation.populate(
                            &mut blu,
                            event.pc,
                            event.clk,
                            &event.page_prot_record,
                        );
                        cols.trap_operation.populate(&mut blu, event.trap_result);
                        let perm = event.page_prot_record.page_prot;
                        cols.trap_code = F::from_canonical_u64(event.trap_result.code_record.value);
                        cols.prot_read_fail = F::from_bool((perm & PROT_READ) == 0);
                        cols.prot_exec_fail = F::from_bool((perm & PROT_EXEC) == 0);
                        blu.add_byte_lookup_event(ByteLookupEvent {
                            opcode: ByteOpcode::AND,
                            a: (perm & (PROT_READ | PROT_EXEC)) as u16,
                            b: perm,
                            c: (PROT_READ | PROT_EXEC),
                        });
                        #[cfg(feature = "mprotect")]
                        for i in 0..3 {
                            cols.addresses[i] = addr_to_limbs(input.public_values.trap_context[i]);
                        }
                        blu.add_u16_range_check((event.pc & 0xFFFF) as u16);
                        blu.add_u16_range_check(((event.pc >> 16) & 0xFFFF) as u16);
                        blu.add_u16_range_check(((event.pc >> 32) & 0xFFFF) as u16);
                        cols.is_real = F::one();
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.trap_exec_events.is_empty()
        }
    }
}

impl<AB> Air<AB> for TrapExecChip
where
    AB: SP1CoreAirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TrapExecColumns<AB::Var> = (*local).borrow();

        // Check that `is_real` is boolean.
        builder.assert_bool(local.is_real);

        // Range check that the `pc` are all valid u16 limbs.
        builder.slice_range_check_u16(&local.state.pc, local.is_real);

        #[cfg(not(feature = "mprotect"))]
        builder.assert_zero(local.is_real);

        // Read the currently set page permissions.
        PageProtOperation::<AB::F>::eval(
            builder,
            local.state.clk_high::<AB>(),
            local.state.clk_low::<AB>(),
            &local.state.pc.map(Into::into),
            local.page_prot_operation,
            local.is_real.into(),
        );

        // Check that `prot_exec_fail` and `prot_read_fail` are boolean flags.
        builder.assert_bool(local.prot_exec_fail);
        builder.assert_bool(local.prot_read_fail);
        // At least one of the permissions must fail.
        builder.when(local.is_real).assert_zero(
            (AB::Expr::one() - local.prot_exec_fail) * (AB::Expr::one() - local.prot_read_fail),
        );

        // Check the flags with an `OR` lookup.
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::AND as u8),
            AB::Expr::from_canonical_u8(PROT_EXEC) * (AB::Expr::one() - local.prot_exec_fail)
                + AB::Expr::from_canonical_u8(PROT_READ) * (AB::Expr::one() - local.prot_read_fail),
            local.page_prot_operation.page_prot_access.prev_prot_bitmap.into(),
            AB::Expr::from_canonical_u8(PROT_EXEC | PROT_READ),
            local.is_real.into(),
        );

        // If `PROT_EXEC` fails, the trap code is `PROT_FAILURE_EXEC`.
        builder
            .when(local.prot_exec_fail)
            .assert_eq(local.trap_code, AB::Expr::from_canonical_u64(PROT_FAILURE_EXEC));

        // If `PROT_EXEC` succeeds but `PROT_READ` fails, the trap code is `PROT_FAILURE_READ`.
        builder
            .when_not(local.prot_exec_fail)
            .when(local.prot_read_fail)
            .assert_eq(local.trap_code, AB::Expr::from_canonical_u64(PROT_FAILURE_READ));

        let next_pc = TrapOperation::<AB::F>::eval(
            builder,
            local.trap_operation,
            local.state.clk_high::<AB>(),
            local.state.clk_low::<AB>(),
            local.trap_code.into(),
            local.state.pc.map(Into::into),
            local.addresses,
            local.is_real.into(),
        );

        // Constrain the state of the CPU.
        // The `next_pc` is constrained by the AIR.
        // The clock is incremented by `8`.
        <CPUState<AB::F> as SP1Operation<AB>>::eval(
            builder,
            CPUStateInput::new(
                local.state,
                [next_pc[0].into(), next_pc[1].into(), next_pc[2].into()],
                AB::Expr::from_canonical_u32(CLK_INC),
                local.is_real.into(),
            ),
        );
    }
}
