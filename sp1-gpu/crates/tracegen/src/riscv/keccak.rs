//! Witgen-IR CPU model for the `KeccakPermute` precompile (iter-074).
//!
//! The chip has NO `witgen` DSL gadget: its host tracegen is the p3_keccak_air
//! `generate_trace_rows_for_perm` (bit-level, 2633 columns) plus 7 VM-context
//! columns. This module records the equivalent op-DAG directly against
//! [`RecordingWitnessBuilder`], one row = one round, with a **pack-time
//! permutation replay**: the host packs each of the 24 rows/event with the round's
//! 25-lane input state (the permutation state after `i` rounds), so the per-row
//! program is round-independent and needs no cross-row dataflow.
//!
//! Lane arithmetic maps onto the existing IR orthogonally — NO new tags:
//! - `rotl64(v, n)` = `Shl(v, n) ^ Shr(v, 64-n)` (disjoint bits, Xor == Or),
//! - `andn(a, b)`   = `And(Xor(a, ALL_ONES), b)`,
//! - single-bit / u16-limb columns are `Bits` extractions of the u64 lanes.
//!
//! Padding AND trapped-event rows are the host's cyclic 24-row dummy pattern
//! (zero-state permutation with `clk/addr/index/is_real = 0`), which packs as
//! ordinary rows — the kernel could cover the padded height directly, no host
//! pre-fill or `is_real` masking/guards needed.
//!
//! Dependencies: `KeccakPermuteChip::generate_dependencies` emits ZERO byte
//! lookups (`populate_chunk` discards its blu vec); the memory/global interactions
//! live in the separate `KeccakPermuteControlChip`. So the recorded program is
//! pure column ops — no lookup tags at all (asserted in tests).
//!
//! The `CudaTracegenAir` wiring is deliberately NOT included yet: the pinned slot
//! footprint (~n_cols, >> the 256-slot kernel cap) rules out the pinned kernel and
//! the streaming footprint exceeds the current smem cap of 24, so the kernel
//! strategy (bigger smem cap / per-round subprograms / bespoke kernel) is decided
//! by the measurements in the tests below.
#![allow(dead_code)]

use std::collections::HashMap;

use rayon::prelude::*;
use slop_keccak_air::{NUM_ROUNDS, RC};
use sp1_core_executor::{
    events::{KeccakPermuteEvent, PrecompileEvent},
    ExecutionRecord, SyscallCode, TrapError,
};
use sp1_core_machine::{
    air::{columns_as_wires, RecordingWitnessBuilder, WireId, WitProgram, WitnessBuilder},
    syscall::precompiles::keccak256::columns::KeccakMemCols,
};

/// Number of witgen inputs per Keccak ROW (one round of one permutation):
/// 25 preimage lanes + 25 round-input lanes + round + index-col + rc + clk +
/// state_addr + is_real.
pub(crate) const NUM_KECCAK_INPUTS: usize = 56;

const IN_PREIMAGE: u32 = 0; // ..25
const IN_A: u32 = 25; // ..50
const IN_ROUND: u32 = 50;
const IN_INDEX: u32 = 51;
const IN_RC: u32 = 52;
const IN_CLK: u32 = 53;
const IN_ADDR: u32 = 54;
const IN_IS_REAL: u32 = 55;

/// Keccak rho rotation offsets (p3_keccak_air `constants::R`, which is pub(crate)
/// there): `R[a][b]` rotates lane `a_prime[b][a]` when forming `B(x=a? ...)` — used
/// exactly as `columns.rs::KeccakCols::b` does.
const R: [[u8; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

/// One keccak-f[1600] round in the exact shape of p3's
/// `generate_trace_row_for_round` (lanes stored y-major: `state[y * 5 + x]`).
fn keccak_round(s: &[u64; 25], round: usize) -> [u64; 25] {
    let mut c = [0u64; 5];
    for x in 0..5 {
        c[x] = s[x] ^ s[5 + x] ^ s[10 + x] ^ s[15 + x] ^ s[20 + x];
    }
    let mut cp = [0u64; 5];
    for x in 0..5 {
        cp[x] = c[x] ^ c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
    }
    // A'[y][x] = A[y][x] ^ C[x] ^ C'[x]  (= A ^ D).
    let mut ap = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            ap[y * 5 + x] = s[y * 5 + x] ^ c[x] ^ cp[x];
        }
    }
    // B(x, y) = rotl(A'[b][a], R[a][b]) with a = (x + 3y) % 5, b = x.
    let b = |x: usize, y: usize| -> u64 {
        let a = (x + 3 * y) % 5;
        let bb = x;
        ap[bb * 5 + a].rotate_left(R[a][bb] as u32)
    };
    // A''[y][x] = B(x, y) ^ andn(B(x+1, y), B(x+2, y)).
    let mut app = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            app[y * 5 + x] = b(x, y) ^ (!b((x + 1) % 5, y) & b((x + 2) % 5, y));
        }
    }
    // Iota: A'''[0][0] = A''[0][0] ^ RC[round].
    app[0] ^= RC[round];
    app
}

/// The pack-time permutation replay: the 24 per-round input states of one
/// permutation (`states[i]` = state after `i` rounds; row `i`'s `a` lanes).
pub(crate) fn keccak_round_states(pre_state: &[u64; 25]) -> [[u64; 25]; NUM_ROUNDS] {
    let mut states = [[0u64; 25]; NUM_ROUNDS];
    let mut s = *pre_state;
    for (round, slot) in states.iter_mut().enumerate() {
        *slot = s;
        s = keccak_round(&s, round);
    }
    states
}

/// Cached-constant helper: reuse one `ConstNat` wire per literal.
fn cnat(rec: &mut RecordingWitnessBuilder, cache: &mut HashMap<u64, WireId>, v: u64) -> WireId {
    if let Some(&w) = cache.get(&v) {
        return w;
    }
    let w = rec.const_nat(v);
    cache.insert(v, w);
    w
}

/// `rotl64(v, n)` on the IR: `(v << n) ^ (v >> (64 - n))` — u64 `Shl` drops the
/// high bits, so the two halves are disjoint and `Xor` acts as `Or`. `n = 0` is a
/// no-op (no wires recorded).
fn rotl(
    rec: &mut RecordingWitnessBuilder,
    cache: &mut HashMap<u64, WireId>,
    v: WireId,
    n: u32,
) -> WireId {
    if n == 0 {
        return v;
    }
    let sl = cnat(rec, cache, n as u64);
    let sr = cnat(rec, cache, 64 - n as u64);
    let hi = rec.shl(v, sl);
    let lo = rec.shr(v, sr);
    rec.xor(hi, lo)
}

/// Record the per-row Keccak op-DAG (the IR mirror of p3's
/// `generate_trace_row_for_round` + the SP1 mem columns), returning the program and
/// the column-wire map for `KeccakMemCols`.
pub(crate) fn record_keccak_program() -> (WitProgram, Vec<u32>) {
    let mut rec = RecordingWitnessBuilder::new(NUM_KECCAK_INPUTS as u32);
    let mut cache: HashMap<u64, WireId> = HashMap::new();
    let w = RecordingWitnessBuilder::input;

    // SAFETY: KeccakMemCols is #[repr(C)] over Copy WireId (a u32 newtype); the
    // zeroed pattern is a valid WireId(0) placeholder and every field is assigned
    // below (the column-equality tests would catch a missed one).
    let mut cols: KeccakMemCols<WireId> = unsafe { core::mem::zeroed() };

    let round = w(IN_ROUND);

    // step_flags[r] = (round == r); export is constant 0 in the host tracegen.
    for r in 0..NUM_ROUNDS {
        let rc_w = cnat(&mut rec, &mut cache, r as u64);
        cols.keccak.step_flags[r] = rec.eq(round, rc_w);
    }
    cols.keccak.export = cnat(&mut rec, &mut cache, 0);

    // preimage / a: 4 u16 limbs per lane.
    for y in 0..5 {
        for x in 0..5 {
            let pre = w(IN_PREIMAGE + (y * 5 + x) as u32);
            let a = w(IN_A + (y * 5 + x) as u32);
            for limb in 0..4 {
                cols.keccak.preimage[y][x][limb] = rec.bits(pre, 16 * limb as u32, 16);
                cols.keccak.a[y][x][limb] = rec.bits(a, 16 * limb as u32, 16);
            }
        }
    }

    // C[x] = xor_y A[y][x]; columns are its 64 bits.
    let mut c_lane = [WireId(0); 5];
    for x in 0..5 {
        let mut acc = w(IN_A + x as u32);
        for y in 1..5 {
            let a = w(IN_A + (y * 5 + x) as u32);
            acc = rec.xor(acc, a);
        }
        c_lane[x] = acc;
        for z in 0..64 {
            cols.keccak.c[x][z] = rec.bits(acc, z as u32, 1);
        }
    }

    // C'[x] = C[x] ^ C[x-1] ^ rotl1(C[x+1]); columns are its 64 bits.
    let mut cp_lane = [WireId(0); 5];
    for x in 0..5 {
        let rot = rotl(&mut rec, &mut cache, c_lane[(x + 1) % 5], 1);
        let t = rec.xor(c_lane[x], c_lane[(x + 4) % 5]);
        let cp = rec.xor(t, rot);
        cp_lane[x] = cp;
        for z in 0..64 {
            cols.keccak.c_prime[x][z] = rec.bits(cp, z as u32, 1);
        }
    }

    // A'[y][x] = A[y][x] ^ C[x] ^ C'[x]; columns are its 64 bits (1600 columns).
    let mut ap_lane = [[WireId(0); 5]; 5];
    for y in 0..5 {
        for x in 0..5 {
            let a = w(IN_A + (y * 5 + x) as u32);
            let t = rec.xor(a, c_lane[x]);
            let ap = rec.xor(t, cp_lane[x]);
            ap_lane[y][x] = ap;
            for z in 0..64 {
                cols.keccak.a_prime[y][x][z] = rec.bits(ap, z as u32, 1);
            }
        }
    }

    // B(x, y) = rotl(A'[b][a], R[a][b]), a = (x + 3y) % 5, b = x — each A' lane is
    // rotated exactly once, so compute the 25 B lanes up front.
    let mut b_lane = [[WireId(0); 5]; 5];
    for x in 0..5 {
        for y in 0..5 {
            let a = (x + 3 * y) % 5;
            let b = x;
            b_lane[x][y] = rotl(&mut rec, &mut cache, ap_lane[b][a], R[a][b] as u32);
        }
    }

    // A''[y][x] = B(x, y) ^ (!B(x+1, y) & B(x+2, y)); columns are its 4 u16 limbs.
    let ones = cnat(&mut rec, &mut cache, u64::MAX);
    let mut app_lane = [[WireId(0); 5]; 5];
    for y in 0..5 {
        for x in 0..5 {
            let not_b1 = rec.xor(b_lane[(x + 1) % 5][y], ones);
            let andn = rec.and(not_b1, b_lane[(x + 2) % 5][y]);
            let app = rec.xor(b_lane[x][y], andn);
            app_lane[y][x] = app;
            for limb in 0..4 {
                cols.keccak.a_prime_prime[y][x][limb] = rec.bits(app, 16 * limb as u32, 16);
            }
        }
    }

    // A''[0][0] bit decomposition (64 columns).
    for z in 0..64 {
        cols.keccak.a_prime_prime_0_0_bits[z] = rec.bits(app_lane[0][0], z as u32, 1);
    }

    // A'''[0][0] = A''[0][0] ^ RC[round]; RC is packed per-row (pure function of
    // the round index), so iota is one Xor + 4 limb extractions.
    let appp = rec.xor(app_lane[0][0], w(IN_RC));
    for limb in 0..4 {
        cols.keccak.a_prime_prime_prime_0_0_limbs[limb] = rec.bits(appp, 16 * limb as u32, 16);
    }

    // SP1 mem columns: clk split (host: `(clk >> 24) as u32` / `clk & 0xFFFFFF`),
    // 3x16-bit state_addr limbs, and the raw index / is_real inputs.
    let clk = w(IN_CLK);
    cols.clk_high = rec.bits(clk, 24, 32);
    cols.clk_low = rec.bits(clk, 0, 24);
    let addr = w(IN_ADDR);
    cols.state_addr[0] = rec.bits(addr, 0, 16);
    cols.state_addr[1] = rec.bits(addr, 16, 16);
    cols.state_addr[2] = rec.bits(addr, 32, 16);
    cols.index = w(IN_INDEX);
    cols.is_real = w(IN_IS_REAL);

    let col_wires: Vec<u32> = columns_as_wires(&cols).iter().map(|cw| cw.0).collect();
    (rec.finish(), col_wires)
}

/// Pack `n_rows` witgen input rows (24 per event, in event order, then padding).
/// Rows of trapped events AND rows past `events.len() * 24` get the host's dummy
/// pattern: the zero-state permutation with `clk/addr/index/is_real = 0` (the
/// partial final chunk takes the dummy pattern's first `n_rows % 24` rows, exactly
/// like the host's `dummy_chunk[..rounds.len()]` copy).
pub(crate) fn pack_keccak_inputs(
    events: &[(Option<TrapError>, &KeccakPermuteEvent)],
    n_rows: usize,
) -> Vec<u64> {
    let dummy_states = keccak_round_states(&[0u64; 25]);
    let mut inputs = vec![0u64; n_rows * NUM_KECCAK_INPUTS];
    inputs.par_chunks_mut(NUM_ROUNDS * NUM_KECCAK_INPUTS).enumerate().for_each(|(e, chunk)| {
        let real = events.get(e).filter(|(trap, _)| trap.is_none()).map(|(_, ev)| ev);
        let states = real.map(|ev| keccak_round_states(&ev.pre_state));
        for (i, row) in chunk.chunks_mut(NUM_KECCAK_INPUTS).enumerate() {
            match (real, &states) {
                (Some(ev), Some(states)) => {
                    row[..25].copy_from_slice(&ev.pre_state);
                    row[25..50].copy_from_slice(&states[i]);
                    row[IN_ROUND as usize] = i as u64;
                    row[IN_INDEX as usize] = i as u64;
                    row[IN_RC as usize] = RC[i];
                    row[IN_CLK as usize] = ev.clk;
                    row[IN_ADDR as usize] = ev.state_addr;
                    row[IN_IS_REAL as usize] = 1;
                }
                _ => {
                    // Dummy row: zero preimage, zero-state round inputs, and
                    // zero clk/addr/index/is_real — only round + rc are live.
                    row[..25].fill(0);
                    row[25..50].copy_from_slice(&dummy_states[i]);
                    row[IN_ROUND as usize] = i as u64;
                    row[IN_RC as usize] = RC[i];
                }
            }
        }
    });
    inputs
}

/// Collect this shard's KECCAK_PERMUTE events with their trap state.
pub(crate) fn collect_events(
    input: &ExecutionRecord,
) -> Vec<(Option<TrapError>, &KeccakPermuteEvent)> {
    input
        .get_precompile_events(SyscallCode::KECCAK_PERMUTE)
        .iter()
        .map(|(syscall_event, event)| {
            let event = if let PrecompileEvent::KeccakPermute(event) = event {
                event
            } else {
                unreachable!()
            };
            (syscall_event.trap_error, event)
        })
        .collect()
}

use slop_alloc::mem::CopyError;
use slop_tensor::Tensor;
use sp1_core_machine::syscall::precompiles::keccak256::KeccakPermuteChip;
use sp1_gpu_cudart::{DeviceBuffer, DeviceMle, TaskScope};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

impl CudaTracegenAir<F> for KeccakPermuteChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    /// Non-fused path unsupported: Keccak's pinned lowering needs 2641 slots (the
    /// column floor) — it ONLY fits via the streaming fused path. Production always
    /// routes here through `generate_trace_device_with_lookups` because
    /// `supports_device_dependencies` is true.
    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("KeccakPermute device tracegen is fused-only (streaming lowering)")
    }

    async fn generate_trace_device_with_lookups(
        &self,
        input: &Self::Record,
        inputs: Vec<u64>,
        hist: crate::LookupHist,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let (program, col_wires) = record_keccak_program();
        let n_cols = col_wires.len();
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");
        // The pack covers the FULL padded height (trapped + padding rows carry the
        // host's cyclic dummy pattern), so every row is a kernel row.
        let n_rows = if height == 0 { 0 } else { inputs.len() / program.num_inputs as usize };
        debug_assert!(n_rows == 0 || n_rows == height);
        let trace = Tensor::<F, TaskScope>::zeros_in([n_cols, height], scope.clone());
        super::generate_trace_and_lookups_slots_into(
            &program, &col_wires, &inputs, n_rows, height, trace, hist, scope,
        )
        .await
    }

    /// Keccak's `generate_dependencies` emits ZERO byte lookups (its interactions
    /// live in the KeccakPermuteControlChip), so the device dependency path is
    /// trivially empty — declaring support routes the chip through the fused path
    /// and correctly skips the host dependency pass.
    fn supports_device_dependencies(&self) -> bool {
        true
    }

    async fn generate_device_dependencies(
        &self,
        _input: &Self::Record,
        _range_dev: &mut DeviceBuffer<u32>,
        _byte_dev: &mut DeviceBuffer<u32>,
        _scope: &TaskScope,
    ) -> Result<(), CopyError> {
        Ok(()) // no byte/range lookups
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_core_executor::{
        events::{KeccakPermuteEvent, PrecompileEvent, SyscallEvent},
        ExecutionRecord, SyscallCode, TrapError,
    };
    use sp1_core_machine::air::{
        interpret_c_columns, interpret_c_slots_columns, interpret_c_slots_streaming_columns, WitOp,
    };
    use sp1_core_machine::syscall::precompiles::keccak256::{
        columns::NUM_KECCAK_MEM_COLS, KeccakPermuteChip,
    };
    use sp1_hypercube::air::MachineAir;

    use crate::F;

    /// `n_real` untrapped + `n_trapped` trapped KECCAK_PERMUTE events.
    fn synth_shard(n_real: usize, n_trapped: usize, seed: u64) -> ExecutionRecord {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut record = ExecutionRecord::default();
        for e in 0..(n_real + n_trapped) {
            let trapped = e >= n_real;
            let clk = (e as u64 + 1) * 1_000_000 + 17;
            let state_addr = (rng.gen::<u64>() & 0xFF_FFFF_FFFF) & !7;
            let pre_state: [u64; 25] = core::array::from_fn(|_| rng.gen::<u64>());
            let post_state = {
                let states = super::keccak_round_states(&pre_state);
                super::keccak_round(&states[23], 23)
            };
            let event = KeccakPermuteEvent {
                clk,
                pre_state,
                post_state,
                state_read_records: Vec::new(),
                state_write_records: Vec::new(),
                state_addr,
                local_mem_access: Vec::new(),
                page_prot_records: Default::default(),
                local_page_prot_access: Vec::new(),
            };
            let syscall_event = SyscallEvent {
                pc: 4,
                next_pc: 8,
                clk,
                should_send: true,
                syscall_code: SyscallCode::KECCAK_PERMUTE,
                syscall_id: SyscallCode::KECCAK_PERMUTE.syscall_id(),
                arg1: state_addr,
                arg2: 0,
                exit_code: 0,
                sig_return_pc_record: None,
                trap_result: None,
                trap_error: trapped.then_some(TrapError::PagePermissionViolation(2)),
            };
            record.precompile_events.add_event(
                SyscallCode::KECCAK_PERMUTE,
                syscall_event,
                PrecompileEvent::KeccakPermute(event),
            );
        }
        record
    }

    /// Columns from the recorded op-DAG must equal the host trace bit-for-bit over
    /// the FULL padded height — real rows, trapped-event dummy rows, and the
    /// (partial-chunk) padding rows — on the SSA, pinned-slot, and streaming
    /// interpreters. Also prints the kernel-strategy decision numbers.
    #[test]
    fn keccak_columns_match_host() {
        // 5 events (4 real + 1 trapped) = 120 rows -> padded 128: 8 partial-chunk
        // padding rows exercise the `dummy_chunk[..len]` tail.
        let shard = synth_shard(4, 1, 0x4ECCA4);
        let chip = KeccakPermuteChip;
        let trace = MachineAir::<F>::generate_trace(&chip, &shard, &mut ExecutionRecord::default());
        let width = NUM_KECCAK_MEM_COLS;
        let height = trace.values.len() / width;

        let (program, col_wires) = super::record_keccak_program();
        assert_eq!(col_wires.len(), NUM_KECCAK_MEM_COLS);

        // Decision numbers for the kernel strategy.
        let (slot, max_slots) = program.allocate_slots(&col_wires);
        let (s_slot, s_max, epi) = program.allocate_slots_streaming(&col_wires);
        println!(
            "Keccak: ops/row={} num_wires={} n_cols={} pinned_max_slots={max_slots} \
             streaming_max_slots={s_max} epilogue={}",
            program.ops.len(),
            program.num_wires(),
            col_wires.len(),
            epi.len(),
        );
        // No lookup ops at all (deps are empty; see the dependencies test).
        assert!(program.ops.iter().all(WitOp::produces_wire), "unexpected lookup op");

        let ni = super::NUM_KECCAK_INPUTS;
        let ops_c = program.to_c();
        let ops_slots = program.to_c_slots(&slot);
        let input_slots = &slot[..ni];
        let col_slots: Vec<u32> = col_wires.iter().map(|&w| slot[w as usize]).collect();
        let (ops_stream, input_cols) = program.to_c_slots_streaming(&s_slot, &col_wires);
        let s_input_slots = &s_slot[..ni];

        let events = super::collect_events(&shard);
        let inputs = super::pack_keccak_inputs(&events, height);
        for row in 0..height {
            let row_in = &inputs[row * ni..(row + 1) * ni];
            let cols: Vec<F> = interpret_c_columns(&ops_c, ni as u32, row_in, &col_wires);
            assert_eq!(
                &trace.values[row * width..(row + 1) * width],
                &cols[..],
                "column mismatch at row {row}"
            );
            let flat: Vec<F> = interpret_c_slots_columns(
                &ops_slots,
                ni as u32,
                row_in,
                input_slots,
                &col_slots,
                max_slots,
            );
            assert_eq!(cols, flat, "pinned-slot column mismatch at row {row}");
            let streamed: Vec<F> = interpret_c_slots_streaming_columns(
                &ops_stream,
                ni as u32,
                row_in,
                s_input_slots,
                &input_cols,
                &epi,
                width,
                s_max,
            );
            assert_eq!(cols, streamed, "streaming column mismatch at row {row}");
        }
    }

    /// The pack-time replay must reproduce the executor's post_state (keccak-f).
    #[test]
    fn keccak_replay_matches_permutation() {
        let mut rng = StdRng::seed_from_u64(0x5EED);
        for _ in 0..8 {
            let pre: [u64; 25] = core::array::from_fn(|_| rng.gen::<u64>());
            let states = super::keccak_round_states(&pre);
            let post = super::keccak_round(&states[23], 23);
            let mut expected = pre;
            tiny_keccak::keccakf(&mut expected);
            assert_eq!(post, expected, "replay != keccak-f");
        }
    }

    /// KeccakPermute's `generate_dependencies` emits NO byte lookups (its
    /// `populate_chunk` discards the blu vec; interactions live in the separate
    /// control chip) — so the device dependency path is trivially empty and the
    /// recorded program must contain no lookup ops.
    #[test]
    fn keccak_dependencies_are_empty() {
        let shard = synth_shard(3, 0, 0xDE9);
        let chip = KeccakPermuteChip;
        let mut dep_out = ExecutionRecord::default();
        MachineAir::<F>::generate_dependencies(&chip, &shard, &mut dep_out);
        assert!(dep_out.byte_lookups.is_empty(), "expected no byte lookups");

        let (program, _) = super::record_keccak_program();
        assert!(
            program.ops.iter().all(sp1_core_machine::air::WitOp::produces_wire),
            "recorded program should have no lookup ops"
        );
    }
}
