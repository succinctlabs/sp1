use core::{borrow::Borrow, marker::PhantomData, mem::size_of, mem::MaybeUninit};
use std::iter::repeat;

use generic_array::GenericArray;
use itertools::{repeat_n, Itertools};
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{
        ByteLookupEvent, ECMulInternalAddEvent, ECMulInternalDoubleEvent, EllipticCurveMulEvent,
        MemoryReadRecord, MemoryRecordEnum,
    },
    ExecutionRecord, Program, SupervisorMode, SyscallCode, UserMode,
};
use sp1_curves::{
    params::{FieldParameters, Limbs, NumBits, NumLimbs, NumWords, NB_BITS_PER_LIMB},
    weierstrass::WeierstrassParameters,
    CurveType, EllipticCurve,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{InteractionScope, MachineAir},
    Word,
};
use sp1_primitives::consts::{PROT_READ, PROT_WRITE};
use typenum::Unsigned;

use crate::{
    air::SP1CoreAirBuilder,
    memory::MemoryAccessColsU8,
    operations::{AddrAddOperation, AddressSlicePageProtOperation, SyscallAddrOperation},
    syscall::precompiles::weierstrass::weierstrass_mul::{
        affine_add, affine_double, event_words_to_limbs,
        interactions::{ec_identity, internal_add_call, internal_double_call, internal_memory_rw},
        limbs_to_event_words,
    },
    utils::limbs_to_words,
    TrustMode,
};

/// Columns for a Weierstrass scalar-multiplication chip.
/// This is implemented as a controller chip that calls some internal chips.
///
/// TODO: lay out the columns required to constrain `p ← scalar * p`.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassMulAssignCols<T, P: FieldParameters + NumWords + NumBits, M: TrustMode> {
    /// Whether this row corresponds to a real syscall invocation.
    pub is_real: T,
    // Clock
    pub clk_high: T,
    pub clk_low: T,
    // Memory rw handling (note that the access columns contain the read values)
    pub exp_ptr: SyscallAddrOperation<T>,
    pub p_ptr: SyscallAddrOperation<T>,
    pub exp_addrs: GenericArray<AddrAddOperation<T>, P::WordsFieldElement>,
    pub p_addrs: GenericArray<AddrAddOperation<T>, P::WordsCurvePoint>,
    pub exp_access: GenericArray<MemoryAccessColsU8<T>, P::WordsFieldElement>,
    pub p_access: GenericArray<MemoryAccessColsU8<T>, P::WordsCurvePoint>,
    pub read_slice_page_prot_access: M::SliceProtCols<T>,
    pub write_slice_page_prot_access: M::SliceProtCols<T>,
    // Final output state
    pub ord_x: Limbs<T, <P as NumLimbs>::Limbs>,
    pub ord_y: Limbs<T, <P as NumLimbs>::Limbs>,
    pub ort_x: Limbs<T, <P as NumLimbs>::Limbs>,
    pub ort_y: Limbs<T, <P as NumLimbs>::Limbs>,
    // For internal dispatch to the Add / Double chips.
    pub exp_bits: GenericArray<T, P::BitsFieldElement>,
    // Columns for first add chip merged into controller
    pub c_at_first_add: T,
    pub ird_at_first_add_x: Limbs<T, <P as NumLimbs>::Limbs>,
    pub ird_at_first_add_y: Limbs<T, <P as NumLimbs>::Limbs>,
}

pub const fn num_weierstrass_mul_cols_supervisor<P: FieldParameters + NumWords + NumBits>() -> usize
{
    size_of::<WeierstrassMulAssignCols<u8, P, SupervisorMode>>()
}

pub const fn num_weierstrass_mul_cols_user<P: FieldParameters + NumWords + NumBits>() -> usize {
    size_of::<WeierstrassMulAssignCols<u8, P, UserMode>>()
}

/// A chip that constrains scalar multiplication of a Weierstrass curve point by a `u32` scalar.
#[derive(Default)]
pub struct WeierstrassMulAssignChip<E, M: TrustMode> {
    _marker: PhantomData<(E, M)>,
}

impl<E: EllipticCurve + WeierstrassParameters, M: TrustMode> WeierstrassMulAssignChip<E, M> {
    pub const fn new() -> Self {
        Self { _marker: PhantomData }
    }

    pub fn populate_row<F: PrimeField32>(
        event: &EllipticCurveMulEvent,
        cols: &mut WeierstrassMulAssignCols<F, E::BaseField, M>,
        new_byte_lookup_events: &mut Vec<ByteLookupEvent>,
        add_sender: &std::sync::mpsc::Sender<ECMulInternalAddEvent>,
        double_sender: &std::sync::mpsc::Sender<ECMulInternalDoubleEvent>,
    ) {
        // is_real and clock
        cols.is_real = F::one();
        cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
        cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);

        // pointers + syscall handling
        cols.p_ptr.populate(new_byte_lookup_events, event.p_ptr, E::NB_LIMBS as u64 * 2);
        cols.exp_ptr.populate(new_byte_lookup_events, event.exp_ptr, E::NB_LIMBS as u64 * 2);

        // Mprotect
        let mut is_not_trap = true;
        let mut trap_code = 0u8;
        if !M::IS_TRUSTED {
            let cols: &mut WeierstrassMulAssignCols<F, E::BaseField, UserMode> =
                unsafe { &mut *(cols as *mut _ as *mut _) };
            cols.read_slice_page_prot_access.populate(
                new_byte_lookup_events,
                event.exp_ptr,
                event.exp_ptr + 8 * (cols.exp_addrs.len() - 1) as u64,
                event.clk,
                PROT_READ,
                &event.page_prot_records.read_page_prot_records,
                &mut is_not_trap,
                &mut trap_code,
            );

            cols.write_slice_page_prot_access.populate(
                new_byte_lookup_events,
                event.p_ptr,
                event.p_ptr + 8 * (cols.p_addrs.len() - 1) as u64,
                event.clk + 1,
                PROT_READ | PROT_WRITE,
                &event.page_prot_records.write_page_prot_records,
                &mut is_not_trap,
                &mut trap_code,
            );
        }

        // Populate the memory access columns.
        for i in 0..cols.exp_access.len() {
            cols.exp_addrs[i].populate(new_byte_lookup_events, event.exp_ptr, 8 * i as u64);
            if is_not_trap {
                let record = MemoryRecordEnum::Read(event.exp_memory_records[i]);
                cols.exp_access[i].populate(record, new_byte_lookup_events);
            } else {
                cols.exp_access[i] = MemoryAccessColsU8::default();
            }
        }
        for i in 0..cols.p_access.len() {
            cols.p_addrs[i].populate(new_byte_lookup_events, event.p_ptr, 8 * i as u64);
            if is_not_trap {
                let record = MemoryRecordEnum::Write(event.p_memory_records[i]);
                cols.p_access[i].populate(record, new_byte_lookup_events);
            } else {
                cols.p_access[i] = MemoryAccessColsU8::default();
            }
        }

        // Reconstruct output values from memory write records
        let half = event.p_memory_records.len() / 2;
        cols.ort_x = event.p_memory_records[..half]
            .iter()
            .flat_map(|r| r.value.to_le_bytes())
            .map(F::from_canonical_u8)
            .collect();
        cols.ort_y = event.p_memory_records[half..]
            .iter()
            .flat_map(|r| r.value.to_le_bytes())
            .map(F::from_canonical_u8)
            .collect();
        // Reconstruct final ord values TODO, need to figure out how to avoid redundancy with internal chips

        // Get bits of exponent
        let exp_bits: Vec<bool> = event
            .exp_memory_records
            .iter()
            .flat_map(|r| -> [bool; 64] {
                let value = r.value;
                core::array::from_fn(|i| ((value >> i) & 1 == 1) && is_not_trap)
            })
            .collect();
        cols.exp_bits = exp_bits.iter().map(|b| F::from_canonical_u8(*b as u8)).collect();

        // Trapped rows emit no internal add/double events and have no meaningful
        // intermediate state to populate.
        if !is_not_trap {
            return;
        }

        // Walk the standard double-and-add chain in the same order as the AIR:
        //   sum(0), double(0), sum(1), double(1), ..., double(n-2), sum(n-1).
        // - `sum(i)` (i.e., add(i)) fires only when `b_i == 1`. The very first such
        //   add cannot be handled by the internal-add chip because the running
        //   total is the EC identity at that point; the controller absorbs that
        //   one itself via the `c_at_first_add` / `ird_at_first_add_*` columns.
        // - `double(i)` is sent for every `i < n - 1` (the last double is always
        //   skipped — the chain ends on the n-1th add slot).
        //
        // c-values mirror the AIR:
        //   add(i)    → c = i + S_{i-1}    (carries `first_add_marker = S_{i-1}`)
        //   double(i) → c = i + S_i
        // where S_i = b_0 + b_1 + ... + b_i, S_{-1} = 0.
        let exp_num_bits = exp_bits.len();
        let half = event.p.len() / 2;
        let mut doubler_x: Limbs<F, <E::BaseField as NumLimbs>::Limbs> =
            event_words_to_limbs(&event.p[..half]);
        let mut doubler_y: Limbs<F, <E::BaseField as NumLimbs>::Limbs> =
            event_words_to_limbs(&event.p[half..]);
        // Running total starts as the EC identity. The first add never reaches
        // `affine_add` (the controller handles it directly), and every subsequent
        // add overwrites `total_*` before reading the previous identity value, so
        // a zero placeholder here is sufficient for both the channel payloads and
        // the affine-add inputs.
        let mut total_x: Limbs<F, <E::BaseField as NumLimbs>::Limbs> = Default::default();
        let mut total_y: Limbs<F, <E::BaseField as NumLimbs>::Limbs> = Default::default();
        let mut s_prev: u16 = 0;

        for (i, &b_i) in exp_bits.iter().enumerate() {
            let c_add = i as u16 + s_prev;
            if b_i {
                // `S_{i-1} == 0` is the AIR's own first-add discriminator
                // (`first_add_marker` on the opcode bus).
                if s_prev == 0 {
                    // First add: handled by the controller row, not the internal chip.
                    cols.c_at_first_add = F::from_canonical_u16(c_add);
                    cols.ird_at_first_add_x = doubler_x.clone();
                    cols.ird_at_first_add_y = doubler_y.clone();
                    total_x = doubler_x.clone();
                    total_y = doubler_y.clone();
                } else {
                    // Snapshot ird/irt *before* updating the running total.
                    let mut ird = limbs_to_event_words(&doubler_x);
                    ird.extend(limbs_to_event_words(&doubler_y));
                    let mut irt = limbs_to_event_words(&total_x);
                    irt.extend(limbs_to_event_words(&total_y));
                    add_sender
                        .send(ECMulInternalAddEvent {
                            c: c_add,
                            // `first_add_marker = S_{i-1}`, guaranteed non-zero here.
                            is_first_add: s_prev,
                            ird,
                            irt,
                        })
                        .expect("internal add channel disconnected");

                    let (new_x, new_y) =
                        affine_add::<F, E>(&total_x, &total_y, &doubler_x, &doubler_y);
                    total_x = new_x;
                    total_y = new_y;
                }
            }

            let s_i = s_prev + b_i as u16;
            if i + 1 < exp_num_bits {
                let c_double = i as u16 + s_i;
                let mut ird = limbs_to_event_words(&doubler_x);
                ird.extend(limbs_to_event_words(&doubler_y));
                let mut irt = limbs_to_event_words(&total_x);
                irt.extend(limbs_to_event_words(&total_y));
                double_sender
                    .send(ECMulInternalDoubleEvent { c: c_double, ird, irt })
                    .expect("internal double channel disconnected");

                let (new_x, new_y) = affine_double::<F, E>(&doubler_x, &doubler_y);
                doubler_x = new_x;
                doubler_y = new_y;
            }
            s_prev = s_i;
        }

        // After the loop, `doubler_*` holds 2^(n-1) * P, which is the final output
        // running doubler (`ord`) on the memory bus. `ort_*` was already filled in
        // from the syscall's write-back records above.
        cols.ord_x = doubler_x;
        cols.ord_y = doubler_y;
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters, M: TrustMode> MachineAir<F>
    for WeierstrassMulAssignChip<E, M>
{
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        match (E::CURVE_TYPE, M::IS_TRUSTED) {
            (CurveType::Secp256k1, true) => "Secp256k1MulAssign",
            (CurveType::Secp256k1, false) => "Secp256k1MulAssignUser",
            _ => panic!("Unsupported curve for WeierstrassMulAssignChip"),
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return Some(0);
        }
        let nb_rows = match E::CURVE_TYPE {
            CurveType::Secp256k1 => input.get_precompile_events(SyscallCode::SECP256K1_MUL).len(),
            _ => panic!("Unsupported curve"),
        };
        let padded_nb_rows = nb_rows.next_multiple_of(32).max(16);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        if input.program.enable_untrusted_programs == M::IS_TRUSTED {
            return;
        }
        let padded_nb_rows =
            <WeierstrassMulAssignChip<E, M> as MachineAir<F>>::num_rows(self, input).unwrap();
        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => input.get_precompile_events(SyscallCode::SECP256K1_MUL),
            _ => panic!("Unsupported curve"),
        };

        let num_event_rows = events.len();
        let num_cols = <WeierstrassMulAssignChip<E, M> as BaseAir<F>>::width(self);
        let chunk_size = 64;

        // Padding rows set to all 0
        unsafe {
            let padding_start = num_event_rows * num_cols;
            let padding_size = (padded_nb_rows - num_event_rows) * num_cols;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        todo!()
    }

    fn included(&self, shard: &Self::Record) -> bool {
        // Skeleton: only include the chip variant that matches the program's trust mode, and
        // only when there are events. The real implementation should also honor shard.shape.
        let has_events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                !shard.get_precompile_events(SyscallCode::SECP256K1_MUL).is_empty()
            }
            _ => false,
        };
        has_events && (M::IS_TRUSTED != shard.program.enable_untrusted_programs)
    }
}

impl<F, E: EllipticCurve + WeierstrassParameters, M: TrustMode> BaseAir<F>
    for WeierstrassMulAssignChip<E, M>
{
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            num_weierstrass_mul_cols_supervisor::<E::BaseField>()
        } else {
            num_weierstrass_mul_cols_user::<E::BaseField>()
        }
    }
}

impl<AB, E: EllipticCurve + WeierstrassParameters, M: TrustMode> Air<AB>
    for WeierstrassMulAssignChip<E, M>
where
    AB: SP1CoreAirBuilder,
    Limbs<AB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        //setup
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &WeierstrassMulAssignCols<AB::Var, E::BaseField, M> = (*local).borrow();

        // is_real and trap setup
        builder.assert_bool(local.is_real);
        let mut is_not_trap = local.is_real.into();
        let mut trap_code = AB::Expr::zero();
        let num_words_field_element = <E::BaseField as NumLimbs>::Limbs::USIZE / 8;
        let exp_num_bits = <E::BaseField as NumBits>::BitsFieldElement::USIZE;

        //Mprotect handling
        if !M::IS_TRUSTED {
            // Reborrow with concrete trust mode
            let local = main.row_slice(0);
            let local: &WeierstrassMulAssignCols<AB::Var, E::BaseField, UserMode> =
                (*local).borrow();

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(local.is_real);

            AddressSlicePageProtOperation::<AB::F>::eval(
                builder,
                local.clk_high.into(),
                local.clk_low.into(),
                &local.exp_ptr.addr.map(Into::into),
                &local.exp_addrs[local.exp_addrs.len() - 1].value.map(Into::into),
                PROT_READ,
                &local.read_slice_page_prot_access,
                &mut is_not_trap,
                &mut trap_code,
            );

            AddressSlicePageProtOperation::<AB::F>::eval(
                builder,
                local.clk_high.into(),
                local.clk_low.into() + AB::Expr::one(),
                &local.p_ptr.addr.map(Into::into),
                &local.p_addrs[local.p_addrs.len() - 1].value.map(Into::into),
                PROT_READ | PROT_WRITE,
                &local.write_slice_page_prot_access,
                &mut is_not_trap,
                &mut trap_code,
            );
        }

        // Array indexing of input/output pointers
        let exp_ptr = SyscallAddrOperation::<AB::F>::eval(
            builder,
            E::NB_LIMBS as u32 * 2,
            local.exp_ptr,
            local.is_real.into(),
        );
        let p_ptr = SyscallAddrOperation::<AB::F>::eval(
            builder,
            E::NB_LIMBS as u32 * 2,
            local.p_ptr,
            local.is_real.into(),
        );
        // exp_addrs[i] = exp_ptr + 8 * i
        for i in 0..local.exp_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([exp_ptr[0].into(), exp_ptr[1].into(), exp_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.exp_addrs[i],
                local.is_real.into(),
            );
        }
        // p_addrs[i] = p_ptr + 8 * i
        for i in 0..local.p_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([p_ptr[0].into(), p_ptr[1].into(), p_ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.p_addrs[i],
                local.is_real.into(),
            );
        }

        // Memory rw handling
        builder.eval_memory_access_slice_read(
            local.clk_high,
            local.clk_low.into(),
            &local.exp_addrs.iter().map(|addr| addr.value.map(Into::into)).collect_vec(),
            &local.exp_access.iter().map(|access| access.memory_access).collect_vec(),
            is_not_trap.clone(),
        );
        // Note that the result is range-checked in the internal operations
        let x_result_words = limbs_to_words::<AB>(local.ort_x.0.to_vec());
        let y_result_words = limbs_to_words::<AB>(local.ort_y.0.to_vec());
        let result_words = x_result_words.into_iter().chain(y_result_words).collect_vec();
        builder.eval_memory_access_slice_write(
            local.clk_high,
            local.clk_low + AB::Expr::one(),
            &local.p_addrs.iter().map(|addr| addr.value.map(Into::into)).collect::<Vec<_>>(),
            &local.p_access.iter().map(|access| access.memory_access).collect_vec(),
            result_words,
            is_not_trap.clone(),
        );

        // Syscall handling
        let syscall_id_felt = match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                AB::F::from_canonical_u32(SyscallCode::SECP256K1_MUL.syscall_id())
            }

            _ => panic!("Unsupported curve"),
        };
        builder.receive_syscall(
            local.clk_high,
            local.clk_low.into(),
            syscall_id_felt,
            trap_code.clone(),
            p_ptr.map(Into::into),
            exp_ptr.map(Into::into),
            local.is_real,
            InteractionScope::Local,
        );

        // Exponent bits
        local.exp_bits.iter().for_each(|bit| {
            builder.assert_bool(*bit);
        });
        // Check that they match the exponent limbs
        let two_powers =
            AB::Expr::from_canonical_u8(2).powers().take(NB_BITS_PER_LIMB).collect_vec();
        let words_from_exp_bits = local.exp_bits.chunks(NB_BITS_PER_LIMB).map(|chunk| {
            chunk
                .iter()
                .zip(&two_powers)
                .fold(AB::Expr::zero(), |acc, (bit, power)| acc + (*bit).into() * power.clone())
        });
        let exp_limbs = builder
            .generate_limbs(&local.exp_access[0..num_words_field_element], is_not_trap.clone());
        // Assert only for real rows so that all can be set to zero otherwise
        exp_limbs.into_iter().zip_eq(words_from_exp_bits).for_each(|(limb, word_from_bits)| {
            builder.when(is_not_trap.clone()).assert_eq(limb, word_from_bits);
        });

        // Internal interactions
        // compute S_i = \sum_{j <= i} b_j for bits b_j
        let bit_totals = local
            .exp_bits
            .iter()
            .scan(AB::Expr::zero(), |acc, bit| {
                *acc = acc.clone() + *bit;
                Some(acc.clone())
            })
            .collect_vec();
        // Initial memory send: `(clk, c=0, ird, ec_identity)`.
        let ird_x_limbs = builder
            .generate_limbs(&local.p_access[0..num_words_field_element], is_not_trap.clone());
        let ird_x: Limbs<AB::Expr, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(ird_x_limbs.try_into().expect("failed to convert limbs"));
        let ird_y_limbs =
            builder.generate_limbs(&local.p_access[num_words_field_element..], is_not_trap.clone());
        let ird_y: Limbs<AB::Expr, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(ird_y_limbs.try_into().expect("failed to convert limbs"));
        let [zero_x, zero_y] = ec_identity::<E, AB>();
        builder.send(
            internal_memory_rw::<AB, E::BaseField>(
                local.clk_high,
                local.clk_low,
                AB::Expr::zero(), // c = 0 for initial send
                ird_x,
                ird_y,
                zero_x.clone(),
                zero_y.clone(),
                is_not_trap.clone(),
            ),
            InteractionScope::Local,
        );
        // Final memory receive: `(clk, c = 255 + Σ b_j, ord, ort)`.
        builder.receive(
            internal_memory_rw::<AB, E::BaseField>(
                local.clk_high,
                local.clk_low,
                AB::Expr::from_canonical_usize(exp_num_bits - 1)
                    + bit_totals.last().unwrap().clone(),
                local.ord_x,
                local.ord_y,
                local.ort_x,
                local.ort_y,
                is_not_trap.clone(),
            ),
            InteractionScope::Local,
        );

        // Internal OpCalls: Order: sum(0), double(0), sum(1), double(1), ..., double(n-2), sum(n-1)
        // sums are skipped if the corresponding bit is zero, the last double is always skipped.
        // Internal add OpCalls.
        local
            .exp_bits
            .iter()
            .zip(std::iter::once(&AB::Expr::zero()).chain(bit_totals.iter())) // shift: ith coor is now sum(i-1)
            .enumerate()
            .for_each(|(i, (bit, shifted_bit_total))| {
                builder.send(
                    internal_add_call::<AB>(
                        local.clk_high,
                        local.clk_low,
                        AB::Expr::from_canonical_usize(i) + shifted_bit_total.clone(),
                        shifted_bit_total.clone(), // marker if add should actually be first add
                        *bit, // skips when bit is zero, this should always be zero when row is fake
                    ),
                    InteractionScope::Local,
                );
            });
        // Internal mul OpCalls. Note we skip the last double
        bit_totals.iter().take(exp_num_bits - 1).enumerate().for_each(|(i, bit_total)| {
            builder.send(
                internal_double_call::<AB>(
                    local.clk_high,
                    local.clk_low,
                    AB::Expr::from_canonical_usize(i) + bit_total.clone(),
                    is_not_trap.clone(),
                ),
                InteractionScope::Local,
            );
        });

        // First add interactions
        // Memory read
        builder.receive(
            internal_memory_rw::<AB, E::BaseField>(
                local.clk_high,
                local.clk_low,
                local.c_at_first_add,
                local.ird_at_first_add_x,
                local.ird_at_first_add_y,
                zero_x,
                zero_y,
                is_not_trap.clone(),
            ),
            InteractionScope::Local,
        );
        // Memory write
        builder.send(
            internal_memory_rw::<AB, E::BaseField>(
                local.clk_high,
                local.clk_low,
                local.c_at_first_add + AB::Expr::one(),
                local.ird_at_first_add_x, // doubler
                local.ird_at_first_add_y,
                local.ird_at_first_add_x, // running total set to doubler
                local.ird_at_first_add_y,
                is_not_trap.clone(),
            ),
            InteractionScope::Local,
        );
        // OpCall receive
        builder.receive(
            internal_add_call::<AB>(
                local.clk_high,
                local.clk_low,
                local.c_at_first_add,
                AB::Expr::zero(), // first add marker is zero => this is the first add
                is_not_trap,      // bit should be one at first add
            ),
            InteractionScope::Local,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sp1_core_executor::{
        ExecutionRecord, ExecutionReport, GasEstimatingVMEnum, MinimalExecutor, Program,
        SP1CoreOpts, SupervisorMode, SyscallCode, TracingVMEnum,
    };
    use sp1_hypercube::air::PROOF_NONCE_NUM_WORDS;
    use test_artifacts::SECP256K1_MUL_ELF;

    /// Runs the secp256k1 scalar-multiplication test program end-to-end through both the JIT
    /// executor and the tracing executor, without proving.
    ///
    /// This exercises the full executor wiring for `SECP256K1_MUL`:
    ///
    /// - Phase 1 (`MinimalExecutor`, the JIT path) hits the entrypoint syscall →
    ///   `ecall_handler` dispatch → `weierstrass_mul_assign_syscall` → `ec_mul` →
    ///   `sw_scalar_mul_k256` chain and produces compressed `MinimalTrace` chunks.
    /// - Phase 2 replays each chunk twice:
    ///   - `GasEstimatingVMEnum` accumulates an `ExecutionReport` (instruction / syscall counts,
    ///     gas, cycle-tracker labels).
    ///   - `TracingVMEnum` accumulates an `ExecutionRecord` populated with the precompile events
    ///     (`PrecompileEvent::Secp256k1Mul`) that the AIR would normally consume. We don't
    ///     actually run the AIR, so this chip's stubbed `eval` / `generate_trace_into` never
    ///     fire — which is the whole point while the chip is still incomplete.
    ///
    /// The four `mul_assign` invocations in the test program show up both in the
    /// `ExecutionReport`'s `syscall_counts` and in the tracing record's `Secp256k1Mul` event
    /// list.
    #[test]
    fn test_run_secp256k1_mul_executor_only() {
        let program = Program::from(&SECP256K1_MUL_ELF).unwrap();
        let program = Arc::new(program);

        // Phase 1: produce trace chunks via the JIT executor. `max_trace_size = Some(...)` is
        // what enables chunk recording — with `None` the chunks come back empty.
        let opts = SP1CoreOpts::default();
        let mut executor = MinimalExecutor::<SupervisorMode>::new(
            program.clone(),
            false,
            Some(opts.minimal_trace_chunk_threshold),
        );
        let mut chunks = Vec::new();
        while let Some(chunk) = executor.execute_chunk() {
            chunks.push(chunk);
        }
        assert!(executor.is_done(), "executor did not reach halt");

        let proof_nonce = [0u32; PROOF_NONCE_NUM_WORDS];

        // Phase 2a: gas-estimating replay → ExecutionReport.
        let mut report = ExecutionReport::default();
        for chunk in &chunks {
            let mut vm =
                GasEstimatingVMEnum::new(chunk, program.clone(), proof_nonce, opts.clone());
            report += vm.execute().expect("gas-estimating replay failed");
        }
        eprintln!("\n=== ExecutionReport ===\n{report}=== end ===");

        // Phase 2b: tracing replay → ExecutionRecord with PrecompileEvents.
        let mut total_mul_events = 0usize;
        for chunk in &chunks {
            let mut record =
                ExecutionRecord::new(program.clone(), proof_nonce, opts.global_dependencies_opt);
            let mut vm =
                TracingVMEnum::new(chunk, program.clone(), opts.clone(), proof_nonce, &mut record);
            vm.execute().expect("tracing replay failed");
            drop(vm);

            total_mul_events += record.get_precompile_events(SyscallCode::SECP256K1_MUL).len();
        }
        eprintln!("tracing executor emitted {total_mul_events} Secp256k1Mul events");

        // The guest program issues `mul_assign` four times. Both the report's syscall counter
        // and the tracing record's event count should agree on that number.
        assert_eq!(report.syscall_counts[SyscallCode::SECP256K1_MUL], 4);
        assert_eq!(total_mul_events, 4);
    }
}
