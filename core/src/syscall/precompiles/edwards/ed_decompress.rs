use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use std::marker::PhantomData;

use curve25519_dalek::edwards::CompressedEdwardsY;
use generic_array::GenericArray;
use num::BigUint;
use num::One;
use num::Zero;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use serde::Deserialize;
use serde::Serialize;
use sp1_derive::AlignedBorrow;
use typenum::U32;

use crate::air::BaseAirBuilder;
use crate::air::MachineAir;
use crate::air::SP1AirBuilder;
use crate::bytes::event::ByteRecord;
use crate::bytes::ByteLookupEvent;
use crate::memory::MemoryReadCols;
use crate::memory::MemoryWriteCols;
use crate::operations::field::field_op::FieldOpCols;
use crate::operations::field::field_op::FieldOperation;
use crate::operations::field::field_sqrt::FieldSqrtCols;
use crate::operations::field::params::Limbs;
use crate::operations::field::params::{limbs_from_vec, FieldParameters};
use crate::operations::field::range::FieldLtCols;
use crate::runtime::ExecutionRecord;
use crate::runtime::MemoryReadRecord;
use crate::runtime::MemoryWriteRecord;
use crate::runtime::Program;
use crate::runtime::Syscall;
use crate::runtime::SyscallCode;
use crate::syscall::precompiles::SyscallContext;
use crate::utils::bytes_to_words_le;
use crate::utils::ec::edwards::ed25519::decompress;
use crate::utils::ec::edwards::ed25519::ed25519_sqrt;
use crate::utils::ec::edwards::ed25519::Ed25519BaseField;
use crate::utils::ec::edwards::EdwardsParameters;
use crate::utils::ec::COMPRESSED_POINT_BYTES;
use crate::utils::ec::NUM_BYTES_FIELD_ELEMENT;
use crate::utils::limbs_from_access;
use crate::utils::limbs_from_prev_access;
use crate::utils::pad_rows;
use crate::utils::words_to_bytes_le;

use super::{WordsFieldElement, WORDS_FIELD_ELEMENT};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdDecompressEvent {
    pub lookup_id: u128,
    pub shard: u32,
    pub channel: u8,
    pub clk: u32,
    pub ptr: u32,
    pub sign: bool,
    pub y_bytes: [u8; COMPRESSED_POINT_BYTES],
    pub decompressed_x_bytes: [u8; NUM_BYTES_FIELD_ELEMENT],
    pub x_memory_records: [MemoryWriteRecord; WORDS_FIELD_ELEMENT],
    pub y_memory_records: [MemoryReadRecord; WORDS_FIELD_ELEMENT],
}

pub const NUM_ED_DECOMPRESS_COLS: usize = size_of::<EdDecompressCols<u8>>();

/// A set of columns to compute `EdDecompress` given a pointer to a 16 word slice formatted as such:
/// The 31st byte of the slice is the sign bit. The second half of the slice is the 255-bit
/// compressed Y (without sign bit).
///
/// After `EdDecompress`, the first 32 bytes of the slice are overwritten with the decompressed X.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct EdDecompressCols<T> {
    pub is_real: T,
    pub shard: T,
    pub channel: T,
    pub clk: T,
    pub nonce: T,
    pub ptr: T,
    pub sign: T,
    pub x_access: GenericArray<MemoryWriteCols<T>, WordsFieldElement>,
    pub y_access: GenericArray<MemoryReadCols<T>, WordsFieldElement>,
    pub(crate) y_range: FieldLtCols<T, Ed25519BaseField>,
    pub(crate) yy: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) u: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) dyy: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) v: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) u_div_v: FieldOpCols<T, Ed25519BaseField>,
    pub(crate) x: FieldSqrtCols<T, Ed25519BaseField>,
    pub(crate) neg_x: FieldOpCols<T, Ed25519BaseField>,
}

impl<F: PrimeField32> EdDecompressCols<F> {
    pub fn populate<P: FieldParameters, E: EdwardsParameters>(
        &mut self,
        event: EdDecompressEvent,
        record: &mut ExecutionRecord,
    ) {
        let mut new_byte_lookup_events = Vec::new();
        self.is_real = F::from_bool(true);
        self.shard = F::from_canonical_u32(event.shard);
        self.channel = F::from_canonical_u8(event.channel);
        self.clk = F::from_canonical_u32(event.clk);
        self.ptr = F::from_canonical_u32(event.ptr);
        self.nonce = F::from_canonical_u32(
            record
                .nonce_lookup
                .get(&event.lookup_id)
                .copied()
                .unwrap_or_default(),
        );
        self.sign = F::from_bool(event.sign);
        for i in 0..8 {
            self.x_access[i].populate(
                event.channel,
                event.x_memory_records[i],
                &mut new_byte_lookup_events,
            );
            self.y_access[i].populate(
                event.channel,
                event.y_memory_records[i],
                &mut new_byte_lookup_events,
            );
        }

        let y = &BigUint::from_bytes_le(&event.y_bytes);
        self.populate_field_ops::<E>(&mut new_byte_lookup_events, event.shard, event.channel, y);

        record.add_byte_lookup_events(new_byte_lookup_events);
    }

    fn populate_field_ops<E: EdwardsParameters>(
        &mut self,
        blu_events: &mut Vec<ByteLookupEvent>,
        shard: u32,
        channel: u8,
        y: &BigUint,
    ) {
        let one = BigUint::one();
        self.y_range
            .populate(blu_events, shard, channel, y, &Ed25519BaseField::modulus());
        let yy = self
            .yy
            .populate(blu_events, shard, channel, y, y, FieldOperation::Mul);
        let u = self
            .u
            .populate(blu_events, shard, channel, &yy, &one, FieldOperation::Sub);
        let dyy = self.dyy.populate(
            blu_events,
            shard,
            channel,
            &E::d_biguint(),
            &yy,
            FieldOperation::Mul,
        );
        let v = self
            .v
            .populate(blu_events, shard, channel, &one, &dyy, FieldOperation::Add);
        let u_div_v =
            self.u_div_v
                .populate(blu_events, shard, channel, &u, &v, FieldOperation::Div);
        let x = self
            .x
            .populate(blu_events, shard, channel, &u_div_v, ed25519_sqrt);
        self.neg_x.populate(
            blu_events,
            shard,
            channel,
            &BigUint::zero(),
            &x,
            FieldOperation::Sub,
        );
    }
}

impl<V: Copy> EdDecompressCols<V> {
    pub fn eval<AB: SP1AirBuilder<Var = V>, P: FieldParameters, E: EdwardsParameters>(
        &self,
        builder: &mut AB,
    ) where
        V: Into<AB::Expr>,
    {
        builder.assert_bool(self.sign);

        let y: Limbs<V, U32> = limbs_from_prev_access(&self.y_access);
        let max_num_limbs = P::to_limbs_field_vec(&Ed25519BaseField::modulus());
        self.y_range.eval(
            builder,
            &y,
            &limbs_from_vec::<AB::Expr, P::Limbs, AB::F>(max_num_limbs),
            self.shard,
            self.channel,
            self.is_real,
        );
        self.yy.eval(
            builder,
            &y,
            &y,
            FieldOperation::Mul,
            self.shard,
            self.channel,
            self.is_real,
        );
        self.u.eval(
            builder,
            &self.yy.result,
            &[AB::Expr::one()].iter(),
            FieldOperation::Sub,
            self.shard,
            self.channel,
            self.is_real,
        );
        let d_biguint = E::d_biguint();
        let d_const = E::BaseField::to_limbs_field::<AB::F, _>(&d_biguint);
        self.dyy.eval(
            builder,
            &d_const,
            &self.yy.result,
            FieldOperation::Mul,
            self.shard,
            self.channel,
            self.is_real,
        );
        self.v.eval(
            builder,
            &[AB::Expr::one()].iter(),
            &self.dyy.result,
            FieldOperation::Add,
            self.shard,
            self.channel,
            self.is_real,
        );
        self.u_div_v.eval(
            builder,
            &self.u.result,
            &self.v.result,
            FieldOperation::Div,
            self.shard,
            self.channel,
            self.is_real,
        );
        self.x.eval(
            builder,
            &self.u_div_v.result,
            AB::F::zero(),
            self.shard,
            self.channel,
            self.is_real,
        );
        self.neg_x.eval(
            builder,
            &[AB::Expr::zero()].iter(),
            &self.x.multiplication.result,
            FieldOperation::Sub,
            self.shard,
            self.channel,
            self.is_real,
        );

        builder.eval_memory_access_slice(
            self.shard,
            self.channel,
            self.clk,
            self.ptr,
            &self.x_access,
            self.is_real,
        );
        builder.eval_memory_access_slice(
            self.shard,
            self.channel,
            self.clk,
            self.ptr.into() + AB::F::from_canonical_u32(32),
            &self.y_access,
            self.is_real,
        );

        // Constrain that the correct result is written into x.
        let x_limbs: Limbs<V, U32> = limbs_from_access(&self.x_access);
        builder
            .when(self.is_real)
            .when(self.sign)
            .assert_all_eq(self.neg_x.result, x_limbs);
        builder
            .when(self.is_real)
            .when_not(self.sign)
            .assert_all_eq(self.x.multiplication.result, x_limbs);

        builder.receive_syscall(
            self.shard,
            self.channel,
            self.clk,
            self.nonce,
            AB::F::from_canonical_u32(SyscallCode::ED_DECOMPRESS.syscall_id()),
            self.ptr,
            self.sign,
            self.is_real,
        );
    }
}

#[derive(Default)]
pub struct EdDecompressChip<E> {
    _phantom: PhantomData<E>,
}

impl<E: EdwardsParameters> Syscall for EdDecompressChip<E> {
    fn execute(&self, rt: &mut SyscallContext, arg1: u32, sign: u32) -> Option<u32> {
        let start_clk = rt.clk;
        let slice_ptr = arg1;
        assert!(slice_ptr % 4 == 0, "Pointer must be 4-byte aligned.");
        assert!(sign <= 1, "Sign bit must be 0 or 1.");

        let (y_memory_records_vec, y_vec) = rt.mr_slice(
            slice_ptr + (COMPRESSED_POINT_BYTES as u32),
            WORDS_FIELD_ELEMENT,
        );
        let y_memory_records: [MemoryReadRecord; 8] = y_memory_records_vec.try_into().unwrap();

        let sign_bool = sign != 0;

        let y_bytes: [u8; COMPRESSED_POINT_BYTES] = words_to_bytes_le(&y_vec);

        // Copy bytes into another array so we can modify the last byte and make CompressedEdwardsY,
        // which we'll use to compute the expected X.
        // Re-insert sign bit into last bit of Y for CompressedEdwardsY format
        let mut compressed_edwards_y: [u8; COMPRESSED_POINT_BYTES] = y_bytes;
        compressed_edwards_y[compressed_edwards_y.len() - 1] &= 0b0111_1111;
        compressed_edwards_y[compressed_edwards_y.len() - 1] |= (sign as u8) << 7;

        // Compute actual decompressed X
        let compressed_y = CompressedEdwardsY(compressed_edwards_y);
        let decompressed = decompress(&compressed_y);

        let mut decompressed_x_bytes = decompressed.x.to_bytes_le();
        decompressed_x_bytes.resize(32, 0u8);
        let decompressed_x_words: [u32; WORDS_FIELD_ELEMENT] =
            bytes_to_words_le(&decompressed_x_bytes);

        // Write decompressed X into slice
        let x_memory_records_vec = rt.mw_slice(slice_ptr, &decompressed_x_words);
        let x_memory_records: [MemoryWriteRecord; 8] = x_memory_records_vec.try_into().unwrap();

        let lookup_id = rt.syscall_lookup_id;
        let shard = rt.current_shard();
        let channel = rt.current_channel();
        rt.record_mut()
            .ed_decompress_events
            .push(EdDecompressEvent {
                lookup_id,
                shard,
                channel,
                clk: start_clk,
                ptr: slice_ptr,
                sign: sign_bool,
                y_bytes,
                decompressed_x_bytes: decompressed_x_bytes.try_into().unwrap(),
                x_memory_records,
                y_memory_records,
            });
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        0
    }
}

impl<E: EdwardsParameters> EdDecompressChip<E> {
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<F: PrimeField32, E: EdwardsParameters> MachineAir<F> for EdDecompressChip<E> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "EdDecompress".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        for i in 0..input.ed_decompress_events.len() {
            let event = &input.ed_decompress_events[i];
            let mut row = [F::zero(); NUM_ED_DECOMPRESS_COLS];
            let cols: &mut EdDecompressCols<F> = row.as_mut_slice().borrow_mut();
            cols.populate::<E::BaseField, E>(event.clone(), output);

            rows.push(row);
        }

        pad_rows(&mut rows, || {
            let mut row = [F::zero(); NUM_ED_DECOMPRESS_COLS];
            let cols: &mut EdDecompressCols<F> = row.as_mut_slice().borrow_mut();
            let zero = BigUint::zero();
            cols.populate_field_ops::<E>(&mut vec![], 0, 0, &zero);
            row
        });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_ED_DECOMPRESS_COLS,
        );

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut EdDecompressCols<F> = trace.values
                [i * NUM_ED_DECOMPRESS_COLS..(i + 1) * NUM_ED_DECOMPRESS_COLS]
                .borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.ed_decompress_events.is_empty()
    }
}

impl<F, E: EdwardsParameters> BaseAir<F> for EdDecompressChip<E> {
    fn width(&self) -> usize {
        NUM_ED_DECOMPRESS_COLS
    }
}

impl<AB, E: EdwardsParameters> Air<AB> for EdDecompressChip<E>
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &EdDecompressCols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &EdDecompressCols<AB::Var> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        local.eval::<AB, E::BaseField, E>(builder);
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{
        runtime::Program,
        stark::DefaultProver,
        utils::{self, tests::ED_DECOMPRESS_ELF},
    };

    #[test]
    fn test_ed_decompress() {
        utils::setup_logger();
        let program = Program::from(ED_DECOMPRESS_ELF);
        utils::run_test::<DefaultProver<_, _>>(program).unwrap();
    }
}
