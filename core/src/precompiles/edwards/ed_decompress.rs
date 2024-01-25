use crate::air::BaseAirBuilder;
use crate::air::CurtaAirBuilder;
use crate::air::WORD_SIZE;
use crate::cpu::cols::cpu_cols::MemoryAccessCols;
use crate::cpu::MemoryReadRecord;
use crate::cpu::MemoryWriteRecord;
use crate::operations::field::ed_sqrt::EdSqrtCols;
use crate::operations::field::fp_op::FpOpCols;
use crate::operations::field::fp_op::FpOperation;
use crate::precompiles::PrecompileRuntime;
use crate::runtime::Segment;
use crate::utils::bytes_to_words_le;
use crate::utils::ec::edwards::ed25519::decompress;
use crate::utils::ec::edwards::EdwardsParameters;
use crate::utils::ec::field::FieldParameters;
use crate::utils::ec::COMPRESSED_POINT_BYTES;
use crate::utils::ec::COMPRESSED_POINT_WORDS;
use crate::utils::ec::NUM_WORDS_POINT;
use crate::utils::limbs_from_access;
use crate::utils::pad_rows;
use crate::utils::words_to_bytes_le;
use crate::utils::Chip;
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use curve25519_dalek::edwards::CompressedEdwardsY;
use num::BigUint;
use num::One;
use num::Zero;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::Field;
use p3_matrix::MatrixRowSlices;
use std::marker::PhantomData;

use p3_matrix::dense::RowMajorMatrix;
use std::fmt::Debug;
use valida_derive::AlignedBorrow;

#[derive(Debug, Clone, Copy)]
pub struct EdDecompressEvent {
    pub segment: u32,
    pub clk: u32,
    pub ptr: u32,
    pub sign: bool,
    pub y_bytes: [u8; COMPRESSED_POINT_BYTES],
    pub decompressed_x_bytes: [u8; COMPRESSED_POINT_BYTES],
    pub x_memory_records: [MemoryWriteRecord; COMPRESSED_POINT_WORDS],
    pub y_memory_records: [MemoryReadRecord; COMPRESSED_POINT_WORDS],
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
    pub segment: T,
    pub clk: T,
    pub ptr: T,
    pub x_access: [MemoryAccessCols<T>; NUM_WORDS_POINT],
    pub y_access: [MemoryAccessCols<T>; COMPRESSED_POINT_WORDS],
    pub(crate) yy: FpOpCols<T>,
    pub(crate) u: FpOpCols<T>,
    pub(crate) dyy: FpOpCols<T>,
    pub(crate) v: FpOpCols<T>,
    pub(crate) u_div_v: FpOpCols<T>,
    pub(crate) x: EdSqrtCols<T>,
    pub(crate) neg_x: FpOpCols<T>,
}

impl<F: Field> EdDecompressCols<F> {
    pub fn populate<P: FieldParameters, E: EdwardsParameters>(
        &mut self,
        event: EdDecompressEvent,
        segment: &mut Segment,
    ) {
        let mut new_field_events = Vec::new();
        self.is_real = F::from_bool(true);
        self.segment = F::from_canonical_u32(event.segment);
        self.clk = F::from_canonical_u32(event.clk);
        self.ptr = F::from_canonical_u32(event.ptr);
        for i in 0..COMPRESSED_POINT_WORDS {
            self.x_access[i].populate_write(event.x_memory_records[i], &mut new_field_events);
        }
        for i in 0..COMPRESSED_POINT_WORDS {
            self.y_access[i].populate_read(event.y_memory_records[i], &mut new_field_events);
        }

        let y = &BigUint::from_bytes_le(&event.y_bytes);
        self.populate_fp_ops::<P, E>(y);

        segment.field_events.append(&mut new_field_events);
    }

    fn populate_fp_ops<P: FieldParameters, E: EdwardsParameters>(&mut self, y: &BigUint) {
        let one = BigUint::one();
        let yy = self.yy.populate::<P>(y, y, FpOperation::Mul);
        let u = self.u.populate::<P>(&yy, &one, FpOperation::Sub);
        let dyy = self
            .dyy
            .populate::<P>(&E::d_biguint(), &yy, FpOperation::Mul);
        let v = self.v.populate::<P>(&one, &dyy, FpOperation::Add);
        let u_div_v = self.u_div_v.populate::<P>(&u, &v, FpOperation::Div);
        let x = self.x.populate::<P>(&u_div_v);
        self.neg_x
            .populate::<P>(&BigUint::zero(), &x, FpOperation::Sub);
    }
}

impl<V: Copy> EdDecompressCols<V> {
    pub fn eval<AB: CurtaAirBuilder<Var = V>, P: FieldParameters, E: EdwardsParameters>(
        &self,
        builder: &mut AB,
    ) where
        V: Into<AB::Expr>,
    {
        // Get the 31st byte of the slice, which should be the sign bit.
        let sign: AB::Expr =
            self.x_access[COMPRESSED_POINT_WORDS - 1].prev_value[WORD_SIZE - 1].into();
        builder.assert_bool(sign.clone());

        let y = limbs_from_access(&self.y_access);
        self.yy
            .eval::<AB, P, _, _>(builder, &y, &y, FpOperation::Sub);
        self.u.eval::<AB, P, _, _>(
            builder,
            &self.yy.result,
            &[AB::Expr::one()].iter(),
            FpOperation::Sub,
        );
        let d_biguint = E::d_biguint();
        let d_const = E::BaseField::to_limbs_field::<AB::F>(&d_biguint);
        self.dyy
            .eval::<AB, P, _, _>(builder, &self.yy.result, &d_const, FpOperation::Mul);
        self.v.eval::<AB, P, _, _>(
            builder,
            &self.dyy.result,
            &[AB::Expr::one()].iter(),
            FpOperation::Add,
        );
        self.u_div_v.eval::<AB, P, _, _>(
            builder,
            &self.dyy.result,
            &[AB::Expr::one()].iter(),
            FpOperation::Div,
        );
        self.x.eval::<AB>(builder, &self.u_div_v.result);
        self.neg_x.eval::<AB, P, _, _>(
            builder,
            &[AB::Expr::one()].iter(),
            &self.x.multiplication.result,
            FpOperation::Sub,
        );

        let x_limbs = limbs_from_access(&self.x_access);
        builder
            .when(self.is_real)
            .when(sign.clone())
            .assert_all_eq(self.neg_x.result, x_limbs);
        builder
            .when(self.is_real)
            .when(AB::Expr::one() - sign.clone())
            .assert_all_eq(self.x.multiplication.result, x_limbs);
    }
}

pub struct EdDecompressChip<E> {
    _phantom: PhantomData<E>,
}

impl<E: EdwardsParameters> EdDecompressChip<E> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    pub fn execute(rt: &mut PrecompileRuntime) -> u32 {
        let a0 = crate::runtime::Register::X10;

        let start_clk = rt.clk;

        // TODO: this will have to be be constrained, but can do it later.
        let slice_ptr = rt.register_unsafe(a0);
        if slice_ptr % 4 != 0 {
            panic!();
        }

        let (y_memory_records_vec, y_vec) = rt.mr_slice(
            slice_ptr + (COMPRESSED_POINT_BYTES as u32),
            COMPRESSED_POINT_WORDS,
        );
        let y_memory_records = y_memory_records_vec.try_into().unwrap();

        // This unsafe read is okay because we do mw_slice into the first 8 words later.
        let sign = rt.byte_unsafe(slice_ptr + (COMPRESSED_POINT_BYTES as u32) - 1);
        let sign_bool = sign != 0;

        let mut y_bytes: [u8; COMPRESSED_POINT_BYTES] = words_to_bytes_le(&y_vec);
        // Re-insert sign bit into last bit of Y for CompressedEdwardsY format
        y_bytes[y_bytes.len() - 1] &= 0b0111_1111;
        y_bytes[y_bytes.len() - 1] |= (sign as u8) << 7;

        // Compute actual decompressed X
        let compressed_y = CompressedEdwardsY(y_bytes);
        let decompressed = decompress(&compressed_y);

        let mut decompressed_x_bytes = decompressed.x.to_bytes_le();
        decompressed_x_bytes.resize(32, 0u8);
        let decompressed_x_words: [u32; COMPRESSED_POINT_WORDS] =
            bytes_to_words_le(&decompressed_x_bytes);

        // Write decompressed X into slice
        let x_memory_records_vec = rt.mw_slice(slice_ptr, &decompressed_x_words);
        let x_memory_records = x_memory_records_vec.try_into().unwrap();

        let segment = rt.current_segment;
        rt.segment_mut()
            .ed_decompress_events
            .push(EdDecompressEvent {
                segment,
                clk: start_clk,
                ptr: slice_ptr,
                sign: sign_bool,
                y_bytes,
                decompressed_x_bytes: decompressed_x_bytes.try_into().unwrap(),
                x_memory_records,
                y_memory_records,
            });

        slice_ptr
    }
}

impl<F: Field, E: EdwardsParameters> Chip<F> for EdDecompressChip<E> {
    fn name(&self) -> String {
        "EdDecompress".to_string()
    }

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        for i in 0..segment.ed_decompress_events.len() {
            let event = segment.ed_decompress_events[i];
            let mut row = [F::zero(); NUM_ED_DECOMPRESS_COLS];
            let cols: &mut EdDecompressCols<F> = unsafe { std::mem::transmute(&mut row) };
            cols.populate::<E::BaseField, E>(event, segment);

            rows.push(row);
        }

        pad_rows(&mut rows, || {
            let mut row = [F::zero(); NUM_ED_DECOMPRESS_COLS];
            let cols: &mut EdDecompressCols<F> = unsafe { std::mem::transmute(&mut row) };
            let zero = BigUint::zero();
            cols.populate_fp_ops::<E::BaseField, E>(&zero);
            row
        });

        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_ED_DECOMPRESS_COLS,
        )
    }
}

impl<F, E: EdwardsParameters> BaseAir<F> for EdDecompressChip<E> {
    fn width(&self) -> usize {
        NUM_ED_DECOMPRESS_COLS
    }
}

impl<AB, E: EdwardsParameters> Air<AB> for EdDecompressChip<E>
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row: &EdDecompressCols<AB::Var> = main.row_slice(0).borrow();
        row.eval::<AB, E::BaseField, E>(builder);
    }
}

#[cfg(test)]
pub mod tests {

    use crate::{runtime::Program, utils::prove};

    #[test]
    fn test_ed_decompress() {
        let program = Program::from_elf("../programs/ed_decompress");
        prove(program);
    }
}
