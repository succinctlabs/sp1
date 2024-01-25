use crate::air::CurtaAirBuilder;
use crate::air::WORD_SIZE;
use crate::cpu::cols::cpu_cols::MemoryAccessCols;
use crate::cpu::MemoryReadRecord;
use crate::cpu::MemoryRecordEnum;
use crate::cpu::MemoryWriteRecord;
use crate::operations::field::fp_op::FpOpCols;
use crate::operations::field::fp_op::FpOperation;
use crate::operations::field::params::NUM_LIMBS;
use crate::precompiles::PrecompileRuntime;
use crate::runtime::Segment;
use crate::utils::ec::edwards::ed25519::decompress;
use crate::utils::ec::edwards::EdwardsParameters;
use crate::utils::ec::field::FieldParameters;
use crate::utils::limbs_from_access;
use crate::utils::pad_rows;
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

const COMPRESSED_POINT_BYTES: usize = 32;
const COMPRESSED_POINT_WORDS: usize = COMPRESSED_POINT_BYTES / WORD_SIZE;

// TODO: this should be moved to utils/ec/utils.rs
const AFFINE_POINT_WORDS: usize = 2 * COMPRESSED_POINT_WORDS;

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

/// A set of columns to compute `EdDecompress` where a, b are field elements.
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed
/// or made generic in the future.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct EdDecompressCols<T> {
    pub is_real: T,
    pub segment: T,
    pub clk: T,
    // ptr points to a 16 word slice of memory. The last 8 words are the compressed y point.
    // The bit right before the last 8 words is the sign bit.
    pub ptr: T,
    pub x_access: [MemoryAccessCols<T>; COMPRESSED_POINT_WORDS],
    pub y_access: [MemoryAccessCols<T>; COMPRESSED_POINT_WORDS],
    pub(crate) yy: FpOpCols<T>,
    pub(crate) u: FpOpCols<T>,
    pub(crate) dyy: FpOpCols<T>,
    pub(crate) v: FpOpCols<T>,
    pub(crate) u_div_v: FpOpCols<T>,
    pub(crate) x: FpOpCols<T>,
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
            self.x_access[i].populate(
                MemoryRecordEnum::Write(event.x_memory_records[i]),
                &mut new_field_events,
            );
        }
        for i in 0..COMPRESSED_POINT_WORDS {
            self.y_access[i].populate(
                MemoryRecordEnum::Read(event.y_memory_records[i]),
                &mut new_field_events,
            );
        }

        let y = &BigUint::from_bytes_le(&event.y_bytes);
        self.populate_fp_ops::<P, E>(y);

        segment.field_events.append(&mut new_field_events);

        // As a sanity check, we should check that
        // q_access is set properly to the decompressed point, which is if sign: neg_x, else x.
        // Otherwise the eval will fail.
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
        // let mut x = self.x.populate::<P>(&u_div_v, &one, FpOperation::Sqrt);
        // let neg_x = self
        //     .neg_x
        //     .populate::<P>(&BigUint::zero(), &x, FpOperation::Sub);
    }
}

impl<V: Copy> EdDecompressCols<V> {
    pub fn eval<AB: CurtaAirBuilder<Var = V>, P: FieldParameters, E: EdwardsParameters>(
        &self,
        builder: &mut AB,
    ) where
        V: Into<AB::Expr>,
    {
        let sign: AB::Expr =
            self.x_access[COMPRESSED_POINT_WORDS - 1].prev_value[WORD_SIZE - 1].into();
        builder.assert_bool(sign.clone());

        let y = limbs_from_access(&self.y_access);
        self.yy
            .eval::<AB, P, _, _>(builder, &y, &y, FpOperation::Sub);
        // let const_poly = Polynomial::from_coefficients(vec![AB::Expr::one()]);
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
        // self.x.eval::<AB, P, _, _>(
        //     builder,
        //     &self.u_div_v.result,
        //     &[AB::Expr::one()].iter(),
        //     FpOperation::Sqrt,
        // );
        self.neg_x.eval::<AB, P, _, _>(
            builder,
            &[AB::Expr::one()].iter(),
            &self.x.result,
            FpOperation::Sub,
        );

        for i in 0..NUM_LIMBS {
            builder
                .when(self.is_real.clone())
                .when(sign.clone())
                .assert_eq(self.neg_x.result[i], self.x_access[i / 4].value[i % 4]);
            builder
                .when(self.is_real.clone())
                .when(AB::Expr::one() - sign.clone())
                .assert_eq(self.x.result[i], self.x_access[i / 4].value[i % 4]);
        }
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
        let a1 = crate::runtime::Register::X11;

        let start_clk = rt.clk;

        // TODO: these will have to be be constrained, but can do it later.
        let slice_ptr = rt.register_unsafe(a0);
        if slice_ptr % 4 != 0 {
            panic!();
        }

        let slice: [u32; 16] = rt.slice_unsafe(slice_ptr, 16).try_into().unwrap();
        let (y_memory_records_vec, y_vec) = rt.mr_slice(slice_ptr + 32, 8);
        let y_memory_records = y_memory_records_vec.try_into().unwrap();

        let mut slice_bytes = [0u8; 64];
        for i in 0..16 {
            let word = slice[i];
            slice_bytes[4 * i..4 * (i + 1)].copy_from_slice(&word.to_le_bytes());
        }

        let sign = slice_bytes[31];
        let sign_bool = sign != 0;

        // Separate y_bytes array with readded sign bit for CompressedEdwardsY format
        let mut y_bytes = [0_u8; 32];
        y_bytes.copy_from_slice(&slice_bytes[32..]);
        y_bytes[31] &= 0b0111_1111;
        y_bytes[31] |= sign << 7;

        println!("y_bytes: {:?}", y_bytes);
        println!("sign: {:?}", sign_bool);

        let compressed_y = CompressedEdwardsY(y_bytes);
        let decompressed = decompress(&compressed_y);

        let mut decompressed_x_bytes = decompressed.x.to_bytes_le();
        decompressed_x_bytes.resize(32, 0u8);
        println!("decompressed: {:?}", decompressed_x_bytes);
        let mut decompressed_x_words = [0_u32; 8];
        for i in 0..8 {
            let word =
                u32::from_le_bytes(decompressed_x_bytes[4 * i..4 * (i + 1)].try_into().unwrap());
            decompressed_x_words[i] = word;
        }

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
                y_bytes: slice_bytes[32..].try_into().unwrap(),
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

// TODO: MIGRATE TESTS FOR THE ED_DECOMPRESS FROM THE OLD AIR:
// https://github.com/succinctlabs/curta/blob/ebbd97c0f4f91bfa792fa5746e1d3f5334316189/curta/src/chip/ec/edwards/ed25519/decompress.rs#L99

#[cfg(test)]
pub mod tests {

    use curve25519_dalek::edwards::CompressedEdwardsY;
    use tracing::Level;
    use tracing_subscriber::EnvFilter;

    use crate::utils::ec::edwards::ed25519::decompress;
    use crate::{runtime::Program, utils::prove};

    #[test]
    fn test_ed_add() {
        let key = hex::decode("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
            .unwrap();
        println!("key: {:?}", key);
        let compressed_y = CompressedEdwardsY(key.as_slice().try_into().unwrap());
        let decompressed = decompress(&compressed_y);
        let mut bytes = decompressed.x.to_bytes_le();
        bytes.resize(32, 0u8);
        println!("decompressed: {:?}", bytes);
    }

    #[test]
    fn test_ed_add2() {
        tracing_subscriber::fmt::init();
        let program = Program::from_elf("/Users/ctian/Documents/workspace/curta-vm/target/riscv32im-risc0-zkvm-elf/release/ed_decompress");
        prove(program);
    }
}

// [47, 252, 114, 91, 153, 234, 110, 201, 201, 153, 152, 14, 68, 231, 90, 221, 137, 110, 250, 67, 10, 64, 37, 70, 163, 101, 111, 223, 185, 1, 180, 88]
