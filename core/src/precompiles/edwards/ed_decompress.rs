use crate::air::CurtaAirBuilder;
use crate::air::WORD_SIZE;
use crate::cpu::cols::cpu_cols::MemoryAccessCols;
use crate::cpu::MemoryReadRecord;
use crate::cpu::MemoryWriteRecord;
use crate::operations::field::fp_op::FpOpCols;
use crate::operations::field::fp_op::FpOperation;
use crate::operations::field::params::FieldParameters;
use crate::operations::field::params::Limbs;
use crate::precompiles::PrecompileRuntime;
use crate::runtime::Segment;
use crate::utils::Chip;
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use num::BigUint;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::Field;
use p3_matrix::MatrixRowSlices;

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
    pub p_ptr: u32,
    pub sign: bool,
    pub p_bytes: [u8; COMPRESSED_POINT_BYTES],
    pub q_ptr: u32,
    pub q: [u32; AFFINE_POINT_WORDS], // Used for sanity check.
    // pub q_ptr_record: MemoryReadRecord,
    pub p_memory_records: [MemoryReadRecord; COMPRESSED_POINT_WORDS + 1],
    pub q_memory_records: [MemoryWriteRecord; AFFINE_POINT_WORDS],
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
    // p_ptr points to a compressed point bytes, starting with the sign.
    pub p_ptr: T,
    pub p_access: [MemoryAccessCols<T>; COMPRESSED_POINT_WORDS + 1],
    // q_ptr is to where we should write the decompressed AffinePoint.
    pub q_ptr: T,
    // pub q_ptr_access: MemoryAccessCols<T>,
    pub q_access: [MemoryAccessCols<T>; AFFINE_POINT_WORDS],
    pub(crate) yy: FpOpCols<T>,
    pub(crate) u: FpOpCols<T>,
    pub(crate) dyy: FpOpCols<T>,
    pub(crate) v: FpOpCols<T>,
    pub(crate) u_div_v: FpOpCols<T>,
    pub(crate) x: FpOpCols<T>,
    pub(crate) neg_x: FpOpCols<T>,
}

fn limbs_from_memory_access<T: Debug>(access: &[MemoryAccessCols<T>]) -> Limbs<T> {
    let v = access.iter().flat_map(|x| x.value.0).collect::<Vec<T>>();
    Limbs(v.try_into().unwrap())
}

impl<F: Field> EdDecompressCols<F> {
    pub fn populate<P: FieldParameters>(
        &mut self,
        event: EdDecompressEvent,
        segment: &mut Segment,
    ) {
        let mut new_field_events = Vec::new();
        self.is_real = F::from_bool(true);
        self.segment = F::from_canonical_u32(event.segment);
        self.clk = F::from_canonical_u32(event.clk);
        self.p_ptr = F::from_canonical_u32(event.p_ptr);
        for i in 0..COMPRESSED_POINT_WORDS + 1 {
            self.p_access[i].populate_read(event.p_memory_records[i], &mut new_field_events);
        }
        self.q_ptr = F::from_canonical_u32(event.q_ptr);
        for i in 0..AFFINE_POINT_WORDS {
            self.q_access[i].populate_write(event.q_memory_records[i], &mut new_field_events);
        }

        let point_bytes = event.p_bytes;
        let y = &BigUint::from_bytes_le(&point_bytes);
        let yy = self.yy.populate::<P>(y, y, FpOperation::Mul);
        let u = self.u.populate::<P>(&yy, &F::one(), FpOperation::Sub);
        let dyy = self.dyy.populate::<P>(&P::D, &yy, FpOperation::Mul);
        let v = self.v.populate::<P>(&F::one(), &dyy, FpOperation::Add);
        let u_div_v = self.u_div_v.populate::<P>(&u, &v, FpOperation::Div);
        let mut x = self.x.populate::<P>(&u_div_v, &F::one(), FpOperation::Sqrt);
        let neg_x = self.neg_x.populate::<P>(&F::zero(), &x, FpOperation::Sub);

        // As a sanity check, we should check that
        // q_access is set properly to the decompressed point, which is if sign: neg_x, else x.
        // Otherwise the eval will fail.
    }
}

impl<V: Copy> EdDecompressCols<V> {
    pub fn eval<AB: CurtaAirBuilder<Var = V>, P: FieldParameters>(&self, builder: &mut AB)
    where
        V: Into<AB::Expr>,
    {
        let y = limbs_from_memory_access(&self.p_access[1..]);
        self.yy.eval::<AB, P>(builder, &y, &y, FpOperation::Sub);
        self.u
            .eval_const::<AB, P>(builder, &self.yy.result, &AB::Expr::one(), FpOperation::Sub);
        self.dyy
            .eval_const::<AB, P>(builder, &self.yy.result, &P::D, FpOperation::Mul);
        self.v.eval_const::<AB, P>(
            builder,
            &self.dyy.result,
            &AB::Expr::one(),
            FpOperation::Add,
        );
        self.u_div_v.eval_const::<AB, P>(
            builder,
            &self.dyy.result,
            &AB::Expr::one(),
            FpOperation::Div,
        );
        self.x
            .eval::<AB, P>(builder, &self.u_div_v.result, FpOperation::Sqrt);
        self.neg_x
            .eval::<AB, P>(builder, &AB::Expr::zero(), &self.x.result, FpOperation::Sub);

        builder
            .when(self.is_real.clone())
            .when(sign)
            .assert_eq(self.neg_x.result, q_x);
        builder
            .when(self.is_real.clone())
            .when_ne(sign)
            .assert_eq(self.x.result, q_x);
    }
}

pub struct EdDecompressChip {}

impl EdDecompressChip {
    pub fn new() -> Self {
        Self {}
    }

    pub fn execute(rt: &mut PrecompileRuntime) -> u32 {
        todo!();
    }
}

impl<F: Field> Chip<F> for EdDecompressChip {
    fn name(&self) -> String {
        "EdAddAssign".to_string()
    }

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F> {
        // let mut rows = Vec::new();

        // let mut new_field_events = Vec::new();

        // for i in 0..segment.ed_decompress_events.len() {
        //     let event = segment.ed_decompress_events[i];
        //     let mut row = [F::zero(); NUM_ED_DECOMPRESS_COLS];
        //     let cols: &mut EdDecompressCols<F> = unsafe { std::mem::transmute(&mut row) };
        //     cols.populate(event, segment);
        // }

        // TODO: pad
        todo!();
    }
}

impl<F> BaseAir<F> for EdDecompressChip {
    fn width(&self) -> usize {
        NUM_ED_DECOMPRESS_COLS
    }
}

impl<AB> Air<AB> for EdDecompressChip
where
    AB: CurtaAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row: &EdDecompressCols<AB::Var> = main.row_slice(0).borrow();
        // row.eval(builder);
    }
}

// TODO: MIGRATE TESTS FOR THE ED_DECOMPRESS FROM THE OLD AIR:
// https://github.com/succinctlabs/curta/blob/ebbd97c0f4f91bfa792fa5746e1d3f5334316189/curta/src/chip/ec/edwards/ed25519/decompress.rs#L99
