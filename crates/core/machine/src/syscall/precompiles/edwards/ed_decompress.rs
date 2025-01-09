use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use std::marker::PhantomData;

use crate::air::MemoryAirBuilder;
use generic_array::GenericArray;
use num::{BigUint, One, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord, EdDecompressEvent, FieldOperation, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_curves::{
    edwards::{
        ed25519::{ed25519_sqrt, Ed25519BaseField},
        EdwardsParameters, WordsFieldElement,
    },
    params::{FieldParameters, Limbs},
};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{BaseAirBuilder, InteractionScope, MachineAir, SP1AirBuilder};
use typenum::U32;

use crate::{
    memory::{MemoryReadCols, MemoryWriteCols},
    operations::field::{field_op::FieldOpCols, field_sqrt::FieldSqrtCols, range::FieldLtCols},
    utils::{limbs_from_access, limbs_from_prev_access, pad_rows_fixed},
};

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
    pub clk: T,
    pub ptr: T,
    pub sign: T,
    pub x_access: GenericArray<MemoryWriteCols<T>, WordsFieldElement>,
    pub y_access: GenericArray<MemoryReadCols<T>, WordsFieldElement>,
    pub(crate) neg_x_range: FieldLtCols<T, Ed25519BaseField>,
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
        self.clk = F::from_canonical_u32(event.clk);
        self.ptr = F::from_canonical_u32(event.ptr);
        self.sign = F::from_bool(event.sign);
        for i in 0..8 {
            self.x_access[i].populate(event.x_memory_records[i], &mut new_byte_lookup_events);
            self.y_access[i].populate(event.y_memory_records[i], &mut new_byte_lookup_events);
        }

        let y = &BigUint::from_bytes_le(&event.y_bytes);
        self.populate_field_ops::<E>(&mut new_byte_lookup_events, y);

        record.add_byte_lookup_events(new_byte_lookup_events);
    }

    fn populate_field_ops<E: EdwardsParameters>(
        &mut self,
        blu_events: &mut Vec<ByteLookupEvent>,
        y: &BigUint,
    ) {
        let one = BigUint::one();
        self.y_range.populate(blu_events, y, &Ed25519BaseField::modulus());
        let yy = self.yy.populate(blu_events, y, y, FieldOperation::Mul);
        let u = self.u.populate(blu_events, &yy, &one, FieldOperation::Sub);
        let dyy = self.dyy.populate(blu_events, &E::d_biguint(), &yy, FieldOperation::Mul);
        let v = self.v.populate(blu_events, &one, &dyy, FieldOperation::Add);
        let u_div_v = self.u_div_v.populate(blu_events, &u, &v, FieldOperation::Div);

        let x = self.x.populate(blu_events, &u_div_v, |v| {
            ed25519_sqrt(v).expect("curve25519 expected field element to be a square")
        });
        let neg_x = self.neg_x.populate(blu_events, &BigUint::zero(), &x, FieldOperation::Sub);
        self.neg_x_range.populate(blu_events, &neg_x, &Ed25519BaseField::modulus());
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
        let max_num_limbs =
            Ed25519BaseField::to_limbs_field::<AB::Expr, AB::F>(&Ed25519BaseField::modulus());
        self.y_range.eval(builder, &y, &max_num_limbs, self.is_real);
        self.yy.eval(builder, &y, &y, FieldOperation::Mul, self.is_real);
        self.u.eval(
            builder,
            &self.yy.result,
            &[AB::Expr::one()].iter(),
            FieldOperation::Sub,
            self.is_real,
        );
        let d_biguint = E::d_biguint();
        let d_const = E::BaseField::to_limbs_field::<AB::F, _>(&d_biguint);
        self.dyy.eval(builder, &d_const, &self.yy.result, FieldOperation::Mul, self.is_real);
        self.v.eval(
            builder,
            &[AB::Expr::one()].iter(),
            &self.dyy.result,
            FieldOperation::Add,
            self.is_real,
        );
        self.u_div_v.eval(
            builder,
            &self.u.result,
            &self.v.result,
            FieldOperation::Div,
            self.is_real,
        );

        // Constrain that `x` is a square root. Note that `x.multiplication.result` is constrained to be canonical here.
        self.x.eval(builder, &self.u_div_v.result, AB::F::zero(), self.is_real);
        self.neg_x.eval(
            builder,
            &[AB::Expr::zero()].iter(),
            &self.x.multiplication.result,
            FieldOperation::Sub,
            self.is_real,
        );
        // Constrain that `neg_x.result` is also canonical.
        self.neg_x_range.eval(builder, &self.neg_x.result, &max_num_limbs, self.is_real);

        builder.eval_memory_access_slice(
            self.shard,
            self.clk,
            self.ptr,
            &self.x_access,
            self.is_real,
        );
        builder.eval_memory_access_slice(
            self.shard,
            self.clk,
            self.ptr.into() + AB::F::from_canonical_u32(32),
            &self.y_access,
            self.is_real,
        );

        // Constrain that the correct result is written into x.
        // Since the result is either `neg_x.result` or `x.multiplication.result`, the written value is canonical.
        let x_limbs: Limbs<V, U32> = limbs_from_access(&self.x_access);
        builder.when(self.is_real).when(self.sign).assert_all_eq(self.neg_x.result, x_limbs);
        builder
            .when(self.is_real)
            .when_not(self.sign)
            .assert_all_eq(self.x.multiplication.result, x_limbs);

        builder.receive_syscall(
            self.shard,
            self.clk,
            AB::F::from_canonical_u32(SyscallCode::ED_DECOMPRESS.syscall_id()),
            self.ptr,
            self.sign,
            self.is_real,
            InteractionScope::Local,
        );
    }
}

#[derive(Default)]
pub struct EdDecompressChip<E> {
    _phantom: PhantomData<E>,
}

impl<E: EdwardsParameters> EdDecompressChip<E> {
    pub const fn new() -> Self {
        Self { _phantom: PhantomData }
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
        let events = input.get_precompile_events(SyscallCode::ED_DECOMPRESS);

        for (_, event) in events {
            let event = if let PrecompileEvent::EdDecompress(event) = event {
                event
            } else {
                unreachable!();
            };
            let mut row = [F::zero(); NUM_ED_DECOMPRESS_COLS];
            let cols: &mut EdDecompressCols<F> = row.as_mut_slice().borrow_mut();
            cols.populate::<E::BaseField, E>(event.clone(), output);

            rows.push(row);
        }

        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = [F::zero(); NUM_ED_DECOMPRESS_COLS];
                let cols: &mut EdDecompressCols<F> = row.as_mut_slice().borrow_mut();
                let zero = BigUint::zero();
                cols.populate_field_ops::<E>(&mut vec![], &zero);
                row
            },
            input.fixed_log2_rows::<F, _>(self),
        );

        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_ED_DECOMPRESS_COLS)
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.get_precompile_events(SyscallCode::ED_DECOMPRESS).is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
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

        local.eval::<AB, E::BaseField, E>(builder);
    }
}

#[cfg(test)]
pub mod tests {
    use sp1_core_executor::Program;
    use sp1_stark::CpuProver;
    use test_artifacts::ED_DECOMPRESS_ELF;

    use crate::{io::SP1Stdin, utils};

    #[test]
    fn test_ed_decompress() {
        utils::setup_logger();
        let program = Program::from(ED_DECOMPRESS_ELF).unwrap();
        let stdin = SP1Stdin::new();
        utils::run_test::<CpuProver<_, _>>(program, stdin).unwrap();
    }
}
