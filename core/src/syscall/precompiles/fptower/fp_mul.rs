use crate::air::{BaseAirBuilder, MachineAir, Polynomial, SP1AirBuilder};
use crate::alu::MulChip;
use crate::bytes::event::ByteRecord;
use crate::bytes::ByteLookupEvent;
use crate::memory::{value_as_limbs, MemoryCols, MemoryReadCols, MemoryWriteCols};
use crate::operations::field::field_op::{FieldOpCols, FieldOperation};
use crate::operations::field::params::{FieldParameters, NumWords};
use crate::operations::field::params::{Limbs, NumLimbs};
use crate::runtime::{ExecutionRecord, Program, Syscall, SyscallCode, SyscallContext};
use crate::runtime::{MemoryReadRecord, MemoryWriteRecord};
use crate::stark::MachineRecord;
use crate::utils::ec::weierstrass::WeierstrassParameters;
use crate::utils::ec::{CurveType, EllipticCurve};
use crate::utils::{limbs_from_prev_access, pad_rows, words_to_bytes_le_vec};
use generic_array::GenericArray;
use itertools::Itertools;
use num::BigUint;
use num::Zero;
use p3_air::AirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use serde::{Deserialize, Serialize};
use sp1_derive::AlignedBorrow;
use std::borrow::{Borrow, BorrowMut};
use std::marker::PhantomData;
use std::mem::size_of;
use typenum::Unsigned;

pub const fn num_fp_mul_cols<P: FieldParameters + NumWords>() -> usize {
    size_of::<FpMulAssignCols<u32, P>>()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpMulEvent {
    pub lookup_id: usize,
    pub shard: u32,
    pub channel: u8,
    pub clk: u32,
    pub x_ptr: u32,
    pub x: Vec<u32>,
    pub y_ptr: u32,
    pub y: Vec<u32>,
    pub x_memory_records: Vec<MemoryWriteRecord>,
    pub y_memory_records: Vec<MemoryReadRecord>,
}

/// A set of columns for the FpMul operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FpMulAssignCols<T, P: FieldParameters + NumWords> {
    pub is_real: T,
    pub shard: T,
    pub channel: T,
    pub nonce: T,
    pub clk: T,
    pub x_ptr: T,
    pub y_ptr: T,
    pub x_access: GenericArray<MemoryWriteCols<T>, P::WordsFieldElement>,
    pub y_access: GenericArray<MemoryReadCols<T>, P::WordsFieldElement>,
    pub(crate) output: FieldOpCols<T, P>,
}

#[derive(Default)]
pub struct FpMulAssignChip<P> {
    _marker: PhantomData<P>,
}

impl<E: EllipticCurve> Syscall for FpMulAssignChip<E> {
    fn execute(&self, rt: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
        let clk = rt.clk;
        let x_ptr = arg1;
        if x_ptr % 4 != 0 {
            panic!();
        }
        let y_ptr = arg2;
        if y_ptr % 4 != 0 {
            panic!();
        }

        let num_words = <E::BaseField as NumWords>::WordsFieldElement::USIZE;

        let x = rt.slice_unsafe(x_ptr, num_words);
        let (y_memory_records, y) = rt.mr_slice(y_ptr, num_words);
        rt.clk += 1;

        let a = BigUint::from_slice(&x);
        let b = BigUint::from_slice(&y);

        let modulus = &BigUint::from_bytes_le(E::BaseField::MODULUS);

        let result = (a * b) % modulus;
        let mut result = result.to_u32_digits();
        result.resize(E::NB_LIMBS, 0);

        let x_memory_records = rt.mw_slice(x_ptr, &result);

        let lookup_id = rt.syscall_lookup_id as usize;
        let shard = rt.current_shard();
        let channel = rt.current_channel();
        rt.record_mut().bls12381_fp_mul_events.push(FpMulEvent {
            lookup_id,
            shard,
            channel,
            clk,
            x_ptr,
            x,
            y_ptr,
            y,
            x_memory_records,
            y_memory_records,
        });
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}

impl<E: EllipticCurve> FpMulAssignChip<E> {
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn populate_field_ops<F: PrimeField32>(
        blu_events: &mut Vec<ByteLookupEvent>,
        shard: u32,
        channel: u8,
        cols: &mut FpMulAssignCols<F, E::BaseField>,
        p: BigUint,
        q: BigUint,
    ) {
        let modulus_bytes = E::BaseField::MODULUS;
        let modulus = BigUint::from_bytes_le(modulus_bytes);
        cols.output.populate_with_modulus(
            blu_events,
            shard,
            channel,
            &p,
            &q,
            &modulus,
            FieldOperation::Mul,
        );
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> MachineAir<F>
    for FpMulAssignChip<E>
{
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        match E::CURVE_TYPE {
            // CurveType::Secp256k1 => "Secp256k1AddAssign".to_string(),
            // CurveType::Bn254 => "Bn254AddAssign".to_string(),
            CurveType::Bls12381 => "Bls12831FpMulAssign".to_string(),
            _ => panic!("Unsupported curve"),
        }
    }

    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = match E::CURVE_TYPE {
            // CurveType::Secp256k1 => &input.secp256k1_add_events,
            // CurveType::Bn254 => &input.bn254_add_events,
            CurveType::Bls12381 => &input.bls12381_fp_mul_events,
            _ => panic!("Unsupported curve"),
        };

        let mut rows = Vec::new();
        let mut new_byte_lookup_events = Vec::new();

        for i in 0..events.len() {
            let event = &events[i];
            let mut row = vec![F::zero(); num_fp_mul_cols::<E::BaseField>()];
            let cols: &mut FpMulAssignCols<F, E::BaseField> = row.as_mut_slice().borrow_mut();

            let p = BigUint::from_bytes_le(&words_to_bytes_le_vec(&event.x));
            let q = BigUint::from_bytes_le(&words_to_bytes_le_vec(&event.y));

            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.channel = F::from_canonical_u8(event.channel);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.x_ptr = F::from_canonical_u32(event.x_ptr);
            cols.y_ptr = F::from_canonical_u32(event.y_ptr);

            Self::populate_field_ops(
                &mut new_byte_lookup_events,
                event.shard,
                event.channel,
                cols,
                p,
                q,
            );

            // Populate the memory access columns.
            for i in 0..cols.y_access.len() {
                cols.y_access[i].populate(
                    event.channel,
                    event.y_memory_records[i],
                    &mut new_byte_lookup_events,
                );
            }
            for i in 0..cols.x_access.len() {
                cols.x_access[i].populate(
                    event.channel,
                    event.x_memory_records[i],
                    &mut new_byte_lookup_events,
                );
            }
            rows.push(row)
        }

        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows(&mut rows, || {
            let mut row = vec![F::zero(); num_fp_mul_cols::<E::BaseField>()];
            let cols: &mut FpMulAssignCols<F, E::BaseField> = row.as_mut_slice().borrow_mut();
            let zero = BigUint::zero();
            Self::populate_field_ops(&mut vec![], 0, 0, cols, zero.clone(), zero);
            row
        });

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            num_fp_mul_cols::<E::BaseField>(),
        );

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut FpMulAssignCols<F, E::BaseField> =
                trace.values[i * num_fp_mul_cols::<E::BaseField>()
                    ..(i + 1) * num_fp_mul_cols::<E::BaseField>()]
                    .borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        match E::CURVE_TYPE {
            CurveType::Bls12381 => !shard.bls12381_fp_mul_events.is_empty(),
            _ => panic!("Unsupported curve"),
        }
    }
}

impl<F, E: EllipticCurve> BaseAir<F> for FpMulAssignChip<E> {
    fn width(&self) -> usize {
        num_fp_mul_cols::<E::BaseField>()
    }
}

impl<AB, E: EllipticCurve> Air<AB> for FpMulAssignChip<E>
where
    AB: SP1AirBuilder,
    Limbs<AB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &FpMulAssignCols<AB::Var, E::BaseField> = (*local).borrow();

        let p = limbs_from_prev_access(&local.x_access);
        let q = limbs_from_prev_access(&local.y_access);

        // let modulus_coeffs = E::BaseField::MODULUS
        //     .iter()
        //     .map(|&limbs| AB::Expr::from_canonical_u8(limbs))
        //     .collect_vec();
        // let p_modulus = Polynomial::from_coefficients(&modulus_coeffs);

        // local.output.eval_with_modulus(
        //     builder,
        //     &p,
        //     &q,
        //     &p_modulus,
        //     FieldOperation::Mul,
        //     local.shard,
        //     local.channel,
        //     local.is_real,
        // );

        // builder
        //     .when(local.is_real)
        //     .assert_all_eq(local.output.result, value_as_limbs(&local.x_access));

        builder.eval_memory_access_slice(
            local.shard,
            local.channel,
            local.clk.into(),
            local.y_ptr,
            &local.y_access,
            local.is_real,
        );
        builder.eval_memory_access_slice(
            local.shard,
            local.channel,
            local.clk + AB::F::from_canonical_u32(1), // We read p at +1 since p, q could be the same.
            local.x_ptr,
            &local.x_access,
            local.is_real,
        );

        let syscall_id_felt = match E::CURVE_TYPE {
            // CurveType::Secp256k1 => {
            //     AB::F::from_canonical_u32(SyscallCode::SECP256K1_ADD.syscall_id())
            // }
            // CurveType::Bn254 => AB::F::from_canonical_u32(SyscallCode::BN254_ADD.syscall_id()),
            CurveType::Bls12381 => {
                AB::F::from_canonical_u32(SyscallCode::BLS12381_FP_MUL.syscall_id())
            }
            _ => panic!("Unsupported curve"),
        };

        builder.receive_syscall(
            local.shard,
            local.channel,
            local.clk,
            local.nonce,
            syscall_id_felt,
            local.x_ptr,
            local.y_ptr,
            local.is_real,
        );
    }
}
