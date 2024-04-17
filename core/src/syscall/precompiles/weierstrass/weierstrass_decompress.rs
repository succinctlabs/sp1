use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use std::fmt::Debug;

use generic_array::GenericArray;
use num::BigUint;
use num::Zero;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_derive::AlignedBorrow;
use std::marker::PhantomData;
use typenum::Unsigned;

use crate::air::BaseAirBuilder;
use crate::air::MachineAir;
use crate::air::SP1AirBuilder;
use crate::memory::MemoryReadCols;
use crate::memory::MemoryReadWriteCols;
use crate::operations::field::field_op::FieldOpCols;
use crate::operations::field::field_op::FieldOperation;
use crate::operations::field::field_sqrt::FieldSqrtCols;
use crate::operations::field::params::Limbs;
use crate::runtime::ExecutionRecord;
use crate::runtime::Program;
use crate::runtime::Syscall;
use crate::runtime::SyscallCode;
use crate::syscall::precompiles::create_ec_decompress_event;
use crate::syscall::precompiles::SyscallContext;
use crate::utils::bytes_to_words_le_vec;
use crate::utils::ec::field::FieldParameters;
use crate::utils::ec::field::NumLimbs;
use crate::utils::ec::field::NumWords;
use crate::utils::ec::weierstrass::bls12_381::bls12381_sqrt;
use crate::utils::ec::weierstrass::secp256k1::secp256k1_sqrt;
use crate::utils::ec::weierstrass::WeierstrassParameters;
use crate::utils::ec::CurveType;
use crate::utils::ec::EllipticCurve;
use crate::utils::limbs_from_access;
use crate::utils::limbs_from_prev_access;
use crate::utils::pad_rows;

pub const fn num_weierstrass_decompress_cols<P: FieldParameters + NumWords>() -> usize {
    size_of::<WeierstrassDecompressCols<u8, P>>()
}

/// A set of columns to compute `WeierstrassDecompress` that decompresses a point on a Weierstrass
/// curve.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassDecompressCols<T, P: FieldParameters + NumWords> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub ptr: T,
    pub is_odd: T,
    pub x_access: GenericArray<MemoryReadCols<T>, P::WordsFieldElement>,
    pub y_access: GenericArray<MemoryReadWriteCols<T>, P::WordsFieldElement>,
    pub(crate) x_2: FieldOpCols<T, P>,
    pub(crate) x_3: FieldOpCols<T, P>,
    pub(crate) x_3_plus_b: FieldOpCols<T, P>,
    pub(crate) y: FieldSqrtCols<T, P>,
    pub(crate) neg_y: FieldOpCols<T, P>,
    pub(crate) y_least_bits: [T; 8],
}

#[derive(Default)]
pub struct WeierstrassDecompressChip<E> {
    _marker: PhantomData<E>,
}

impl<E: EllipticCurve> Syscall for WeierstrassDecompressChip<E> {
    fn execute(&self, rt: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_ec_decompress_event::<E>(rt, arg1, arg2);
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => rt.record_mut().k256_decompress_events.push(event),
            CurveType::Bls12381 => rt.record_mut().bls12381_decompress_events.push(event),
            _ => panic!("Unsupported curve"),
        }
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        0
    }
}

impl<E: EllipticCurve + WeierstrassParameters> WeierstrassDecompressChip<E> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData::<E>,
        }
    }

    fn populate_field_ops<F: PrimeField32>(
        cols: &mut WeierstrassDecompressCols<F, E::BaseField>,
        x: BigUint,
    ) {
        // Y = sqrt(x^3 + b)
        let x_2 = cols
            .x_2
            .populate(&x.clone(), &x.clone(), FieldOperation::Mul);
        let x_3 = cols.x_3.populate(&x_2, &x, FieldOperation::Mul);
        let b = E::b_int();
        let x_3_plus_b = cols.x_3_plus_b.populate(&x_3, &b, FieldOperation::Add);

        let sqrt_fn = match E::CURVE_TYPE {
            CurveType::Secp256k1 => secp256k1_sqrt,
            CurveType::Bls12381 => bls12381_sqrt,
            _ => panic!("Unsupported curve"),
        };
        let y = cols.y.populate(&x_3_plus_b, sqrt_fn);

        let zero = BigUint::zero();
        cols.neg_y.populate(&zero, &y, FieldOperation::Sub);
        // Decompose bits of least significant Y byte
        let y_bytes = y.to_bytes_le();
        let y_lsb = if y_bytes.is_empty() { 0 } else { y_bytes[0] };
        for i in 0..8 {
            cols.y_least_bits[i] = F::from_canonical_u32(((y_lsb >> i) & 1) as u32);
        }
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> MachineAir<F>
    for WeierstrassDecompressChip<E>
where
    [(); num_weierstrass_decompress_cols::<E::BaseField>()]:,
{
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1Decompress".to_string(),
            CurveType::Bls12381 => "Bls12381Decompress".to_string(),
            _ => panic!("Unsupported curve"),
        }
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => &input.k256_decompress_events,
            CurveType::Bls12381 => &input.bls12381_decompress_events,
            _ => panic!("Unsupported curve"),
        };

        let mut rows = Vec::new();

        let mut new_byte_lookup_events = Vec::new();

        for i in 0..events.len() {
            let event = events[i].clone();
            let mut row = [F::zero(); num_weierstrass_decompress_cols::<E::BaseField>()];
            let cols: &mut WeierstrassDecompressCols<F, E::BaseField> =
                row.as_mut_slice().borrow_mut();

            cols.is_real = F::from_bool(true);
            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.ptr = F::from_canonical_u32(event.ptr);
            cols.is_odd = F::from_canonical_u32(event.is_odd as u32);

            let x = BigUint::from_bytes_le(&event.x_bytes);
            Self::populate_field_ops(cols, x);

            for i in 0..cols.x_access.len() {
                cols.x_access[i].populate(event.x_memory_records[i], &mut new_byte_lookup_events);
            }
            for i in 0..cols.y_access.len() {
                cols.y_access[i]
                    .populate_write(event.y_memory_records[i], &mut new_byte_lookup_events);
            }

            rows.push(row);
        }
        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows(&mut rows, || {
            let mut row = [F::zero(); num_weierstrass_decompress_cols::<E::BaseField>()];
            let cols: &mut WeierstrassDecompressCols<F, E::BaseField> =
                row.as_mut_slice().borrow_mut();

            // take X of the generator as a dummy value to make sure Y^2 = X^3 + b holds
            let dummy_value = E::generator().0;
            let dummy_bytes = dummy_value.to_bytes_le();
            let words = bytes_to_words_le_vec(&dummy_bytes);
            for i in 0..cols.x_access.len() {
                cols.x_access[i].access.value = words[i].into();
            }

            Self::populate_field_ops(cols, dummy_value);
            row
        });

        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            num_weierstrass_decompress_cols::<E::BaseField>(),
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => !shard.k256_decompress_events.is_empty(),
            CurveType::Bls12381 => !shard.bls12381_decompress_events.is_empty(),
            _ => panic!("Unsupported curve"),
        }
    }
}

impl<F, E: EllipticCurve> BaseAir<F> for WeierstrassDecompressChip<E> {
    fn width(&self) -> usize {
        num_weierstrass_decompress_cols::<E::BaseField>()
    }
}

impl<AB, E: EllipticCurve + WeierstrassParameters> Air<AB> for WeierstrassDecompressChip<E>
where
    AB: SP1AirBuilder,
    Limbs<AB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0);
        let row: &WeierstrassDecompressCols<AB::Var, E::BaseField> = (*row).borrow();

        let num_limbs = <E::BaseField as NumLimbs>::Limbs::USIZE;
        let num_words_field_element = num_limbs / 4;

        builder.assert_bool(row.is_odd);

        let x: Limbs<AB::Var, <E::BaseField as NumLimbs>::Limbs> =
            limbs_from_prev_access(&row.x_access);
        row.x_2
            .eval::<AB, _, _>(builder, &x, &x, FieldOperation::Mul);
        row.x_3
            .eval::<AB, _, _>(builder, &row.x_2.result, &x, FieldOperation::Mul);
        let b = E::b_int();
        let b_const = E::BaseField::to_limbs_field::<AB::F, _>(&b);
        row.x_3_plus_b
            .eval::<AB, _, _>(builder, &row.x_3.result, &b_const, FieldOperation::Add);
        row.y.eval::<AB>(builder, &row.x_3_plus_b.result);
        row.neg_y.eval::<AB, _, _>(
            builder,
            &[AB::Expr::zero()].iter(),
            &row.y.multiplication.result,
            FieldOperation::Sub,
        );

        // Constrain decomposition of least significant byte of Y into `y_least_bits`
        for i in 0..8 {
            builder.when(row.is_real).assert_bool(row.y_least_bits[i]);
        }
        let y_least_byte = row.y.multiplication.result.0[0];
        let powers_of_two = [1, 2, 4, 8, 16, 32, 64, 128].map(AB::F::from_canonical_u32);
        let recomputed_byte: AB::Expr = row
            .y_least_bits
            .iter()
            .zip(powers_of_two)
            .map(|(p, b)| (*p).into() * b)
            .sum();
        builder
            .when(row.is_real)
            .assert_eq(recomputed_byte, y_least_byte);

        // Interpret the lowest bit of Y as whether it is odd or not.
        let y_is_odd = row.y_least_bits[0];

        let y_limbs: Limbs<AB::Var, <E::BaseField as NumLimbs>::Limbs> =
            limbs_from_access(&row.y_access);
        builder
            .when(row.is_real)
            .when_ne(y_is_odd, AB::Expr::one() - row.is_odd)
            .assert_all_eq(row.y.multiplication.result, y_limbs);
        builder
            .when(row.is_real)
            .when_ne(y_is_odd, row.is_odd)
            .assert_all_eq(row.neg_y.result, y_limbs);

        for i in 0..num_words_field_element {
            builder.eval_memory_access(
                row.shard,
                row.clk,
                row.ptr.into() + AB::F::from_canonical_u32((i as u32) * 4 + num_limbs as u32),
                &row.x_access[i],
                row.is_real,
            );
        }
        for i in 0..num_words_field_element {
            builder.eval_memory_access(
                row.shard,
                row.clk,
                row.ptr.into() + AB::F::from_canonical_u32((i as u32) * 4),
                &row.y_access[i],
                row.is_real,
            );
        }

        let syscall_id = match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                AB::F::from_canonical_u32(SyscallCode::SECP256K1_DECOMPRESS.syscall_id())
            }
            CurveType::Bls12381 => {
                AB::F::from_canonical_u32(SyscallCode::BLS12381_DECOMPRESS.syscall_id())
            }
            _ => panic!("Unsupported curve"),
        };

        builder.receive_syscall(
            row.shard,
            row.clk,
            syscall_id,
            row.ptr,
            row.is_odd,
            row.is_real,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::Program;
    use crate::{
        utils::{self, tests::BLS12381_DECOMPRESS_ELF},
        SP1Stdin,
    };
    use amcl::bls381::bls381::basic::key_pair_generate_g2;
    use amcl::bls381::bls381::utils::deserialize_g1;
    use amcl::rand::RAND;
    use elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use crate::utils::run_test_io;
    use crate::utils::tests::SECP256K1_DECOMPRESS_ELF;

    #[test]
    fn test_weierstrass_bls_decompress() {
        utils::setup_logger();
        let (_, compressed) = key_pair_generate_g2(&mut RAND::new());

        let inputs = SP1Stdin::from(&compressed);
        let mut proof = run_test_io(Program::from(BLS12381_DECOMPRESS_ELF), inputs).unwrap();

        let mut result = [0; 96];
        proof.public_values.read_slice(&mut result);

        let point = deserialize_g1(&compressed).unwrap();
        let x = point.getx().to_string();
        let y = point.gety().to_string();
        let decompressed = hex::decode(format!("{x}{y}")).unwrap();
        assert_eq!(result, decompressed.as_slice());
    }

    #[test]
    fn test_weierstrass_k256_decompress() {
        utils::setup_logger();

        let mut rng = StdRng::seed_from_u64(2);

        let secret_key = k256::SecretKey::random(&mut rng);
        let public_key = secret_key.public_key();
        let encoded = public_key.to_encoded_point(false);
        let decompressed = encoded.as_bytes();
        let compressed = public_key.to_sec1_bytes();

        let inputs = SP1Stdin::from(&compressed);

        let mut proof = run_test_io(Program::from(SECP256K1_DECOMPRESS_ELF), inputs).unwrap();
        let mut result = [0; 65];
        proof.public_values.read_slice(&mut result);
        assert_eq!(result, decompressed);
    }
}
