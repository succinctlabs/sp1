use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use std::fmt::Debug;

use crate::{air::MemoryAirBuilder, utils::zeroed_f_vec};
use generic_array::GenericArray;
use num::{BigUint, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{
    events::{ByteRecord, FieldOperation, PrecompileEvent},
    syscalls::SyscallCode,
    ExecutionRecord, Program,
};
use sp1_curves::{
    params::{limbs_from_vec, FieldParameters, Limbs, NumLimbs, NumWords},
    weierstrass::{bls12_381::bls12381_sqrt, secp256k1::secp256k1_sqrt, WeierstrassParameters},
    CurveType, EllipticCurve,
};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{BaseAirBuilder, InteractionScope, MachineAir, SP1AirBuilder};
use std::marker::PhantomData;
use typenum::Unsigned;

use crate::{
    memory::{MemoryReadCols, MemoryReadWriteCols},
    operations::field::{field_op::FieldOpCols, field_sqrt::FieldSqrtCols, range::FieldLtCols},
    utils::{bytes_to_words_le_vec, limbs_from_access, limbs_from_prev_access, pad_rows_fixed},
};

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
    pub nonce: T,
    pub ptr: T,
    pub sign_bit: T,
    pub x_access: GenericArray<MemoryReadCols<T>, P::WordsFieldElement>,
    pub y_access: GenericArray<MemoryReadWriteCols<T>, P::WordsFieldElement>,
    pub(crate) range_x: FieldLtCols<T, P>,
    pub(crate) x_2: FieldOpCols<T, P>,
    pub(crate) x_3: FieldOpCols<T, P>,
    pub(crate) x_3_plus_b: FieldOpCols<T, P>,
    pub(crate) y: FieldSqrtCols<T, P>,
    pub(crate) neg_y: FieldOpCols<T, P>,
}

/// A set of columns to compute `WeierstrassDecompress` that decompresses a point on a Weierstrass
/// curve.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct LexicographicChoiceCols<T, P: FieldParameters + NumWords> {
    pub comparison_lt_cols: FieldLtCols<T, P>,
    pub neg_y_range_check: FieldLtCols<T, P>,
    pub is_y_eq_sqrt_y_result: T,
    pub when_sqrt_y_res_is_lt: T,
    pub when_neg_y_res_is_lt: T,
}

/// The convention for choosing the decompressed `y` value given a sign bit.
pub enum SignChoiceRule {
    /// Lease significant bit convention.
    ///
    /// In this convention, the `sign_bit` matches the pairty of the `y` value. This is the
    /// convention used in the ECDSA signature scheme, for example, in the secp256k1 curve.
    LeastSignificantBit,
    /// Lexicographic convention.
    ///
    /// In this convention, the `sign_bit` corresponds to whether the `y` value is larger than its
    /// negative counterpart with respect to the embedding of ptime field elements as integers.
    /// This onvention used in the BLS signature scheme, for example, in the BLS12-381 curve.
    Lexicographic,
}

pub struct WeierstrassDecompressChip<E> {
    sign_rule: SignChoiceRule,
    _marker: PhantomData<E>,
}

impl<E: EllipticCurve + WeierstrassParameters> WeierstrassDecompressChip<E> {
    pub const fn new(sign_rule: SignChoiceRule) -> Self {
        Self { sign_rule, _marker: PhantomData::<E> }
    }

    pub const fn with_lsb_rule() -> Self {
        Self { sign_rule: SignChoiceRule::LeastSignificantBit, _marker: PhantomData::<E> }
    }

    pub const fn with_lexicographic_rule() -> Self {
        Self { sign_rule: SignChoiceRule::Lexicographic, _marker: PhantomData::<E> }
    }

    fn populate_field_ops<F: PrimeField32>(
        record: &mut impl ByteRecord,
        shard: u32,
        cols: &mut WeierstrassDecompressCols<F, E::BaseField>,
        x: BigUint,
    ) {
        // Y = sqrt(x^3 + b)
        cols.range_x.populate(record, shard, &x, &E::BaseField::modulus());
        let x_2 = cols.x_2.populate(record, shard, &x.clone(), &x.clone(), FieldOperation::Mul);
        let x_3 = cols.x_3.populate(record, shard, &x_2, &x, FieldOperation::Mul);
        let b = E::b_int();
        let x_3_plus_b = cols.x_3_plus_b.populate(record, shard, &x_3, &b, FieldOperation::Add);

        let sqrt_fn = match E::CURVE_TYPE {
            CurveType::Secp256k1 => secp256k1_sqrt,
            CurveType::Bls12381 => bls12381_sqrt,
            _ => panic!("Unsupported curve"),
        };
        let y = cols.y.populate(record, shard, &x_3_plus_b, sqrt_fn);

        let zero = BigUint::zero();
        cols.neg_y.populate(record, shard, &zero, &y, FieldOperation::Sub);
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> MachineAir<F>
    for WeierstrassDecompressChip<E>
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
            CurveType::Secp256k1 => input.get_precompile_events(SyscallCode::SECP256K1_DECOMPRESS),
            CurveType::Bls12381 => input.get_precompile_events(SyscallCode::BLS12381_DECOMPRESS),
            _ => panic!("Unsupported curve"),
        };

        let mut rows = Vec::new();
        let weierstrass_width = num_weierstrass_decompress_cols::<E::BaseField>();
        let width = BaseAir::<F>::width(self);

        let mut new_byte_lookup_events = Vec::new();

        let modulus = E::BaseField::modulus();

        for (_, event) in events {
            let event = match (E::CURVE_TYPE, event) {
                (CurveType::Secp256k1, PrecompileEvent::Secp256k1Decompress(event)) => event,
                (CurveType::Bls12381, PrecompileEvent::Bls12381Decompress(event)) => event,
                _ => panic!("Unsupported curve"),
            };

            let mut row = zeroed_f_vec(width);
            let cols: &mut WeierstrassDecompressCols<F, E::BaseField> =
                row[0..weierstrass_width].borrow_mut();

            cols.is_real = F::from_bool(true);
            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.ptr = F::from_canonical_u32(event.ptr);
            cols.sign_bit = F::from_bool(event.sign_bit);

            let x = BigUint::from_bytes_le(&event.x_bytes);
            Self::populate_field_ops(&mut new_byte_lookup_events, event.shard, cols, x);

            for i in 0..cols.x_access.len() {
                cols.x_access[i].populate(event.x_memory_records[i], &mut new_byte_lookup_events);
            }
            for i in 0..cols.y_access.len() {
                cols.y_access[i]
                    .populate_write(event.y_memory_records[i], &mut new_byte_lookup_events);
            }

            if matches!(self.sign_rule, SignChoiceRule::Lexicographic) {
                let lsb = cols.y.lsb;
                let choice_cols: &mut LexicographicChoiceCols<F, E::BaseField> =
                    row[weierstrass_width..width].borrow_mut();

                let decompressed_y = BigUint::from_bytes_le(&event.decompressed_y_bytes);
                let neg_y = &modulus - &decompressed_y;

                let is_y_eq_sqrt_y_result =
                    F::from_canonical_u8(event.decompressed_y_bytes[0] % 2) == lsb;
                choice_cols.is_y_eq_sqrt_y_result = F::from_bool(is_y_eq_sqrt_y_result);

                if is_y_eq_sqrt_y_result {
                    choice_cols.neg_y_range_check.populate(
                        &mut new_byte_lookup_events,
                        event.shard,
                        &neg_y,
                        &modulus,
                    );
                } else {
                    choice_cols.neg_y_range_check.populate(
                        &mut new_byte_lookup_events,
                        event.shard,
                        &decompressed_y,
                        &modulus,
                    );
                }
                if event.sign_bit {
                    assert!(neg_y < decompressed_y);
                    choice_cols.when_sqrt_y_res_is_lt = F::from_bool(!is_y_eq_sqrt_y_result);
                    choice_cols.when_neg_y_res_is_lt = F::from_bool(is_y_eq_sqrt_y_result);
                    choice_cols.comparison_lt_cols.populate(
                        &mut new_byte_lookup_events,
                        event.shard,
                        &neg_y,
                        &decompressed_y,
                    );
                } else {
                    assert!(neg_y > decompressed_y);
                    choice_cols.when_sqrt_y_res_is_lt = F::from_bool(is_y_eq_sqrt_y_result);
                    choice_cols.when_neg_y_res_is_lt = F::from_bool(!is_y_eq_sqrt_y_result);
                    choice_cols.comparison_lt_cols.populate(
                        &mut new_byte_lookup_events,
                        event.shard,
                        &decompressed_y,
                        &neg_y,
                    );
                }
            }

            rows.push(row);
        }
        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = zeroed_f_vec(width);
                let cols: &mut WeierstrassDecompressCols<F, E::BaseField> =
                    row.as_mut_slice()[0..weierstrass_width].borrow_mut();

                // take X of the generator as a dummy value to make sure Y^2 = X^3 + b holds
                let dummy_value = E::generator().0;
                let dummy_bytes = dummy_value.to_bytes_le();
                let words = bytes_to_words_le_vec(&dummy_bytes);
                for i in 0..cols.x_access.len() {
                    cols.x_access[i].access.value = words[i].into();
                }

                Self::populate_field_ops(&mut vec![], 0, cols, dummy_value);
                row
            },
            input.fixed_log2_rows::<F, _>(self),
        );

        let mut trace = RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), width);

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut WeierstrassDecompressCols<F, E::BaseField> =
                trace.values[i * width..i * width + weierstrass_width].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match E::CURVE_TYPE {
                CurveType::Secp256k1 => {
                    !shard.get_precompile_events(SyscallCode::SECP256K1_DECOMPRESS).is_empty()
                }
                CurveType::Bls12381 => {
                    !shard.get_precompile_events(SyscallCode::BLS12381_DECOMPRESS).is_empty()
                }
                _ => panic!("Unsupported curve"),
            }
        }
    }
}

impl<F, E: EllipticCurve> BaseAir<F> for WeierstrassDecompressChip<E> {
    fn width(&self) -> usize {
        num_weierstrass_decompress_cols::<E::BaseField>()
            + match self.sign_rule {
                SignChoiceRule::LeastSignificantBit => 0,
                SignChoiceRule::Lexicographic => {
                    size_of::<LexicographicChoiceCols<u8, E::BaseField>>()
                }
            }
    }
}

impl<AB, E: EllipticCurve + WeierstrassParameters> Air<AB> for WeierstrassDecompressChip<E>
where
    AB: SP1AirBuilder,
    Limbs<AB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let weierstrass_cols = num_weierstrass_decompress_cols::<E::BaseField>();
        let local_slice = main.row_slice(0);
        let local: &WeierstrassDecompressCols<AB::Var, E::BaseField> =
            (*local_slice)[0..weierstrass_cols].borrow();
        let next = main.row_slice(1);
        let next: &WeierstrassDecompressCols<AB::Var, E::BaseField> =
            (*next)[0..weierstrass_cols].borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder.when_transition().assert_eq(local.nonce + AB::Expr::one(), next.nonce);

        let num_limbs = <E::BaseField as NumLimbs>::Limbs::USIZE;
        let num_words_field_element = num_limbs / 4;

        builder.assert_bool(local.sign_bit);

        let x: Limbs<AB::Var, <E::BaseField as NumLimbs>::Limbs> =
            limbs_from_prev_access(&local.x_access);
        let max_num_limbs = E::BaseField::to_limbs_field_vec(&E::BaseField::modulus());
        local.range_x.eval(
            builder,
            &x,
            &limbs_from_vec::<AB::Expr, <E::BaseField as NumLimbs>::Limbs, AB::F>(max_num_limbs),
            local.is_real,
        );
        local.x_2.eval(builder, &x, &x, FieldOperation::Mul, local.is_real);
        local.x_3.eval(builder, &local.x_2.result, &x, FieldOperation::Mul, local.is_real);
        let b = E::b_int();
        let b_const = E::BaseField::to_limbs_field::<AB::F, _>(&b);
        local.x_3_plus_b.eval(
            builder,
            &local.x_3.result,
            &b_const,
            FieldOperation::Add,
            local.is_real,
        );

        local.neg_y.eval(
            builder,
            &[AB::Expr::zero()].iter(),
            &local.y.multiplication.result,
            FieldOperation::Sub,
            local.is_real,
        );

        local.y.eval(builder, &local.x_3_plus_b.result, local.y.lsb, local.is_real);

        let y_limbs: Limbs<AB::Var, <E::BaseField as NumLimbs>::Limbs> =
            limbs_from_access(&local.y_access);

        // Constrain the y value according the sign rule convention.
        match self.sign_rule {
            SignChoiceRule::LeastSignificantBit => {
                // When the sign rule is LeastSignificantBit, the sign_bit should match the parity
                // of the result. The parity of the square root result is given by the local.y.lsb
                // value. Thus, if the sign_bit matches the local.y.lsb value, then the result
                // should be the square root of the y value. Otherwise, the result should be the
                // negative square root of the y value.
                builder
                    .when(local.is_real)
                    .when_ne(local.y.lsb, AB::Expr::one() - local.sign_bit)
                    .assert_all_eq(local.y.multiplication.result, y_limbs);
                builder
                    .when(local.is_real)
                    .when_ne(local.y.lsb, local.sign_bit)
                    .assert_all_eq(local.neg_y.result, y_limbs);
            }
            SignChoiceRule::Lexicographic => {
                // When the sign rule is Lexicographic, the sign_bit corresponds to whether
                // the result is greater than or less its negative with respect to the lexicographic
                // ordering, embedding prime field values as integers.
                //
                // In order to endorce these constraints, we will use the auxiliary choice columns.

                // Get the choice columns from the row slice
                let choice_cols: &LexicographicChoiceCols<AB::Var, E::BaseField> = (*local_slice)
                    [weierstrass_cols
                        ..weierstrass_cols
                            + size_of::<LexicographicChoiceCols<u8, E::BaseField>>()]
                    .borrow();

                // Range check the neg_y value since we are now using a lexicographic comparison.
                let modulus_limbs = E::BaseField::to_limbs_field_vec(&E::BaseField::modulus());
                let modulus_limbs =
                    limbs_from_vec::<AB::Expr, <E::BaseField as NumLimbs>::Limbs, AB::F>(
                        modulus_limbs,
                    );
                choice_cols.neg_y_range_check.eval(
                    builder,
                    &local.neg_y.result,
                    &modulus_limbs,
                    local.is_real,
                );

                // Assert that the flags are booleans.
                builder.assert_bool(choice_cols.is_y_eq_sqrt_y_result);
                builder.assert_bool(choice_cols.when_sqrt_y_res_is_lt);
                builder.assert_bool(choice_cols.when_neg_y_res_is_lt);

                // Assert that the `when` flags are disjoint:
                builder.when(local.is_real).assert_one(
                    choice_cols.when_sqrt_y_res_is_lt + choice_cols.when_neg_y_res_is_lt,
                );

                // Assert that the value of `y` matches the claimed value by the flags.

                builder
                    .when(local.is_real)
                    .when(choice_cols.is_y_eq_sqrt_y_result)
                    .assert_all_eq(local.y.multiplication.result, y_limbs);

                builder
                    .when(local.is_real)
                    .when_not(choice_cols.is_y_eq_sqrt_y_result)
                    .assert_all_eq(local.neg_y.result, y_limbs);

                // Assert that the comparison only turns on when `is_real` is true.
                builder.when_not(local.is_real).assert_zero(choice_cols.when_sqrt_y_res_is_lt);
                builder.when_not(local.is_real).assert_zero(choice_cols.when_neg_y_res_is_lt);

                // Assert that the flags are set correctly. When the sign_bit is true, we want that
                // `neg_y < y`, and vice versa when the sign_bit is false. Hence, when should have:
                // - When `sign_bit` is true , then when_sqrt_y_res_is_lt = (y != sqrt(y)).
                // - When `sign_bit` is false, then when_neg_y_res_is_lt = (y == sqrt(y)).
                // - When `sign_bit` is true , then when_sqrt_y_res_is_lt = (y != sqrt(y)).
                // - When `sign_bit` is false, then when_neg_y_res_is_lt = (y == sqrt(y)).
                //
                // Since the when less-than flags are disjoint, we can assert that:
                // - When `sign_bit` is true , then is_y_eq_sqrt_y_result == when_neg_y_res_is_lt.
                // - When `sign_bit` is false, then is_y_eq_sqrt_y_result == when_sqrt_y_res_is_lt.
                builder
                    .when(local.is_real)
                    .when(local.sign_bit)
                    .assert_eq(choice_cols.is_y_eq_sqrt_y_result, choice_cols.when_neg_y_res_is_lt);
                builder.when(local.is_real).when_not(local.sign_bit).assert_eq(
                    choice_cols.is_y_eq_sqrt_y_result,
                    choice_cols.when_sqrt_y_res_is_lt,
                );

                // Assert the less-than comparisons according to the flags.

                choice_cols.comparison_lt_cols.eval(
                    builder,
                    &local.y.multiplication.result,
                    &local.neg_y.result,
                    choice_cols.when_sqrt_y_res_is_lt,
                );

                choice_cols.comparison_lt_cols.eval(
                    builder,
                    &local.neg_y.result,
                    &local.y.multiplication.result,
                    choice_cols.when_neg_y_res_is_lt,
                );
            }
        }

        for i in 0..num_words_field_element {
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.ptr.into() + AB::F::from_canonical_u32((i as u32) * 4 + num_limbs as u32),
                &local.x_access[i],
                local.is_real,
            );
        }
        for i in 0..num_words_field_element {
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.ptr.into() + AB::F::from_canonical_u32((i as u32) * 4),
                &local.y_access[i],
                local.is_real,
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
            local.shard,
            local.clk,
            local.nonce,
            syscall_id,
            local.ptr,
            local.sign_bit,
            local.is_real,
            InteractionScope::Local,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        io::SP1Stdin,
        utils::{self, tests::BLS12381_DECOMPRESS_ELF},
    };
    use amcl::{
        bls381::bls381::{basic::key_pair_generate_g2, utils::deserialize_g1},
        rand::RAND,
    };
    use elliptic_curve::sec1::ToEncodedPoint;
    use rand::{thread_rng, Rng};
    use sp1_core_executor::Program;
    use sp1_stark::CpuProver;

    use crate::utils::{run_test_io, tests::SECP256K1_DECOMPRESS_ELF};

    #[test]
    fn test_weierstrass_bls_decompress() {
        utils::setup_logger();
        let mut rng = thread_rng();
        let mut rand = RAND::new();

        let len = 100;
        let num_tests = 10;
        let random_slice = (0..len).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        rand.seed(len, &random_slice);

        for _ in 0..num_tests {
            let (_, compressed) = key_pair_generate_g2(&mut rand);

            let stdin = SP1Stdin::from(&compressed);
            let mut public_values = run_test_io::<CpuProver<_, _>>(
                Program::from(BLS12381_DECOMPRESS_ELF).unwrap(),
                stdin,
            )
            .unwrap();

            let mut result = [0; 96];
            public_values.read_slice(&mut result);

            let point = deserialize_g1(&compressed).unwrap();
            let x = point.getx().to_string();
            let y = point.gety().to_string();
            let decompressed = hex::decode(format!("{x}{y}")).unwrap();
            assert_eq!(result, decompressed.as_slice());
        }
    }

    #[test]
    fn test_weierstrass_k256_decompress() {
        utils::setup_logger();

        let mut rng = thread_rng();

        let num_tests = 10;

        for _ in 0..num_tests {
            let secret_key = k256::SecretKey::random(&mut rng);
            let public_key = secret_key.public_key();
            let encoded = public_key.to_encoded_point(false);
            let decompressed = encoded.as_bytes();
            let compressed = public_key.to_sec1_bytes();

            let inputs = SP1Stdin::from(&compressed);

            let mut public_values = run_test_io::<CpuProver<_, _>>(
                Program::from(SECP256K1_DECOMPRESS_ELF).unwrap(),
                inputs,
            )
            .unwrap();
            let mut result = [0; 65];
            public_values.read_slice(&mut result);
            assert_eq!(result, decompressed);
        }
    }
}
