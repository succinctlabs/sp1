use crate::{
    air::SP1CoreAirBuilder,
    memory::{MemoryAccessCols, MemoryAccessColsU8},
    operations::{
        field::{
            field_inner_product::FieldInnerProductCols, field_op::FieldOpCols,
            field_sqrt::FieldSqrtCols, range::FieldLtCols,
        },
        AddrAddOperation, SyscallAddrOperation,
    },
    utils::{bytes_to_words_le_vec, limbs_to_words, next_multiple_of_32},
};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use generic_array::GenericArray;
use itertools::Itertools;
use num::{BigUint, One, Zero};
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteRecord, FieldOperation, MemoryReadRecord, MemoryRecordEnum, PrecompileEvent},
    ExecutionRecord, Program, SyscallCode,
};
use sp1_curves::{
    params::{limbs_from_vec, FieldParameters, Limbs, NumLimbs, NumWords},
    weierstrass::{
        bls12_381::bls12381_sqrt, secp256k1::secp256k1_sqrt, secp256r1::secp256r1_sqrt,
        WeierstrassParameters,
    },
    CurveType, EllipticCurve,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{BaseAirBuilder, InteractionScope, MachineAir},
    Word,
};
use sp1_primitives::polynomial::Polynomial;
use std::{fmt::Debug, marker::PhantomData, mem::MaybeUninit};
use typenum::Unsigned;

pub const fn num_weierstrass_decompress_cols<P: FieldParameters + NumWords>() -> usize {
    size_of::<WeierstrassDecompressCols<u8, P>>()
}

/// A set of columns to compute `WeierstrassDecompress` that decompresses a point on a Weierstrass
/// curve. **TODO**: this precompile has no page protection, as it's expected to be deprecated.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassDecompressCols<T, P: FieldParameters + NumWords> {
    pub is_real: T,
    pub clk_high: T,
    pub clk_low: T,
    pub ptr: SyscallAddrOperation<T>,
    pub x_addrs: GenericArray<AddrAddOperation<T>, P::WordsFieldElement>,
    pub y_addrs: GenericArray<AddrAddOperation<T>, P::WordsFieldElement>,
    pub sign_bit: T,
    pub x_access: GenericArray<MemoryAccessColsU8<T>, P::WordsFieldElement>,
    pub y_access: GenericArray<MemoryAccessCols<T>, P::WordsFieldElement>,
    pub y_value: GenericArray<Word<T>, P::WordsFieldElement>,
    pub(crate) range_x: FieldLtCols<T, P>,
    pub(crate) neg_y_range_check: FieldLtCols<T, P>,
    pub(crate) x_2: FieldOpCols<T, P>,
    pub(crate) x_3: FieldOpCols<T, P>,
    pub(crate) ax_plus_b: FieldInnerProductCols<T, P>,
    pub(crate) x_3_plus_b_plus_ax: FieldOpCols<T, P>,
    pub(crate) y: FieldSqrtCols<T, P>,
    pub(crate) neg_y: FieldOpCols<T, P>,
}

/// A set of columns to compute `WeierstrassDecompress` that decompresses a point on a Weierstrass
/// curve.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct LexicographicChoiceCols<T, P: FieldParameters + NumWords> {
    pub comparison_lt_cols: FieldLtCols<T, P>,
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
        cols: &mut WeierstrassDecompressCols<F, E::BaseField>,
        x: BigUint,
    ) {
        // Y = sqrt(x^3 + ax + b)
        cols.range_x.populate(record, &x, &E::BaseField::modulus());
        let x_2 = cols.x_2.populate(record, &x.clone(), &x.clone(), FieldOperation::Mul);
        let x_3 = cols.x_3.populate(record, &x_2, &x, FieldOperation::Mul);
        let b = E::b_int();
        let a = E::a_int();
        let param_vec = vec![a, b];
        let x_vec = vec![x, BigUint::one()];
        let ax_plus_b = cols.ax_plus_b.populate(record, &param_vec, &x_vec);
        let x_3_plus_b_plus_ax =
            cols.x_3_plus_b_plus_ax.populate(record, &x_3, &ax_plus_b, FieldOperation::Add);

        let sqrt_fn = match E::CURVE_TYPE {
            CurveType::Secp256k1 => secp256k1_sqrt,
            CurveType::Secp256r1 => secp256r1_sqrt,
            CurveType::Bls12381 => bls12381_sqrt,
            _ => panic!("Unsupported curve"),
        };

        let y = cols.y.populate(record, &x_3_plus_b_plus_ax, sqrt_fn);
        let zero = BigUint::zero();
        let neg_y = cols.neg_y.populate(record, &zero, &y, FieldOperation::Sub);
        cols.neg_y_range_check.populate(record, &neg_y, &E::BaseField::modulus());
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> MachineAir<F>
    for WeierstrassDecompressChip<E>
{
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1Decompress",
            CurveType::Secp256r1 => "Secp256r1Decompress",
            CurveType::Bls12381 => "Bls12381Decompress",
            _ => panic!("Unsupported curve"),
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                input.get_precompile_events(SyscallCode::SECP256K1_DECOMPRESS).len()
            }
            CurveType::Secp256r1 => {
                input.get_precompile_events(SyscallCode::SECP256R1_DECOMPRESS).len()
            }
            CurveType::Bls12381 => {
                input.get_precompile_events(SyscallCode::BLS12381_DECOMPRESS).len()
            }
            _ => panic!("Unsupported curve"),
        };
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let padded_nb_rows =
            <WeierstrassDecompressChip<E> as MachineAir<F>>::num_rows(self, input).unwrap();
        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => input.get_precompile_events(SyscallCode::SECP256K1_DECOMPRESS),
            CurveType::Secp256r1 => input.get_precompile_events(SyscallCode::SECP256R1_DECOMPRESS),
            CurveType::Bls12381 => input.get_precompile_events(SyscallCode::BLS12381_DECOMPRESS),
            _ => panic!("Unsupported curve"),
        };

        let num_event_rows = events.len();
        let num_cols = num_weierstrass_decompress_cols::<E::BaseField>();

        let mut new_byte_lookup_events = Vec::new();

        unsafe {
            let padding_start = num_event_rows * num_cols;
            let padding_size = (padded_nb_rows - num_event_rows) * num_cols;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values =
            unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * num_cols) };

        let weierstrass_width = num_weierstrass_decompress_cols::<E::BaseField>();
        let width = BaseAir::<F>::width(self);
        let num_limbs = <E::BaseField as NumLimbs>::Limbs::USIZE;
        let modulus = E::BaseField::modulus();

        values.chunks_mut(num_cols).enumerate().for_each(|(idx, row)| {
            let cols: &mut WeierstrassDecompressCols<F, E::BaseField> = row.borrow_mut();
            let event = &events[idx].1;
            let event = match (E::CURVE_TYPE, event) {
                (CurveType::Secp256k1, PrecompileEvent::Secp256k1Decompress(event)) => event,
                (CurveType::Secp256r1, PrecompileEvent::Secp256r1Decompress(event)) => event,
                (CurveType::Bls12381, PrecompileEvent::Bls12381Decompress(event)) => event,
                _ => panic!("Unsupported curve"),
            };

            cols.is_real = F::from_bool(true);
            cols.clk_high = F::from_canonical_u32((event.clk >> 24) as u32);
            cols.clk_low = F::from_canonical_u32((event.clk & 0xFFFFFF) as u32);
            cols.ptr.populate(&mut new_byte_lookup_events, event.ptr, E::NB_LIMBS as u64 * 2);
            cols.sign_bit = F::from_bool(event.sign_bit);

            let x = BigUint::from_bytes_le(&event.x_bytes);
            Self::populate_field_ops(&mut new_byte_lookup_events, cols, x);

            for i in 0..cols.x_access.len() {
                let record = MemoryRecordEnum::Read(event.x_memory_records[i]);
                cols.x_access[i].populate(record, &mut new_byte_lookup_events);
                cols.x_addrs[i].populate(
                    &mut new_byte_lookup_events,
                    event.ptr + num_limbs as u64,
                    8 * i as u64,
                );
            }
            for i in 0..cols.y_access.len() {
                let record = MemoryRecordEnum::Write(event.y_memory_records[i]);
                let current_record = record.current_record();
                cols.y_access[i].populate(record, &mut new_byte_lookup_events);
                cols.y_value[i] = Word::from(current_record.value);
                cols.y_addrs[i].populate(&mut new_byte_lookup_events, event.ptr, 8 * i as u64);
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

                if event.sign_bit {
                    assert!(neg_y < decompressed_y);
                    choice_cols.when_sqrt_y_res_is_lt = F::from_bool(!is_y_eq_sqrt_y_result);
                    choice_cols.when_neg_y_res_is_lt = F::from_bool(is_y_eq_sqrt_y_result);
                    choice_cols.comparison_lt_cols.populate(
                        &mut new_byte_lookup_events,
                        &neg_y,
                        &decompressed_y,
                    );
                } else {
                    assert!(neg_y > decompressed_y);
                    choice_cols.when_sqrt_y_res_is_lt = F::from_bool(is_y_eq_sqrt_y_result);
                    choice_cols.when_neg_y_res_is_lt = F::from_bool(!is_y_eq_sqrt_y_result);
                    choice_cols.comparison_lt_cols.populate(
                        &mut new_byte_lookup_events,
                        &decompressed_y,
                        &neg_y,
                    );
                }
            }
        });

        for row in num_event_rows..padded_nb_rows {
            let row_start = row * num_cols;
            let row = unsafe {
                core::slice::from_raw_parts_mut(
                    buffer[row_start..row_start + weierstrass_width].as_mut_ptr() as *mut F,
                    num_cols,
                )
            };
            let cols: &mut WeierstrassDecompressCols<F, E::BaseField> = row.borrow_mut();
            // take X of the generator as a dummy value to make sure Y^2 = X^3 + b holds
            let dummy_value = E::generator().0;
            let dummy_bytes = dummy_value.to_bytes_le();
            let words = bytes_to_words_le_vec(&dummy_bytes);
            let mut blu = vec![];
            for i in 0..cols.x_access.len() {
                cols.x_access[i].populate(
                    MemoryRecordEnum::Read(MemoryReadRecord {
                        prev_timestamp: 0,
                        value: words[i],
                        timestamp: 1,
                        prev_page_prot_record: None,
                    }),
                    &mut blu,
                );
            }
            Self::populate_field_ops(&mut vec![], cols, dummy_value);
        }
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match E::CURVE_TYPE {
                CurveType::Secp256k1 => {
                    !shard.get_precompile_events(SyscallCode::SECP256K1_DECOMPRESS).is_empty()
                }
                CurveType::Secp256r1 => {
                    !shard.get_precompile_events(SyscallCode::SECP256R1_DECOMPRESS).is_empty()
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
    AB: SP1CoreAirBuilder,
    Limbs<AB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let weierstrass_cols = num_weierstrass_decompress_cols::<E::BaseField>();
        let local_slice = main.row_slice(0);
        let local: &WeierstrassDecompressCols<AB::Var, E::BaseField> =
            (*local_slice)[0..weierstrass_cols].borrow();

        let num_limbs = <E::BaseField as NumLimbs>::Limbs::USIZE;
        let num_words_field_element = num_limbs / 8;

        builder.assert_bool(local.sign_bit);

        let x_limbs = builder.generate_limbs(&local.x_access, local.is_real.into());
        let x: Limbs<AB::Expr, <E::BaseField as NumLimbs>::Limbs> =
            Limbs(x_limbs.try_into().expect("failed to convert limbs"));
        let max_num_limbs = E::BaseField::to_limbs_field_vec(&E::BaseField::modulus());
        local.range_x.eval(
            builder,
            &x,
            &limbs_from_vec::<AB::Expr, <E::BaseField as NumLimbs>::Limbs, AB::F>(max_num_limbs),
            local.is_real,
        );
        local.x_2.eval(builder, &x, &x, FieldOperation::Mul, local.is_real);
        local.x_3.eval(builder, &local.x_2.result, &x, FieldOperation::Mul, local.is_real);
        let b_const = E::BaseField::to_limbs_field::<AB::F, _>(&E::b_int());
        let a_const = E::BaseField::to_limbs_field::<AB::F, _>(&E::a_int());
        let params = [a_const, b_const];
        let p_x: Polynomial<AB::Expr> = x.into();
        let p_one: Polynomial<AB::Expr> =
            E::BaseField::to_limbs_field::<AB::F, _>(&BigUint::one()).into();
        local.ax_plus_b.eval::<AB>(builder, &params, &[p_x, p_one], local.is_real);
        local.x_3_plus_b_plus_ax.eval(
            builder,
            &local.x_3.result,
            &local.ax_plus_b.result,
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
        // Range check the `neg_y.result` to be canonical.
        let modulus_limbs = E::BaseField::to_limbs_field_vec(&E::BaseField::modulus());
        let modulus_limbs =
            limbs_from_vec::<AB::Expr, <E::BaseField as NumLimbs>::Limbs, AB::F>(modulus_limbs);
        local.neg_y_range_check.eval(builder, &local.neg_y.result, &modulus_limbs, local.is_real);

        // Constrain that `y` is a square root. Note that `y.multiplication.result` is constrained
        // to be canonical here. Since `y_limbs` is constrained to be either
        // `y.multiplication.result` or `neg_y.result`, `y_limbs` will be canonical.
        local.y.eval(builder, &local.x_3_plus_b_plus_ax.result, local.y.lsb, local.is_real);

        let neg_y_words = limbs_to_words::<AB>(local.neg_y.result.0.to_vec());
        let mul_words = limbs_to_words::<AB>(local.y.multiplication.result.0.to_vec());
        let y_value_words =
            local.y_value.to_vec().iter().map(|w| w.map(|x| x.into())).collect_vec();

        // Constrain the y value according the sign rule convention.
        match self.sign_rule {
            SignChoiceRule::LeastSignificantBit => {
                // When the sign rule is LeastSignificantBit, the sign_bit should match the parity
                // of the result. The parity of the square root result is given by the local.y.lsb
                // value. Thus, if the sign_bit matches the local.y.lsb value, then the result
                // should be the square root of the y value. Otherwise, the result should be the
                // negative square root of the y value.
                for (mul_word, y_value_word) in mul_words.iter().zip(y_value_words.iter()) {
                    builder
                        .when(local.is_real)
                        .when_ne(local.y.lsb, AB::Expr::one() - local.sign_bit)
                        .assert_all_eq(mul_word.clone(), y_value_word.clone());
                }
                for (neg_y_word, y_value_word) in neg_y_words.iter().zip(y_value_words.iter()) {
                    builder
                        .when(local.is_real)
                        .when_ne(local.y.lsb, local.sign_bit)
                        .assert_all_eq(neg_y_word.clone(), y_value_word.clone());
                }
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

                // Assert that the flags are booleans.
                builder.assert_bool(choice_cols.is_y_eq_sqrt_y_result);
                builder.assert_bool(choice_cols.when_sqrt_y_res_is_lt);
                builder.assert_bool(choice_cols.when_neg_y_res_is_lt);

                // Assert that the `when` flags are disjoint:
                builder.when(local.is_real).assert_one(
                    choice_cols.when_sqrt_y_res_is_lt + choice_cols.when_neg_y_res_is_lt,
                );

                // Assert that the value of `y` matches the claimed value by the flags.
                for (mul_word, y_value_word) in mul_words.iter().zip(y_value_words.iter()) {
                    builder
                        .when(local.is_real)
                        .when(choice_cols.is_y_eq_sqrt_y_result)
                        .assert_all_eq(mul_word.clone(), y_value_word.clone());
                }
                for (neg_y_word, y_value_word) in neg_y_words.iter().zip(y_value_words.iter()) {
                    builder
                        .when(local.is_real)
                        .when_not(choice_cols.is_y_eq_sqrt_y_result)
                        .assert_all_eq(neg_y_word.clone(), y_value_word.clone());
                }

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

        let ptr = SyscallAddrOperation::<AB::F>::eval(
            builder,
            E::NB_LIMBS as u32 * 2,
            local.ptr,
            local.is_real.into(),
        );

        // x_addrs[i] = ptr + 8 * i + num_limbs
        for i in 0..local.x_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([ptr[0].into(), ptr[1].into(), ptr[2].into(), AB::Expr::zero()]),
                Word::from(num_limbs as u64 + 8 * i as u64),
                local.x_addrs[i],
                local.is_real.into(),
            );
        }

        // y_addrs[i] = ptr + 8 * i
        for i in 0..local.y_addrs.len() {
            AddrAddOperation::<AB::F>::eval(
                builder,
                Word([ptr[0].into(), ptr[1].into(), ptr[2].into(), AB::Expr::zero()]),
                Word::from(8 * i as u64),
                local.y_addrs[i],
                local.is_real.into(),
            );
        }

        for i in 0..num_words_field_element {
            builder.eval_memory_access_read(
                local.clk_high,
                local.clk_low,
                &local.x_addrs[i].value.map(Into::into),
                local.x_access[i].memory_access,
                local.is_real,
            );
        }
        for i in 0..num_words_field_element {
            builder.eval_memory_access_write(
                local.clk_high,
                local.clk_low + AB::Expr::one(),
                &local.y_addrs[i].value.map(Into::into),
                local.y_access[i],
                local.y_value[i],
                local.is_real,
            );
        }

        let syscall_id = match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                AB::F::from_canonical_u32(SyscallCode::SECP256K1_DECOMPRESS.syscall_id())
            }
            CurveType::Secp256r1 => {
                AB::F::from_canonical_u32(SyscallCode::SECP256R1_DECOMPRESS.syscall_id())
            }
            CurveType::Bls12381 => {
                AB::F::from_canonical_u32(SyscallCode::BLS12381_DECOMPRESS.syscall_id())
            }
            _ => panic!("Unsupported curve"),
        };

        builder.receive_syscall(
            local.clk_high,
            local.clk_low,
            syscall_id,
            ptr.map(Into::into),
            [local.sign_bit.into(), AB::Expr::zero(), AB::Expr::zero()].map(Into::into),
            local.is_real,
            InteractionScope::Local,
        );
    }
}

// #[cfg(test)]
// mod tests {
//     use std::sync::Arc;

//     use crate::{
//         io::SP1Stdin,
//         utils::{self, run_test},
//     };
//     use amcl::{
//         bls381::bls381::{basic::key_pair_generate_g2, utils::deserialize_g1},
//         rand::RAND,
//     };
//     use elliptic_curve::sec1::ToEncodedPoint;
//     use rand::{rngs::StdRng, Rng, SeedableRng};
//     use sp1_core_executor::Program;
//     use test_artifacts::{
//         BLS12381_DECOMPRESS_ELF, SECP256K1_DECOMPRESS_ELF, SECP256R1_DECOMPRESS_ELF,
//     };

//     #[tokio::test]
//     async fn test_weierstrass_bls_decompress() {
//         utils::setup_logger();
//         let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
//         let mut rand = RAND::new();

//         let len = 100;
//         let num_tests = 10;
//         let random_slice = (0..len).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
//         rand.seed(len, &random_slice);

//         for _ in 0..num_tests {
//             let (_, compressed) = key_pair_generate_g2(&mut rand);

//             let stdin = SP1Stdin::from(&compressed);
//             let mut public_values =
//                 run_test(Arc::new(Program::from(&BLS12381_DECOMPRESS_ELF).unwrap()), stdin)
//                     .await
//                     .unwrap();

//             let mut result = [0; 96];
//             public_values.read_slice(&mut result);

//             let point = deserialize_g1(&compressed).unwrap();
//             let x = point.getx().to_string();
//             let y = point.gety().to_string();
//             let decompressed = hex::decode(format!("{x}{y}")).unwrap();
//             assert_eq!(result, decompressed.as_slice());
//         }
//     }

//     #[tokio::test]
//     async fn test_weierstrass_k256_decompress() {
//         utils::setup_logger();
//         let mut rng = StdRng::seed_from_u64(0xDEADBEEF);

//         let num_tests = 10;

//         for _ in 0..num_tests {
//             let secret_key = k256::SecretKey::random(&mut rng);
//             let public_key = secret_key.public_key();
//             let encoded = public_key.to_encoded_point(false);
//             let decompressed = encoded.as_bytes();
//             let compressed = public_key.to_sec1_bytes();

//             let inputs = SP1Stdin::from(&compressed);

//             let mut public_values =
//                 run_test(Arc::new(Program::from(&SECP256K1_DECOMPRESS_ELF).unwrap()), inputs)
//                     .await
//                     .unwrap();
//             let mut result = [0; 65];
//             public_values.read_slice(&mut result);
//             assert_eq!(result, decompressed);
//         }
//     }

//     #[tokio::test]
//     async fn test_weierstrass_p256_decompress() {
//         utils::setup_logger();
//         let mut rng = StdRng::seed_from_u64(0xDEADBEEF);

//         let num_tests = 1;

//         for _ in 0..num_tests {
//             let secret_key = p256::SecretKey::random(&mut rng);
//             let public_key = secret_key.public_key();
//             let encoded = public_key.to_encoded_point(false);
//             let decompressed = encoded.as_bytes();
//             let encoded_compressed = public_key.to_encoded_point(true);
//             let compressed = encoded_compressed.as_bytes();

//             let inputs = SP1Stdin::from(compressed);

//             let mut public_values =
//                 run_test(Arc::new(Program::from(&SECP256R1_DECOMPRESS_ELF).unwrap()), inputs)
//                     .await
//                     .unwrap();
//             let mut result = [0; 65];
//             public_values.read_slice(&mut result);
//             assert_eq!(result, decompressed);
//         }
//     }
// }
