use itertools::izip;

use num::BigUint;

use p3_air::AirBuilder;
use p3_field::AbstractField;
use p3_field::PrimeField32;

use sp1_derive::AlignedBorrow;

use crate::{
    air::Polynomial,
    bytes::{event::ByteRecord, ByteLookupEvent, ByteOpcode},
    stark::SP1AirBuilder,
};

use super::params::FieldParameters;
use super::params::Limbs;

/// Operation columns for verifying that an element is within the range `[0, modulus)`.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldRangeCols<T, P: FieldParameters> {
    /// Boolean flags to indicate the first byte in which the element is smaller than the modulus.
    pub(crate) byte_flags: Limbs<T, P::Limbs>,

    pub(crate) comparison_byte: T,
}

impl<F: PrimeField32, P: FieldParameters> FieldRangeCols<F, P> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecord,
        shard: u32,
        channel: u32,
        value: &BigUint,
    ) {
        let value_limbs = P::to_limbs(value);
        let modulus_limbs = P::to_limbs(&P::modulus());

        let mut byte_flags = vec![0u8; P::NB_LIMBS];

        for (byte, modulus_byte, flag) in izip!(
            value_limbs.iter().rev(),
            modulus_limbs.iter().rev(),
            byte_flags.iter_mut().rev()
        ) {
            assert!(byte <= modulus_byte);
            if byte < modulus_byte {
                *flag = 1;
                self.comparison_byte = F::from_canonical_u8(*byte);
                record.add_byte_lookup_event(ByteLookupEvent {
                    opcode: ByteOpcode::LTU,
                    shard,
                    channel,
                    a1: 1,
                    a2: 0,
                    b: *byte as u32,
                    c: *modulus_byte as u32,
                });
                break;
            }
        }

        for (byte, flag) in izip!(byte_flags.iter(), self.byte_flags.0.iter_mut()) {
            *flag = F::from_canonical_u8(*byte);
        }
    }
}

impl<V: Copy, P: FieldParameters> FieldRangeCols<V, P> {
    pub fn eval<AB: SP1AirBuilder<Var = V>, E: Into<Polynomial<AB::Expr>> + Clone>(
        &self,
        builder: &mut AB,
        element: &E,
        shard: impl Into<AB::Expr> + Clone,
        channel: impl Into<AB::Expr> + Clone,
        is_real: impl Into<AB::Expr> + Clone,
    ) where
        V: Into<AB::Expr>,
        Limbs<V, P::Limbs>: Copy,
    {
        // The byte flags give a specification of which byte is `first_eq`, i,e, the first most
        // significant byte for which the element is smaller than the modulus. To verify the
        // less-than claim we need to check that:
        // * For all bytes until `first_eq` the element byte is equal to the modulus byte.
        // * For the `first_eq` byte the element byte is smaller than the modulus byte.
        // * all byte flags are boolean.
        // * only one byte flag is set to one, and the rest are set to zero.

        // Check the flags are of valid form.

        // Verrify that only one flag is set to one.
        let mut sum_flags: AB::Expr = AB::Expr::zero();
        for &flag in self.byte_flags.0.iter() {
            // Assert that the flag is boolean.
            builder.assert_bool(flag);
            // Add the flag to the sum.
            sum_flags += flag.into();
        }
        // Assert that the sum is equal to one.
        builder.assert_one(sum_flags);

        // Check the less-than condition.

        // A flag to indicate whether an equality check is necessary (this is for all bytes from
        // most significant until the first inequality.
        let mut is_inequality_visited = AB::Expr::zero();

        // The bytes of the modulus.
        let modulus_bytes = P::MODULUS.to_vec();

        let element: Polynomial<_> = element.clone().into();

        let mut first_lt_byte = AB::Expr::zero();
        let mut modulus_comparison_byte = AB::Expr::zero();
        for (byte, modulus_byte, &flag) in izip!(
            element.coefficients().iter().rev(),
            modulus_bytes.into_iter().rev(),
            self.byte_flags.0.iter().rev()
        ) {
            // Once the byte flag was set to one, we turn off the quality check flag.
            // We can do this by calculating the sum of the flags since only `1` is set to `1`.
            is_inequality_visited += flag.into();

            first_lt_byte += byte.clone() * flag;
            modulus_comparison_byte += flag.into() * AB::F::from_canonical_u8(modulus_byte);

            builder
                .when_not(is_inequality_visited.clone())
                .assert_eq(byte.clone(), AB::F::from_canonical_u8(modulus_byte));
        }

        builder.assert_eq(self.comparison_byte, first_lt_byte);

        // Send the comparison interaction.
        builder.send_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            AB::F::one(),
            self.comparison_byte,
            modulus_comparison_byte,
            shard,
            channel,
            is_real,
        )
    }
}
