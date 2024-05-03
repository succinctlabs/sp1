#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::explicit_counter_loop)]
#![allow(type_alias_bounds)]

pub mod challenger;
pub mod constraints;
pub mod domain;
pub mod fri;
pub mod mmcs;
pub mod poseidon2;
pub mod stark;
pub mod types;
pub mod utils;
pub mod witness;

pub const SPONGE_SIZE: usize = 3;
pub const DIGEST_SIZE: usize = 1;
pub const RATE: usize = 16;

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_bn254_fr::Bn254Fr;
    use p3_field::AbstractField;
    use sp1_recursion_compiler::config::OuterConfig;
    use sp1_recursion_compiler::constraints::ConstraintCompiler;
    use sp1_recursion_compiler::ir::Config;
    use sp1_recursion_compiler::ir::Ext;
    use sp1_recursion_compiler::ir::ExtConst;
    use sp1_recursion_compiler::ir::{Builder, Felt, Witness};
    use sp1_recursion_gnark_ffi::Groth16Prover;

    #[test]
    fn test_base_babybear() {
        let mut builder = Builder::<OuterConfig>::default();
        let a_val = BabyBear::from_wrapped_u32(3124235823);
        let b_val = BabyBear::from_wrapped_u32(3252375321);
        let a: Felt<_> = builder.eval(a_val);
        let b: Felt<_> = builder.eval(b_val);

        // Testing base addition.
        let a_plus_b: Felt<_> = builder.eval(a + b);
        builder.assert_felt_eq(a_plus_b, a_val + b_val);

        // Testing base subtraction.
        let a_minus_b: Felt<_> = builder.eval(a - b);
        builder.assert_felt_eq(a_minus_b, a_val - b_val);

        // Testing base multiplication.
        let a_times_b: Felt<_> = builder.eval(a * b);
        builder.assert_felt_eq(a_times_b, a_val * b_val);

        // Testing large linear combination.
        let dot_product: Felt<_> = builder.eval(a * a + b * b + a * b);
        builder.assert_felt_eq(dot_product, a_val * a_val + b_val * b_val + a_val * b_val);

        // Testing high degree multiplication.
        let a_times_b_times_c: Felt<_> =
            builder.eval(a_val * b_val * a_val * b_val * a_val * b_val);
        builder.assert_felt_eq(
            a_times_b_times_c,
            a_val * b_val * a_val * b_val * a_val * b_val,
        );

        let mut backend = ConstraintCompiler::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);

        let witness = Witness::default();
        Groth16Prover::test::<OuterConfig>(constraints.clone(), witness);
    }

    #[test]
    fn test_extension_babybear() {
        let mut builder = Builder::<OuterConfig>::default();
        let one_val = <OuterConfig as Config>::EF::from_wrapped_u32(1);
        let a_val = <OuterConfig as Config>::EF::from_wrapped_u32(3124235823);
        let b_val = <OuterConfig as Config>::EF::from_wrapped_u32(3252375321);
        let one: Ext<_, _> = builder.eval(BabyBear::one());
        let a: Ext<_, _> = builder.eval(a_val.cons());
        let b: Ext<_, _> = builder.eval(b_val.cons());

        // Testing extension addition.
        let a_plus_b: Ext<_, _> = builder.eval(a + b);
        builder.assert_ext_eq(a_plus_b, (a_val + b_val).cons());

        // // Testing negation.
        // let neg_a: Ext<_, _> = builder.eval(-a);
        // builder.assert_ext_eq(neg_a, (-a_val).cons());

        // Testing extension subtraction.
        let a_minus_b: Ext<_, _> = builder.eval(a - b);
        builder.assert_ext_eq(a_minus_b, (a_val - b_val).cons());

        // Testing base multiplication.
        let a_times_b: Ext<_, _> = builder.eval(a * b);
        builder.assert_ext_eq(a_times_b, (a_val * b_val).cons());

        // Testing base division.
        let a_div_b: Ext<_, _> = builder.eval(a / b);
        builder.assert_ext_eq(a_div_b, (a_val / b_val).cons());

        // Testing base inversion.
        let a_inv: Ext<_, _> = builder.eval(one / a);
        builder.assert_ext_eq(a_inv, (one_val / a_val).cons());

        // Testing large linear combination.
        let dot_product: Ext<_, _> = builder.eval(a * a + b * b + a * b);
        builder.assert_ext_eq(
            dot_product,
            (a_val * a_val + b_val * b_val + a_val * b_val).cons(),
        );

        // Testing high degree multiplication.
        let a_times_b_times_c: Ext<_, _> = builder.eval(a * b * a * b * a * b);
        builder.assert_ext_eq(
            a_times_b_times_c,
            (a_val * b_val * a_val * b_val * a_val * b_val).cons(),
        );

        let mut backend = ConstraintCompiler::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);

        let witness = Witness::default();
        Groth16Prover::test::<OuterConfig>(constraints.clone(), witness);
    }

    #[test]
    fn test_commit() {
        let mut builder = Builder::<OuterConfig>::default();
        let vkey_hash_bn254 = Bn254Fr::from_canonical_u32(1345237507);
        let commited_values_digest_bn254 = Bn254Fr::from_canonical_u32(102);
        let vkey_hash = builder.eval(vkey_hash_bn254);
        let commited_values_digest = builder.eval(commited_values_digest_bn254);
        builder.commit_vkey_hash_circuit(vkey_hash);
        builder.commit_commited_values_digest_circuit(commited_values_digest);

        let mut backend = ConstraintCompiler::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);

        let mut witness = Witness::default();
        witness.write_vkey_hash(vkey_hash_bn254);
        witness.write_commited_values_digest(commited_values_digest_bn254);

        Groth16Prover::test::<OuterConfig>(constraints.clone(), witness);
    }

    #[test]
    #[should_panic]
    fn test_commit_vkey_fail() {
        let mut builder = Builder::<OuterConfig>::default();
        let vkey_hash_bn254 = Bn254Fr::from_canonical_u32(1345237507);
        let commited_values_digest_bn254 = Bn254Fr::from_canonical_u32(102);
        let vkey_hash = builder.eval(vkey_hash_bn254);
        let commited_values_digest = builder.eval(commited_values_digest_bn254);
        builder.commit_vkey_hash_circuit(vkey_hash);
        builder.commit_commited_values_digest_circuit(commited_values_digest);

        let mut backend = ConstraintCompiler::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);

        let mut witness = Witness::default();
        witness.write_commited_values_digest(commited_values_digest_bn254);

        Groth16Prover::test::<OuterConfig>(constraints.clone(), witness);
    }

    #[test]
    #[should_panic]
    fn test_commit_commited_values_digest_fail() {
        let mut builder = Builder::<OuterConfig>::default();
        let vkey_hash_bn254 = Bn254Fr::from_canonical_u32(1345237507);
        let commited_values_digest_bn254 = Bn254Fr::from_canonical_u32(102);
        let vkey_hash = builder.eval(vkey_hash_bn254);
        let commited_values_digest = builder.eval(commited_values_digest_bn254);
        builder.commit_vkey_hash_circuit(vkey_hash);
        builder.commit_commited_values_digest_circuit(commited_values_digest);

        let mut backend = ConstraintCompiler::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);

        let mut witness = Witness::default();
        witness.write_vkey_hash(vkey_hash_bn254);

        Groth16Prover::test::<OuterConfig>(constraints.clone(), witness);
    }
}
