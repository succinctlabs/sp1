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
pub mod witness;

pub const SPONGE_SIZE: usize = 3;
pub const DIGEST_SIZE: usize = 1;
pub const RATE: usize = 16;

#[cfg(test)]
mod tests {
    use p3_bn254_fr::Bn254Fr;
    use p3_field::AbstractField;
    use sp1_recursion_compiler::config::OuterConfig;
    use sp1_recursion_compiler::constraints::ConstraintCompiler;
    use sp1_recursion_compiler::ir::{Builder, Witness};
    use sp1_recursion_gnark_ffi::Groth16Prover;

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
        witness.set_vkey_hash(vkey_hash_bn254);
        witness.set_commited_values_digest(commited_values_digest_bn254);

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
        witness.set_commited_values_digest(commited_values_digest_bn254);

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
        witness.set_vkey_hash(vkey_hash_bn254);

        Groth16Prover::test::<OuterConfig>(constraints.clone(), witness);
    }
}
