//! An implementation of Poseidon2 over BN254.

use std::array;

use itertools::Itertools;
use p3_field::{AbstractField, Field};
use sp1_recursion_compiler::ir::{Builder, Config, DslIr, Felt, Var};

use crate::{challenger::reduce_32, types::OuterDigestVariable, DIGEST_SIZE, RATE, SPONGE_SIZE};

pub trait Poseidon2CircuitBuilder<C: Config> {
    fn p2_permute_mut(&mut self, state: [Var<C::N>; SPONGE_SIZE]);
    fn p2_hash(&mut self, input: &[Felt<C::F>]) -> OuterDigestVariable<C>;
    fn p2_compress(&mut self, input: [OuterDigestVariable<C>; 2]) -> OuterDigestVariable<C>;
    fn p2_babybear_permute_mut(&mut self, state: [Felt<C::F>; 16]);
    fn p2_babybear_hash(&mut self, input: &[Felt<C::F>]) -> [Felt<C::F>; 8];
}

impl<C: Config> Poseidon2CircuitBuilder<C> for Builder<C> {
    fn p2_permute_mut(&mut self, state: [Var<C::N>; SPONGE_SIZE]) {
        self.push(DslIr::CircuitPoseidon2Permute(state))
    }

    fn p2_hash(&mut self, input: &[Felt<C::F>]) -> OuterDigestVariable<C> {
        assert!(C::N::bits() == p3_bn254_fr::Bn254Fr::bits());
        assert!(C::F::bits() == p3_baby_bear::BabyBear::bits());
        let num_f_elms = C::N::bits() / C::F::bits();
        let mut state: [Var<C::N>; SPONGE_SIZE] =
            [self.eval(C::N::zero()), self.eval(C::N::zero()), self.eval(C::N::zero())];
        for block_chunk in &input.iter().chunks(RATE) {
            for (chunk_id, chunk) in (&block_chunk.chunks(num_f_elms)).into_iter().enumerate() {
                let chunk = chunk.collect_vec().into_iter().copied().collect::<Vec<_>>();
                state[chunk_id] = reduce_32(self, chunk.as_slice());
            }
            self.p2_permute_mut(state);
        }

        [state[0]]
    }

    fn p2_compress(&mut self, input: [OuterDigestVariable<C>; 2]) -> OuterDigestVariable<C> {
        let state: [Var<C::N>; SPONGE_SIZE] =
            [self.eval(input[0][0]), self.eval(input[1][0]), self.eval(C::N::zero())];
        self.p2_permute_mut(state);
        [state[0]; DIGEST_SIZE]
    }

    fn p2_babybear_permute_mut(&mut self, state: [Felt<C::F>; 16]) {
        self.push(DslIr::CircuitPoseidon2PermuteBabyBear(Box::new(state)));
    }

    fn p2_babybear_hash(&mut self, input: &[Felt<C::F>]) -> [Felt<C::F>; 8] {
        let mut state: [Felt<C::F>; 16] = array::from_fn(|_| self.eval(C::F::zero()));

        for block_chunk in &input.iter().chunks(8) {
            state.iter_mut().zip(block_chunk).for_each(|(s, i)| *s = self.eval(*i));
            self.p2_babybear_permute_mut(state);
        }

        array::from_fn(|i| state[i])
    }
}

#[cfg(test)]
pub mod tests {
    use p3_baby_bear::BabyBear;
    use p3_bn254_fr::Bn254Fr;
    use p3_field::AbstractField;
    use p3_symmetric::{CryptographicHasher, Permutation, PseudoCompressionFunction};
    use rand::{thread_rng, Rng};
    use sp1_recursion_compiler::{
        config::OuterConfig,
        constraints::ConstraintCompiler,
        ir::{Builder, Felt, Var, Witness},
    };
    use sp1_recursion_core::stark::config::{outer_perm, OuterCompress, OuterHash};
    use sp1_recursion_gnark_ffi::PlonkBn254Prover;
    use sp1_stark::{inner_perm, InnerHash};

    use crate::{poseidon2::Poseidon2CircuitBuilder, types::OuterDigestVariable};

    #[test]
    fn test_p2_permute_mut() {
        let poseidon2 = outer_perm();
        let input: [Bn254Fr; 3] = [
            Bn254Fr::from_canonical_u32(0),
            Bn254Fr::from_canonical_u32(1),
            Bn254Fr::from_canonical_u32(2),
        ];
        let mut output = input;
        poseidon2.permute_mut(&mut output);

        let mut builder = Builder::<OuterConfig>::default();
        let a: Var<_> = builder.eval(input[0]);
        let b: Var<_> = builder.eval(input[1]);
        let c: Var<_> = builder.eval(input[2]);
        builder.p2_permute_mut([a, b, c]);

        builder.assert_var_eq(a, output[0]);
        builder.assert_var_eq(b, output[1]);
        builder.assert_var_eq(c, output[2]);

        let mut backend = ConstraintCompiler::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        PlonkBn254Prover::test::<OuterConfig>(constraints.clone(), Witness::default());
    }

    #[test]
    fn test_p2_babybear_permute_mut() {
        let mut rng = thread_rng();
        let mut builder = Builder::<OuterConfig>::default();
        let input: [BabyBear; 16] = [rng.gen(); 16];
        let input_vars: [Felt<_>; 16] = input.map(|x| builder.eval(x));
        builder.p2_babybear_permute_mut(input_vars);

        let perm = inner_perm();
        let result = perm.permute(input);
        for i in 0..16 {
            builder.assert_felt_eq(input_vars[i], result[i]);
        }

        let mut backend = ConstraintCompiler::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        PlonkBn254Prover::test::<OuterConfig>(constraints.clone(), Witness::default());
    }

    #[test]
    fn test_p2_hash() {
        let perm = outer_perm();
        let hasher = OuterHash::new(perm.clone()).unwrap();

        let input: [BabyBear; 7] = [
            BabyBear::from_canonical_u32(0),
            BabyBear::from_canonical_u32(1),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(2),
        ];
        let output = hasher.hash_iter(input);

        let mut builder = Builder::<OuterConfig>::default();
        let a: Felt<_> = builder.eval(input[0]);
        let b: Felt<_> = builder.eval(input[1]);
        let c: Felt<_> = builder.eval(input[2]);
        let d: Felt<_> = builder.eval(input[3]);
        let e: Felt<_> = builder.eval(input[4]);
        let f: Felt<_> = builder.eval(input[5]);
        let g: Felt<_> = builder.eval(input[6]);
        let result = builder.p2_hash(&[a, b, c, d, e, f, g]);

        builder.assert_var_eq(result[0], output[0]);

        let mut backend = ConstraintCompiler::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        PlonkBn254Prover::test::<OuterConfig>(constraints.clone(), Witness::default());
    }

    #[test]
    fn test_p2_compress() {
        let perm = outer_perm();
        let compressor = OuterCompress::new(perm.clone());

        let a: [Bn254Fr; 1] = [Bn254Fr::two()];
        let b: [Bn254Fr; 1] = [Bn254Fr::two()];
        let gt = compressor.compress([a, b]);

        let mut builder = Builder::<OuterConfig>::default();
        let a: OuterDigestVariable<OuterConfig> = [builder.eval(a[0])];
        let b: OuterDigestVariable<OuterConfig> = [builder.eval(b[0])];
        let result = builder.p2_compress([a, b]);
        builder.assert_var_eq(result[0], gt[0]);

        let mut backend = ConstraintCompiler::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        PlonkBn254Prover::test::<OuterConfig>(constraints.clone(), Witness::default());
    }

    #[test]
    fn test_p2_babybear_hash() {
        let perm = inner_perm();
        let hasher = InnerHash::new(perm.clone());

        let input: [BabyBear; 26] = [
            BabyBear::from_canonical_u32(0),
            BabyBear::from_canonical_u32(1),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(2),
            BabyBear::from_canonical_u32(3),
            BabyBear::from_canonical_u32(3),
            BabyBear::from_canonical_u32(3),
            BabyBear::from_canonical_u32(3),
            BabyBear::from_canonical_u32(3),
            BabyBear::from_canonical_u32(3),
            BabyBear::from_canonical_u32(3),
            BabyBear::from_canonical_u32(3),
            BabyBear::from_canonical_u32(3),
            BabyBear::from_canonical_u32(3),
            BabyBear::from_canonical_u32(3),
        ];
        let output = hasher.hash_iter(input);
        println!("{:?}", output);

        let mut builder = Builder::<OuterConfig>::default();
        let input_felts: [Felt<_>; 26] = input.map(|x| builder.eval(x));
        let result = builder.p2_babybear_hash(input_felts.as_slice());

        for i in 0..8 {
            builder.assert_felt_eq(result[i], output[i]);
        }

        let mut backend = ConstraintCompiler::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        PlonkBn254Prover::test::<OuterConfig>(constraints.clone(), Witness::default());
    }
}
