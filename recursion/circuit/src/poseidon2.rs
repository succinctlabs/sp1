//! An implementation of Poseidon2 over BN254.

use itertools::Itertools;
use p3_field::AbstractField;
use p3_field::Field;
use sp1_recursion_compiler::ir::Felt;
use sp1_recursion_compiler::ir::{Builder, Config, DslIR, Var};

use crate::challenger::reduce_32;
use crate::mmcs::OuterDigest;
use crate::DIGEST_SIZE;
use crate::RATE;
use crate::SPONGE_SIZE;

pub trait P2CircuitBuilder<C: Config> {
    fn p2_permute_mut(&mut self, state: [Var<C::N>; SPONGE_SIZE]);
    fn p2_hash(&mut self, input: &[Felt<C::F>]) -> OuterDigest<C>;
    fn p2_compress(&mut self, input: [OuterDigest<C>; 2]) -> OuterDigest<C>;
}

impl<C: Config> P2CircuitBuilder<C> for Builder<C> {
    fn p2_permute_mut(&mut self, state: [Var<C::N>; SPONGE_SIZE]) {
        self.push(DslIR::CircuitPoseidon2Permute(state))
    }

    fn p2_hash(&mut self, input: &[Felt<C::F>]) -> OuterDigest<C> {
        let num_f_elms = C::N::bits() / C::F::bits();
        let mut state: [Var<C::N>; SPONGE_SIZE] = [
            self.eval(C::N::zero()),
            self.eval(C::N::zero()),
            self.eval(C::N::zero()),
        ];
        for block_chunk in &input.iter().chunks(RATE) {
            for (chunk_id, chunk) in (&block_chunk.chunks(num_f_elms)).into_iter().enumerate() {
                let chunk = chunk.collect_vec().into_iter().copied().collect::<Vec<_>>();
                state[chunk_id] = reduce_32(self, chunk.as_slice());
            }
            self.p2_permute_mut(state);
        }

        [state[0]]
    }

    fn p2_compress(&mut self, input: [OuterDigest<C>; 2]) -> OuterDigest<C> {
        let state: [Var<C::N>; SPONGE_SIZE] = [
            self.eval(input[0][0]),
            self.eval(input[1][0]),
            self.eval(C::N::zero()),
        ];
        self.p2_permute_mut(state);
        [state[0]; DIGEST_SIZE]
    }
}

#[cfg(test)]
pub mod tests {
    use ff::PrimeField as FFPrimeField;
    use p3_baby_bear::BabyBear;
    use p3_bn254_fr::FFBn254Fr;
    use p3_bn254_fr::{Bn254Fr, DiffusionMatrixBN254};
    use p3_field::AbstractField;
    use p3_poseidon2::Poseidon2;
    use p3_symmetric::{CryptographicHasher, Permutation, PseudoCompressionFunction};
    use serial_test::serial;
    use sp1_recursion_compiler::constraints::{gnark_ffi, ConstraintBackend};
    use sp1_recursion_compiler::ir::{Builder, Felt, Var};
    use sp1_recursion_compiler::OuterConfig;
    use sp1_recursion_core::stark::config::{OuterCompress, OuterHash, OuterPerm};
    use zkhash::ark_ff::BigInteger;
    use zkhash::ark_ff::PrimeField;
    use zkhash::fields::bn256::FpBN256 as ark_FpBN256;
    use zkhash::poseidon2::poseidon2_instance_bn256::RC3;

    use crate::mmcs::OuterDigest;
    use crate::poseidon2::P2CircuitBuilder;

    fn bn254_from_ark_ff(input: ark_FpBN256) -> Bn254Fr {
        let bytes = input.into_bigint().to_bytes_le();

        let mut res = <FFBn254Fr as ff::PrimeField>::Repr::default();

        for (i, digit) in res.0.as_mut().iter_mut().enumerate() {
            *digit = bytes[i];
        }

        let value = FFBn254Fr::from_repr(res);

        if value.is_some().into() {
            Bn254Fr {
                value: value.unwrap(),
            }
        } else {
            panic!("Invalid field element")
        }
    }

    pub fn bn254_poseidon2_rc3() -> Vec<[Bn254Fr; 3]> {
        RC3.iter()
            .map(|vec| {
                vec.iter()
                    .cloned()
                    .map(bn254_from_ark_ff)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect()
    }

    #[test]
    #[serial]
    fn test_p2_permute_mut() {
        const WIDTH: usize = 3;
        const D: u64 = 5;
        const ROUNDS_F: usize = 8;
        const ROUNDS_P: usize = 56;

        let poseidon2: Poseidon2<Bn254Fr, DiffusionMatrixBN254, WIDTH, D> = Poseidon2::new(
            ROUNDS_F,
            ROUNDS_P,
            bn254_poseidon2_rc3(),
            DiffusionMatrixBN254,
        );

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

        let mut backend = ConstraintBackend::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        gnark_ffi::test_circuit(constraints);
    }

    #[test]
    #[serial]
    fn test_p2_hash() {
        const ROUNDS_F: usize = 8;
        const ROUNDS_P: usize = 56;

        let perm: OuterPerm = Poseidon2::new(
            ROUNDS_F,
            ROUNDS_P,
            bn254_poseidon2_rc3(),
            DiffusionMatrixBN254,
        );
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
        let output = hasher.hash_iter(input.into_iter());

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

        let mut backend = ConstraintBackend::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        gnark_ffi::test_circuit(constraints);
    }

    #[test]
    #[serial]
    fn test_p2_compress() {
        const ROUNDS_F: usize = 8;
        const ROUNDS_P: usize = 56;

        let perm: OuterPerm = Poseidon2::new(
            ROUNDS_F,
            ROUNDS_P,
            bn254_poseidon2_rc3(),
            DiffusionMatrixBN254,
        );
        let compressor = OuterCompress::new(perm.clone());

        let a: [Bn254Fr; 1] = [Bn254Fr::two()];
        let b: [Bn254Fr; 1] = [Bn254Fr::two()];
        let gt = compressor.compress([a, b]);

        let mut builder = Builder::<OuterConfig>::default();
        let a: OuterDigest<OuterConfig> = [builder.eval(a[0])];
        let b: OuterDigest<OuterConfig> = [builder.eval(b[0])];
        let result = builder.p2_compress([a, b]);
        builder.assert_var_eq(result[0], gt[0]);

        let mut backend = ConstraintBackend::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        gnark_ffi::test_circuit(constraints);
    }
}
