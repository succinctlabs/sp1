//! A duplex challenger for Poseidon2 over BN254.

use p3_field::AbstractField;
use p3_field::Field;
use sp1_recursion_compiler::ir::{Builder, Config, Felt, Var};

use crate::poseidon2::P2CircuitBuilder;

const WIDTH: usize = 3;

pub struct MultiFieldChallengerVariable<C: Config> {
    sponge_state: [Var<C::N>; 3],
    input_buffer: Vec<Felt<C::F>>,
    output_buffer: Vec<Felt<C::F>>,
    num_f_elms: usize,
}

pub fn reduce_64<C: Config>(builder: &mut Builder<C>, vals: &[Felt<C::F>]) -> Var<C::N> {
    let alpha: Var<C::N> = builder.eval(C::N::from_canonical_u64(C::F::order().to_u64_digits()[0]));

    let res: Var<C::N> = builder.eval(C::N::zero());
    for val in vals.iter().rev() {
        let bits = builder.num2bits_f(*val);
        let val_v = builder.bits_to_num_var(&bits);
        builder.assign(res, res * alpha + val_v);
    }

    res
}

pub fn split_64<C: Config>(builder: &mut Builder<C>, val: Var<C::N>) -> [Felt<C::F>; WIDTH] {
    let alpha: Var<C::N> = builder.eval(C::N::from_canonical_u64(C::F::order().to_u64_digits()[0]));
    todo!()
}

impl<C: Config> MultiFieldChallengerVariable<C> {
    pub fn new(builder: &mut Builder<C>) -> Self {
        MultiFieldChallengerVariable::<C> {
            sponge_state: [builder.uninit(), builder.uninit(), builder.uninit()],
            input_buffer: vec![],
            output_buffer: vec![],
            num_f_elms: C::N::bits() / C::F::bits(),
        }
    }

    pub fn duplexing(&mut self, builder: &mut Builder<C>) {
        assert!(self.input_buffer.len() <= self.num_f_elms * WIDTH);

        for (i, f_chunk) in self.input_buffer.chunks(self.num_f_elms).enumerate() {
            self.sponge_state[i] = reduce_64(builder, f_chunk);
        }
        self.input_buffer.clear();

        builder.p2_permute_mut(self.sponge_state);

        self.output_buffer.clear();
        for &pf_val in self.sponge_state.iter() {
            let f_vals = split_64(builder, pf_val);
            for f_val in f_vals {
                self.output_buffer.push(f_val);
            }
        }
    }

    pub fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        self.output_buffer.clear();

        self.input_buffer.push(value);
        if self.input_buffer.len() == self.num_f_elms * WIDTH {
            self.duplexing(builder);
        }
    }

    pub fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
            self.duplexing(builder);
        }

        self.output_buffer
            .pop()
            .expect("output buffer should be non-empty")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::Write;
    use std::marker::PhantomData;

    use p3_baby_bear::BabyBear;
    use p3_bn254_fr::{Bn254Fr, DiffusionMatrixBN254};
    use p3_challenger::{CanObserve, CanSample};
    use p3_field::AbstractField;
    use rand::thread_rng;
    use sp1_recursion_compiler::gnark::GnarkBackend;
    use sp1_recursion_compiler::ir::Builder;
    use sp1_recursion_core::stark::bn254::{Challenger, Perm};

    use crate::{poseidon2::tests::bn254_poseidon2_rc3, GnarkConfig};

    use super::MultiFieldChallengerVariable;

    #[test]
    fn test_challenger() {
        let perm = Perm::new(8, 56, bn254_poseidon2_rc3(), DiffusionMatrixBN254);
        let mut challenger = Challenger::new(perm).unwrap();
        let value = BabyBear::from_canonical_usize(1);
        challenger.observe(value);
        challenger.observe(value);
        challenger.observe(value);
        let gt: BabyBear = challenger.sample();
        println!("gt: {}", gt);

        // let mut builder = Builder::<GnarkConfig>::default();
        // let mut challenger = DuplexChallengerVariable::new(&mut builder);
        // let value = builder.eval(Bn254Fr::from_canonical_usize(1));
        // challenger.observe(&mut builder, value);
        // challenger.observe(&mut builder, value);
        // challenger.observe(&mut builder, value);
        // let _ = challenger.sample(&mut builder);

        // let mut backend = GnarkBackend::<GnarkConfig> {
        //     nb_backend_vars: 0,
        //     used: HashMap::new(),
        //     phantom: PhantomData,
        // };
        // let result = backend.compile(builder.operations);
        // let manifest_dir = env!("CARGO_MANIFEST_DIR");
        // let path = format!("{}/build/verifier.go", manifest_dir);
        // let mut file = File::create(path).unwrap();
        // file.write_all(result.as_bytes()).unwrap();
    }
}
