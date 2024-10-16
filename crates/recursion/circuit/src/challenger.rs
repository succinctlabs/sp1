use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, Field};
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{DslIr, Var},
    prelude::{Builder, Config, Ext, Felt},
};
use sp1_recursion_core::{
    air::ChallengerPublicValues,
    runtime::{HASH_RATE, PERMUTATION_WIDTH},
    stark::{OUTER_MULTI_FIELD_CHALLENGER_DIGEST_SIZE, OUTER_MULTI_FIELD_CHALLENGER_RATE},
    NUM_BITS,
};

// Constants for the Multifield challenger.
pub const POSEIDON_2_BB_RATE: usize = 16;

// use crate::{DigestVariable, VerifyingKeyVariable};

pub trait CanCopyChallenger<C: Config> {
    fn copy(&self, builder: &mut Builder<C>) -> Self;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpongeChallengerShape {
    pub input_buffer_len: usize,
    pub output_buffer_len: usize,
}

/// Reference: [p3_challenger::CanObserve].
pub trait CanObserveVariable<C: Config, V> {
    fn observe(&mut self, builder: &mut Builder<C>, value: V);

    fn observe_slice(&mut self, builder: &mut Builder<C>, values: impl IntoIterator<Item = V>) {
        for value in values {
            self.observe(builder, value);
        }
    }
}

pub trait CanSampleVariable<C: Config, V> {
    fn sample(&mut self, builder: &mut Builder<C>) -> V;
}

/// Reference: [p3_challenger::FieldChallenger].
pub trait FieldChallengerVariable<C: Config, Bit>:
    CanObserveVariable<C, Felt<C::F>> + CanSampleVariable<C, Felt<C::F>> + CanSampleBitsVariable<C, Bit>
{
    fn sample_ext(&mut self, builder: &mut Builder<C>) -> Ext<C::F, C::EF>;

    fn check_witness(&mut self, builder: &mut Builder<C>, nb_bits: usize, witness: Felt<C::F>);

    fn duplexing(&mut self, builder: &mut Builder<C>);
}

pub trait CanSampleBitsVariable<C: Config, V> {
    fn sample_bits(&mut self, builder: &mut Builder<C>, nb_bits: usize) -> Vec<V>;
}

/// Reference: [p3_challenger::DuplexChallenger]
#[derive(Clone, Debug)]
pub struct DuplexChallengerVariable<C: Config> {
    pub sponge_state: [Felt<C::F>; PERMUTATION_WIDTH],
    pub input_buffer: Vec<Felt<C::F>>,
    pub output_buffer: Vec<Felt<C::F>>,
}

impl<C: Config<F = BabyBear>> DuplexChallengerVariable<C> {
    /// Creates a new duplex challenger with the default state.
    pub fn new(builder: &mut Builder<C>) -> Self {
        DuplexChallengerVariable::<C> {
            sponge_state: core::array::from_fn(|_| builder.eval(C::F::zero())),
            input_buffer: vec![],
            output_buffer: vec![],
        }
    }

    /// Creates a new challenger with the same state as an existing challenger.
    pub fn copy(&self, builder: &mut Builder<C>) -> Self {
        let DuplexChallengerVariable { sponge_state, input_buffer, output_buffer } = self;
        let sponge_state = sponge_state.map(|x| builder.eval(x));
        let mut copy_vec = |v: &Vec<Felt<C::F>>| v.iter().map(|x| builder.eval(*x)).collect();
        DuplexChallengerVariable::<C> {
            sponge_state,
            input_buffer: copy_vec(input_buffer),
            output_buffer: copy_vec(output_buffer),
        }
    }

    fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        self.output_buffer.clear();

        self.input_buffer.push(value);

        if self.input_buffer.len() == HASH_RATE {
            self.duplexing(builder);
        }
    }

    fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
            self.duplexing(builder);
        }

        self.output_buffer.pop().expect("output buffer should be non-empty")
    }

    fn sample_bits(&mut self, builder: &mut Builder<C>, nb_bits: usize) -> Vec<Felt<C::F>> {
        assert!(nb_bits <= NUM_BITS);
        let rand_f = self.sample(builder);
        let mut rand_f_bits = builder.num2bits_v2_f(rand_f, NUM_BITS);
        rand_f_bits.truncate(nb_bits);
        rand_f_bits
    }

    pub fn public_values(&self, builder: &mut Builder<C>) -> ChallengerPublicValues<Felt<C::F>> {
        assert!(self.input_buffer.len() <= PERMUTATION_WIDTH);
        assert!(self.output_buffer.len() <= PERMUTATION_WIDTH);

        let sponge_state = self.sponge_state;
        let num_inputs = builder.eval(C::F::from_canonical_usize(self.input_buffer.len()));
        let num_outputs = builder.eval(C::F::from_canonical_usize(self.output_buffer.len()));

        let input_buffer: [_; PERMUTATION_WIDTH] = self
            .input_buffer
            .iter()
            .copied()
            .chain((self.input_buffer.len()..PERMUTATION_WIDTH).map(|_| builder.eval(C::F::zero())))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let output_buffer: [_; PERMUTATION_WIDTH] = self
            .output_buffer
            .iter()
            .copied()
            .chain(
                (self.output_buffer.len()..PERMUTATION_WIDTH).map(|_| builder.eval(C::F::zero())),
            )
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        ChallengerPublicValues {
            sponge_state,
            num_inputs,
            input_buffer,
            num_outputs,
            output_buffer,
        }
    }
}

impl<C: Config<F = BabyBear>> CanCopyChallenger<C> for DuplexChallengerVariable<C> {
    fn copy(&self, builder: &mut Builder<C>) -> Self {
        DuplexChallengerVariable::copy(self, builder)
    }
}

impl<C: Config<F = BabyBear>> CanObserveVariable<C, Felt<C::F>> for DuplexChallengerVariable<C> {
    fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        DuplexChallengerVariable::observe(self, builder, value);
    }

    fn observe_slice(
        &mut self,
        builder: &mut Builder<C>,
        values: impl IntoIterator<Item = Felt<C::F>>,
    ) {
        for value in values {
            self.observe(builder, value);
        }
    }
}

impl<C: Config<F = BabyBear>, const N: usize> CanObserveVariable<C, [Felt<C::F>; N]>
    for DuplexChallengerVariable<C>
{
    fn observe(&mut self, builder: &mut Builder<C>, values: [Felt<C::F>; N]) {
        for value in values {
            self.observe(builder, value);
        }
    }
}

impl<C: Config<F = BabyBear>> CanSampleVariable<C, Felt<C::F>> for DuplexChallengerVariable<C> {
    fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        DuplexChallengerVariable::sample(self, builder)
    }
}

impl<C: Config<F = BabyBear>> CanSampleBitsVariable<C, Felt<C::F>> for DuplexChallengerVariable<C> {
    fn sample_bits(&mut self, builder: &mut Builder<C>, nb_bits: usize) -> Vec<Felt<C::F>> {
        DuplexChallengerVariable::sample_bits(self, builder, nb_bits)
    }
}

impl<C: Config<F = BabyBear>> FieldChallengerVariable<C, Felt<C::F>>
    for DuplexChallengerVariable<C>
{
    fn sample_ext(&mut self, builder: &mut Builder<C>) -> Ext<C::F, C::EF> {
        let a = self.sample(builder);
        let b = self.sample(builder);
        let c = self.sample(builder);
        let d = self.sample(builder);
        builder.ext_from_base_slice(&[a, b, c, d])
    }

    fn check_witness(
        &mut self,
        builder: &mut Builder<C>,
        nb_bits: usize,
        witness: Felt<<C as Config>::F>,
    ) {
        self.observe(builder, witness);
        let element_bits = self.sample_bits(builder, nb_bits);
        for bit in element_bits {
            builder.assert_felt_eq(bit, C::F::zero());
        }
    }

    fn duplexing(&mut self, builder: &mut Builder<C>) {
        assert!(self.input_buffer.len() <= HASH_RATE);

        self.sponge_state[0..self.input_buffer.len()].copy_from_slice(self.input_buffer.as_slice());
        self.input_buffer.clear();

        self.sponge_state = builder.poseidon2_permute_v2(self.sponge_state);

        self.output_buffer.clear();
        self.output_buffer.extend_from_slice(&self.sponge_state);
    }
}

#[derive(Clone)]
pub struct MultiField32ChallengerVariable<C: Config> {
    sponge_state: [Var<C::N>; 3],
    input_buffer: Vec<Felt<C::F>>,
    output_buffer: Vec<Felt<C::F>>,
    num_f_elms: usize,
}

impl<C: Config> MultiField32ChallengerVariable<C> {
    pub fn new(builder: &mut Builder<C>) -> Self {
        MultiField32ChallengerVariable::<C> {
            sponge_state: [
                builder.eval(C::N::zero()),
                builder.eval(C::N::zero()),
                builder.eval(C::N::zero()),
            ],
            input_buffer: vec![],
            output_buffer: vec![],
            num_f_elms: C::N::bits() / 64,
        }
    }

    pub fn duplexing(&mut self, builder: &mut Builder<C>) {
        assert!(self.input_buffer.len() <= self.num_f_elms * OUTER_MULTI_FIELD_CHALLENGER_RATE);

        for (i, f_chunk) in self.input_buffer.chunks(self.num_f_elms).enumerate() {
            self.sponge_state[i] = reduce_32(builder, f_chunk);
        }
        self.input_buffer.clear();

        // TODO make this a method for the builder.
        builder.push_op(DslIr::CircuitPoseidon2Permute(self.sponge_state));

        self.output_buffer.clear();
        for &pf_val in self.sponge_state.iter() {
            let f_vals = split_32(builder, pf_val, self.num_f_elms);
            for f_val in f_vals {
                self.output_buffer.push(f_val);
            }
        }
    }

    pub fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        self.output_buffer.clear();

        self.input_buffer.push(value);
        if self.input_buffer.len() == self.num_f_elms * OUTER_MULTI_FIELD_CHALLENGER_RATE {
            self.duplexing(builder);
        }
    }

    pub fn observe_commitment(
        &mut self,
        builder: &mut Builder<C>,
        value: [Var<C::N>; OUTER_MULTI_FIELD_CHALLENGER_DIGEST_SIZE],
    ) {
        for val in value {
            let f_vals: Vec<Felt<C::F>> = split_32(builder, val, self.num_f_elms);
            for f_val in f_vals {
                self.observe(builder, f_val);
            }
        }
    }

    pub fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
            self.duplexing(builder);
        }

        self.output_buffer.pop().expect("output buffer should be non-empty")
    }

    pub fn sample_ext(&mut self, builder: &mut Builder<C>) -> Ext<C::F, C::EF> {
        let a = self.sample(builder);
        let b = self.sample(builder);
        let c = self.sample(builder);
        let d = self.sample(builder);
        builder.felts2ext(&[a, b, c, d])
    }

    pub fn sample_bits(&mut self, builder: &mut Builder<C>, bits: usize) -> Vec<Var<C::N>> {
        let rand_f = self.sample(builder);
        builder.num2bits_f_circuit(rand_f)[0..bits].to_vec()
    }

    pub fn check_witness(&mut self, builder: &mut Builder<C>, bits: usize, witness: Felt<C::F>) {
        self.observe(builder, witness);
        let element = self.sample_bits(builder, bits);
        for bit in element {
            builder.assert_var_eq(bit, C::N::from_canonical_usize(0));
        }
    }
}

impl<C: Config> CanCopyChallenger<C> for MultiField32ChallengerVariable<C> {
    /// Creates a new challenger with the same state as an existing challenger.
    fn copy(&self, builder: &mut Builder<C>) -> Self {
        let MultiField32ChallengerVariable {
            sponge_state,
            input_buffer,
            output_buffer,
            num_f_elms,
        } = self;
        let sponge_state = sponge_state.map(|x| builder.eval(x));
        let mut copy_vec = |v: &Vec<Felt<C::F>>| v.iter().map(|x| builder.eval(*x)).collect();
        MultiField32ChallengerVariable::<C> {
            sponge_state,
            num_f_elms: *num_f_elms,
            input_buffer: copy_vec(input_buffer),
            output_buffer: copy_vec(output_buffer),
        }
    }
}

impl<C: Config> CanObserveVariable<C, Felt<C::F>> for MultiField32ChallengerVariable<C> {
    fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        MultiField32ChallengerVariable::observe(self, builder, value);
    }
}

impl<C: Config> CanObserveVariable<C, [Var<C::N>; OUTER_MULTI_FIELD_CHALLENGER_DIGEST_SIZE]>
    for MultiField32ChallengerVariable<C>
{
    fn observe(
        &mut self,
        builder: &mut Builder<C>,
        value: [Var<C::N>; OUTER_MULTI_FIELD_CHALLENGER_DIGEST_SIZE],
    ) {
        self.observe_commitment(builder, value)
    }
}

impl<C: Config> CanObserveVariable<C, Var<C::N>> for MultiField32ChallengerVariable<C> {
    fn observe(&mut self, builder: &mut Builder<C>, value: Var<C::N>) {
        self.observe_commitment(builder, [value])
    }
}

impl<C: Config> CanSampleVariable<C, Felt<C::F>> for MultiField32ChallengerVariable<C> {
    fn sample(&mut self, builder: &mut Builder<C>) -> Felt<C::F> {
        MultiField32ChallengerVariable::sample(self, builder)
    }
}

impl<C: Config> CanSampleBitsVariable<C, Var<C::N>> for MultiField32ChallengerVariable<C> {
    fn sample_bits(&mut self, builder: &mut Builder<C>, bits: usize) -> Vec<Var<C::N>> {
        MultiField32ChallengerVariable::sample_bits(self, builder, bits)
    }
}

impl<C: Config> FieldChallengerVariable<C, Var<C::N>> for MultiField32ChallengerVariable<C> {
    fn sample_ext(&mut self, builder: &mut Builder<C>) -> Ext<C::F, C::EF> {
        MultiField32ChallengerVariable::sample_ext(self, builder)
    }

    fn check_witness(&mut self, builder: &mut Builder<C>, bits: usize, witness: Felt<C::F>) {
        MultiField32ChallengerVariable::check_witness(self, builder, bits, witness);
    }

    fn duplexing(&mut self, builder: &mut Builder<C>) {
        MultiField32ChallengerVariable::duplexing(self, builder);
    }
}

pub fn reduce_32<C: Config>(builder: &mut Builder<C>, vals: &[Felt<C::F>]) -> Var<C::N> {
    let mut power = C::N::one();
    let result: Var<C::N> = builder.eval(C::N::zero());
    for val in vals.iter() {
        let val = builder.felt2var_circuit(*val);
        builder.assign(result, result + val * power);
        power *= C::N::from_canonical_u64(1u64 << 32);
    }
    result
}

pub fn split_32<C: Config>(builder: &mut Builder<C>, val: Var<C::N>, n: usize) -> Vec<Felt<C::F>> {
    let bits = builder.num2bits_v_circuit(val, 256);
    let mut results = Vec::new();
    for i in 0..n {
        let result: Felt<C::F> = builder.eval(C::F::zero());
        for j in 0..64 {
            let bit = bits[i * 64 + j];
            let t = builder.eval(result + C::F::from_wrapped_u64(1 << j));
            let z = builder.select_f(bit, t, result);
            builder.assign(result, z);
        }
        results.push(result);
    }
    results
}

#[cfg(test)]
pub(crate) mod tests {
    use std::iter::zip;

    use crate::{
        challenger::{CanCopyChallenger, MultiField32ChallengerVariable},
        hash::{FieldHasherVariable, BN254_DIGEST_SIZE},
        utils::tests::run_test_recursion,
    };
    use p3_baby_bear::BabyBear;
    use p3_bn254_fr::Bn254Fr;
    use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger};
    use p3_field::AbstractField;
    use p3_symmetric::{CryptographicHasher, Hash, PseudoCompressionFunction};
    use sp1_recursion_compiler::{
        circuit::{AsmBuilder, AsmConfig},
        config::OuterConfig,
        constraints::ConstraintCompiler,
        ir::{Builder, Config, Ext, ExtConst, Felt, Var},
    };
    use sp1_recursion_core::stark::{outer_perm, BabyBearPoseidon2Outer, OuterCompress, OuterHash};
    use sp1_recursion_gnark_ffi::PlonkBn254Prover;
    use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig};

    use crate::{
        challenger::{DuplexChallengerVariable, FieldChallengerVariable},
        witness::OuterWitness,
    };

    type SC = BabyBearPoseidon2;
    type C = OuterConfig;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;

    #[test]
    fn test_compiler_challenger() {
        let config = SC::default();
        let mut challenger = config.challenger();
        challenger.observe(F::one());
        challenger.observe(F::two());
        challenger.observe(F::two());
        challenger.observe(F::two());
        let result: F = challenger.sample();
        println!("expected result: {}", result);
        let result_ef: EF = challenger.sample_ext_element();
        println!("expected result_ef: {}", result_ef);

        let mut builder = AsmBuilder::<F, EF>::default();

        let mut challenger = DuplexChallengerVariable::<AsmConfig<F, EF>> {
            sponge_state: core::array::from_fn(|_| builder.eval(F::zero())),
            input_buffer: vec![],
            output_buffer: vec![],
        };
        let one: Felt<_> = builder.eval(F::one());
        let two: Felt<_> = builder.eval(F::two());

        challenger.observe(&mut builder, one);
        challenger.observe(&mut builder, two);
        challenger.observe(&mut builder, two);
        challenger.observe(&mut builder, two);
        let element = challenger.sample(&mut builder);
        let element_ef = challenger.sample_ext(&mut builder);

        let expected_result: Felt<_> = builder.eval(result);
        let expected_result_ef: Ext<_, _> = builder.eval(result_ef.cons());
        builder.print_f(element);
        builder.assert_felt_eq(expected_result, element);
        builder.print_e(element_ef);
        builder.assert_ext_eq(expected_result_ef, element_ef);

        run_test_recursion(builder.into_operations(), None);
    }

    #[test]
    fn test_challenger_outer() {
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;
        type N = <C as Config>::N;

        let config = SC::default();
        let mut challenger = config.challenger();
        challenger.observe(F::one());
        challenger.observe(F::two());
        challenger.observe(F::two());
        challenger.observe(F::two());
        let commit = Hash::from([N::two()]);
        challenger.observe(commit);
        let result: F = challenger.sample();
        println!("expected result: {}", result);
        let result_ef: EF = challenger.sample_ext_element();
        println!("expected result_ef: {}", result_ef);
        let mut bits = challenger.sample_bits(30);
        let mut bits_vec = vec![];
        for _ in 0..30 {
            bits_vec.push(bits % 2);
            bits >>= 1;
        }
        println!("expected bits: {:?}", bits_vec);

        let mut builder = Builder::<C>::default();

        // let width: Var<_> = builder.eval(F::from_canonical_usize(PERMUTATION_WIDTH));
        let mut challenger = MultiField32ChallengerVariable::<C>::new(&mut builder);
        let one: Felt<_> = builder.eval(F::one());
        let two: Felt<_> = builder.eval(F::two());
        let two_var: Var<_> = builder.eval(N::two());
        // builder.halt();
        challenger.observe(&mut builder, one);
        challenger.observe(&mut builder, two);
        challenger.observe(&mut builder, two);
        challenger.observe(&mut builder, two);
        challenger.observe_commitment(&mut builder, [two_var]);

        // Check to make sure the copying works.
        challenger = challenger.copy(&mut builder);
        let element = challenger.sample(&mut builder);
        let element_ef = challenger.sample_ext(&mut builder);
        let bits = challenger.sample_bits(&mut builder, 31);

        let expected_result: Felt<_> = builder.eval(result);
        let expected_result_ef: Ext<_, _> = builder.eval(result_ef.cons());
        builder.print_f(element);
        builder.assert_felt_eq(expected_result, element);
        builder.print_e(element_ef);
        builder.assert_ext_eq(expected_result_ef, element_ef);
        for (expected_bit, bit) in zip(bits_vec.iter(), bits.iter()) {
            let expected_bit: Var<_> = builder.eval(N::from_canonical_usize(*expected_bit));
            builder.print_v(*bit);
            builder.assert_var_eq(expected_bit, *bit);
        }

        let mut backend = ConstraintCompiler::<C>::default();
        let constraints = backend.emit(builder.into_operations());
        let witness = OuterWitness::default();
        PlonkBn254Prover::test::<C>(constraints, witness);
    }

    #[test]
    fn test_select_chain_digest() {
        type N = <C as Config>::N;

        let mut builder = Builder::<C>::default();

        let one: Var<_> = builder.eval(N::one());
        let two: Var<_> = builder.eval(N::two());

        let to_swap = [[one], [two]];
        let result = BabyBearPoseidon2Outer::select_chain_digest(&mut builder, one, to_swap);

        builder.assert_var_eq(result[0][0], two);
        builder.assert_var_eq(result[1][0], one);

        let mut backend = ConstraintCompiler::<C>::default();
        let constraints = backend.emit(builder.into_operations());
        let witness = OuterWitness::default();
        PlonkBn254Prover::test::<C>(constraints, witness);
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

        let mut builder = Builder::<C>::default();
        let a: Felt<_> = builder.eval(input[0]);
        let b: Felt<_> = builder.eval(input[1]);
        let c: Felt<_> = builder.eval(input[2]);
        let d: Felt<_> = builder.eval(input[3]);
        let e: Felt<_> = builder.eval(input[4]);
        let f: Felt<_> = builder.eval(input[5]);
        let g: Felt<_> = builder.eval(input[6]);
        let result = BabyBearPoseidon2Outer::hash(&mut builder, &[a, b, c, d, e, f, g]);

        builder.assert_var_eq(result[0], output[0]);

        let mut backend = ConstraintCompiler::<C>::default();
        let constraints = backend.emit(builder.into_operations());
        PlonkBn254Prover::test::<C>(constraints.clone(), OuterWitness::default());
    }

    #[test]
    fn test_p2_compress() {
        type OuterDigestVariable = [Var<<C as Config>::N>; BN254_DIGEST_SIZE];
        let perm = outer_perm();
        let compressor = OuterCompress::new(perm.clone());

        let a: [Bn254Fr; 1] = [Bn254Fr::two()];
        let b: [Bn254Fr; 1] = [Bn254Fr::two()];
        let gt = compressor.compress([a, b]);

        let mut builder = Builder::<C>::default();
        let a: OuterDigestVariable = [builder.eval(a[0])];
        let b: OuterDigestVariable = [builder.eval(b[0])];
        let result = BabyBearPoseidon2Outer::compress(&mut builder, [a, b]);
        builder.assert_var_eq(result[0], gt[0]);

        let mut backend = ConstraintCompiler::<C>::default();
        let constraints = backend.emit(builder.into_operations());
        PlonkBn254Prover::test::<C>(constraints.clone(), OuterWitness::default());
    }
}
