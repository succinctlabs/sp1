use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_commit::{ExtensionMmcs, TwoAdicMultiplicativeCoset};
use p3_field::extension::BinomialExtensionField;
use p3_field::{AbstractField, Field, TwoAdicField};
use p3_fri::FriConfig;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use sp1_core::air::MachineAir;
use sp1_core::stark::{Dom, ShardProof, StarkGenericConfig, StarkMachine, StarkVerifyingKey};
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::asm::AsmConfig;
use sp1_recursion_compiler::ir::{Array, Builder, Config, Felt, MemVariable, Var};
use sp1_recursion_core::air::ChallengerPublicValues;
use sp1_recursion_core::runtime::{DIGEST_SIZE, PERMUTATION_WIDTH};

use crate::challenger::DuplexChallengerVariable;
use crate::fri::types::FriConfigVariable;
use crate::fri::TwoAdicMultiplicativeCosetVariable;
use crate::stark::EMPTY;
use crate::types::{QuotientDataValues, VerifyingKeyVariable};

type SC = BabyBearPoseidon2;
type F = <SC as StarkGenericConfig>::Val;
type EF = <SC as StarkGenericConfig>::Challenge;
type C = AsmConfig<F, EF>;
type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>;
type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    FieldMerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hash, Compress, 8>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type RecursionConfig = AsmConfig<Val, Challenge>;
type RecursionBuilder = Builder<RecursionConfig>;

pub fn const_fri_config(
    builder: &mut RecursionBuilder,
    config: &FriConfig<ChallengeMmcs>,
) -> FriConfigVariable<RecursionConfig> {
    let two_addicity = Val::TWO_ADICITY;
    let mut generators = builder.dyn_array(two_addicity);
    let mut subgroups = builder.dyn_array(two_addicity);
    for i in 0..two_addicity {
        let constant_generator = Val::two_adic_generator(i);
        builder.set(&mut generators, i, constant_generator);

        let constant_domain = TwoAdicMultiplicativeCoset {
            log_n: i,
            shift: Val::one(),
        };
        let domain_value: TwoAdicMultiplicativeCosetVariable<_> = builder.constant(constant_domain);
        builder.set(&mut subgroups, i, domain_value);
    }
    FriConfigVariable {
        log_blowup: builder.eval(BabyBear::from_canonical_usize(config.log_blowup)),
        blowup: builder.eval(BabyBear::from_canonical_usize(1 << config.log_blowup)),
        num_queries: builder.eval(BabyBear::from_canonical_usize(config.num_queries)),
        proof_of_work_bits: builder.eval(BabyBear::from_canonical_usize(config.proof_of_work_bits)),
        subgroups,
        generators,
    }
}

pub fn clone<T: MemVariable<C>>(builder: &mut RecursionBuilder, var: &T) -> T {
    let mut arr = builder.dyn_array(1);
    builder.set(&mut arr, 0, var.clone());
    builder.get(&arr, 0)
}

pub fn clone_array<T: MemVariable<C>>(
    builder: &mut RecursionBuilder,
    arr: &Array<C, T>,
) -> Array<C, T> {
    let mut new_arr = builder.dyn_array(arr.len());
    builder.range(0, arr.len()).for_each(|i, builder| {
        let var = builder.get(arr, i);
        builder.set(&mut new_arr, i, var);
    });
    new_arr
}

// OPT: this can be done much more efficiently, but in the meantime this should work
pub fn felt2var<C: Config>(builder: &mut Builder<C>, felt: Felt<C::F>) -> Var<C::N> {
    let bits = builder.num2bits_f(felt);
    builder.bits2num_v(&bits)
}

pub fn var2felt<C: Config>(builder: &mut Builder<C>, var: Var<C::N>) -> Felt<C::F> {
    let bits = builder.num2bits_v(var);
    builder.bits2num_f(&bits)
}

/// Asserts that the challenger variable is equal to a challenger in public values.
pub fn assert_challenger_eq_pv<C: Config>(
    builder: &mut Builder<C>,
    var: &DuplexChallengerVariable<C>,
    values: ChallengerPublicValues<Felt<C::F>>,
) {
    for i in 0..PERMUTATION_WIDTH {
        let element = builder.get(&var.sponge_state, i);
        builder.assert_felt_eq(element, values.sponge_state[i]);
    }
    let num_inputs_var = felt2var(builder, values.num_inputs);
    builder.assert_var_eq(var.nb_inputs, num_inputs_var);
    let mut input_buffer_array: Array<_, Felt<_>> = builder.dyn_array(PERMUTATION_WIDTH);
    for i in 0..PERMUTATION_WIDTH {
        builder.set(&mut input_buffer_array, i, values.input_buffer[i]);
    }
    builder.range(0, num_inputs_var).for_each(|i, builder| {
        let element = builder.get(&var.input_buffer, i);
        let values_element = builder.get(&input_buffer_array, i);
        builder.assert_felt_eq(element, values_element);
    });
    let num_outputs_var = felt2var(builder, values.num_outputs);
    builder.assert_var_eq(var.nb_outputs, num_outputs_var);
    let mut output_buffer_array: Array<_, Felt<_>> = builder.dyn_array(PERMUTATION_WIDTH);
    for i in 0..PERMUTATION_WIDTH {
        builder.set(&mut output_buffer_array, i, values.output_buffer[i]);
    }
    builder.range(0, num_outputs_var).for_each(|i, builder| {
        let element = builder.get(&var.output_buffer, i);
        let values_element = builder.get(&output_buffer_array, i);
        builder.assert_felt_eq(element, values_element);
    });
}

/// Assigns a challenger variable from a challenger in public values.
pub fn assign_challenger_from_pv<C: Config>(
    builder: &mut Builder<C>,
    dst: &mut DuplexChallengerVariable<C>,
    values: ChallengerPublicValues<Felt<C::F>>,
) {
    for i in 0..PERMUTATION_WIDTH {
        builder.set(&mut dst.sponge_state, i, values.sponge_state[i]);
    }
    let num_inputs_var = felt2var(builder, values.num_inputs);
    builder.assign(dst.nb_inputs, num_inputs_var);
    for i in 0..PERMUTATION_WIDTH {
        builder.set(&mut dst.input_buffer, i, values.input_buffer[i]);
    }
    let num_outputs_var = felt2var(builder, values.num_outputs);
    builder.assign(dst.nb_outputs, num_outputs_var);
    for i in 0..PERMUTATION_WIDTH {
        builder.set(&mut dst.output_buffer, i, values.output_buffer[i]);
    }
}

pub fn get_challenger_public_values<C: Config>(
    builder: &mut Builder<C>,
    var: &DuplexChallengerVariable<C>,
) -> ChallengerPublicValues<Felt<C::F>> {
    let sponge_state = core::array::from_fn(|i| builder.get(&var.sponge_state, i));
    let num_inputs = var2felt(builder, var.nb_inputs);
    let input_buffer = core::array::from_fn(|i| builder.get(&var.input_buffer, i));
    let num_outputs = var2felt(builder, var.nb_outputs);
    let output_buffer = core::array::from_fn(|i| builder.get(&var.output_buffer, i));

    ChallengerPublicValues {
        sponge_state,
        num_inputs,
        input_buffer,
        num_outputs,
        output_buffer,
    }
}

/// Hash the verifying key + prep domains into a single digest.
/// poseidon2( commit[0..8] || pc_start || prep_domains[N].{log_n, .size, .shift, .g})
pub fn hash_vkey<C: Config>(
    builder: &mut Builder<C>,
    vk: &VerifyingKeyVariable<C>,
) -> Array<C, Felt<C::F>> {
    let domain_slots: Var<_> = builder.eval(vk.prep_domains.len() * 4);
    let vkey_slots: Var<_> = builder.constant(C::N::from_canonical_usize(DIGEST_SIZE + 1));
    let total_slots: Var<_> = builder.eval(vkey_slots + domain_slots);
    let mut inputs = builder.dyn_array(total_slots);
    builder.range(0, DIGEST_SIZE).for_each(|i, builder| {
        let element = builder.get(&vk.commitment, i);
        builder.set(&mut inputs, i, element);
    });
    builder.set(&mut inputs, DIGEST_SIZE, vk.pc_start);
    let four: Var<_> = builder.constant(C::N::from_canonical_usize(4));
    let one: Var<_> = builder.constant(C::N::one());
    builder
        .range(0, vk.prep_domains.len())
        .for_each(|i, builder| {
            let sorted_index = builder.get(&vk.preprocessed_sorted_idxs, i);
            let domain = builder.get(&vk.prep_domains, i);
            let log_n_index: Var<_> = builder.eval(vkey_slots + sorted_index * four);
            let size_index: Var<_> = builder.eval(log_n_index + one);
            let shift_index: Var<_> = builder.eval(size_index + one);
            let g_index: Var<_> = builder.eval(shift_index + one);
            let log_n_felt = var2felt(builder, domain.log_n);
            let size_felt = var2felt(builder, domain.size);
            builder.set(&mut inputs, log_n_index, log_n_felt);
            builder.set(&mut inputs, size_index, size_felt);
            builder.set(&mut inputs, shift_index, domain.shift);
            builder.set(&mut inputs, g_index, domain.g);
        });
    builder.poseidon2_hash(&inputs)
}

pub(crate) fn get_sorted_indices<SC: StarkGenericConfig, A: MachineAir<SC::Val>>(
    machine: &StarkMachine<SC, A>,
    proof: &ShardProof<SC>,
) -> Vec<usize> {
    machine
        .chips_sorted_indices(proof)
        .into_iter()
        .map(|x| match x {
            Some(x) => x,
            None => EMPTY,
        })
        .collect()
}

pub(crate) fn get_preprocessed_data<SC: StarkGenericConfig, A: MachineAir<SC::Val>>(
    machine: &StarkMachine<SC, A>,
    vk: &StarkVerifyingKey<SC>,
) -> (Vec<usize>, Vec<Dom<SC>>) {
    let chips = machine.chips();
    let (prep_sorted_indices, prep_domains) = machine
        .preprocessed_chip_ids()
        .into_iter()
        .map(|chip_idx| {
            let name = chips[chip_idx].name().clone();
            let prep_sorted_idx = vk.chip_ordering[&name];
            (prep_sorted_idx, vk.chip_information[prep_sorted_idx].1)
        })
        .unzip();
    (prep_sorted_indices, prep_domains)
}

pub(crate) fn get_chip_quotient_data<SC: StarkGenericConfig, A: MachineAir<SC::Val>>(
    machine: &StarkMachine<SC, A>,
    proof: &ShardProof<SC>,
) -> Vec<QuotientDataValues> {
    machine
        .shard_chips_ordered(&proof.chip_ordering)
        .map(|chip| {
            let log_quotient_degree = chip.log_quotient_degree();
            QuotientDataValues {
                log_quotient_degree,
                quotient_size: 1 << log_quotient_degree,
            }
        })
        .collect()
}
