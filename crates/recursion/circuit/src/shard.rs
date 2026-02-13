use crate::{
    basefold::RecursiveBasefoldProof,
    challenger::CanObserveVariable,
    jagged::{
        JaggedPcsProofVariable, RecursiveJaggedPcsVerifier, RecursiveMachineJaggedPcsVerifier,
    },
    logup_gkr::RecursiveLogUpGkrVerifier,
    zerocheck::RecursiveVerifierConstraintFolder,
    CircuitConfig, SP1FieldConfigVariable,
};
use slop_air::Air;
use slop_algebra::AbstractField;
use slop_challenger::IopCtx;
use slop_commit::Rounds;
use slop_multilinear::{Evaluations, MleEval};
use slop_sumcheck::PartialSumcheckProof;

use sp1_hypercube::{
    air::MachineAir, septic_digest::SepticDigest, GenericVerifierPublicValuesConstraintFolder,
    LogupGkrProof, Machine, ShardOpenedValues,
};
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Felt, SymbolicExt},
    prelude::{Ext, SymbolicFelt},
};
use sp1_recursion_executor::{DIGEST_SIZE, NUM_BITS};
use std::collections::{BTreeMap, BTreeSet};

#[allow(clippy::type_complexity)]
pub struct ShardProofVariable<C: CircuitConfig, SC: SP1FieldConfigVariable<C> + Send + Sync> {
    /// The commitments to main traces.
    pub main_commitment: SC::DigestVariable,
    /// The values of the traces at the final random point.
    pub opened_values: ShardOpenedValues<Felt<SP1Field>, Ext<SP1Field, SP1ExtensionField>>,
    /// The zerocheck IOP proof.
    pub zerocheck_proof: PartialSumcheckProof<Ext<SP1Field, SP1ExtensionField>>,
    /// The public values
    pub public_values: Vec<Felt<SP1Field>>,
    // TODO: The `LogUp+GKR` IOP proofs.
    pub logup_gkr_proof: LogupGkrProof<Felt<SP1Field>, Ext<SP1Field, SP1ExtensionField>>,
    /// The evaluation proof.
    pub evaluation_proof: JaggedPcsProofVariable<RecursiveBasefoldProof<C, SC>, SC::DigestVariable>,
}

pub struct MachineVerifyingKeyVariable<C: CircuitConfig, SC: SP1FieldConfigVariable<C>> {
    pub pc_start: [Felt<SP1Field>; 3],
    /// The starting global digest of the program, after incorporating the initial memory.
    pub initial_global_cumulative_sum: SepticDigest<Felt<SP1Field>>,
    /// The preprocessed commitments.
    pub preprocessed_commit: SC::DigestVariable,
    /// Flag indicating if untrusted programs are allowed.
    pub enable_untrusted_programs: Felt<SP1Field>,
}
impl<C, SC> MachineVerifyingKeyVariable<C, SC>
where
    C: CircuitConfig,
    SC: SP1FieldConfigVariable<C>,
{
    /// Hash the verifying key + prep domains into a single digest.
    /// poseidon2(commit[0..8] || pc_start || initial_global_cumulative_sum ||
    /// height || name)
    pub fn hash(&self, builder: &mut Builder<C>) -> SC::DigestVariable
    where
        SC::DigestVariable: IntoIterator<Item = Felt<SP1Field>>,
    {
        let num_inputs = DIGEST_SIZE + 3 + 14 + 1;
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(self.preprocessed_commit);
        inputs.extend(self.pc_start);
        inputs.extend(self.initial_global_cumulative_sum.0.x.0);
        inputs.extend(self.initial_global_cumulative_sum.0.y.0);
        inputs.push(self.enable_untrusted_programs);

        SC::hash(builder, &inputs)
    }
}

/// A verifier for shard proofs.
pub struct RecursiveShardVerifier<
    GC: IopCtx<F = SP1Field, EF = SP1ExtensionField> + SP1FieldConfigVariable<C>,
    A: MachineAir<SP1Field>,
    C: CircuitConfig,
> {
    /// The machine.
    pub machine: Machine<SP1Field, A>,
    /// The jagged pcs verifier.
    pub pcs_verifier: RecursiveJaggedPcsVerifier<GC, C>,
    pub _phantom: std::marker::PhantomData<(GC, C, A)>,
}

impl<GC, C, A> RecursiveShardVerifier<GC, A, C>
where
    GC: IopCtx<F = SP1Field, EF = SP1ExtensionField> + SP1FieldConfigVariable<C>,
    A: MachineAir<SP1Field>,
    C: CircuitConfig,
{
    pub fn verify_shard(
        &self,
        builder: &mut Builder<C>,
        vk: &MachineVerifyingKeyVariable<C, GC>,
        proof: &ShardProofVariable<C, GC>,
        challenger: &mut GC::FriChallengerVariable,
    ) where
        A: for<'b> Air<RecursiveVerifierConstraintFolder<'b>>,
    {
        let ShardProofVariable {
            main_commitment,
            opened_values,
            evaluation_proof,
            zerocheck_proof,
            public_values,
            logup_gkr_proof,
        } = proof;

        // Convert height bits to felts.
        let heights = opened_values
            .chips
            .iter()
            .map(|(name, x)| (name.clone(), x.degree.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut height_felts_map: BTreeMap<String, Felt<SP1Field>> = BTreeMap::new();
        let two = SymbolicFelt::from_canonical_u32(2);
        for (name, height) in &heights {
            let mut acc = SymbolicFelt::zero();
            // Assert max height to avoid overflow during prefix-sum-checks.
            assert!(height.len() == self.pcs_verifier.max_log_row_count + 1);
            height.iter().for_each(|x| {
                acc = *x + two * acc;
            });
            height_felts_map.insert(name.clone(), builder.eval(acc));
        }

        // Observe the public values.
        challenger.observe_slice(builder, public_values.to_vec());

        for value in public_values[self.machine.num_pv_elts()..].iter() {
            builder.assert_felt_eq(value, GC::F::zero());
        }

        // Observe the main commitment.
        challenger.observe(builder, *main_commitment);
        let num_chips: Felt<GC::F> = builder.eval(GC::F::from_canonical_usize(heights.len()));
        // Observe the number of chips.
        challenger.observe(builder, num_chips);

        for (name, height) in height_felts_map.iter() {
            challenger.observe(builder, *height);
            let mut inputs: Vec<Felt<GC::F>> = vec![];
            inputs.push(builder.eval(GC::F::from_canonical_usize(name.len())));
            for byte in name.as_bytes() {
                inputs.push(builder.eval(GC::F::from_canonical_u8(*byte)));
            }
            challenger.observe_slice(builder, inputs);
        }

        let shard_chips = self
            .machine
            .chips()
            .iter()
            .filter(|chip| heights.contains_key(chip.name()))
            .cloned()
            .collect::<BTreeSet<_>>();

        let degrees = opened_values.chips.values().map(|x| x.degree.clone()).collect::<Vec<_>>();

        let max_log_row_count = self.pcs_verifier.max_log_row_count;

        // Verify the `LogUp` GKR proof.
        builder.cycle_tracker_v2_enter("verify-logup-gkr");
        RecursiveLogUpGkrVerifier::<C, GC, A>::verify_logup_gkr(
            builder,
            &shard_chips,
            &degrees,
            max_log_row_count,
            logup_gkr_proof,
            public_values,
            challenger,
        );
        builder.cycle_tracker_v2_exit();

        // Verify the zerocheck proof.
        builder.cycle_tracker_v2_enter("verify-zerocheck");
        self.verify_zerocheck(
            builder,
            &shard_chips,
            opened_values,
            &logup_gkr_proof.logup_evaluations,
            zerocheck_proof,
            public_values,
            challenger,
        );
        builder.cycle_tracker_v2_exit();

        // Verify the opening proof.
        let (preprocessed_openings_for_proof, main_openings_for_proof): (Vec<_>, Vec<_>) = proof
            .opened_values
            .chips
            .values()
            .map(|opening| (opening.preprocessed.clone(), opening.main.clone()))
            .unzip();

        let preprocessed_openings = preprocessed_openings_for_proof
            .iter()
            .map(|x| x.local.iter().as_slice())
            .collect::<Vec<_>>();

        let main_openings = main_openings_for_proof
            .iter()
            .map(|x| x.local.iter().copied().collect::<MleEval<_>>())
            .collect::<Evaluations<_>>();

        let filtered_preprocessed_openings = preprocessed_openings
            .clone()
            .into_iter()
            .filter(|x| !x.is_empty())
            .map(|x| x.iter().copied().collect::<MleEval<_>>())
            .collect::<Evaluations<_>>();

        let preprocessed_column_count = filtered_preprocessed_openings
            .iter()
            .map(|table_openings| table_openings.len())
            .collect::<Vec<_>>();

        let added_columns: Vec<usize> =
            proof.evaluation_proof.column_counts.iter().map(|cc| cc[cc.len() - 2] + 1).collect();

        let unfiltered_preprocessed_column_count = preprocessed_openings
            .iter()
            .map(|table_openings| table_openings.len())
            .chain(std::iter::once(added_columns[0] - 1))
            .collect::<Vec<_>>();

        let main_column_count =
            main_openings.iter().map(|table_openings| table_openings.len()).collect::<Vec<_>>();

        let unfiltered_main_column_count = main_openings
            .iter()
            .map(|table_openings| table_openings.len())
            .chain(std::iter::once(added_columns[1] - 1))
            .collect::<Vec<_>>();

        let (commitments, column_counts, unfiltered_column_counts, openings) = (
            vec![vk.preprocessed_commit, *main_commitment],
            vec![preprocessed_column_count, main_column_count.clone()],
            vec![unfiltered_preprocessed_column_count, unfiltered_main_column_count],
            Rounds { rounds: vec![filtered_preprocessed_openings, main_openings] },
        );

        let machine_jagged_verifier =
            RecursiveMachineJaggedPcsVerifier::new(&self.pcs_verifier, column_counts.clone());

        let openings = openings
            .into_iter()
            .map(|round| {
                round
                    .into_iter()
                    .flat_map(std::iter::IntoIterator::into_iter)
                    .collect::<MleEval<_>>()
            })
            .collect::<Vec<_>>();

        builder.cycle_tracker_v2_enter("jagged-verifier");
        let prefix_sum_felts = machine_jagged_verifier.verify_trusted_evaluations(
            builder,
            &commitments,
            zerocheck_proof.point_and_eval.0.clone(),
            &openings,
            evaluation_proof,
            challenger,
        );
        builder.cycle_tracker_v2_exit();

        let row_count_felt: Felt<_> = builder
            .constant(SP1Field::from_canonical_u32(1 << self.pcs_verifier.max_log_row_count));

        let params: Vec<Vec<Felt<SP1Field>>> = unfiltered_column_counts
            .iter()
            .map(|round| {
                round
                    .iter()
                    .copied()
                    .zip(height_felts_map.values().copied().chain(std::iter::once(row_count_felt)))
                    .flat_map(|(column_count, height)| {
                        std::iter::repeat_n(height, column_count).collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        let preprocessed_count = params[0].len();
        let params = params.into_iter().flatten().collect::<Vec<_>>();

        builder.cycle_tracker_v2_enter("jagged - prefix-sum-checks");
        let mut param_index = 0;
        // The prefix_sum_felts coming from the C::prefix_sum_checks call excludes what is the last
        // element, namely the total area, in the Rust verifier. We add that check in manually
        // below. That is why the Rust verifier `skip_indices` has two elements, while this
        // one has one.
        let skip_indices = [preprocessed_count];

        prefix_sum_felts
            .iter()
            .zip(prefix_sum_felts.iter().skip(1))
            .enumerate()
            .filter(|(i, _)| !skip_indices.contains(i))
            .for_each(|(_, (x, y))| {
                let sum = *x + params[param_index];
                builder.assert_felt_eq(sum, *y);
                param_index += 1;
            });

        builder.assert_felt_eq(prefix_sum_felts[0], SP1Field::zero());

        // Check that the preprocessed prefix sum is the correct multiple of `stacking_height`.
        builder.assert_felt_eq(
            prefix_sum_felts[skip_indices[0] + 1],
            SP1Field::from_canonical_usize(
                (1 << self.pcs_verifier.stacked_pcs_verifier.log_stacking_height)
                    * evaluation_proof.pcs_proof.batch_evaluations.rounds[0].num_polynomials(),
            ),
        );

        let preprocessed_padding_col_height =
            builder.eval(prefix_sum_felts[skip_indices[0] + 1] - prefix_sum_felts[skip_indices[0]]);
        let preprocessed_padding_col_bit_decomp = C::num2bits(
            builder,
            preprocessed_padding_col_height,
            self.pcs_verifier.max_log_row_count + 1,
        );

        // We want to constrain the padding column to be in the range [0, 2^{max_log_row_count}].
        // The above constraints ensure that the padding column is in the range [0,
        // 2^{max_log_row_count+1}). The following constraints exclude the range
        // (2^{max_log_row_count}, 2^{max_log_row_count+1}), namely by ensuring that if the
        // the `max_log_row_count`-th bit is 1, then the less significant bits must be zero.
        //
        // NOTE: Strictly speaking, this is not necessary, since the jagged polynomial will
        // force a zero evaluation in case any column height is greater than
        // `2^{max_log_row_count}`, but we add this constraint for extra security, since it
        // does not have a significant performance impact.
        let max_bit = preprocessed_padding_col_bit_decomp[self.pcs_verifier.max_log_row_count];
        let max_bit = C::bits2num(builder, vec![max_bit]);
        let zero: Felt<_> = builder.constant(SP1Field::zero());
        for bit in
            preprocessed_padding_col_bit_decomp.iter().take(self.pcs_verifier.max_log_row_count)
        {
            let bit_felt = C::bits2num(builder, vec![*bit]);
            builder.assert_felt_eq(max_bit * bit_felt, zero);
        }
        let num_cols = prefix_sum_felts.len();

        // Repeat the process above for the main trace padding column.
        let main_padding_col_height =
            builder.eval(prefix_sum_felts[num_cols - 1] - prefix_sum_felts[num_cols - 2]);

        let main_padding_col_bit_decomp = C::num2bits(builder, main_padding_col_height, NUM_BITS);

        let max_bit = main_padding_col_bit_decomp[self.pcs_verifier.max_log_row_count];
        let max_bit = C::bits2num(builder, vec![max_bit]);
        for bit in main_padding_col_bit_decomp.iter().skip(self.pcs_verifier.max_log_row_count + 1)
        {
            C::assert_bit_zero(builder, *bit);
        }
        for bit in main_padding_col_bit_decomp.iter().take(self.pcs_verifier.max_log_row_count) {
            let bit_felt = C::bits2num(builder, vec![*bit]);
            builder.assert_felt_eq(max_bit * bit_felt, zero);
        }

        // Compute the total area from the shape of the stacked PCS proof.
        let total_area_felt: Felt<_> = builder.constant(SP1Field::from_canonical_usize(
            (1 << self.pcs_verifier.stacked_pcs_verifier.log_stacking_height)
                * proof
                    .evaluation_proof
                    .pcs_proof
                    .batch_evaluations
                    .iter()
                    .map(|evaluations| evaluations.num_polynomials())
                    .sum::<usize>(),
        ));

        // Convert the final prefix sum to a symbolic felt.
        let mut acc = SymbolicFelt::zero();
        // Assert max height to avoid overflow during prefix-sum-checks.
        proof.evaluation_proof.params.col_prefix_sums.iter().last().unwrap().iter().for_each(|x| {
            acc = *x + two * acc;
        });

        // Check equality between the two above-computed values.
        builder.assert_felt_eq(acc, total_area_felt);

        builder.cycle_tracker_v2_exit();
    }
}

pub type RecursiveVerifierPublicValuesConstraintFolder<'a> =
    GenericVerifierPublicValuesConstraintFolder<
        'a,
        SP1Field,
        SP1ExtensionField,
        Felt<SP1Field>,
        Ext<SP1Field, SP1ExtensionField>,
        SymbolicExt<SP1Field, SP1ExtensionField>,
    >;

#[cfg(test)]
mod tests {
    use std::{marker::PhantomData, sync::Arc};

    use slop_basefold::{BasefoldVerifier, FriConfig};
    use sp1_core_executor::{Program, SP1Context, SP1CoreOpts};
    use sp1_core_machine::{
        io::SP1Stdin,
        riscv::RiscvAir,
        utils::{prove_core, setup_logger},
    };
    use sp1_hypercube::{
        prover::{CpuShardProver, SP1InnerPcsProver, SimpleProver},
        MachineVerifier, SP1InnerPcs, ShardVerifier, NUM_SP1_COMMITMENTS,
    };
    use sp1_recursion_compiler::{
        circuit::{AsmCompiler, AsmConfig},
        config::InnerConfig,
    };
    use sp1_recursion_machine::test::run_recursion_test_machines;

    use crate::{
        basefold::{stacked::RecursiveStackedPcsVerifier, tcs::RecursiveMerkleTreeTcs},
        challenger::DuplexChallengerVariable,
        dummy::dummy_shard_proof,
        jagged::RecursiveJaggedEvalSumcheckConfig,
        witness::Witnessable,
    };

    use super::*;

    use sp1_primitives::{SP1Field, SP1GlobalContext};
    type GC = SP1GlobalContext;
    type C = InnerConfig;
    type A = RiscvAir<SP1Field>;

    #[tokio::test]
    async fn test_verify_shard() {
        setup_logger();
        let log_stacking_height = 21;
        let max_log_row_count = 22;
        let machine = RiscvAir::machine();
        let verifier = ShardVerifier::from_basefold_parameters(
            FriConfig::default_fri_config(),
            log_stacking_height,
            max_log_row_count,
            machine.clone(),
        );

        let elf = test_artifacts::FIBONACCI_ELF;
        let program = Arc::new(Program::from(&elf).unwrap());
        let shard_prover =
            CpuShardProver::<SP1GlobalContext, SP1InnerPcs, SP1InnerPcsProver, _>::new(
                verifier.clone(),
            );
        let prover = SimpleProver::new(verifier.clone(), shard_prover);

        let (pk, vk) = prover.setup(program.clone()).await;
        let pk = unsafe { pk.into_inner() };
        let (proof, _) = prove_core(
            &prover,
            pk,
            program,
            SP1Stdin::default(),
            SP1CoreOpts::default(),
            SP1Context::default(),
        )
        .await
        .unwrap();

        let mut builder = Builder::<C>::default();

        // Get the vk and shard proof from the test artifacts.

        let mut initial_challenger = verifier.jagged_pcs_verifier.challenger();
        vk.observe_into(&mut initial_challenger);

        let machine_verifier = MachineVerifier::new(verifier);
        machine_verifier.verify(&vk, &proof).unwrap();

        let shard_proof = proof.shard_proofs[0].clone();
        let shape = machine_verifier.shape_from_proof(&shard_proof);

        let dummy_proof = dummy_shard_proof(
            shape.shard_chips,
            max_log_row_count,
            FriConfig::default_fri_config(),
            log_stacking_height as usize,
            &[shape.preprocessed_multiple, shape.main_multiple],
            &[shape.preprocessed_padding_cols, shape.main_padding_cols],
        );

        let vk_variable = vk.read(&mut builder);
        let shard_proof_variable = dummy_proof.read(&mut builder);

        let verifier =
            BasefoldVerifier::<GC>::new(FriConfig::default_fri_config(), NUM_SP1_COMMITMENTS);
        let recursive_verifier = crate::basefold::RecursiveBasefoldVerifier::<C, GC> {
            fri_config: verifier.fri_config,
            tcs: RecursiveMerkleTreeTcs::<C, GC>(PhantomData),
        };
        let recursive_verifier =
            RecursiveStackedPcsVerifier::new(recursive_verifier, log_stacking_height);

        let recursive_jagged_verifier = RecursiveJaggedPcsVerifier::<GC, C> {
            stacked_pcs_verifier: recursive_verifier,
            max_log_row_count,
            jagged_evaluator: RecursiveJaggedEvalSumcheckConfig::<GC>(PhantomData),
        };

        let stark_verifier = RecursiveShardVerifier::<GC, A, C> {
            machine,
            pcs_verifier: recursive_jagged_verifier,
            _phantom: std::marker::PhantomData,
        };

        let mut challenger_variable =
            DuplexChallengerVariable::from_challenger(&mut builder, &initial_challenger);

        builder.cycle_tracker_v2_enter("verify-shard");
        stark_verifier.verify_shard(
            &mut builder,
            &vk_variable,
            &shard_proof_variable,
            &mut challenger_variable,
        );
        builder.cycle_tracker_v2_exit();

        let block = builder.into_root_block();
        let mut compiler = AsmCompiler::default();
        let program = compiler.compile_inner(block).validate().unwrap();

        let mut witness_stream = Vec::new();
        Witnessable::<AsmConfig>::write(&vk, &mut witness_stream);
        Witnessable::<AsmConfig>::write(&shard_proof, &mut witness_stream);

        run_recursion_test_machines(program.clone(), witness_stream).await;
    }
}
