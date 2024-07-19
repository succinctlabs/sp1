use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::AbstractField;
use p3_field::TwoAdicField;
use sp1_core::air::MachineAir;
use sp1_core::stark::Com;
use sp1_core::stark::GenericVerifierConstraintFolder;
use sp1_core::stark::ShardProof;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::stark::StarkMachine;

use sp1_core::stark::StarkVerifyingKey;
use sp1_recursion_compiler::ir::Array;
use sp1_recursion_compiler::ir::Ext;
use sp1_recursion_compiler::ir::ExtConst;
use sp1_recursion_compiler::ir::SymbolicExt;
use sp1_recursion_compiler::ir::SymbolicVar;
use sp1_recursion_compiler::ir::Var;
use sp1_recursion_compiler::ir::{Builder, Config, Usize};
use sp1_recursion_compiler::prelude::Felt;

use sp1_recursion_core::runtime::DIGEST_SIZE;

use crate::challenger::CanObserveVariable;
use crate::challenger::DuplexChallengerVariable;
use crate::challenger::FeltChallenger;
use crate::commit::PolynomialSpaceVariable;
use crate::fri::types::TwoAdicPcsMatsVariable;
use crate::fri::types::TwoAdicPcsRoundVariable;
use crate::fri::TwoAdicMultiplicativeCosetVariable;
use crate::types::ShardCommitmentVariable;
use crate::types::VerifyingKeyVariable;
use crate::{commit::PcsVariable, fri::TwoAdicFriPcsVariable, types::ShardProofVariable};

use crate::types::QuotientData;

pub const EMPTY: usize = 0x_1111_1111;

pub trait StarkRecursiveVerifier<C: Config> {
    fn verify_shard(
        &self,
        builder: &mut Builder<C>,
        vk: &VerifyingKeyVariable<C>,
        pcs: &TwoAdicFriPcsVariable<C>,
        challenger: &mut DuplexChallengerVariable<C>,
        proof: &ShardProofVariable<C>,
        is_complete: impl Into<SymbolicVar<C::N>>,
    );

    fn verify_shards(
        &self,
        builder: &mut Builder<C>,
        vk: &VerifyingKeyVariable<C>,
        pcs: &TwoAdicFriPcsVariable<C>,
        challenger: &mut DuplexChallengerVariable<C>,
        proofs: &Array<C, ShardProofVariable<C>>,
        is_complete: impl Into<SymbolicVar<C::N>> + Clone,
    ) {
        // Assert that the number of shards is not zero.
        builder.assert_usize_ne(proofs.len(), 0);

        // Verify each shard.
        builder.range(0, proofs.len()).for_each(|i, builder| {
            let proof = builder.get(proofs, i);
            self.verify_shard(builder, vk, pcs, challenger, &proof, is_complete.clone());
        });
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StarkVerifier<C: Config, SC: StarkGenericConfig> {
    _phantom: std::marker::PhantomData<(C, SC)>,
}

pub struct ShardProofHint<'a, SC: StarkGenericConfig, A> {
    pub machine: &'a StarkMachine<SC, A>,
    pub proof: &'a ShardProof<SC>,
}

impl<'a, SC: StarkGenericConfig, A: MachineAir<SC::Val>> ShardProofHint<'a, SC, A> {
    pub const fn new(machine: &'a StarkMachine<SC, A>, proof: &'a ShardProof<SC>) -> Self {
        Self { machine, proof }
    }
}

pub struct VerifyingKeyHint<'a, SC: StarkGenericConfig, A> {
    pub machine: &'a StarkMachine<SC, A>,
    pub vk: &'a StarkVerifyingKey<SC>,
}

impl<'a, SC: StarkGenericConfig, A: MachineAir<SC::Val>> VerifyingKeyHint<'a, SC, A> {
    pub const fn new(machine: &'a StarkMachine<SC, A>, vk: &'a StarkVerifyingKey<SC>) -> Self {
        Self { machine, vk }
    }
}

pub type RecursiveVerifierConstraintFolder<'a, C> = GenericVerifierConstraintFolder<
    'a,
    <C as Config>::F,
    <C as Config>::EF,
    Felt<<C as Config>::F>,
    Ext<<C as Config>::F, <C as Config>::EF>,
    SymbolicExt<<C as Config>::F, <C as Config>::EF>,
>;

impl<C: Config, SC: StarkGenericConfig> StarkVerifier<C, SC>
where
    C::F: TwoAdicField,
    SC: StarkGenericConfig<
        Val = C::F,
        Challenge = C::EF,
        Domain = TwoAdicMultiplicativeCoset<C::F>,
    >,
{
    pub fn verify_shard<A>(
        builder: &mut Builder<C>,
        vk: &VerifyingKeyVariable<C>,
        pcs: &TwoAdicFriPcsVariable<C>,
        machine: &StarkMachine<SC, A>,
        challenger: &mut DuplexChallengerVariable<C>,
        proof: &ShardProofVariable<C>,
        check_cumulative_sum: bool,
    ) where
        A: MachineAir<C::F> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
        C::F: TwoAdicField,
        C::EF: TwoAdicField,
        Com<SC>: Into<[SC::Val; DIGEST_SIZE]>,
    {
        builder.cycle_tracker("stage-c-verify-shard-setup");
        let ShardProofVariable {
            commitment,
            opened_values,
            opening_proof,
            ..
        } = proof;

        let ShardCommitmentVariable {
            main_commit,
            permutation_commit,
            quotient_commit,
        } = commitment;

        let permutation_challenges = (0..2)
            .map(|_| challenger.sample_ext(builder))
            .collect::<Vec<_>>();

        challenger.observe(builder, permutation_commit.clone());

        let alpha = challenger.sample_ext(builder);

        challenger.observe(builder, quotient_commit.clone());

        let zeta = challenger.sample_ext(builder);

        let num_shard_chips = opened_values.chips.len();
        let mut trace_domains =
            builder.dyn_array::<TwoAdicMultiplicativeCosetVariable<_>>(num_shard_chips);
        let mut quotient_domains =
            builder.dyn_array::<TwoAdicMultiplicativeCosetVariable<_>>(num_shard_chips);

        let num_preprocessed_chips = machine.preprocessed_chip_ids().len();

        let mut prep_mats: Array<_, TwoAdicPcsMatsVariable<_>> =
            builder.dyn_array(num_preprocessed_chips);
        let mut main_mats: Array<_, TwoAdicPcsMatsVariable<_>> = builder.dyn_array(num_shard_chips);
        let mut perm_mats: Array<_, TwoAdicPcsMatsVariable<_>> = builder.dyn_array(num_shard_chips);

        let num_quotient_mats: Var<_> = builder.eval(C::N::zero());
        builder.range(0, num_shard_chips).for_each(|i, builder| {
            let num_quotient_chunks = builder.get(&proof.quotient_data, i).quotient_size;
            builder.assign(num_quotient_mats, num_quotient_mats + num_quotient_chunks);
        });

        let mut quotient_mats: Array<_, TwoAdicPcsMatsVariable<_>> =
            builder.dyn_array(num_quotient_mats);

        let mut qc_points = builder.dyn_array::<Ext<_, _>>(1);
        builder.set_value(&mut qc_points, 0, zeta);

        // Iterate through machine.chips filtered for preprocessed chips.
        for (preprocessed_id, chip_id) in machine.preprocessed_chip_ids().into_iter().enumerate() {
            // Get index within sorted preprocessed chips.
            let preprocessed_sorted_id = builder.get(&vk.preprocessed_sorted_idxs, preprocessed_id);
            // Get domain from witnessed domains. Array is ordered by machine.chips ordering.
            let domain = builder.get(&vk.prep_domains, preprocessed_id);

            // Get index within all sorted chips.
            let chip_sorted_id = builder.get(&proof.sorted_idxs, chip_id);
            // Get opening from proof.
            let opening = builder.get(&opened_values.chips, chip_sorted_id);

            let mut trace_points = builder.dyn_array::<Ext<_, _>>(2);
            let zeta_next = domain.next_point(builder, zeta);

            builder.set_value(&mut trace_points, 0, zeta);
            builder.set_value(&mut trace_points, 1, zeta_next);

            let mut prep_values = builder.dyn_array::<Array<C, _>>(2);
            builder.set_value(&mut prep_values, 0, opening.preprocessed.local);
            builder.set_value(&mut prep_values, 1, opening.preprocessed.next);
            let main_mat = TwoAdicPcsMatsVariable::<C> {
                domain: domain.clone(),
                values: prep_values,
                points: trace_points.clone(),
            };
            builder.set_value(&mut prep_mats, preprocessed_sorted_id, main_mat);
        }

        let qc_index: Var<_> = builder.eval(C::N::zero());
        builder.range(0, num_shard_chips).for_each(|i, builder| {
            let opening = builder.get(&opened_values.chips, i);
            let QuotientData {
                log_quotient_degree,
                quotient_size,
            } = builder.get(&proof.quotient_data, i);
            let domain = pcs.natural_domain_for_log_degree(builder, Usize::Var(opening.log_degree));
            builder.set_value(&mut trace_domains, i, domain.clone());

            let log_quotient_size: Usize<_> =
                builder.eval(opening.log_degree + log_quotient_degree);
            let quotient_domain =
                domain.create_disjoint_domain(builder, log_quotient_size, Some(pcs.config.clone()));
            builder.set_value(&mut quotient_domains, i, quotient_domain.clone());

            // Get trace_opening_points.
            let mut trace_points = builder.dyn_array::<Ext<_, _>>(2);
            let zeta_next = domain.next_point(builder, zeta);
            builder.set_value(&mut trace_points, 0, zeta);
            builder.set_value(&mut trace_points, 1, zeta_next);

            // Get the main matrix.
            let mut main_values = builder.dyn_array::<Array<C, _>>(2);
            builder.set_value(&mut main_values, 0, opening.main.local);
            builder.set_value(&mut main_values, 1, opening.main.next);
            let main_mat = TwoAdicPcsMatsVariable::<C> {
                domain: domain.clone(),
                values: main_values,
                points: trace_points.clone(),
            };
            builder.set_value(&mut main_mats, i, main_mat);

            // Get the permutation matrix.
            let mut perm_values = builder.dyn_array::<Array<C, _>>(2);
            builder.set_value(&mut perm_values, 0, opening.permutation.local);
            builder.set_value(&mut perm_values, 1, opening.permutation.next);
            let perm_mat = TwoAdicPcsMatsVariable::<C> {
                domain: domain.clone(),
                values: perm_values,
                points: trace_points,
            };
            builder.set_value(&mut perm_mats, i, perm_mat);

            // Get the quotient matrices and values.
            let qc_domains =
                quotient_domain.split_domains(builder, log_quotient_degree, quotient_size);

            builder.range(0, qc_domains.len()).for_each(|j, builder| {
                let qc_dom = builder.get(&qc_domains, j);
                let qc_vals_array = builder.get(&opening.quotient, j);
                let mut qc_values = builder.dyn_array::<Array<C, _>>(1);
                builder.set_value(&mut qc_values, 0, qc_vals_array);
                let qc_mat = TwoAdicPcsMatsVariable::<C> {
                    domain: qc_dom,
                    values: qc_values,
                    points: qc_points.clone(),
                };
                builder.set_value(&mut quotient_mats, qc_index, qc_mat);
                builder.assign(qc_index, qc_index + C::N::one());
            });
        });

        // Create the pcs rounds.
        let mut rounds = builder.dyn_array::<TwoAdicPcsRoundVariable<_>>(4);
        let prep_commit = vk.commitment.clone();
        let prep_round = TwoAdicPcsRoundVariable {
            batch_commit: prep_commit,
            mats: prep_mats,
        };
        let main_round = TwoAdicPcsRoundVariable {
            batch_commit: main_commit.clone(),
            mats: main_mats,
        };
        let perm_round = TwoAdicPcsRoundVariable {
            batch_commit: permutation_commit.clone(),
            mats: perm_mats,
        };
        let quotient_round = TwoAdicPcsRoundVariable {
            batch_commit: quotient_commit.clone(),
            mats: quotient_mats,
        };
        builder.set_value(&mut rounds, 0, prep_round);
        builder.set_value(&mut rounds, 1, main_round);
        builder.set_value(&mut rounds, 2, perm_round);
        builder.set_value(&mut rounds, 3, quotient_round);
        builder.cycle_tracker("stage-c-verify-shard-setup");

        // Verify the pcs proof
        builder.cycle_tracker("stage-d-verify-pcs");
        pcs.verify(builder, rounds, opening_proof.clone(), challenger);
        builder.cycle_tracker("stage-d-verify-pcs");

        builder.cycle_tracker("stage-e-verify-constraints");

        let num_shard_chips_enabled: Var<_> = builder.eval(C::N::zero());
        for (i, chip) in machine.chips().iter().enumerate() {
            tracing::debug!("verifying constraints for chip: {}", chip.name());
            let index = builder.get(&proof.sorted_idxs, i);

            if chip.preprocessed_width() > 0 {
                builder.assert_var_ne(index, C::N::from_canonical_usize(EMPTY));
            }

            builder
                .if_ne(index, C::N::from_canonical_usize(EMPTY))
                .then(|builder| {
                    let values = builder.get(&opened_values.chips, index);
                    let trace_domain = builder.get(&trace_domains, index);
                    let quotient_domain: TwoAdicMultiplicativeCosetVariable<_> =
                        builder.get(&quotient_domains, index);

                    // Check that the quotient data matches the chip's data.
                    let log_quotient_degree = chip.log_quotient_degree();

                    let quotient_size = 1 << log_quotient_degree;
                    let chip_quotient_data = builder.get(&proof.quotient_data, index);
                    builder.assert_usize_eq(
                        chip_quotient_data.log_quotient_degree,
                        log_quotient_degree,
                    );
                    builder.assert_usize_eq(chip_quotient_data.quotient_size, quotient_size);

                    // Get the domains from the chip itself.
                    let qc_domains =
                        quotient_domain.split_domains_const(builder, log_quotient_degree);

                    // Verify the constraints.
                    stacker::maybe_grow(16 * 1024 * 1024, 16 * 1024 * 1024, || {
                        Self::verify_constraints(
                            builder,
                            chip,
                            &values,
                            proof.public_values.clone(),
                            trace_domain,
                            qc_domains,
                            zeta,
                            alpha,
                            &permutation_challenges,
                        );
                    });

                    // Increment the number of shard chips that are enabled.
                    builder.assign(
                        num_shard_chips_enabled,
                        num_shard_chips_enabled + C::N::one(),
                    );
                });
        }

        // Assert that the number of chips in `opened_values` matches the number of shard chips enabled.
        builder.assert_var_eq(num_shard_chips_enabled, num_shard_chips);

        // If we're checking the cumulative sum, assert that the sum of the cumulative sums is zero.
        if check_cumulative_sum {
            let sum: Ext<_, _> = builder.eval(C::EF::zero().cons());
            builder
                .range(0, proof.opened_values.chips.len())
                .for_each(|i, builder| {
                    let cumulative_sum = builder.get(&proof.opened_values.chips, i).cumulative_sum;
                    builder.assign(sum, sum + cumulative_sum);
                });
            builder.assert_ext_eq(sum, C::EF::zero().cons());
        }

        builder.cycle_tracker("stage-e-verify-constraints");
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::borrow::BorrowMut;
    use std::time::Instant;

    use crate::challenger::CanObserveVariable;
    use crate::challenger::FeltChallenger;
    use crate::hints::Hintable;
    use crate::machine::commit_public_values;
    use crate::stark::DuplexChallengerVariable;
    use crate::stark::Ext;
    use crate::stark::ShardProofHint;
    use crate::types::ShardCommitmentVariable;
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_field::AbstractField;
    use rand::Rng;
    use sp1_core::air::POSEIDON_NUM_WORDS;
    use sp1_core::io::SP1Stdin;
    use sp1_core::runtime::Program;
    use sp1_core::stark::DefaultProver;
    use sp1_core::stark::MachineProver;
    use sp1_core::utils::setup_logger;
    use sp1_core::utils::InnerChallenge;
    use sp1_core::utils::InnerVal;
    use sp1_core::utils::SP1CoreOpts;
    use sp1_core::{
        stark::{RiscvAir, StarkGenericConfig},
        utils::BabyBearPoseidon2,
    };
    use sp1_recursion_compiler::config::InnerConfig;
    use sp1_recursion_compiler::ir::Array;
    use sp1_recursion_compiler::ir::Config;
    use sp1_recursion_compiler::ir::Felt;
    use sp1_recursion_compiler::prelude::Usize;
    use sp1_recursion_compiler::{
        asm::AsmBuilder,
        ir::{Builder, ExtConst},
    };

    use sp1_recursion_core::air::RecursionPublicValues;
    use sp1_recursion_core::air::RECURSION_PUBLIC_VALUES_COL_MAP;
    use sp1_recursion_core::air::RECURSIVE_PROOF_NUM_PV_ELTS;
    use sp1_recursion_core::runtime::RecursionProgram;
    use sp1_recursion_core::runtime::Runtime;
    use sp1_recursion_core::runtime::DIGEST_SIZE;

    use sp1_recursion_core::stark::utils::run_test_recursion;
    use sp1_recursion_core::stark::utils::TestConfig;
    use sp1_recursion_core::stark::RecursionAir;

    type SC = BabyBearPoseidon2;
    type Challenge = <SC as StarkGenericConfig>::Challenge;
    type F = InnerVal;
    type EF = InnerChallenge;
    type C = InnerConfig;
    type A = RiscvAir<F>;

    #[test]
    fn test_permutation_challenges() {
        // Generate a dummy proof.
        sp1_core::utils::setup_logger();
        let elf = include_bytes!("../../../tests/fibonacci/elf/riscv32im-succinct-zkvm-elf");

        let machine = A::machine(SC::default());
        let (_, vk) = machine.setup(&Program::from(elf));
        let mut challenger_val = machine.config().challenger();
        let (proof, _, _) = sp1_core::utils::prove::<_, DefaultProver<_, _>>(
            Program::from(elf),
            &SP1Stdin::new(),
            SC::default(),
            SP1CoreOpts::default(),
        )
        .unwrap();
        let proofs = proof.shard_proofs;
        println!("Proof generated successfully");

        challenger_val.observe(vk.commit);

        proofs.iter().for_each(|proof| {
            challenger_val.observe(proof.commitment.main_commit);
            challenger_val.observe_slice(&proof.public_values[0..machine.num_pv_elts()]);
        });

        let permutation_challenges = (0..2)
            .map(|_| challenger_val.sample_ext_element::<EF>())
            .collect::<Vec<_>>();

        // Observe all the commitments.
        let mut builder = Builder::<InnerConfig>::default();

        // Add a hash invocation, since the poseidon2 table expects that it's in the first row.
        let hash_input = builder.constant(vec![vec![F::one()]]);
        builder.poseidon2_hash_x(&hash_input);

        let mut challenger = DuplexChallengerVariable::new(&mut builder);

        let preprocessed_commit_val: [F; DIGEST_SIZE] = vk.commit.into();
        let preprocessed_commit: Array<C, _> = builder.constant(preprocessed_commit_val.to_vec());
        challenger.observe(&mut builder, preprocessed_commit);

        let mut witness_stream = Vec::new();
        for proof in proofs {
            let proof_hint = ShardProofHint::new(&machine, &proof);
            witness_stream.extend(proof_hint.write());
            let proof = ShardProofHint::<SC, A>::read(&mut builder);
            let ShardCommitmentVariable { main_commit, .. } = proof.commitment;
            challenger.observe(&mut builder, main_commit);
            let pv_slice = proof.public_values.slice(
                &mut builder,
                Usize::Const(0),
                Usize::Const(machine.num_pv_elts()),
            );
            challenger.observe_slice(&mut builder, pv_slice);
        }

        // Sample the permutation challenges.
        let permutation_challenges_var = (0..2)
            .map(|_| challenger.sample_ext(&mut builder))
            .collect::<Vec<_>>();

        for i in 0..2 {
            builder.assert_ext_eq(
                permutation_challenges_var[i],
                permutation_challenges[i].cons(),
            );
        }
        builder.halt();

        let program = builder.compile_program();
        run_test_recursion(program, Some(witness_stream.into()), TestConfig::All);
    }

    fn test_public_values_program() -> RecursionProgram<InnerVal> {
        let mut builder = Builder::<InnerConfig>::default();

        // Add a hash invocation, since the poseidon2 table expects that it's in the first row.
        let hash_input = builder.constant(vec![vec![F::one()]]);
        builder.poseidon2_hash_x(&hash_input);

        let mut public_values_stream: Vec<Felt<_>> = (0..RECURSIVE_PROOF_NUM_PV_ELTS)
            .map(|_| builder.uninit())
            .collect();

        let public_values: &mut RecursionPublicValues<_> =
            public_values_stream.as_mut_slice().borrow_mut();

        public_values.sp1_vk_digest = [builder.constant(<C as Config>::F::zero()); DIGEST_SIZE];
        public_values.next_pc = builder.constant(<C as Config>::F::one());
        public_values.next_execution_shard = builder.constant(<C as Config>::F::two());
        public_values.end_reconstruct_deferred_digest =
            [builder.constant(<C as Config>::F::from_canonical_usize(3)); POSEIDON_NUM_WORDS];

        public_values.deferred_proofs_digest =
            [builder.constant(<C as Config>::F::from_canonical_usize(4)); POSEIDON_NUM_WORDS];

        public_values.cumulative_sum =
            [builder.constant(<C as Config>::F::from_canonical_usize(5)); 4];

        commit_public_values(&mut builder, public_values);
        builder.halt();

        builder.compile_program()
    }

    #[test]
    fn test_public_values_failure() {
        let program = test_public_values_program();

        let config = SC::default();

        let mut runtime = Runtime::<InnerVal, Challenge, _>::new(&program, config.perm.clone());
        runtime.run().unwrap();

        let machine = RecursionAir::<_, 3>::machine(SC::default());
        let prover = DefaultProver::new(machine);
        let (pk, vk) = prover.setup(&program);
        let record = runtime.record.clone();

        let mut challenger = prover.config().challenger();
        let mut proof = prover
            .prove(&pk, vec![record], &mut challenger, SP1CoreOpts::recursion())
            .unwrap();

        let mut challenger = prover.config().challenger();
        let verification_result = prover.machine().verify(&vk, &proof, &mut challenger);
        if verification_result.is_err() {
            panic!("Proof should verify successfully");
        }

        // Corrupt the public values.
        proof.shard_proofs[0].public_values[RECURSION_PUBLIC_VALUES_COL_MAP.digest[0]] =
            InnerVal::zero();
        let verification_result = prover.machine().verify(&vk, &proof, &mut challenger);
        if verification_result.is_ok() {
            panic!("Proof should not verify successfully");
        }
    }

    #[test]
    #[ignore]
    fn test_kitchen_sink() {
        setup_logger();

        let time = Instant::now();
        let mut builder = AsmBuilder::<F, EF>::default();

        let a: Felt<_> = builder.eval(F::from_canonical_u32(23));
        let b: Felt<_> = builder.eval(F::from_canonical_u32(17));
        let a_plus_b = builder.eval(a + b);
        let mut rng = rand::thread_rng();
        let a_ext_val = rng.gen::<EF>();
        let b_ext_val = rng.gen::<EF>();
        let a_ext: Ext<_, _> = builder.eval(a_ext_val.cons());
        let b_ext: Ext<_, _> = builder.eval(b_ext_val.cons());
        let a_plus_b_ext = builder.eval(a_ext + b_ext);
        builder.print_f(a_plus_b);
        builder.print_e(a_plus_b_ext);
        builder.halt();

        let program = builder.compile_program();
        let elapsed = time.elapsed();
        println!("Building took: {:?}", elapsed);

        run_test_recursion(program, None, TestConfig::All);
    }
}
