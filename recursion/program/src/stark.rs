use crate::challenger::CanObserveVariable;
use crate::challenger::DuplexChallengerVariable;
use crate::challenger::FeltChallenger;
use crate::commit::PolynomialSpaceVariable;
use crate::folder::RecursiveVerifierConstraintFolder;
use crate::fri::types::TwoAdicPcsMatsVariable;
use crate::fri::types::TwoAdicPcsRoundVariable;
use crate::fri::TwoAdicMultiplicativeCosetVariable;
use crate::types::ShardCommitmentVariable;
use crate::types::VerifyingKeyVariable;
use crate::{commit::PcsVariable, fri::TwoAdicFriPcsVariable, types::ShardProofVariable};
use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::AbstractField;
use p3_field::TwoAdicField;
use sp1_core::air::MachineAir;
use sp1_core::stark::Com;
use sp1_core::stark::MachineStark;
use sp1_core::stark::StarkGenericConfig;
use sp1_recursion_compiler::ir::Array;
use sp1_recursion_compiler::ir::Ext;
use sp1_recursion_compiler::ir::Var;
use sp1_recursion_compiler::ir::{Builder, Config, Usize};
use sp1_recursion_core::runtime::DIGEST_SIZE;

pub const EMPTY: usize = 0x_1111_1111;

#[derive(Debug, Clone, Copy)]
pub struct StarkVerifier<C: Config, SC: StarkGenericConfig> {
    _phantom: std::marker::PhantomData<(C, SC)>,
}

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
        machine: &MachineStark<SC, A>,
        challenger: &mut DuplexChallengerVariable<C>,
        proof: &ShardProofVariable<C>,
        chip_sorted_idxs: Array<C, Var<C::N>>,
        preprocessed_sorted_idxs: Array<C, Var<C::N>>,
        prep_domains: Array<C, TwoAdicMultiplicativeCosetVariable<C>>,
    ) where
        A: MachineAir<C::F> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
        C::F: TwoAdicField,
        C::EF: TwoAdicField,
        Com<SC>: Into<[SC::Val; DIGEST_SIZE]>,
    {
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

        #[allow(unused_variables)]
        let permutation_challenges = (0..2)
            .map(|_| challenger.sample_ext(builder))
            .collect::<Vec<_>>();

        challenger.observe(builder, permutation_commit.clone());

        #[allow(unused_variables)]
        let alpha = challenger.sample_ext(builder);

        challenger.observe(builder, quotient_commit.clone());

        let zeta = challenger.sample_ext(builder);

        let num_shard_chips = opened_values.chips.len();
        let mut trace_domains =
            builder.dyn_array::<TwoAdicMultiplicativeCosetVariable<_>>(num_shard_chips);
        let mut quotient_domains =
            builder.dyn_array::<TwoAdicMultiplicativeCosetVariable<_>>(num_shard_chips);

        // TODO: note hardcoding of log_quotient_degree. The value comes from:
        //         let max_constraint_degree = 3;
        //         let log_quotient_degree = log2_ceil_usize(max_constraint_degree - 1);
        let log_quotient_degree_val = 1;
        let log_quotient_degree = C::N::from_canonical_usize(log_quotient_degree_val);
        let num_quotient_chunks_val = 1 << log_quotient_degree_val;

        let num_preprocessed_chips = machine.preprocessed_chip_ids().len();

        let mut prep_mats: Array<_, TwoAdicPcsMatsVariable<_>> =
            builder.dyn_array(num_preprocessed_chips);
        let mut main_mats: Array<_, TwoAdicPcsMatsVariable<_>> = builder.dyn_array(num_shard_chips);
        let mut perm_mats: Array<_, TwoAdicPcsMatsVariable<_>> = builder.dyn_array(num_shard_chips);

        let num_quotient_mats: Usize<_> = builder.eval(num_shard_chips * num_quotient_chunks_val);
        let mut quotient_mats: Array<_, TwoAdicPcsMatsVariable<_>> =
            builder.dyn_array(num_quotient_mats);

        let mut qc_points = builder.dyn_array::<Ext<_, _>>(1);
        builder.set_value(&mut qc_points, 0, zeta);

        // Iterate through machine.chips filtered for preprocessed chips.
        for (preprocessed_id, chip_id) in machine.preprocessed_chip_ids().into_iter().enumerate() {
            // Get index within sorted preprocessed chips.
            let preprocessed_sorted_id = builder.get(&preprocessed_sorted_idxs, preprocessed_id);
            // Get domain from witnessed domains. Array is ordered by machine.chips ordering.
            let domain = builder.get(&prep_domains, preprocessed_id);

            // Get index within all sorted chips.
            let chip_sorted_id = builder.get(&chip_sorted_idxs, chip_id);
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

        builder.range(0, num_shard_chips).for_each(|i, builder| {
            let opening = builder.get(&opened_values.chips, i);
            let domain = pcs.natural_domain_for_log_degree(builder, Usize::Var(opening.log_degree));
            builder.set_value(&mut trace_domains, i, domain.clone());

            let log_quotient_size: Usize<_> =
                builder.eval(opening.log_degree + log_quotient_degree);
            let quotient_domain =
                domain.create_disjoint_domain(builder, log_quotient_size, Some(pcs.config.clone()));
            builder.set_value(&mut quotient_domains, i, quotient_domain.clone());

            // let trace_opening_points

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

            let qc_domains = quotient_domain.split_domains(builder, log_quotient_degree_val);
            let num_quotient_chunks = C::N::from_canonical_usize(1 << log_quotient_degree_val);
            for (j, qc_dom) in qc_domains.into_iter().enumerate() {
                let qc_vals_array = builder.get(&opening.quotient, j);
                let mut qc_values = builder.dyn_array::<Array<C, _>>(1);
                builder.set_value(&mut qc_values, 0, qc_vals_array);
                let qc_mat = TwoAdicPcsMatsVariable::<C> {
                    domain: qc_dom,
                    values: qc_values,
                    points: qc_points.clone(),
                };
                let j_n = C::N::from_canonical_usize(j);
                let index: Var<_> = builder.eval(i * num_quotient_chunks + j_n);
                builder.set_value(&mut quotient_mats, index, qc_mat);
            }
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

        // Verify the pcs proof
        pcs.verify(builder, rounds, opening_proof.clone(), challenger);

        // TODO CONSTRAIN: that the preprocessed chips get called with verify_constraints.
        for (i, chip) in machine.chips().iter().enumerate() {
            let index = builder.get(&chip_sorted_idxs, i);

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
                    let qc_domains =
                        quotient_domain.split_domains(builder, chip.log_quotient_degree());
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
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Instant;

    use crate::challenger::CanObserveVariable;
    use crate::challenger::FeltChallenger;
    use crate::hints::Hintable;
    use crate::stark::DuplexChallengerVariable;
    use crate::stark::Ext;
    use crate::types::ShardCommitmentVariable;
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_field::AbstractField;
    use rand::Rng;
    use sp1_core::runtime::Program;
    use sp1_core::stark::LocalProver;
    use sp1_core::{
        stark::{RiscvAir, ShardProof, StarkGenericConfig},
        utils::BabyBearPoseidon2,
    };
    use sp1_recursion_compiler::config::InnerConfig;
    use sp1_recursion_compiler::ir::Array;
    use sp1_recursion_compiler::ir::Felt;
    use sp1_recursion_compiler::{
        asm::AsmBuilder,
        ir::{Builder, ExtConst},
    };
    use sp1_recursion_core::runtime::{Runtime, DIGEST_SIZE};
    use sp1_recursion_core::stark::config::InnerChallenge;
    use sp1_recursion_core::stark::config::InnerVal;

    use sp1_recursion_core::stark::RecursionAir;
    use sp1_sdk::utils::setup_logger;
    use sp1_sdk::{ProverClient, SP1Stdin};

    type SC = BabyBearPoseidon2;
    type F = InnerVal;
    type EF = InnerChallenge;
    type C = InnerConfig;
    type A = RiscvAir<F>;

    #[test]
    fn test_permutation_challenges() {
        // Generate a dummy proof.
        sp1_core::utils::setup_logger();
        let elf =
            include_bytes!("../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

        let machine = A::machine(SC::default());
        let (_, vk) = machine.setup(&Program::from(elf));
        let mut challenger_val = machine.config().challenger();
        let client = ProverClient::new();
        let proofs = client
            .prove_local(elf, SP1Stdin::new(), machine.config().clone())
            .unwrap()
            .proof
            .shard_proofs;
        println!("Proof generated successfully");

        challenger_val.observe(vk.commit);

        proofs.iter().for_each(|proof| {
            challenger_val.observe(proof.commitment.main_commit);
            challenger_val.observe_slice(&proof.public_values);
        });

        let permutation_challenges = (0..2)
            .map(|_| challenger_val.sample_ext_element::<EF>())
            .collect::<Vec<_>>();

        // Observe all the commitments.
        let mut builder = Builder::<InnerConfig>::default();

        let mut challenger = DuplexChallengerVariable::new(&mut builder);

        let preprocessed_commit_val: [F; DIGEST_SIZE] = vk.commit.into();
        let preprocessed_commit: Array<C, _> = builder.constant(preprocessed_commit_val.to_vec());
        challenger.observe(&mut builder, preprocessed_commit);

        let mut witness_stream = Vec::new();
        for proof in proofs {
            witness_stream.extend(proof.write());
            let proof = ShardProof::<BabyBearPoseidon2>::read(&mut builder);
            let ShardCommitmentVariable { main_commit, .. } = proof.commitment;
            challenger.observe(&mut builder, main_commit);
            challenger.observe_slice(&mut builder, proof.public_values);
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

        let program = builder.compile_program();

        let mut runtime = Runtime::<F, EF, _>::new(&program, machine.config().perm.clone());
        runtime.witness_stream = witness_stream;
        runtime.run();
        println!(
            "The program executed successfully, number of cycles: {}",
            runtime.timestamp
        );
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

        let program = builder.compile_program();
        let elapsed = time.elapsed();
        println!("Building took: {:?}", elapsed);

        let machine = A::machine(SC::default());
        let mut runtime = Runtime::<F, EF, _>::new(&program, machine.config().perm.clone());

        let time = Instant::now();
        runtime.run();
        let elapsed = time.elapsed();
        runtime.print_stats();
        println!("Execution took: {:?}", elapsed);

        let config = BabyBearPoseidon2::new();
        let machine = RecursionAir::machine(config);
        let (pk, vk) = machine.setup(&program);
        let mut challenger = machine.config().challenger();

        let record_clone = runtime.record.clone();
        machine.debug_constraints(&pk, record_clone, &mut challenger);

        let start = Instant::now();
        let mut challenger = machine.config().challenger();
        let proof = machine.prove::<LocalProver<_, _>>(&pk, runtime.record, &mut challenger);
        let duration = start.elapsed().as_secs();

        let mut challenger = machine.config().challenger();
        machine.verify(&vk, &proof, &mut challenger).unwrap();
        println!("proving duration = {}", duration);
    }
}
