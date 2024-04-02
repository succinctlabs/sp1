use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::AbstractField;
use p3_field::TwoAdicField;

use sp1_core::air::MachineAir;
use sp1_core::stark::Com;
use sp1_core::stark::MachineStark;
use sp1_core::stark::VerifyingKey;
use sp1_core::stark::{ShardCommitment, StarkGenericConfig};

use sp1_recursion_compiler::ir::Array;
use sp1_recursion_compiler::ir::Ext;
use sp1_recursion_compiler::ir::ExtConst;
use sp1_recursion_compiler::ir::Var;
use sp1_recursion_compiler::ir::{Builder, Config, Usize};

use crate::challenger::CanObserveVariable;
use crate::challenger::DuplexChallengerVariable;
use crate::challenger::FeltChallenger;
use crate::commit::PolynomialSpaceVariable;
use crate::folder::RecursiveVerifierConstraintFolder;
use crate::fri::TwoAdicMultiplicativeCosetVariable;
use crate::fri::TwoAdicPcsMatsVariable;
use crate::fri::TwoAdicPcsRoundVariable;

use sp1_recursion_core::runtime::DIGEST_SIZE;

use crate::{commit::PcsVariable, fri::TwoAdicFriPcsVariable, types::ShardProofVariable};

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
        vk: &VerifyingKey<SC>,
        pcs: &TwoAdicFriPcsVariable<C>,
        machine: &MachineStark<SC, A>,
        challenger: &mut DuplexChallengerVariable<C>,
        proof: &ShardProofVariable<C>,
        permutation_challenges: &[C::EF],
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
            sorted_indices,
            ..
        } = proof;

        let ShardCommitment {
            main_commit,
            permutation_commit,
            quotient_commit,
        } = commitment;

        let permutation_challenges_var = (0..2)
            .map(|_| challenger.sample_ext(builder))
            .collect::<Vec<_>>();

        for i in 0..2 {
            builder.assert_ext_eq(
                permutation_challenges_var[i],
                permutation_challenges[i].cons(),
            );
        }

        challenger.observe(builder, permutation_commit.clone());

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

        let num_preprocessed_chips = vk.chip_information.len();

        let mut prep_mats: Array<_, TwoAdicPcsMatsVariable<_>> =
            builder.dyn_array(num_preprocessed_chips);
        let mut main_mats: Array<_, TwoAdicPcsMatsVariable<_>> = builder.dyn_array(num_shard_chips);
        let mut perm_mats: Array<_, TwoAdicPcsMatsVariable<_>> = builder.dyn_array(num_shard_chips);

        let num_quotient_mats: Usize<_> = builder.eval(num_shard_chips * num_quotient_chunks_val);
        let mut quotient_mats: Array<_, TwoAdicPcsMatsVariable<_>> =
            builder.dyn_array(num_quotient_mats);

        let mut qc_points = builder.dyn_array::<Ext<_, _>>(1);
        builder.set(&mut qc_points, 0, zeta);

        for (i, (name, domain, _)) in vk.chip_information.iter().enumerate() {
            let chip_idx = machine
                .chips()
                .iter()
                .rposition(|chip| &chip.name() == name)
                .unwrap();
            let index = sorted_indices[chip_idx];
            let opening = builder.get(&opened_values.chips, index);

            let domain: TwoAdicMultiplicativeCosetVariable<_> = builder.eval_const(*domain);

            let mut trace_points = builder.dyn_array::<Ext<_, _>>(2);
            let zeta_next = domain.next_point(builder, zeta);

            builder.set(&mut trace_points, 0, zeta);
            builder.set(&mut trace_points, 1, zeta_next);

            let mut prep_values = builder.dyn_array::<Array<C, _>>(2);
            builder.set(&mut prep_values, 0, opening.preprocessed.local);
            builder.set(&mut prep_values, 1, opening.preprocessed.next);
            let main_mat = TwoAdicPcsMatsVariable::<C> {
                domain: domain.clone(),
                values: prep_values,
                points: trace_points.clone(),
            };
            builder.set(&mut prep_mats, i, main_mat);
        }

        builder.range(0, num_shard_chips).for_each(|i, builder| {
            let opening = builder.get(&opened_values.chips, i);
            let domain = pcs.natural_domain_for_log_degree(builder, Usize::Var(opening.log_degree));
            builder.set(&mut trace_domains, i, domain.clone());

            let log_quotient_size: Usize<_> =
                builder.eval(opening.log_degree + log_quotient_degree);
            let quotient_domain =
                domain.create_disjoint_domain(builder, log_quotient_size, &pcs.config);
            builder.set(&mut quotient_domains, i, quotient_domain.clone());

            // let trace_opening_points

            let mut trace_points = builder.dyn_array::<Ext<_, _>>(2);
            let zeta_next = domain.next_point(builder, zeta);
            builder.set(&mut trace_points, 0, zeta);
            builder.set(&mut trace_points, 1, zeta_next);

            // Get the main matrix.
            let mut main_values = builder.dyn_array::<Array<C, _>>(2);
            builder.set(&mut main_values, 0, opening.main.local);
            builder.set(&mut main_values, 1, opening.main.next);
            let main_mat = TwoAdicPcsMatsVariable::<C> {
                domain: domain.clone(),
                values: main_values,
                points: trace_points.clone(),
            };
            builder.set(&mut main_mats, i, main_mat);

            // Get the permutation matrix.
            let mut perm_values = builder.dyn_array::<Array<C, _>>(2);
            builder.set(&mut perm_values, 0, opening.permutation.local);
            builder.set(&mut perm_values, 1, opening.permutation.next);
            let perm_mat = TwoAdicPcsMatsVariable::<C> {
                domain: domain.clone(),
                values: perm_values,
                points: trace_points,
            };
            builder.set(&mut perm_mats, i, perm_mat);

            // Get the quotient matrices and values.

            let qc_domains = quotient_domain.split_domains(builder, log_quotient_degree_val);
            let num_quotient_chunks = C::N::from_canonical_usize(1 << log_quotient_degree_val);
            for (j, qc_dom) in qc_domains.into_iter().enumerate() {
                let qc_vals_array = builder.get(&opening.quotient, j);
                let mut qc_values = builder.dyn_array::<Array<C, _>>(1);
                builder.set(&mut qc_values, 0, qc_vals_array);
                let qc_mat = TwoAdicPcsMatsVariable::<C> {
                    domain: qc_dom,
                    values: qc_values,
                    points: qc_points.clone(),
                };
                let j_n = C::N::from_canonical_usize(j);
                let index: Var<_> = builder.eval(i * num_quotient_chunks + j_n);
                builder.set(&mut quotient_mats, index, qc_mat);
            }
        });

        // Create the pcs rounds.
        let mut rounds = builder.dyn_array::<TwoAdicPcsRoundVariable<_>>(4);
        let prep_commit_val: [SC::Val; DIGEST_SIZE] = vk.commit.clone().into();
        let prep_commit = builder.eval_const(prep_commit_val.to_vec());
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
        builder.set(&mut rounds, 0, prep_round);
        builder.set(&mut rounds, 1, main_round);
        builder.set(&mut rounds, 2, perm_round);
        builder.set(&mut rounds, 3, quotient_round);

        // Verify the pcs proof
        pcs.verify(builder, rounds, opening_proof.clone(), challenger);

        for (i, chip) in machine.chips().iter().enumerate() {
            let index = sorted_indices[i];
            builder.if_ne(index, C::N::neg_one()).then(|builder| {
                let values = builder.get(&opened_values.chips, index);
                let trace_domain = builder.get(&trace_domains, index);
                let quotient_domain: TwoAdicMultiplicativeCosetVariable<_> =
                    builder.get(&quotient_domains, index);
                let qc_domains = quotient_domain.split_domains(builder, chip.log_quotient_degree());
                Self::verify_constraints(
                    builder,
                    chip,
                    &values,
                    trace_domain,
                    qc_domains,
                    zeta,
                    alpha,
                    permutation_challenges,
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
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_field::AbstractField;
    use sp1_core::runtime::Program;
    use sp1_core::{
        air::MachineAir,
        stark::{MachineStark, RiscvAir, ShardCommitment, ShardProof, StarkGenericConfig},
        utils::BabyBearPoseidon2,
    };
    use sp1_recursion_compiler::ir::Array;
    use sp1_recursion_compiler::{
        asm::{AsmConfig, VmBuilder},
        ir::{Builder, Config, ExtConst, Usize},
    };
    use sp1_recursion_core::runtime::{Runtime, DIGEST_SIZE};
    use sp1_sdk::{SP1Prover, SP1Stdin};

    use crate::{
        challenger::DuplexChallengerVariable,
        fri::{
            const_fri_config, const_two_adic_pcs_proof, default_fri_config, TwoAdicFriPcsVariable,
        },
        stark::StarkVerifier,
        types::{
            ChipOpenedValuesVariable, Commitment, ShardOpenedValuesVariable, ShardProofVariable,
        },
    };

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    type C = AsmConfig<F, EF>;
    type A = RiscvAir<F>;

    pub(crate) fn const_proof<C>(
        builder: &mut Builder<C>,
        machine: &MachineStark<SC, A>,
        proof: ShardProof<SC>,
    ) -> ShardProofVariable<C>
    where
        C: Config<F = F, EF = EF>,
    {
        let index = builder.materialize(Usize::Const(proof.index));

        // Set up the commitments.
        let mut main_commit: Commitment<_> = builder.dyn_array(DIGEST_SIZE);
        let mut permutation_commit: Commitment<_> = builder.dyn_array(DIGEST_SIZE);
        let mut quotient_commit: Commitment<_> = builder.dyn_array(DIGEST_SIZE);

        let main_commit_val: [_; DIGEST_SIZE] = proof.commitment.main_commit.into();
        let perm_commit_val: [_; DIGEST_SIZE] = proof.commitment.permutation_commit.into();
        let quotient_commit_val: [_; DIGEST_SIZE] = proof.commitment.quotient_commit.into();
        for (i, ((main_val, perm_val), quotient_val)) in main_commit_val
            .into_iter()
            .zip(perm_commit_val)
            .zip(quotient_commit_val)
            .enumerate()
        {
            builder.set(&mut main_commit, i, main_val);
            builder.set(&mut permutation_commit, i, perm_val);
            builder.set(&mut quotient_commit, i, quotient_val);
        }

        let commitment = ShardCommitment {
            main_commit,
            permutation_commit,
            quotient_commit,
        };

        // Set up the opened values.
        let num_shard_chips = proof.opened_values.chips.len();
        let mut opened_values = builder.dyn_array(num_shard_chips);
        for (i, values) in proof.opened_values.chips.iter().enumerate() {
            let values: ChipOpenedValuesVariable<_> = builder.eval_const(values.clone());
            builder.set(&mut opened_values, i, values);
        }
        let opened_values = ShardOpenedValuesVariable {
            chips: opened_values,
        };

        let opening_proof = const_two_adic_pcs_proof(builder, proof.opening_proof);

        let sorted_indices = machine
            .chips()
            .iter()
            .map(|chip| {
                let index = proof
                    .chip_ordering
                    .get(&chip.name())
                    .map(|i| C::N::from_canonical_usize(*i))
                    .unwrap_or(C::N::neg_one());
                builder.eval(index)
            })
            .collect();

        ShardProofVariable {
            index: Usize::Var(index),
            commitment,
            opened_values,
            opening_proof,
            sorted_indices,
        }
    }

    #[test]
    fn test_permutation_challenges() {
        // Generate a dummy proof.
        sp1_core::utils::setup_logger();
        let elf =
            include_bytes!("../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

        let machine = A::machine(SC::default());
        let (_, vk) = machine.setup(&Program::from(elf));
        let mut challenger_val = machine.config().challenger();
        let proofs = SP1Prover::prove_with_config(elf, SP1Stdin::new(), machine.config().clone())
            .unwrap()
            .proof
            .shard_proofs;
        println!("Proof generated successfully");

        challenger_val.observe(vk.commit);

        proofs.iter().for_each(|proof| {
            challenger_val.observe(proof.commitment.main_commit);
        });

        let permutation_challenges = (0..2)
            .map(|_| challenger_val.sample_ext_element::<EF>())
            .collect::<Vec<_>>();

        // Observe all the commitments.
        let mut builder = VmBuilder::<F, EF>::default();

        let mut challenger = DuplexChallengerVariable::new(&mut builder);

        let preprocessed_commit_val: [F; DIGEST_SIZE] = vk.commit.into();
        let preprocessed_commit: Array<C, _> = builder.eval_const(preprocessed_commit_val.to_vec());
        challenger.observe(&mut builder, preprocessed_commit);

        for proof in proofs {
            let proof = const_proof(&mut builder, &machine, proof);
            let ShardCommitment { main_commit, .. } = proof.commitment;
            challenger.observe(&mut builder, main_commit);
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

        let program = builder.compile();

        let mut runtime = Runtime::<F, EF, _>::new(&program, machine.config().perm.clone());
        runtime.run();
        println!(
            "The program executed successfully, number of cycles: {}",
            runtime.timestamp
        );
    }

    #[test]
    #[ignore]
    fn test_recursive_verify_shard() {
        // Generate a dummy proof.
        sp1_core::utils::setup_logger();
        let elf =
            include_bytes!("../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

        let machine = A::machine(SC::default());

        let (_, vk) = machine.setup(&Program::from(elf));
        let mut challenger_val = machine.config().challenger();
        let proofs = SP1Prover::prove_with_config(elf, SP1Stdin::new(), machine.config().clone())
            .unwrap()
            .proof
            .shard_proofs;
        println!("Proof generated successfully");

        challenger_val.observe(vk.commit);
        proofs.iter().for_each(|proof| {
            challenger_val.observe(proof.commitment.main_commit);
        });

        let permutation_challenges = (0..2)
            .map(|_| challenger_val.sample_ext_element::<EF>())
            .collect::<Vec<_>>();

        let time = Instant::now();
        let mut builder = VmBuilder::<F, EF>::default();
        let config = const_fri_config(&mut builder, default_fri_config());
        let pcs = TwoAdicFriPcsVariable { config };

        let mut challenger = DuplexChallengerVariable::new(&mut builder);

        let preprocessed_commit_val: [F; DIGEST_SIZE] = vk.commit.into();
        let preprocessed_commit: Array<C, _> = builder.eval_const(preprocessed_commit_val.to_vec());
        challenger.observe(&mut builder, preprocessed_commit);

        let mut shard_proofs = vec![];
        for proof_val in proofs {
            let proof = const_proof(&mut builder, &machine, proof_val);
            let ShardCommitment { main_commit, .. } = &proof.commitment;
            challenger.observe(&mut builder, main_commit.clone());
            shard_proofs.push(proof);
        }

        for proof in shard_proofs {
            StarkVerifier::<C, SC>::verify_shard(
                &mut builder,
                &vk,
                &pcs,
                &machine,
                &mut challenger.clone(),
                &proof,
                &permutation_challenges,
            );
        }

        let program = builder.compile();
        let elapsed = time.elapsed();
        println!("Building took: {:?}", elapsed);

        let mut runtime = Runtime::<F, EF, _>::new(&program, machine.config().perm.clone());

        let time = Instant::now();
        runtime.run();
        let elapsed = time.elapsed();
        runtime.print_stats();
        println!("Execution took: {:?}", elapsed);
    }

    #[test]
    #[should_panic]
    fn test_recursive_verify_bad_proof() {
        // Generate a dummy proof.
        sp1_core::utils::setup_logger();
        let elf =
            include_bytes!("../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

        let machine = A::machine(SC::default());
        let (_, vk) = machine.setup(&Program::from(elf));
        let mut challenger_val = machine.config().challenger();
        let proofs = SP1Prover::prove_with_config(elf, SP1Stdin::new(), machine.config().clone())
            .unwrap()
            .proof
            .shard_proofs;
        println!("Proof generated successfully");

        proofs.iter().for_each(|proof| {
            challenger_val.observe(proof.commitment.main_commit);
        });

        let permutation_challenges = (0..2)
            .map(|_| challenger_val.sample_ext_element::<EF>())
            .collect::<Vec<_>>();

        // Observe all the commitments.
        let mut builder = VmBuilder::<F, EF>::default();
        let config = const_fri_config(&mut builder, default_fri_config());
        let pcs = TwoAdicFriPcsVariable { config };

        let mut challenger = DuplexChallengerVariable::new(&mut builder);

        let mut shard_proofs = vec![];
        for proof_val in proofs {
            // Change a commitment to be incorrect.
            let mut proof_val = proof_val;
            proof_val.commitment.main_commit = [F::zero(); DIGEST_SIZE].into();
            let proof = const_proof(&mut builder, &machine, proof_val);
            let ShardCommitment { main_commit, .. } = &proof.commitment;
            challenger.observe(&mut builder, main_commit.clone());
            shard_proofs.push(proof);
        }

        for proof in shard_proofs {
            StarkVerifier::<C, SC>::verify_shard(
                &mut builder,
                &vk,
                &pcs,
                &machine,
                &mut challenger.clone(),
                &proof,
                &permutation_challenges,
            );
        }

        let program = builder.compile();

        let mut runtime = Runtime::<F, EF, _>::new(&program, machine.config().perm.clone());

        runtime.run();
    }
}
