use std::marker::PhantomData;

use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::AbstractField;
use p3_field::TwoAdicField;
use sp1_core::{
    air::MachineAir,
    stark::{MachineStark, ShardCommitment, StarkGenericConfig},
};
use sp1_recursion_compiler::ir::ExtConst;
use sp1_recursion_compiler::ir::Usize;
use sp1_recursion_compiler::ir::{Builder, Config};
use sp1_recursion_core::stark::config::outer_fri_config;
use sp1_recursion_program::commit::PolynomialSpaceVariable;
use sp1_recursion_program::folder::RecursiveVerifierConstraintFolder;

use crate::domain::new_coset;
use crate::fri::verify_two_adic_pcs;
use crate::types::TwoAdicPcsMatsVariable;
use crate::types::TwoAdicPcsRoundVariable;
use crate::{challenger::MultiField32ChallengerVariable, types::RecursionShardProofVariable};

#[derive(Debug, Clone, Copy)]
pub struct StarkVerifierCircuit<C: Config, SC: StarkGenericConfig> {
    _phantom: PhantomData<(C, SC)>,
}

impl<C: Config, SC: StarkGenericConfig> StarkVerifierCircuit<C, SC>
where
    SC: StarkGenericConfig<Val = C::F, Challenge = C::EF>,
{
    pub fn verify_shard<A>(
        builder: &mut Builder<C>,
        machine: &MachineStark<SC, A>,
        challenger: &mut MultiField32ChallengerVariable<C>,
        proof: &RecursionShardProofVariable<C>,
        permutation_challenges: &[C::EF],
    ) where
        A: MachineAir<C::F> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, C>>,
        C::F: TwoAdicField,
        C::EF: TwoAdicField,
    {
        let RecursionShardProofVariable {
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

        challenger.observe_commitment(builder, permutation_commit.clone());

        let alpha = challenger.sample_ext(builder);

        challenger.observe_commitment(builder, quotient_commit.clone());

        let zeta = challenger.sample_ext(builder);

        let num_shard_chips = opened_values.chips.len();
        let mut trace_domains = Vec::new();
        let mut quotient_domains = Vec::new();

        let log_quotient_degree_val = 1;
        let log_quotient_degree = C::N::from_canonical_usize(log_quotient_degree_val);
        let num_quotient_chunks_val = 1 << log_quotient_degree_val;

        let mut main_mats: Vec<TwoAdicPcsMatsVariable<_>> = Vec::new();
        let mut perm_mats: Vec<TwoAdicPcsMatsVariable<_>> = Vec::new();

        let num_quotient_mats = num_shard_chips * num_quotient_chunks_val;
        let mut quotient_mats = Vec::new();

        let mut qc_points = Vec::new();
        qc_points.push(zeta);

        for i in 0..num_shard_chips {
            let opening = &opened_values.chips[i];
            let domain = new_coset(builder, opening.log_degree);
            trace_domains.push(domain.clone());

            let log_quotient_size = opening.log_degree + log_quotient_degree_val;
            let quotient_domain =
                domain.create_disjoint_domain(builder, Usize::Const(log_quotient_size));
            quotient_domains.push(quotient_domain.clone());

            let mut trace_points = Vec::new();
            let zeta_next = domain.next_point(builder, zeta);
            trace_points.push(zeta);
            trace_points.push(zeta_next);

            let mut main_values = Vec::new();
            main_values.push(opening.main.local.clone());
            main_values.push(opening.main.next.clone());
            let main_mat = TwoAdicPcsMatsVariable::<C> {
                domain: TwoAdicMultiplicativeCoset {
                    log_n: domain.log_n,
                    shift: domain.shift,
                },
                values: main_values,
                points: trace_points.clone(),
            };
            main_mats.push(main_mat);

            let mut perm_values = Vec::new();
            perm_values.push(opening.permutation.local.clone());
            perm_values.push(opening.permutation.next.clone());
            let perm_mat = TwoAdicPcsMatsVariable::<C> {
                domain: TwoAdicMultiplicativeCoset {
                    log_n: domain.clone().log_n,
                    shift: domain.clone().shift,
                },
                values: perm_values,
                points: trace_points,
            };
            perm_mats.push(perm_mat);

            let qc_domains = quotient_domain.split_domains(builder, log_quotient_degree_val);
            let num_quotient_chunks = 1 << log_quotient_degree_val;
            for (j, qc_dom) in qc_domains.into_iter().enumerate() {
                let qc_vals_array = opening.quotient[j].clone();
                let mut qc_values = Vec::new();
                qc_values.push(qc_vals_array);
                let qc_mat = TwoAdicPcsMatsVariable::<C> {
                    domain: TwoAdicMultiplicativeCoset {
                        log_n: qc_dom.clone().log_n,
                        shift: qc_dom.clone().shift,
                    },
                    values: qc_values,
                    points: qc_points.clone(),
                };
                quotient_mats.push(qc_mat);
            }
        }

        let mut rounds = Vec::new();
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
        rounds.push(main_round);
        rounds.push(perm_round);
        rounds.push(quotient_round);

        let config = outer_fri_config();
        verify_two_adic_pcs(builder, &config, &proof.opening_proof, challenger, rounds);

        // for (i, chip) in machine.chips().iter().enumerate() {
        //     let index = sorted_indices[i];
        //     let values = opened_values.chips[i];
        //     let trace_domain = trace_domains[i];
        //     let quotient_domain = quotient_domains[i];
        //     let qc_domains = quotient_domain.split_domains(builder, chip.log_quotient_degree());
        //     Self::verify_constraints(
        //         builder,
        //         chip,
        //         &values,
        //         trace_domain,
        //         qc_domains,
        //         zeta,
        //         alpha,
        //         permutation_challenges,
        //     );
        // }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Instant;

    use crate::{
        challenger::MultiField32ChallengerVariable, fri::tests::const_two_adic_pcs_proof,
        stark::StarkVerifierCircuit,
    };
    use p3_baby_bear::DiffusionMatrixBabybear;
    use p3_bn254_fr::Bn254Fr;
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_field::{AbstractField, PrimeField32};
    use sp1_core::{
        air::MachineAir,
        stark::{
            LocalProver, MachineStark, RiscvAir, ShardCommitment, ShardProof, StarkGenericConfig,
        },
        utils::{ec::weierstrass::bn254::Bn254, BabyBearPoseidon2},
        SP1Prover, SP1Stdin,
    };
    use sp1_recursion_compiler::{
        asm::VmBuilder,
        constraints::{gnark_ffi, ConstraintBackend},
        ir::{Builder, Config, Usize},
        OuterConfig,
    };
    use sp1_recursion_core::{
        cpu::Instruction,
        runtime::{Opcode, Program, Runtime, DIGEST_SIZE},
        stark::{
            config::{outer_fri_config, BabyBearPoseidon2Outer, OuterVal},
            RecursionAir,
        },
    };

    use crate::types::{
        ChipOpenedValuesVariable, OuterDigest, RecursionShardOpenedValuesVariable,
        RecursionShardProofVariable,
    };

    type SC = BabyBearPoseidon2Outer;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    type C = OuterConfig;
    type A = RecursionAir<F>;

    pub(crate) fn const_proof(
        builder: &mut Builder<C>,
        machine: &MachineStark<SC, A>,
        proof: ShardProof<SC>,
    ) -> RecursionShardProofVariable<C>
    where
        C: Config<F = F, EF = EF>,
    {
        let index = builder.materialize(Usize::Const(proof.index));

        // Set up the commitments.
        let main_commit: [Bn254Fr; 1] = proof.commitment.main_commit.into();
        let permutation_commit: [Bn254Fr; 1] = proof.commitment.permutation_commit.into();
        let quotient_commit: [Bn254Fr; 1] = proof.commitment.quotient_commit.into();
        let mut main_commit: OuterDigest<C> = [builder.eval(main_commit[0])];
        let mut permutation_commit: OuterDigest<C> = [builder.eval(permutation_commit[0])];
        let mut quotient_commit: OuterDigest<C> = [builder.eval(quotient_commit[0])];

        let commitment = ShardCommitment {
            main_commit,
            permutation_commit,
            quotient_commit,
        };

        // Set up the opened values.
        let num_shard_chips = proof.opened_values.chips.len();
        let mut opened_values = Vec::new();
        for (i, values) in proof.opened_values.chips.iter().enumerate() {
            let values: ChipOpenedValuesVariable<_> = builder.eval_const(values.clone());
            opened_values.push(values);
        }
        let opened_values = RecursionShardOpenedValuesVariable {
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
                    .map(|i| Bn254Fr::from_canonical_usize(*i))
                    .unwrap_or(Bn254Fr::neg_one());
                builder.eval(index)
            })
            .collect();

        RecursionShardProofVariable {
            index: proof.index,
            commitment,
            opened_values,
            opening_proof,
            sorted_indices,
        }
    }

    pub fn basic_program<F: PrimeField32>() -> Program<F> {
        let zero = [F::zero(); 4];
        let one = [F::one(), F::zero(), F::zero(), F::zero()];
        Program::<F> {
            instructions: vec![Instruction::new(
                Opcode::ADD,
                F::from_canonical_u32(3),
                zero,
                one,
                false,
                true,
            )],
        }
    }

    #[test]
    fn test_recursive_verify_shard_v2() {
        sp1_core::utils::setup_logger();

        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;
        let program = basic_program::<F>();

        let config = SC::new();
        let mut runtime = Runtime::<F, EF, DiffusionMatrixBabybear>::new_no_perm(&program);
        runtime.run();

        let machine = RecursionAir::machine(config);
        let mut challenger_val = machine.config().challenger();
        let (pk, vk) = machine.setup(&program);
        let mut challenger = machine.config().challenger();

        let start = Instant::now();
        let proofs = machine
            .prove::<LocalProver<_, _>>(&pk, runtime.record, &mut challenger)
            .shard_proofs;
        let duration = start.elapsed().as_secs();

        proofs.iter().for_each(|proof| {
            challenger_val.observe(proof.commitment.main_commit);
        });

        let permutation_challenges = (0..2)
            .map(|_| challenger_val.sample_ext_element::<EF>())
            .collect::<Vec<_>>();

        let time = Instant::now();
        let mut builder = Builder::<OuterConfig>::default();
        let config = outer_fri_config();

        let mut challenger = MultiField32ChallengerVariable::new(&mut builder);

        let mut shard_proofs = vec![];
        for proof_val in proofs {
            let proof = const_proof(&mut builder, &machine, proof_val);
            let ShardCommitment { main_commit, .. } = &proof.commitment;
            challenger.observe_commitment(&mut builder, main_commit.clone());
            shard_proofs.push(proof);
        }

        for proof in shard_proofs {
            StarkVerifierCircuit::<C, SC>::verify_shard(
                &mut builder,
                &machine,
                &mut challenger,
                &proof,
                &permutation_challenges,
            );
        }

        let mut backend = ConstraintBackend::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        gnark_ffi::test_circuit(constraints);
    }

    // #[test]
    // fn test_recursive_verify_shard() {
    //     // Generate a dummy proof.
    //     sp1_core::utils::setup_logger();

    //     let elf =
    //         include_bytes!("../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

    //     let machine = A::machine(SC::default());
    //     let mut challenger_val = machine.config().challenger();
    //     let proofs = SP1Prover::prove_with_config(elf, SP1Stdin::new(), machine.config().clone())
    //         .unwrap()
    //         .proof
    //         .shard_proofs;
    //     println!("Proof generated successfully");

    //     proofs.iter().for_each(|proof| {
    //         challenger_val.observe(proof.commitment.main_commit);
    //     });

    //     let permutation_challenges = (0..2)
    //         .map(|_| challenger_val.sample_ext_element::<EF>())
    //         .collect::<Vec<_>>();

    //     let time = Instant::now();
    //     let mut builder = Builder::<OuterConfig>::default();
    //     let config = outer_fri_config();

    //     let mut challenger = MultiField32ChallengerVariable::new(&mut builder);

    //     let mut shard_proofs = vec![];
    //     for proof_val in proofs {
    //         let proof = const_proof(&mut builder, &machine, proof_val);
    //         let ShardCommitment { main_commit, .. } = &proof.commitment;
    //         challenger.observe_commitment(&mut builder, main_commit.clone());
    //         shard_proofs.push(proof);
    //     }

    //     for proof in shard_proofs {
    //         StarkVerifierCircuit::<C, SC>::verify_shard(
    //             &mut builder,
    //             &machine,
    //             &mut challenger,
    //             &proof,
    //             &permutation_challenges,
    //         );
    //     }

    //     let mut backend = ConstraintBackend::<OuterConfig>::default();
    //     let constraints = backend.emit(builder.operations);
    //     gnark_ffi::test_circuit(constraints);
    // }
}
