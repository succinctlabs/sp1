use p3_challenger::CanObserve;
use p3_challenger::CanSampleBits;
use p3_challenger::DuplexChallenger;
use p3_commit::Pcs;
use p3_commit::PolynomialSpace;
use p3_dft::Radix2DitParallel;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_fri::TwoAdicFriPcs;
use rand::rngs::OsRng;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::poseidon2_instance::RC_16_30;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::asm::AsmConfig;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::ir::Array;
use sp1_recursion_compiler::ir::Ext;
use sp1_recursion_compiler::ir::Felt;
use sp1_recursion_compiler::ir::SymbolicExt;
use sp1_recursion_compiler::ir::Usize;
use sp1_recursion_compiler::ir::Var;
use sp1_recursion_compiler::verifier::challenger::DuplexChallengerVariable;
use sp1_recursion_compiler::verifier::fri;
use sp1_recursion_compiler::verifier::fri::pcs::TwoAdicPcsMats;
use sp1_recursion_compiler::verifier::fri::pcs::TwoAdicPcsRound;
use sp1_recursion_compiler::verifier::fri::types::Commitment;
use sp1_recursion_compiler::verifier::fri::types::FriCommitPhaseProofStepVariable;
use sp1_recursion_compiler::verifier::fri::types::FriConfigVariable;
use sp1_recursion_compiler::verifier::fri::types::FriProofVariable;
use sp1_recursion_compiler::verifier::fri::types::FriQueryProofVariable;
use sp1_recursion_compiler::verifier::fri::types::DIGEST_SIZE;
use sp1_recursion_compiler::verifier::fri::TwoAdicPcsProof;
use sp1_recursion_compiler::verifier::TwoAdicMultiplicativeCoset;
use sp1_recursion_core::runtime::Runtime;

use itertools::Itertools;
use p3_baby_bear::{BabyBear, DiffusionMatrixBabybear};
use p3_challenger::FieldChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::{Radix2Dit, TwoAdicSubgroupDft};
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{prover, verifier, FriConfig};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::util::reverse_matrix_index_bits;
use p3_matrix::{Matrix, MatrixRows};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::Poseidon2;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_util::log2_strict_usize;
use sp1_recursion_core::runtime::POSEIDON2_WIDTH;

pub type Val = BabyBear;
pub type Challenge = BinomialExtensionField<Val, 4>;
pub type Perm = Poseidon2<Val, DiffusionMatrixBabybear, 16, 7>;
pub type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
pub type ValMmcs =
    FieldMerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 8>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Challenger = DuplexChallenger<Val, Perm, 16>;
type MyFriConfig = FriConfig<ChallengeMmcs>;
pub type Dft = Radix2DitParallel;
type MyPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

#[test]
fn test_pcs_verify() {
    let log_degrees = &[3];
    let perm = Perm::new(8, 22, RC_16_30.to_vec(), DiffusionMatrixBabybear);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress));
    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 10,
        proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let dft = Dft {};
    let max_log_n = log_degrees.iter().copied().max().unwrap();
    let pcs: MyPcs = MyPcs::new(max_log_n, dft, val_mmcs, fri_config);
    let mut challenger = Challenger::new(perm.clone());
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress));
    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 10,
        proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };

    let mut rng = &mut OsRng;
    let domains_and_polys = log_degrees
        .iter()
        .map(|&d| {
            (
                <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, 1 << d),
                RowMajorMatrix::<Val>::rand(&mut rng, 1 << d, 10),
            )
        })
        .collect::<Vec<_>>();

    let (commit, data) =
        <MyPcs as Pcs<Challenge, Challenger>>::commit(&pcs, domains_and_polys.clone());

    challenger.observe(commit);

    let zeta = challenger.sample_ext_element::<Challenge>();

    let points = domains_and_polys
        .iter()
        .map(|_| vec![zeta])
        .collect::<Vec<_>>();

    let (opening, proof) = pcs.open(vec![(&data, points)], &mut challenger);

    // verify the proof.
    let mut challenger = Challenger::new(perm);
    challenger.observe(commit);
    let _ = challenger.sample_ext_element::<Challenge>();

    let os = domains_and_polys
        .iter()
        .zip(&opening[0])
        .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
        .collect();
    pcs.verify(vec![(commit, os)], &proof, &mut challenger)
        .unwrap();

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    type C = AsmConfig<F, EF>;

    let mut builder = VmBuilder::<F, EF>::default();
    let commit: [F; DIGEST_SIZE] = commit.into();
    let mut commitvar: Array<C, Felt<F>> = builder.dyn_array(DIGEST_SIZE);
    for i in 0..DIGEST_SIZE {
        let el: Felt<F> = builder.eval(commit[i]);
        builder.set(&mut commitvar, i, el);
    }

    let os: Vec<_> = domains_and_polys
        .iter()
        .zip(&opening[0])
        .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
        .collect();
    let mut mats: Array<C, TwoAdicPcsMats<C>> = builder.dyn_array(os.len());
    for (m, (domain, poly)) in os.into_iter().enumerate() {
        let domain = builder.const_domain(&domain);
        let points = poly.iter().map(|(p, _)| *p).collect::<Vec<_>>();
        let values = poly.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>();
        let mut pointsvar: Array<C, Ext<F, EF>> = builder.dyn_array(points.len());
        for i in 0..points.len() {
            let el: Ext<F, EF> = builder.eval(SymbolicExt::Const(points[i]));
            builder.set(&mut pointsvar, i, el);
        }
        let mut valuesvar: Array<C, Array<C, Ext<F, EF>>> = builder.dyn_array(values.len());
        for i in 0..values.len() {
            let mut tmp = builder.dyn_array(values[i].len());
            for j in 0..values[i].len() {
                let el: Ext<F, EF> = builder.eval(SymbolicExt::Const(values[i][j]));
                builder.set(&mut tmp, j, el);
            }
            builder.set(&mut valuesvar, i, tmp);
        }
        let mat = TwoAdicPcsMats::<C> {
            domain,
            points: pointsvar,
            values: valuesvar,
        };
        builder.set(&mut mats, m, mat);
    }

    let mut rounds: Array<C, TwoAdicPcsRound<C>> = builder.dyn_array(1);
    let round = TwoAdicPcsRound::<C> {
        batch_commit: commitvar,
        mats,
    };
    builder.set(&mut rounds, 0, round);

    let configvar = FriConfigVariable::<AsmConfig<F, EF>> {
        log_blowup: builder.eval(F::from_canonical_usize(fri_config.log_blowup)),
        num_queries: builder.eval(F::from_canonical_usize(fri_config.num_queries)),
        proof_of_work_bits: builder.eval(F::from_canonical_usize(fri_config.proof_of_work_bits)),
    };
    let mut fri_proofvar = FriProofVariable::<AsmConfig<F, EF>> {
        commit_phase_commits: builder.dyn_array(proof.fri_proof.commit_phase_commits.len()),
        query_proofs: builder.dyn_array(proof.fri_proof.query_proofs.len()),
        final_poly: builder.eval(SymbolicExt::Const(proof.fri_proof.final_poly)),
        pow_witness: builder.eval(proof.fri_proof.pow_witness),
    };
    let mut proofvar = TwoAdicPcsProof::<C> {
        fri_proof: fri_proofvar,
        query_openings: builder.dyn_array(proof.query_openings.len()), // TODO: fix this
    };
    let width: Var<_> = builder.eval(F::from_canonical_usize(POSEIDON2_WIDTH));
    let mut challengervar = DuplexChallengerVariable::<AsmConfig<F, EF>> {
        sponge_state: builder.array(Usize::Var(width)),
        nb_inputs: builder.eval(F::zero()),
        input_buffer: builder.array(Usize::Var(width)),
        nb_outputs: builder.eval(F::zero()),
        output_buffer: builder.array(Usize::Var(width)),
    };
    fri::verify_two_adic_pcs(
        &mut builder,
        &configvar,
        rounds,
        proofvar,
        &mut challengervar,
    );
}
