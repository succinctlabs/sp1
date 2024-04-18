use clap::Parser;

#[derive(Parser)]
#[command(name = "MyApp")]
#[command(version = "1.0")]
#[command(about = "Does awesome things", long_about = None)]
struct Cli {
    #[arg(long)]
    columns: usize,
    #[arg(long)]
    log2_rows: usize,
    #[arg(long)]
    num_runs: usize,
}

use core::num;
use itertools::Itertools;
use p3_challenger::CanObserve;
use p3_challenger::FieldChallenger;
use p3_commit::Pcs;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use rand::rngs::OsRng;
use sp1_core::utils::inner_fri_config;
use sp1_core::utils::inner_perm;
use sp1_core::utils::InnerChallenge;
use sp1_core::utils::InnerChallenger;
use sp1_core::utils::InnerCompress;
use sp1_core::utils::InnerDft;
use sp1_core::utils::InnerHash;
use sp1_core::utils::InnerPcs;
use sp1_core::utils::InnerPcsProof;
use sp1_core::utils::InnerVal;
use sp1_core::utils::InnerValMmcs;
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_compiler::ir::Array;
use sp1_recursion_compiler::ir::Builder;
use sp1_recursion_compiler::ir::Usize;
use sp1_recursion_compiler::ir::Var;
use sp1_recursion_core::runtime::Runtime;
use sp1_recursion_core::runtime::DIGEST_SIZE;
use sp1_recursion_program::challenger::CanObserveVariable;
use sp1_recursion_program::challenger::DuplexChallengerVariable;
use sp1_recursion_program::challenger::FeltChallenger;
use sp1_recursion_program::fri::types::TwoAdicPcsRoundVariable;
use sp1_recursion_program::fri::TwoAdicMultiplicativeCosetVariable;
use sp1_recursion_program::hints::Hintable;
use std::cmp::Reverse;

use sp1_recursion_program::commit::PcsVariable;
use sp1_recursion_program::fri::TwoAdicFriPcsVariable;
use sp1_recursion_program::reduce::const_fri_config;

fn main() {
    // cargo run --release -p sp1-prover --bin pcs-benchmark -- --columns 100 --log2-rows 19 --num-runs 10
    // 1) read column / rows from command line
    // 2) generate mock proof
    // 3) run pcs commit and track how much time it takes
    let cli = Cli::parse();

    let num_cols = cli.columns;
    let log2_rows = cli.log2_rows;

    println!("Warming up proof...");
    for _ in 0..3 {
        full_proof(num_cols, log2_rows);
    }
    println!("Starting run of proof...");
    let now = std::time::Instant::now();
    for _ in 0..cli.num_runs {
        full_proof(num_cols, log2_rows);
    }
    println!(
        "Time to generate {} proofs: {:.2}",
        cli.num_runs,
        now.elapsed().as_secs_f64()
    );
    println!("Warming up pcs_commit...");
    for _ in 0..3 {
        pcs_commit(num_cols, log2_rows);
    }
    println!("Starting run of pcs_commit...");
    let now = std::time::Instant::now();
    for _ in 0..cli.num_runs {
        pcs_commit(num_cols, log2_rows);
    }
    println!(
        "Time to run {} commits: {:.2}",
        cli.num_runs,
        now.elapsed().as_secs_f64()
    );
}

fn full_proof(num_cols: usize, log2_rows: usize) {
    let mut rng = &mut OsRng;
    let log_degrees = &[log2_rows];
    let perm = inner_perm();
    let fri_config = inner_fri_config();
    let hash = InnerHash::new(perm.clone());
    let compress = InnerCompress::new(perm.clone());
    let val_mmcs = InnerValMmcs::new(hash, compress);
    let dft = InnerDft {};
    let pcs_val: InnerPcs = InnerPcs::new(
        log_degrees.iter().copied().max().unwrap(),
        dft,
        val_mmcs,
        fri_config,
    );

    // Generate proof.
    let domains_and_polys = log_degrees
        .iter()
        .map(|&d| {
            (
                <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::natural_domain_for_degree(
                    &pcs_val,
                    1 << d,
                ),
                RowMajorMatrix::<InnerVal>::rand(&mut rng, 1 << d, num_cols),
            )
        })
        .sorted_by_key(|(dom, _)| Reverse(dom.log_n))
        .collect::<Vec<_>>();
    let (commit, data) = <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::commit(
        &pcs_val,
        domains_and_polys.clone(),
    );
    let mut challenger = InnerChallenger::new(perm.clone());
    challenger.observe(commit);
    let zeta = challenger.sample_ext_element::<InnerChallenge>();
    let points = domains_and_polys
        .iter()
        .map(|_| vec![zeta])
        .collect::<Vec<_>>();
    let (opening, proof) = pcs_val.open(vec![(&data, points)], &mut challenger);

    // Verify proof.
    let mut challenger = InnerChallenger::new(perm.clone());
    challenger.observe(commit);
    challenger.sample_ext_element::<InnerChallenge>();
    let os: Vec<(
        TwoAdicMultiplicativeCoset<InnerVal>,
        Vec<(InnerChallenge, Vec<InnerChallenge>)>,
    )> = domains_and_polys
        .iter()
        .zip(&opening[0])
        .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
        .collect();
    pcs_val
        .verify(vec![(commit, os.clone())], &proof, &mut challenger)
        .unwrap();

    // Test the recursive Pcs.
    let mut builder = Builder::<InnerConfig>::default();
    let config = const_fri_config(&mut builder, inner_fri_config());
    let pcs = TwoAdicFriPcsVariable { config };
    let rounds =
        builder.constant::<Array<_, TwoAdicPcsRoundVariable<_>>>(vec![(commit, os.clone())]);

    // Test natural domain for degree.
    for log_d_val in log_degrees.iter() {
        let log_d: Var<_> = builder.eval(InnerVal::from_canonical_usize(*log_d_val));
        let domain = pcs.natural_domain_for_log_degree(&mut builder, Usize::Var(log_d));

        let domain_val =
            <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::natural_domain_for_degree(
                &pcs_val,
                1 << log_d_val,
            );

        let expected_domain: TwoAdicMultiplicativeCosetVariable<_> = builder.constant(domain_val);

        builder.assert_eq::<TwoAdicMultiplicativeCosetVariable<_>>(domain, expected_domain);
    }

    // Test proof verification.
    let proofvar = InnerPcsProof::read(&mut builder);
    let mut challenger = DuplexChallengerVariable::new(&mut builder);
    let commit = <[InnerVal; DIGEST_SIZE]>::from(commit).to_vec();
    let commit = builder.constant::<Array<_, _>>(commit);
    challenger.observe(&mut builder, commit);
    challenger.sample_ext(&mut builder);
    pcs.verify(&mut builder, rounds, proofvar, &mut challenger);

    let program = builder.compile_program();
    let mut runtime = Runtime::<InnerVal, InnerChallenge, _>::new(&program, perm.clone());
    runtime.witness_stream.extend(proof.write());
    runtime.run();
    println!(
        "The program executed successfully, number of cycles: {}",
        runtime.clk.as_canonical_u32() / 4
    );
}

fn pcs_commit(columns: usize, log2_rows: usize) {
    let mut rng = &mut OsRng;
    let log_degrees = &[log2_rows];
    let perm = inner_perm();
    let fri_config = inner_fri_config();
    let hash = InnerHash::new(perm.clone());
    let compress = InnerCompress::new(perm.clone());
    let val_mmcs = InnerValMmcs::new(hash, compress);
    let dft = InnerDft {};
    let pcs_val: InnerPcs = InnerPcs::new(
        log_degrees.iter().copied().max().unwrap(),
        dft,
        val_mmcs,
        fri_config,
    );

    // Generate proof.
    let domains_and_polys = log_degrees
        .iter()
        .map(|&d| {
            (
                <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::natural_domain_for_degree(
                    &pcs_val,
                    1 << d,
                ),
                RowMajorMatrix::<InnerVal>::rand(&mut rng, 1 << d, columns),
            )
        })
        .sorted_by_key(|(dom, _)| Reverse(dom.log_n))
        .collect::<Vec<_>>();
    let (_, _) =
        <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::commit(&pcs_val, domains_and_polys);
}
