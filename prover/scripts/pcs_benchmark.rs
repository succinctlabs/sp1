use std::cmp::Reverse;

use clap::Parser;
use itertools::Itertools;
use p3_challenger::CanObserve;
use p3_challenger::FieldChallenger;
use p3_commit::Pcs;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_matrix::dense::RowMajorMatrix;
use rand::rngs::OsRng;
use sp1_core::utils::{
    inner_fri_config, inner_perm, InnerChallenge, InnerChallenger, InnerCompress, InnerDft,
    InnerHash, InnerPcs, InnerVal, InnerValMmcs,
};

#[derive(Parser)]
#[command(name = "PcsBenchmark")]
#[command(version = "1.0")]
struct Cli {
    #[arg(long)]
    columns: usize,
    #[arg(long)]
    log2_rows: usize,
    #[arg(long)]
    num_runs: usize,
}

fn main() {
    let cli = Cli::parse();
    let num_cols = cli.columns;
    let log2_rows = cli.log2_rows;

    let mut rng = &mut OsRng;
    let log_degrees = &[log2_rows];
    let perm = inner_perm();
    let fri_config = inner_fri_config();
    let hash = InnerHash::new(perm.clone());
    let compress = InnerCompress::new(perm.clone());
    let val_mmcs = InnerValMmcs::new(hash, compress);
    let dft = InnerDft {};
    let pcs: InnerPcs = InnerPcs::new(
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
                    &pcs,
                    1 << d,
                ),
                RowMajorMatrix::<InnerVal>::rand(&mut rng, 1 << d, num_cols),
            )
        })
        .sorted_by_key(|(dom, _)| Reverse(dom.log_n))
        .collect::<Vec<_>>();
    let (mut commit, mut data) =
        <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::commit(&pcs, domains_and_polys.clone());

    let start = std::time::Instant::now();
    for _ in 0..cli.num_runs {
        (commit, data) = <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::commit(
            &pcs,
            domains_and_polys.clone(),
        );
    }
    let elapsed = start.elapsed().as_secs_f64() / cli.num_runs as f64;
    println!(
        "took average {:.2} seconds for {} runs.",
        elapsed, cli.num_runs
    );

    let mut challenger = InnerChallenger::new(perm.clone());
    challenger.observe(commit);
    let zeta = challenger.sample_ext_element::<InnerChallenge>();
    let points = domains_and_polys
        .iter()
        .map(|_| vec![zeta])
        .collect::<Vec<_>>();
    let (opening, proof) = pcs.open(vec![(&data, points)], &mut challenger);

    // Verify proof.
    let mut challenger = InnerChallenger::new(perm.clone());
    challenger.observe(commit);
    challenger.sample_ext_element::<InnerChallenge>();
    type U = Vec<(InnerChallenge, Vec<InnerChallenge>)>;
    type T = TwoAdicMultiplicativeCoset<InnerVal>;
    let os: Vec<(T, U)> = domains_and_polys
        .iter()
        .zip(&opening[0])
        .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
        .collect();
    pcs.verify(vec![(commit, os.clone())], &proof, &mut challenger)
        .unwrap();
}
