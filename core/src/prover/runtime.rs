use crate::cpu::trace::CpuChip;
use crate::runtime::Runtime;

use crate::program::ProgramChip;
use crate::prover::generate_permutation_trace;
use crate::prover::{debug_cumulative_sums, quotient_values};
use crate::utils::AirChip;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, UnivariatePcs, UnivariatePcsWithLde};
use p3_uni_stark::decompose_and_flatten;
use p3_util::log2_ceil_usize;

use crate::alu::{AddChip, BitwiseChip, LtChip, ShiftChip, SubChip};
use crate::memory::MemoryChip;
use crate::prover::debug_constraints;
use p3_field::{ExtensionField, PrimeField, PrimeField32, TwoAdicField};
use p3_matrix::Matrix;
use p3_uni_stark::StarkConfig;
use p3_util::log2_strict_usize;

impl Runtime {
    /// Prove the program.
    #[allow(unused)]
    pub fn prove<F, EF, SC>(&mut self, config: &SC, challenger: &mut SC::Challenger)
    where
        F: PrimeField + TwoAdicField + PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkConfig<Val = F, Challenge = EF>,
    {
        // Initialize chips.
        let program = ProgramChip::new();
        let cpu = CpuChip::new();
        let memory = MemoryChip::new();
        let add = AddChip::new();
        let sub = SubChip::new();
        let bitwise = BitwiseChip::new();
        let shift = ShiftChip::new();
        let lt = LtChip::new();
        let chips: [Box<dyn AirChip<SC>>; 8] = [
            Box::new(program),
            Box::new(cpu),
            Box::new(memory),
            Box::new(add),
            Box::new(sub),
            Box::new(bitwise),
            Box::new(shift),
            Box::new(lt),
        ];

        // Compute some statistics.
        let mut main_cols = 0usize;
        let mut perm_cols = 0usize;
        for chip in chips.iter() {
            main_cols += chip.air_width();
            perm_cols += (chip.all_interactions().len() + 1) * 5;
        }
        println!("MAIN_COLS: {}", main_cols);
        println!("PERM_COLS: {}", perm_cols);

        // For each chip, generate the trace.
        let traces = chips
            .iter()
            .map(|chip| chip.generate_trace(self))
            .collect::<Vec<_>>();
        // NOTE(Uma): to debug the CPU & Memory interactions, you can use something like this: https://gist.github.com/puma314/1318b2805acce922604e1457e0211c8f

        // For each trace, compute the degree.
        let degrees: [usize; 8] = traces
            .iter()
            .map(|trace| trace.height())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let log_degrees = degrees.map(|d| log2_strict_usize(d));
        let max_constraint_degree = 3;
        let log_quotient_degree = log2_ceil_usize(max_constraint_degree - 1);
        let g_subgroups = log_degrees.map(|log_deg| SC::Val::two_adic_generator(log_deg));

        // Commit to the batch of traces.
        let (main_commit, main_data) = config.pcs().commit_batches(traces.to_vec());
        challenger.observe(main_commit);

        // Obtain the challenges used for the permutation argument.
        let mut permutation_challenges: Vec<EF> = Vec::new();
        for _ in 0..2 {
            permutation_challenges.push(challenger.sample_ext_element());
        }

        // Generate the permutation traces.
        let permutation_traces = chips
            .iter()
            .enumerate()
            .map(|(i, chip)| {
                generate_permutation_trace(
                    chip.as_ref(),
                    &traces[i],
                    permutation_challenges.clone(),
                )
            })
            .collect::<Vec<_>>();

        // Commit to the permutation traces.
        let flattened_permutation_traces = permutation_traces
            .iter()
            .map(|trace| trace.flatten_to_base())
            .collect::<Vec<_>>();
        let (permutation_commit, permutation_data) =
            config.pcs().commit_batches(flattened_permutation_traces);
        challenger.observe(permutation_commit);

        // For each chip, compute the quotient polynomial.
        let main_ldes = config.pcs().get_ldes(&main_data);
        let permutation_ldes = config.pcs().get_ldes(&permutation_data);
        let alpha: SC::Challenge = challenger.sample_ext_element::<SC::Challenge>();

        // Compute the quotient values.
        let quotient_values = (0..chips.len()).map(|i| {
            quotient_values(
                config,
                &*chips[i],
                log_degrees[i],
                log_quotient_degree,
                &main_ldes[i],
                alpha,
            )
        });

        // Compute the quotient chunks.
        let quotient_chunks = quotient_values
            .map(|values| {
                decompose_and_flatten::<SC>(
                    values,
                    SC::Challenge::from_base(config.pcs().coset_shift()),
                    log_quotient_degree,
                )
            })
            .collect::<Vec<_>>();

        // Commit to the quotient chunks.
        let (quotient_commit, quotient_commit_data): (Vec<_>, Vec<_>) = (0..chips.len())
            .map(|i| {
                config.pcs().commit_shifted_batch(
                    quotient_chunks[i].clone(),
                    config
                        .pcs()
                        .coset_shift()
                        .exp_power_of_2(log_quotient_degree),
                )
            })
            .into_iter()
            .unzip();

        // Observe the quotient commitments.
        for commit in quotient_commit {
            challenger.observe(commit);
        }

        // Compute the quotient argument.
        let zeta: SC::Challenge = challenger.sample_ext_element();
        let zeta_and_next = [zeta, zeta * g_subgroups[0]];
        let prover_data_and_points = [
            (&main_data, zeta_and_next.as_slice()),
            (&permutation_data, zeta_and_next.as_slice()),
        ];
        let (openings, opening_proof) = config
            .pcs()
            .open_multi_batches(&prover_data_and_points, challenger);
        let (openings, opening_proofs): (Vec<_>, Vec<_>) = (0..chips.len())
            .map(|i| {
                let prover_data_and_points = [(&quotient_commit_data[i], zeta_and_next.as_slice())];
                config
                    .pcs()
                    .open_multi_batches(&prover_data_and_points, challenger)
            })
            .into_iter()
            .unzip();

        // Check that the table-specific constraints are correct for each chip.
        for i in 0..chips.len() {
            debug_constraints(
                &*chips[i],
                &traces[i],
                &permutation_traces[i],
                &permutation_challenges,
            );
        }

        // Check the permutation argument between all tables.
        debug_cumulative_sums::<F, EF>(&permutation_traces[..]);
    }
}
