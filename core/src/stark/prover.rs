use std::marker::PhantomData;

use crate::alu::divrem::DivRemChip;
use crate::alu::mul::MulChip;
use crate::bytes::ByteChip;
use crate::memory::MemoryGlobalChip;
use crate::stark::debug_constraints;

use crate::alu::{AddChip, BitwiseChip, LtChip, ShiftLeft, ShiftRightChip, SubChip};
use crate::cpu::CpuChip;
use crate::memory::MemoryChipKind;
use crate::precompiles::sha256::{ShaCompressChip, ShaExtendChip};
use crate::program::ProgramChip;
use crate::runtime::Segment;
use crate::stark::permutation::generate_permutation_trace;
use crate::stark::quotient_values;
use crate::utils::AirChip;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, UnivariatePcs, UnivariatePcsWithLde};
use p3_field::{AbstractExtensionField, AbstractField};
use p3_field::{PrimeField32, TwoAdicField};
use p3_matrix::{Matrix, MatrixRowSlices};
use p3_maybe_rayon::*;
use p3_uni_stark::decompose_and_flatten;
use p3_uni_stark::StarkConfig;
use p3_util::log2_ceil_usize;
use p3_util::log2_strict_usize;

use super::types::*;

pub const NUM_CHIPS: usize = 13;

pub(crate) struct Prover<SC>(PhantomData<SC>);

impl<SC: StarkConfig> Prover<SC> {
    pub fn segment_chips() -> [Box<dyn AirChip<SC>>; NUM_CHIPS]
    where
        SC::Val: PrimeField32,
    {
        // Initialize chips.
        let program = ProgramChip::new();
        let cpu = CpuChip::new();
        let add = AddChip::new();
        let sub = SubChip::new();
        let bitwise = BitwiseChip::new();
        let mul = MulChip::new();
        let divrem = DivRemChip::new();
        let shift_right = ShiftRightChip::new();
        let shift_left = ShiftLeft::new();
        let lt = LtChip::new();
        let bytes = ByteChip::<SC::Val>::new();
        let sha_extend = ShaExtendChip::new();
        let sha_compress = ShaCompressChip::new();
        // This vector contains chips ordered to address dependencies. Some operations, like div,
        // depend on others like mul for verification. To prevent race conditions and ensure correct
        // execution sequences, dependent operations are positioned before their dependencies.
        [
            Box::new(program),
            Box::new(cpu),
            Box::new(add),
            Box::new(sub),
            Box::new(bitwise),
            Box::new(divrem),
            Box::new(mul),
            Box::new(shift_right),
            Box::new(shift_left),
            Box::new(lt),
            Box::new(sha_extend),
            Box::new(sha_compress),
            Box::new(bytes),
        ]
    }

    pub fn global_chips() -> [Box<dyn AirChip<SC>>; 3]
    where
        SC::Val: PrimeField32,
    {
        // Initialize chips.
        let memory_init = MemoryGlobalChip::new(MemoryChipKind::Init);
        let memory_finalize = MemoryGlobalChip::new(MemoryChipKind::Finalize);
        let program_memory_init = MemoryGlobalChip::new(MemoryChipKind::Program);
        [
            Box::new(memory_init),
            Box::new(memory_finalize),
            Box::new(program_memory_init),
        ]
    }

    pub fn commit_main(
        config: &SC,
        chips: &[Box<dyn AirChip<SC>>],
        segment: &mut Segment,
    ) -> MainData<SC>
    where
        SC::Val: PrimeField32,
    {
        // For each chip, generate the trace.
        let traces = chips
            .iter()
            .map(|chip| chip.generate_trace(segment))
            .collect::<Vec<_>>();

        // Commit to the batch of traces.
        let (main_commit, main_data) = config.pcs().commit_batches(traces.to_vec());

        MainData {
            traces,
            main_commit,
            main_data,
        }
    }

    /// Prove the program for the given segment and given a commitment to the main data.
    #[allow(unused)]
    pub fn prove(
        config: &SC,
        challenger: &mut SC::Challenger,
        chips: &[Box<dyn AirChip<SC>>],
        main_data: &MainData<SC>,
    ) -> SegmentDebugProof<SC>
    where
        SC::Val: PrimeField32,
        SC: Send + Sync,
    {
        // Compute some statistics.
        let mut main_cols = 0usize;
        let mut perm_cols = 0usize;
        for chip in chips.iter() {
            main_cols += chip.air_width();
            perm_cols += (chip.all_interactions().len() + 1) * 5;
        }
        println!("MAIN_COLS: {}", main_cols);
        println!("PERM_COLS: {}", perm_cols);

        let traces = &main_data.traces;

        // For each trace, compute the degree.
        let degrees = traces
            .iter()
            .map(|trace| trace.height())
            .collect::<Vec<_>>();
        let log_degrees = degrees
            .iter()
            .map(|d| log2_strict_usize(*d))
            .collect::<Vec<_>>();
        let max_constraint_degree = 3;
        let log_quotient_degree = log2_ceil_usize(max_constraint_degree - 1);
        let g_subgroups = log_degrees
            .iter()
            .map(|log_deg| SC::Val::two_adic_generator(*log_deg))
            .collect::<Vec<_>>();

        // Obtain the challenges used for the permutation argument.
        let mut permutation_challenges: Vec<SC::Challenge> = Vec::new();
        for _ in 0..2 {
            permutation_challenges.push(challenger.sample_ext_element());
        }

        // Generate the permutation traces.
        let permutation_traces = chips
            .par_iter()
            .enumerate()
            .map(|(i, chip)| {
                generate_permutation_trace(
                    chip.as_ref(),
                    &traces[i],
                    permutation_challenges.clone(),
                )
            })
            .collect::<Vec<_>>();

        // Get the commulutative sums of the permutation traces.
        let commulative_sums = permutation_traces
            .par_iter()
            .map(|trace| trace.row_slice(trace.height() - 1).last().copied().unwrap())
            .collect::<Vec<_>>();

        // Commit to the permutation traces.
        let flattened_permutation_traces = permutation_traces
            .par_iter()
            .map(|trace| trace.flatten_to_base())
            .collect::<Vec<_>>();
        let (permutation_commit, permutation_data) =
            config.pcs().commit_batches(flattened_permutation_traces);
        challenger.observe(permutation_commit.clone());

        // For each chip, compute the quotient polynomial.
        let main_ldes = config.pcs().get_ldes(&main_data.main_data);
        let permutation_ldes = config.pcs().get_ldes(&permutation_data);
        let alpha: SC::Challenge = challenger.sample_ext_element::<SC::Challenge>();

        // Compute the quotient values.
        let quotient_values = (0..chips.len()).into_par_iter().map(|i| {
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

        // Check the shapes of the quotient chunks.
        for (i, mat) in quotient_chunks.iter().enumerate() {
            assert_eq!(mat.width(), SC::Challenge::D << log_quotient_degree);
            assert_eq!(mat.height(), traces[i].height());
        }

        let num_quotient_chunks = quotient_chunks.len();
        let coset_shift = config
            .pcs()
            .coset_shift()
            .exp_power_of_2(log_quotient_degree);
        let (quotient_commit, quotient_data) = config
            .pcs()
            .commit_shifted_batches(quotient_chunks, coset_shift);

        // Observe the quotient commitments.
        challenger.observe(quotient_commit.clone());

        // Compute the quotient argument.
        let zeta: SC::Challenge = challenger.sample_ext_element();
        let g_subgroup = g_subgroups[0];

        let trace_openning_points = g_subgroups
            .iter()
            .map(|g| vec![zeta, zeta * *g])
            .collect::<Vec<_>>();

        let zeta_quot_pow = zeta.exp_power_of_2(log_quotient_degree);
        let quotient_openning_points = (0..num_quotient_chunks)
            .map(|_| vec![zeta_quot_pow])
            .collect::<Vec<_>>();

        let (openings, openning_proof) = config.pcs().open_multi_batches(
            &[
                (&main_data.main_data, &trace_openning_points),
                (&permutation_data, &trace_openning_points),
                (&quotient_data, &quotient_openning_points),
            ],
            challenger,
        );

        // Checking the shapes of opennings match our expectations.
        //
        // This is a sanity check to make sure we are using the API correctly. We should remove this
        // once everything is stable.

        // Check for the correct number of openning collections.
        assert_eq!(openings.len(), 3);

        // Check the shape of the main trace opennings.
        assert_eq!(openings[0].len(), chips.len());
        for (chip, opening) in chips.iter().zip(openings[0].iter()) {
            let width = chip.air_width();
            assert_eq!(opening.len(), 2);
            assert_eq!(opening[0].len(), width);
            assert_eq!(opening[1].len(), width);
        }
        // Check the shape of the permutation trace opennings.
        assert_eq!(openings[1].len(), chips.len());
        for (perm, opening) in permutation_traces.iter().zip(openings[1].iter()) {
            let width = perm.width() * SC::Challenge::D;
            assert_eq!(opening.len(), 2);
            assert_eq!(opening[0].len(), width);
            assert_eq!(opening[1].len(), width);
        }
        // Check the shape of the quotient opennings.
        assert_eq!(openings[2].len(), num_quotient_chunks);
        for opening in openings[2].iter() {
            let width = SC::Challenge::D << log_quotient_degree;
            assert_eq!(opening.len(), 1);
            assert_eq!(opening[0].len(), width);
        }

        // Collect the opened values for each chip.
        let [main_values, permutation_values, quotient_values] = openings.try_into().unwrap();

        let main_opened_values = main_values
            .into_iter()
            .map(|op| {
                let [local, next] = op.try_into().unwrap();
                AirOpenedValues { local, next }
            })
            .collect::<Vec<_>>();
        let permutation_opened_values = permutation_values
            .into_iter()
            .map(|op| {
                let [local, next] = op.try_into().unwrap();
                AirOpenedValues { local, next }
            })
            .collect::<Vec<_>>();
        let quotient_opened_values = quotient_values
            .into_iter()
            .map(|mut op| op.pop().unwrap())
            .collect::<Vec<_>>();

        let opened_values = SegmentOpenedValues {
            main: main_opened_values,
            permutation: permutation_opened_values,
            quotient: quotient_opened_values,
        };

        let proof = SegmentProof::<SC> {
            commitment: SegmentCommitment {
                main_commit: main_data.main_commit.clone(),
                permutation_commit,
                quotient_commit,
            },
            opened_values,
            commulative_sums,
            openning_proof,
            degree_bits: log_degrees,
        };

        // Check that the table-specific constraints are correct for each chip.
        for i in 0..chips.len() {
            debug_constraints(
                &*chips[i],
                &traces[i],
                &permutation_traces[i],
                &permutation_challenges,
            );
        }

        SegmentDebugProof {
            main_commit: main_data.main_commit.clone(),
            traces: traces.clone(),
            permutation_traces,
        }
    }
}
