use crate::bytes::ByteChip;
use crate::cpu::trace::CpuChip;
use crate::memory::MemoryGlobalChip;

use crate::alu::{AddChip, BitwiseChip, LeftShiftChip, LtChip, RightShiftChip, SubChip};
use crate::memory::MemoryChipKind;
use crate::program::ProgramChip;
use crate::prover::debug_constraints;
use crate::prover::generate_permutation_trace;
use crate::prover::quotient_values;
use crate::runtime::Runtime;
use crate::runtime::Segment;
use crate::utils::AirChip;
use crate::utils::Chip;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, UnivariatePcs, UnivariatePcsWithLde};
use p3_field::{ExtensionField, PrimeField, PrimeField32, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::decompose_and_flatten;
use p3_uni_stark::StarkConfig;
use p3_util::log2_ceil_usize;
use p3_util::log2_strict_usize;

use crate::prover::debug_cumulative_sums;

type Val<SC> = <SC as StarkConfig>::Val;
type Challenge<SC> = <SC as StarkConfig>::Challenge;
type ValMat<SC> = RowMajorMatrix<Val<SC>>;
type ChallengeMat<SC> = RowMajorMatrix<Challenge<SC>>;
type Com<SC> = <<SC as StarkConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Commitment;
type PcsProverData<SC> = <<SC as StarkConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::ProverData;

pub struct SegmentDebugProof<SC: StarkConfig> {
    pub main_commit: Com<SC>,
    pub traces: Vec<ValMat<SC>>,
    pub permutation_traces: Vec<ChallengeMat<SC>>,
}

impl Runtime {
    /// Prove the program.
    #[allow(unused)]
    pub fn prove<F, EF, SC>(&mut self, config: &SC, challenger: &mut SC::Challenger)
    where
        F: PrimeField + TwoAdicField + PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkConfig<Val = F, Challenge = EF>,
        SC::Challenger: Clone,
    {
        let segment_main_data = self
            .segments
            .iter_mut()
            .map(|segment| segment.commit_main(config))
            .collect::<Vec<_>>();

        // TODO: Observe the challenges in a tree-like structure for easily verifiable reconstruction
        // in a map-reduce recursion setting.
        segment_main_data.iter().map(|main_data| {
            challenger.observe(main_data.main_commit.clone());
        });

        // We clone the challenger so that each segment can observe the same "global" challenges.
        let proofs: Vec<SegmentDebugProof<SC>> = segment_main_data
            .iter()
            .map(|main_data| Segment::prove(config, &mut challenger.clone(), &main_data))
            .collect();

        // TODO: clean up this duplicated code.
        let program_memory_init = MemoryGlobalChip::new(MemoryChipKind::Program);
        let init_chip = MemoryGlobalChip::new(MemoryChipKind::Init);
        let finalize_chip = MemoryGlobalChip::new(MemoryChipKind::Finalize);

        let traces = [
            program_memory_init.generate_trace(&mut self.global_segment),
            init_chip.generate_trace(&mut self.global_segment),
            finalize_chip.generate_trace(&mut self.global_segment),
        ]
        .to_vec();

        let (main_commit, main_data) = config.pcs().commit_batches(traces.clone());
        let global_data = MainData {
            traces,
            main_commit,
            main_data,
        };
        let global_proof = Segment::prove(config, &mut challenger.clone(), &global_data);

        let mut all_permutation_traces = proofs
            .iter()
            .flat_map(|proof| proof.permutation_traces.clone())
            .collect::<Vec<_>>();
        all_permutation_traces.extend(global_proof.permutation_traces.clone());
        // TODO: from the global_proof, make sure that the cumulative sum is 0.
        // Compute the cumulative bus sum from all segments
        // Make sure that this cumulative bus sum is 0.
        debug_cumulative_sums::<F, EF>(&all_permutation_traces);
    }

    // pub fn verify(self, config: &SC, challenger: &mut SC::Challenger, proof: Proof) {
    //     // Take in a bunch of segment proofs
    //     // Then verify eachv segment proof independently.
    //     // Then add up the buses and make sure that the cumulative sum is 0.
    //     // Check that the segment proof has program_committment = fixed_program_committment
    //     let global_challenger = &mut SC::Challenger::new();
    //     global_challenger.observe(segment_commit);
    // }
}

pub struct MainData<SC: StarkConfig> {
    traces: Vec<ValMat<SC>>,
    main_commit: Com<SC>,
    main_data: PcsProverData<SC>,
}

impl Segment {
    const NUM_CHIPS: usize = 9;

    pub fn chips<F, EF, SC>() -> [Box<dyn AirChip<SC>>; Self::NUM_CHIPS]
    where
        F: PrimeField + TwoAdicField + PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkConfig<Val = F, Challenge = EF>,
    {
        // Initialize chips.
        let program = ProgramChip::new();
        let cpu = CpuChip::new();
        let add = AddChip::new();
        let sub = SubChip::new();
        let bitwise = BitwiseChip::new();
        let right_shift = RightShiftChip::new();
        let left_shift = LeftShiftChip::new();
        let lt = LtChip::new();
        let bytes = ByteChip::<F>::new();
        // let memory_init = MemoryInitChip::new(true);
        // let memory_finalize = MemoryInitChip::new(false);
        [
            Box::new(program),
            Box::new(cpu),
            Box::new(add),
            Box::new(sub),
            Box::new(bitwise),
            Box::new(right_shift),
            Box::new(left_shift),
            Box::new(lt),
            Box::new(bytes),
            // Box::new(memory_init),
            // Box::new(memory_finalize),
        ]
    }

    pub fn commit_main<F, EF, SC>(&mut self, config: &SC) -> MainData<SC>
    where
        F: PrimeField + TwoAdicField + PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkConfig<Val = F, Challenge = EF>,
    {
        let chips = Segment::chips::<F, EF, SC>();

        // For each chip, generate the trace.
        let traces = chips
            .iter()
            .map(|chip| chip.generate_trace(self))
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
    pub fn prove<F, EF, SC>(
        config: &SC,
        challenger: &mut SC::Challenger,
        main_data: &MainData<SC>,
    ) -> SegmentDebugProof<SC>
    where
        F: PrimeField + TwoAdicField + PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkConfig<Val = F, Challenge = EF>,
    {
        let chips = Segment::chips::<F, EF, SC>();

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
        let degrees: [usize; Self::NUM_CHIPS] = traces
            .iter()
            .map(|trace| trace.height())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let log_degrees = degrees.map(|d| log2_strict_usize(d));
        let max_constraint_degree = 3;
        let log_quotient_degree = log2_ceil_usize(max_constraint_degree - 1);
        let g_subgroups = log_degrees.map(|log_deg| SC::Val::two_adic_generator(log_deg));

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
        let main_ldes = config.pcs().get_ldes(&main_data.main_data);
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
            (&main_data.main_data, zeta_and_next.as_slice()),
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
        // debug_cumulative_sums::<F, EF>(&permutation_traces[..]);

        SegmentDebugProof {
            main_commit: main_data.main_commit.clone(),
            traces: traces.clone(),
            permutation_traces,
        }
    }

    /// Prove the program for the given segment, including committing to the main trace and proving.
    #[allow(unused)]
    pub fn full_prove<F, EF, SC>(
        &mut self,
        config: &SC,
        challenger: &mut SC::Challenger,
        main_data: &MainData<SC>,
    ) -> SegmentDebugProof<SC>
    where
        F: PrimeField + TwoAdicField + PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkConfig<Val = F, Challenge = EF>,
    {
        let main_data = self.commit_main(config);
        challenger.observe(main_data.main_commit.clone());
        Self::prove(config, challenger, &main_data)
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
pub mod tests {

    use crate::runtime::tests::fibonacci_program;
    use crate::runtime::tests::simple_program;
    use crate::runtime::Program;
    use crate::runtime::Runtime;
    use log::debug;
    use p3_baby_bear::BabyBear;
    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::Field;
    use p3_fri::FriBasedPcs;
    use p3_fri::FriConfigImpl;
    use p3_fri::FriLdt;
    use p3_keccak::Keccak256Hash;
    use p3_ldt::QuotientMmcs;
    use p3_mds::coset_mds::CosetMds;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::DiffusionMatrixBabybear;
    use p3_poseidon2::Poseidon2;
    use p3_symmetric::CompressionFunctionFromHasher;
    use p3_symmetric::SerializingHasher32;
    use p3_uni_stark::StarkConfigImpl;
    use rand::thread_rng;

    pub fn prove(program: Program) {
        type Val = BabyBear;
        type Domain = Val;
        type Challenge = BinomialExtensionField<Val, 4>;
        type PackedChallenge = BinomialExtensionField<<Domain as Field>::Packing, 4>;

        type MyMds = CosetMds<Val, 16>;
        let mds = MyMds::default();

        type Perm = Poseidon2<Val, MyMds, DiffusionMatrixBabybear, 16, 5>;
        let perm = Perm::new_from_rng(8, 22, mds, DiffusionMatrixBabybear, &mut thread_rng());

        type MyHash = SerializingHasher32<Keccak256Hash>;
        let hash = MyHash::new(Keccak256Hash {});

        type MyCompress = CompressionFunctionFromHasher<Val, MyHash, 2, 8>;
        let compress = MyCompress::new(hash);

        type ValMmcs = FieldMerkleTreeMmcs<Val, MyHash, MyCompress, 8>;
        let val_mmcs = ValMmcs::new(hash, compress);

        type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        type Dft = Radix2DitParallel;
        let dft = Dft {};

        type Challenger = DuplexChallenger<Val, Perm, 16>;

        type Quotient = QuotientMmcs<Domain, Challenge, ValMmcs>;
        type MyFriConfig = FriConfigImpl<Val, Challenge, Quotient, ChallengeMmcs, Challenger>;
        let fri_config = MyFriConfig::new(40, challenge_mmcs);
        let ldt = FriLdt { config: fri_config };

        type Pcs = FriBasedPcs<MyFriConfig, ValMmcs, Dft, Challenger>;
        type MyConfig = StarkConfigImpl<Val, Challenge, PackedChallenge, Pcs, Challenger>;

        let pcs = Pcs::new(dft, val_mmcs, ldt);
        let config = StarkConfigImpl::new(pcs);
        let mut challenger = Challenger::new(perm.clone());

        let mut runtime = Runtime::new(program);
        runtime.write_witness(&[1, 2]);
        runtime.run();
        runtime
            .segment
            .prove::<_, _, MyConfig>(&config, &mut challenger);
    }

    #[test]
    fn test_simple_prove() {
        let program = simple_program();
        prove(program);
    }

    #[test]
    fn test_fibonnaci_prove() {
        if env_logger::try_init().is_err() {
            debug!("Logger already initialized")
        }
        let program = fibonacci_program();
        prove(program);
    }
}
