use crate::alu::divrem::DivRemChip;
use crate::alu::mul::MulChip;
use crate::bytes::ByteChip;
use crate::memory::MemoryGlobalChip;

use crate::alu::{AddChip, BitwiseChip, LeftShiftChip, LtChip, RightShiftChip, SubChip};
use crate::cpu::CpuChip;
use crate::memory::MemoryChipKind;
use crate::precompiles::sha256::{ShaCompressChip, ShaExtendChip};
use crate::program::ProgramChip;
use crate::prover::debug_constraints;
use crate::prover::debug_cumulative_sums;
use crate::prover::generate_permutation_trace;
use crate::prover::quotient_values;
use crate::runtime::Runtime;
use crate::runtime::Segment;
use crate::utils::AirChip;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, UnivariatePcs, UnivariatePcsWithLde};
use p3_field::{ExtensionField, PrimeField, PrimeField32, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::{Matrix, MatrixRowSlices};
use p3_maybe_rayon::*;
use p3_uni_stark::decompose_and_flatten;
use p3_uni_stark::StarkConfig;
use p3_util::log2_ceil_usize;
use p3_util::log2_strict_usize;

use super::types::*;

impl Runtime {
    /// Prove the program.
    #[allow(unused)]
    pub fn prove<F, EF, SC>(&mut self, config: &SC, challenger: &mut SC::Challenger)
    where
        F: PrimeField + TwoAdicField + PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkConfig<Val = F, Challenge = EF> + Send + Sync,
        SC::Challenger: Clone,
        <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::Commitment: Send + Sync,
        <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::ProverData: Send + Sync,
    {
        let segment_chips = Prover::segment_chips::<F, EF, SC>();
        let segment_main_data = self
            .segments
            .par_iter_mut()
            .map(|segment| Prover::commit_main(config, &segment_chips, segment))
            .collect::<Vec<_>>();

        // TODO: Observe the challenges in a tree-like structure for easily verifiable reconstruction
        // in a map-reduce recursion setting.
        segment_main_data.iter().map(|main_data| {
            challenger.observe(main_data.main_commit.clone());
        });

        // We clone the challenger so that each segment can observe the same "global" challenges.
        let proofs: Vec<SegmentDebugProof<SC>> = segment_main_data
            .iter()
            .map(|main_data| {
                Prover::prove(config, &mut challenger.clone(), &segment_chips, &main_data)
            })
            .collect();

        let global_chips = Prover::global_chips::<F, EF, SC>();
        let global_main_data = Prover::commit_main(config, &global_chips, &mut self.global_segment);
        let global_proof = Prover::prove(
            config,
            &mut challenger.clone(),
            &global_chips,
            &global_main_data,
        );

        let mut all_permutation_traces = proofs
            .iter()
            .flat_map(|proof| proof.permutation_traces.clone())
            .collect::<Vec<_>>();
        all_permutation_traces.extend(global_proof.permutation_traces.clone());

        // Compute the cumulative bus sum from all segments
        // Make sure that this cumulative bus sum is 0.
        debug_cumulative_sums::<F, EF>(&all_permutation_traces);
    }
}

struct Prover {}

const NUM_CHIPS: usize = 12;
impl Prover {
    pub fn segment_chips<F, EF, SC>() -> [Box<dyn AirChip<SC>>; NUM_CHIPS]
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
        let mul = MulChip::new();
        let _divrem = DivRemChip::new();
        let shift_right = RightShiftChip::new();
        let shift_left = LeftShiftChip::new();
        let lt = LtChip::new();
        let bytes = ByteChip::<F>::new();
        let sha_extend = ShaExtendChip::new();
        let sha_compress = ShaCompressChip::new();
        // This is where we create a vector of chips.
        [
            Box::new(program),
            Box::new(cpu),
            Box::new(add),
            Box::new(sub),
            Box::new(bitwise),
            Box::new(mul),
            // TODO: We need to add this here, but it doesn't work yet.
            // Box::new(divrem),
            Box::new(shift_right),
            Box::new(shift_left),
            Box::new(lt),
            Box::new(sha_extend),
            Box::new(sha_compress),
            Box::new(bytes),
        ]
    }

    pub fn global_chips<F, EF, SC>() -> [Box<dyn AirChip<SC>>; 3]
    where
        F: PrimeField + TwoAdicField + PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkConfig<Val = F, Challenge = EF>,
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

    pub fn commit_main<F, EF, SC>(
        config: &SC,
        chips: &[Box<dyn AirChip<SC>>],
        segment: &mut Segment,
    ) -> MainData<SC>
    where
        F: PrimeField + TwoAdicField + PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkConfig<Val = F, Challenge = EF>,
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
    pub fn prove<F, EF, SC>(
        config: &SC,
        challenger: &mut SC::Challenger,
        chips: &[Box<dyn AirChip<SC>>],
        main_data: &MainData<SC>,
    ) -> SegmentDebugProof<SC>
    where
        F: PrimeField + TwoAdicField + PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkConfig<Val = F, Challenge = EF> + Send + Sync,
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
        let mut permutation_challenges: Vec<EF> = Vec::new();
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
            assert_eq!(mat.width(), EF::D << log_quotient_degree);
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
            let width = perm.width() * EF::D;
            assert_eq!(opening.len(), 2);
            assert_eq!(opening[0].len(), width);
            assert_eq!(opening[1].len(), width);
        }
        // Check the shape of the quotient opennings.
        assert_eq!(openings[2].len(), num_quotient_chunks);
        for opening in openings[2].iter() {
            let width = EF::D << log_quotient_degree;
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

#[cfg(test)]
#[allow(non_snake_case)]
pub mod tests {

    use crate::runtime::tests::ecall_lwa_program;
    use crate::runtime::tests::fibonacci_program;
    use crate::runtime::tests::simple_memory_program;
    use crate::runtime::tests::simple_program;
    use crate::runtime::Instruction;
    use crate::runtime::Opcode;
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
        runtime.prove::<_, _, MyConfig>(&config, &mut challenger);
    }

    #[test]
    fn test_simple_prove() {
        let program = simple_program();
        prove(program);
    }

    #[test]
    fn test_ecall_lwa_prove() {
        let program = ecall_lwa_program();
        prove(program);
    }

    #[test]
    fn test_sll_prove() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
            Instruction::new(Opcode::SLL, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        prove(program);
    }

    #[test]
    fn test_sub_prove() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
            Instruction::new(Opcode::SUB, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        prove(program);
    }

    #[test]
    fn test_add_prove() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        let program = Program::new(instructions, 0, 0);
        prove(program);
    }

    #[test]
    fn test_mul_prove() {
        let mul_ops = [Opcode::MUL, Opcode::MULH, Opcode::MULHU, Opcode::MULHSU];
        for mul_op in mul_ops.iter() {
            let instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
                Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
                Instruction::new(*mul_op, 31, 30, 29, false, false),
            ];
            let program = Program::new(instructions, 0, 0);
            prove(program);
        }
    }

    #[test]
    fn test_fibonacci_prove() {
        if env_logger::try_init().is_err() {
            debug!("Logger already initialized")
        }
        let program = fibonacci_program();
        prove(program);
    }

    #[test]
    fn test_simple_memory_program_prove() {
        let program = simple_memory_program();
        prove(program);
    }
}
