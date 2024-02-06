use crate::air::CurtaAirBuilder;
use crate::alu::divrem::DivRemChip;
use crate::alu::mul::MulChip;
use crate::bytes::ByteChip;
use crate::field::FieldLTUChip;
use crate::lookup::Interaction;
use crate::memory::MemoryGlobalChip;

use crate::alu::{AddChip, BitwiseChip, LtChip, ShiftLeftChip, ShiftRightChip, SubChip};
use crate::cpu::CpuChip;
use crate::memory::MemoryChipKind;
use crate::precompiles::edwards::ed_add::EdAddAssignChip;
use crate::precompiles::edwards::ed_decompress::EdDecompressChip;
use crate::precompiles::k256::decompress::K256DecompressChip;
use crate::precompiles::keccak256::KeccakPermuteChip;
use crate::precompiles::sha256::{ShaCompressChip, ShaExtendChip};
use crate::precompiles::weierstrass::weierstrass_add::WeierstrassAddAssignChip;
use crate::precompiles::weierstrass::weierstrass_double::WeierstrassDoubleAssignChip;
use crate::program::ProgramChip;
use crate::runtime::{Runtime, Segment};
use crate::stark::Verifier;
use crate::utils::ec::edwards::ed25519::Ed25519Parameters;
use crate::utils::ec::edwards::EdwardsCurve;
use crate::utils::ec::weierstrass::secp256k1::Secp256k1Parameters;
use crate::utils::ec::weierstrass::SWCurve;
use crate::utils::Chip;
use p3_air::{Air, BaseAir};
use p3_challenger::CanObserve;
use p3_maybe_rayon::prelude::IndexedParallelIterator;
use p3_maybe_rayon::prelude::IntoParallelIterator;
use p3_maybe_rayon::prelude::ParallelIterator;
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::OpeningProof;

#[cfg(not(feature = "perf"))]
use crate::stark::debug_cumulative_sums;

use p3_commit::Pcs;
use p3_field::{ExtensionField, Field, PrimeField, PrimeField32, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;

use super::prover::Prover;
use super::types::{MainData, SegmentProof};
use super::{StarkConfig, VerificationError};

// pub const NUM_CHIPS: usize = 20;
pub const NUM_CHIPS: usize = 12;

enum ChipType<F: Field> {
    Program(ProgramChip),
    Cpu(CpuChip),
    Add(AddChip),
    Sub(SubChip),
    Bitwise(BitwiseChip),
    Mul(MulChip),
    DivRem(DivRemChip),
    ShiftRight(ShiftRightChip),
    ShiftLeft(ShiftLeftChip),
    Lt(LtChip),
    Bytes(ByteChip<F>),
    Field(FieldLTUChip),
    ShaExtend(ShaExtendChip),
    ShaCompress(ShaCompressChip),
    EdAdd(EdAddAssignChip<EdwardsCurve<Ed25519Parameters>, Ed25519Parameters>),
    EdDecompress(EdDecompressChip<Ed25519Parameters>),
    KeccakPermute(KeccakPermuteChip),
    WeierstrassAdd(WeierstrassAddAssignChip<SWCurve<Secp256k1Parameters>, Secp256k1Parameters>),
    WeierstrassDouble(
        WeierstrassDoubleAssignChip<SWCurve<Secp256k1Parameters>, Secp256k1Parameters>,
    ),
    K256Decompress(K256DecompressChip),
    MemoryInit(MemoryGlobalChip),
    MemoryFinalize(MemoryGlobalChip),
    MemoryProgram(MemoryGlobalChip),
}

pub struct ChipInfo<F: Field> {
    chip: ChipType<F>,
}

impl<F: PrimeField32> ChipInfo<F> {
    pub fn all_interactions(&self) -> Vec<Interaction<F>>
    where
        F: PrimeField32,
    {
        match &self.chip {
            ChipType::Program(chip) => chip.all_interactions(),
            ChipType::Cpu(chip) => chip.all_interactions(),
            ChipType::Add(chip) => chip.all_interactions(),
            ChipType::Sub(chip) => chip.all_interactions(),
            ChipType::Bitwise(chip) => chip.all_interactions(),
            ChipType::Mul(chip) => chip.all_interactions(),
            ChipType::DivRem(chip) => chip.all_interactions(),
            ChipType::ShiftRight(chip) => chip.all_interactions(),
            ChipType::ShiftLeft(chip) => chip.all_interactions(),
            ChipType::Lt(chip) => chip.all_interactions(),
            ChipType::Bytes(chip) => chip.all_interactions(),
            ChipType::Field(chip) => chip.all_interactions(),
            ChipType::ShaExtend(chip) => chip.all_interactions(),
            ChipType::ShaCompress(chip) => chip.all_interactions(),
            ChipType::EdAdd(chip) => chip.all_interactions(),
            ChipType::EdDecompress(chip) => chip.all_interactions(),
            ChipType::KeccakPermute(chip) => chip.all_interactions(),
            ChipType::WeierstrassAdd(chip) => chip.all_interactions(),
            ChipType::WeierstrassDouble(chip) => chip.all_interactions(),
            ChipType::K256Decompress(chip) => chip.all_interactions(),
            ChipType::MemoryInit(chip) => chip.all_interactions(),
            ChipType::MemoryFinalize(chip) => chip.all_interactions(),
            ChipType::MemoryProgram(chip) => chip.all_interactions(),
        }
    }

    pub fn sends(&self) -> Vec<Interaction<F>>
    where
        F: PrimeField32,
    {
        match &self.chip {
            ChipType::Program(chip) => chip.sends(),
            ChipType::Cpu(chip) => chip.sends(),
            ChipType::Add(chip) => chip.sends(),
            ChipType::Sub(chip) => chip.sends(),
            ChipType::Bitwise(chip) => chip.sends(),
            ChipType::Mul(chip) => chip.sends(),
            ChipType::DivRem(chip) => chip.sends(),
            ChipType::ShiftRight(chip) => chip.sends(),
            ChipType::ShiftLeft(chip) => chip.sends(),
            ChipType::Lt(chip) => chip.sends(),
            ChipType::Bytes(chip) => chip.sends(),
            ChipType::Field(chip) => chip.sends(),
            ChipType::ShaExtend(chip) => chip.sends(),
            ChipType::ShaCompress(chip) => chip.sends(),
            ChipType::EdAdd(chip) => chip.sends(),
            ChipType::EdDecompress(chip) => chip.sends(),
            ChipType::KeccakPermute(chip) => chip.sends(),
            ChipType::WeierstrassAdd(chip) => chip.sends(),
            ChipType::WeierstrassDouble(chip) => chip.sends(),
            ChipType::K256Decompress(chip) => chip.sends(),
            ChipType::MemoryInit(chip) => chip.sends(),
            ChipType::MemoryFinalize(chip) => chip.sends(),
            ChipType::MemoryProgram(chip) => chip.sends(),
        }
    }

    pub fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F>
    where
        F: PrimeField32,
    {
        match &self.chip {
            ChipType::Program(chip) => chip.generate_trace(segment),
            ChipType::Cpu(chip) => chip.generate_trace(segment),
            ChipType::Add(chip) => chip.generate_trace(segment),
            ChipType::Sub(chip) => chip.generate_trace(segment),
            ChipType::Bitwise(chip) => chip.generate_trace(segment),
            ChipType::Mul(chip) => chip.generate_trace(segment),
            ChipType::DivRem(chip) => chip.generate_trace(segment),
            ChipType::ShiftRight(chip) => chip.generate_trace(segment),
            ChipType::ShiftLeft(chip) => chip.generate_trace(segment),
            ChipType::Lt(chip) => chip.generate_trace(segment),
            ChipType::Bytes(chip) => chip.generate_trace(segment),
            ChipType::Field(chip) => chip.generate_trace(segment),
            ChipType::ShaExtend(chip) => chip.generate_trace(segment),
            ChipType::ShaCompress(chip) => chip.generate_trace(segment),
            ChipType::EdAdd(chip) => chip.generate_trace(segment),
            ChipType::EdDecompress(chip) => chip.generate_trace(segment),
            ChipType::KeccakPermute(chip) => chip.generate_trace(segment),
            ChipType::WeierstrassAdd(chip) => chip.generate_trace(segment),
            ChipType::WeierstrassDouble(chip) => chip.generate_trace(segment),
            ChipType::K256Decompress(chip) => chip.generate_trace(segment),
            ChipType::MemoryInit(chip) => chip.generate_trace(segment),
            ChipType::MemoryFinalize(chip) => chip.generate_trace(segment),
            ChipType::MemoryProgram(chip) => chip.generate_trace(segment),
        }
    }

    pub fn name(&self) -> String
    where
        F: PrimeField32,
    {
        match &self.chip {
            ChipType::Program(chip) => <ProgramChip as Chip<F>>::name(chip),
            ChipType::Cpu(chip) => <CpuChip as Chip<F>>::name(chip),
            ChipType::Add(chip) => <AddChip as Chip<F>>::name(chip),
            ChipType::Sub(chip) => <SubChip as Chip<F>>::name(chip),
            ChipType::Bitwise(chip) => <BitwiseChip as Chip<F>>::name(chip),
            ChipType::Mul(chip) => <MulChip as Chip<F>>::name(chip),
            ChipType::DivRem(chip) => <DivRemChip as Chip<F>>::name(chip),
            ChipType::ShiftRight(chip) => <ShiftRightChip as Chip<F>>::name(chip),
            ChipType::ShiftLeft(chip) => <ShiftLeftChip as Chip<F>>::name(chip),
            ChipType::Lt(chip) => <LtChip as Chip<F>>::name(chip),
            ChipType::Bytes(chip) => <ByteChip<F> as Chip<F>>::name(chip),
            ChipType::Field(chip) => <FieldLTUChip as Chip<F>>::name(chip),
            ChipType::ShaExtend(chip) => <ShaExtendChip as Chip<F>>::name(chip),
            ChipType::ShaCompress(chip) => <ShaCompressChip as Chip<F>>::name(chip),
            ChipType::EdAdd(chip) => <EdAddAssignChip<
                EdwardsCurve<Ed25519Parameters>,
                Ed25519Parameters,
            > as Chip<F>>::name(chip),
            ChipType::EdDecompress(chip) => {
                <EdDecompressChip<Ed25519Parameters> as Chip<F>>::name(chip)
            }
            ChipType::KeccakPermute(chip) => <KeccakPermuteChip as Chip<F>>::name(chip),
            ChipType::WeierstrassAdd(chip) => <WeierstrassAddAssignChip<
                SWCurve<Secp256k1Parameters>,
                Secp256k1Parameters,
            > as Chip<F>>::name(chip),
            ChipType::WeierstrassDouble(chip) => <WeierstrassDoubleAssignChip<
                SWCurve<Secp256k1Parameters>,
                Secp256k1Parameters,
            > as Chip<F>>::name(chip),
            ChipType::K256Decompress(chip) => <K256DecompressChip as Chip<F>>::name(chip),
            ChipType::MemoryInit(chip) => <MemoryGlobalChip as Chip<F>>::name(chip),
            ChipType::MemoryFinalize(chip) => <MemoryGlobalChip as Chip<F>>::name(chip),
            ChipType::MemoryProgram(chip) => <MemoryGlobalChip as Chip<F>>::name(chip),
        }
    }

    pub fn eval<AB: CurtaAirBuilder>(&self, builder: &mut AB)
    where
        F: PrimeField32,
        AB::F: ExtensionField<F>,
    {
        match &self.chip {
            ChipType::Program(chip) => chip.eval(builder),
            ChipType::Cpu(chip) => chip.eval(builder),
            ChipType::Add(chip) => chip.eval(builder),
            ChipType::Sub(chip) => chip.eval(builder),
            ChipType::Bitwise(chip) => chip.eval(builder),
            ChipType::Mul(chip) => chip.eval(builder),
            ChipType::DivRem(chip) => chip.eval(builder),
            ChipType::ShiftRight(chip) => chip.eval(builder),
            ChipType::ShiftLeft(chip) => chip.eval(builder),
            ChipType::Lt(chip) => chip.eval(builder),
            ChipType::Bytes(chip) => chip.eval(builder),
            ChipType::Field(chip) => chip.eval(builder),
            ChipType::ShaExtend(chip) => chip.eval(builder),
            ChipType::ShaCompress(chip) => chip.eval(builder),
            ChipType::EdAdd(chip) => chip.eval(builder),
            ChipType::EdDecompress(chip) => chip.eval(builder),
            ChipType::KeccakPermute(chip) => chip.eval(builder),
            ChipType::WeierstrassAdd(chip) => chip.eval(builder),
            ChipType::WeierstrassDouble(chip) => chip.eval(builder),
            ChipType::K256Decompress(chip) => chip.eval(builder),
            ChipType::MemoryInit(chip) => chip.eval(builder),
            ChipType::MemoryFinalize(chip) => chip.eval(builder),
            ChipType::MemoryProgram(chip) => chip.eval(builder),
        }
    }

    pub fn air_width(&self) -> usize
    where
        F: PrimeField32,
    {
        match &self.chip {
            ChipType::Program(chip) => <ProgramChip as BaseAir<F>>::width(chip),
            ChipType::Cpu(chip) => <CpuChip as BaseAir<F>>::width(chip),
            ChipType::Add(chip) => <AddChip as BaseAir<F>>::width(chip),
            ChipType::Sub(chip) => <SubChip as BaseAir<F>>::width(chip),
            ChipType::Bitwise(chip) => <BitwiseChip as BaseAir<F>>::width(chip),
            ChipType::Mul(chip) => <MulChip as BaseAir<F>>::width(chip),
            ChipType::DivRem(chip) => <DivRemChip as BaseAir<F>>::width(chip),
            ChipType::ShiftRight(chip) => <ShiftRightChip as BaseAir<F>>::width(chip),
            ChipType::ShiftLeft(chip) => <ShiftLeftChip as BaseAir<F>>::width(chip),
            ChipType::Lt(chip) => <LtChip as BaseAir<F>>::width(chip),
            ChipType::Bytes(chip) => <ByteChip<F> as BaseAir<F>>::width(chip),
            ChipType::Field(chip) => <FieldLTUChip as BaseAir<F>>::width(chip),
            ChipType::ShaExtend(chip) => <ShaExtendChip as BaseAir<F>>::width(chip),
            ChipType::ShaCompress(chip) => <ShaCompressChip as BaseAir<F>>::width(chip),
            ChipType::EdAdd(chip) => <EdAddAssignChip<
                EdwardsCurve<Ed25519Parameters>,
                Ed25519Parameters,
            > as BaseAir<F>>::width(chip),
            ChipType::EdDecompress(chip) => {
                <EdDecompressChip<Ed25519Parameters> as BaseAir<F>>::width(chip)
            }
            ChipType::KeccakPermute(chip) => <KeccakPermuteChip as BaseAir<F>>::width(chip),
            ChipType::WeierstrassAdd(chip) => <WeierstrassAddAssignChip<
                SWCurve<Secp256k1Parameters>,
                Secp256k1Parameters,
            > as BaseAir<F>>::width(chip),
            ChipType::WeierstrassDouble(chip) => <WeierstrassDoubleAssignChip<
                SWCurve<Secp256k1Parameters>,
                Secp256k1Parameters,
            > as BaseAir<F>>::width(chip),
            ChipType::K256Decompress(chip) => <K256DecompressChip as BaseAir<F>>::width(chip),
            ChipType::MemoryInit(chip) => <MemoryGlobalChip as BaseAir<F>>::width(chip),
            ChipType::MemoryFinalize(chip) => <MemoryGlobalChip as BaseAir<F>>::width(chip),
            ChipType::MemoryProgram(chip) => <MemoryGlobalChip as BaseAir<F>>::width(chip),
        }
    }

    pub fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>>
    where
        F: PrimeField32,
    {
        match &self.chip {
            ChipType::Program(chip) => chip.preprocessed_trace(),
            ChipType::Cpu(chip) => chip.preprocessed_trace(),
            ChipType::Add(chip) => chip.preprocessed_trace(),
            ChipType::Sub(chip) => chip.preprocessed_trace(),
            ChipType::Bitwise(chip) => chip.preprocessed_trace(),
            ChipType::Mul(chip) => chip.preprocessed_trace(),
            ChipType::DivRem(chip) => chip.preprocessed_trace(),
            ChipType::ShiftRight(chip) => chip.preprocessed_trace(),
            ChipType::ShiftLeft(chip) => chip.preprocessed_trace(),
            ChipType::Lt(chip) => chip.preprocessed_trace(),
            ChipType::Bytes(chip) => chip.preprocessed_trace(),
            ChipType::Field(chip) => chip.preprocessed_trace(),
            ChipType::ShaExtend(chip) => chip.preprocessed_trace(),
            ChipType::ShaCompress(chip) => chip.preprocessed_trace(),
            ChipType::EdAdd(chip) => chip.preprocessed_trace(),
            ChipType::EdDecompress(chip) => chip.preprocessed_trace(),
            ChipType::KeccakPermute(chip) => chip.preprocessed_trace(),
            ChipType::WeierstrassAdd(chip) => chip.preprocessed_trace(),
            ChipType::WeierstrassDouble(chip) => chip.preprocessed_trace(),
            ChipType::K256Decompress(chip) => chip.preprocessed_trace(),
            ChipType::MemoryInit(chip) => chip.preprocessed_trace(),
            ChipType::MemoryFinalize(chip) => chip.preprocessed_trace(),
            ChipType::MemoryProgram(chip) => chip.preprocessed_trace(),
        }
    }
}

impl Runtime {
    pub fn segment_chips<F: Field>() -> [Box<ChipInfo<F>>; NUM_CHIPS] {
        // Initialize chips.
        println!("cycle-tracker-start: creating chips");
        let program = ProgramChip::new();
        let cpu = CpuChip::new();
        let add = AddChip::default();
        let sub = SubChip::default();
        let bitwise = BitwiseChip::default();
        let mul = MulChip::default();
        let divrem = DivRemChip::default();
        let shift_right = ShiftRightChip::default();
        let shift_left = ShiftLeftChip::default();
        let lt = LtChip::default();
        let bytes = ByteChip::<F>::new();
        let field = FieldLTUChip::default();
        println!("cycle-tracker-end: creating chips");
        // let sha_extend = ShaExtendChip::new();
        // let sha_compress = ShaCompressChip::new();
        // let ed_add = EdAddAssignChip::<EdwardsCurve<Ed25519Parameters>, Ed25519Parameters>::new();
        // let ed_decompress = EdDecompressChip::<Ed25519Parameters>::new();
        // let keccak_permute = KeccakPermuteChip::new();
        // let weierstrass_add =
        //     WeierstrassAddAssignChip::<SWCurve<Secp256k1Parameters>, Secp256k1Parameters>::new();
        // let weierstrass_double =
        //     WeierstrassDoubleAssignChip::<SWCurve<Secp256k1Parameters>, Secp256k1Parameters>::new();
        // let k256_decompress = K256DecompressChip::new();
        // This vector contains chips ordered to address dependencies. Some operations, like div,
        // depend on others like mul for verification. To prevent race conditions and ensure correct
        // execution sequences, dependent operations are positioned before their dependencies.

        println!("cycle-tracker-start: boxing program chip");
        let boxed_program = Box::new(ChipInfo::<F> {
            chip: ChipType::Program(program),
        });
        println!("cycle-tracker-end: boxing program chip");

        [
            boxed_program,
            Box::new(ChipInfo {
                chip: ChipType::Cpu(cpu),
            }),
            Box::new(ChipInfo {
                chip: ChipType::Add(add),
            }),
            Box::new(ChipInfo {
                chip: ChipType::Sub(sub),
            }),
            Box::new(ChipInfo {
                chip: ChipType::Bitwise(bitwise),
            }),
            Box::new(ChipInfo {
                chip: ChipType::Mul(mul),
            }),
            Box::new(ChipInfo {
                chip: ChipType::DivRem(divrem),
            }),
            Box::new(ChipInfo {
                chip: ChipType::ShiftRight(shift_right),
            }),
            Box::new(ChipInfo {
                chip: ChipType::ShiftLeft(shift_left),
            }),
            Box::new(ChipInfo {
                chip: ChipType::Lt(lt),
            }),
            Box::new(ChipInfo {
                chip: ChipType::Bytes(bytes),
            }),
            Box::new(ChipInfo {
                chip: ChipType::Field(field),
            }),
            // Box::new(ChipInfo {
            //     chip: ChipType::ShaExtend(sha_extend),
            // }),
            // Box::new(ChipInfo {
            //     chip: ChipType::ShaCompress(sha_compress),
            // }),
            // Box::new(ChipInfo {
            //     chip: ChipType::EdAdd(ed_add),
            // }),
            // Box::new(ChipInfo {
            //     chip: ChipType::EdDecompress(ed_decompress),
            // }),
            // Box::new(ChipInfo {
            //     chip: ChipType::KeccakPermute(keccak_permute),
            // }),
            // Box::new(ChipInfo {
            //     chip: ChipType::WeierstrassAdd(weierstrass_add),
            // }),
            // Box::new(ChipInfo {
            //     chip: ChipType::WeierstrassDouble(weierstrass_double),
            // }),
            // Box::new(ChipInfo {
            //     chip: ChipType::K256Decompress(k256_decompress),
            // }),
        ]
    }

    pub fn global_chips<F: Field>() -> [Box<ChipInfo<F>>; 3] {
        // Initialize chips.
        let memory_init = MemoryGlobalChip::new(MemoryChipKind::Init);
        let memory_finalize = MemoryGlobalChip::new(MemoryChipKind::Finalize);
        let program_memory_init = MemoryGlobalChip::new(MemoryChipKind::Program);
        [
            Box::new(ChipInfo {
                chip: ChipType::MemoryInit(memory_init),
            }),
            Box::new(ChipInfo {
                chip: ChipType::MemoryFinalize(memory_finalize),
            }),
            Box::new(ChipInfo {
                chip: ChipType::MemoryProgram(program_memory_init),
            }),
        ]
    }

    /// Prove the program.
    ///
    /// The function returns a vector of segment proofs, one for each segment, and a global proof.
    pub fn prove<F, EF, SC, P>(
        &mut self,
        config: &SC,
        challenger: &mut SC::Challenger,
    ) -> (Vec<SegmentProof<SC>>, SegmentProof<SC>)
    where
        F: PrimeField + TwoAdicField + PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkConfig<Val = F, Challenge = EF> + Send + Sync,
        SC::Challenger: Clone,
        <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::Commitment: Send + Sync,
        <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::ProverData: Send + Sync,
        MainData<SC>: Serialize + DeserializeOwned,
        P: Prover<SC>,
        OpeningProof<SC>: Send + Sync,
    {
        let num_segments = self.segments.len();
        let (cycle_count, keccak_count, sha_count) =
            self.segments.iter().fold((0, 0, 0), |acc, s| {
                (
                    acc.0 + s.cpu_events.len(),
                    acc.1 + s.keccak_permute_events.len(),
                    acc.2 + s.sha_compress_events.len(),
                )
            });
        tracing::info!(
            "total_cycles: {}, segments: {}, keccak: {}, sha: {}",
            cycle_count,
            num_segments,
            keccak_count,
            sha_count,
        );
        let segment_chips = Self::segment_chips::<F>();

        let (commitments, segment_main_data) =
            P::generate_segment_traces::<F, EF>(config, &mut self.segments, &segment_chips);

        // TODO: Observe the challenges in a tree-like structure for easily verifiable reconstruction
        // in a map-reduce recursion setting.
        tracing::info_span!("observe challenges for all segments").in_scope(|| {
            commitments.into_iter().for_each(|commitment| {
                challenger.observe(commitment);
            });
        });

        // We clone the challenger so that each segment can observe the same "global" challenges.
        let local_segment_proofs: Vec<_> =
            tracing::info_span!("proving all segments").in_scope(|| {
                segment_main_data
                    .into_par_iter()
                    .enumerate()
                    .map(|(i, main_data)| {
                        tracing::info_span!("proving segment", segment = i).in_scope(|| {
                            P::prove(config, &mut challenger.clone(), &segment_chips, main_data)
                        })
                    })
                    .collect()
            });

        #[cfg(feature = "proof-debug")]
        // Verify the segment proofs.
        tracing::info_span!("proving all segments").in_scope(|| {
            local_segment_proofs
                .iter()
                .enumerate()
                .for_each(|(i, proof)| {
                    tracing::info_span!("verifying segment", segment = i).in_scope(|| {
                        Verifier::verify(config, &segment_chips, &mut challenger.clone(), proof)
                            .unwrap()
                    })
                })
        });

        let global_chips = Self::global_chips::<F>();
        let global_main_data =
            tracing::info_span!("commit main for global segments").in_scope(|| {
                P::commit_main(config, &global_chips, &mut self.global_segment).to_in_memory()
            });
        let global_proof = tracing::info_span!("proving global segments").in_scope(|| {
            P::prove(
                config,
                &mut challenger.clone(),
                &global_chips,
                global_main_data,
            )
        });

        #[cfg(feature = "proof-debug")]
        // Verify the global proof.
        tracing::info_span!("verifying global segments").in_scope(|| {
            Verifier::verify(
                config,
                &global_chips,
                &mut challenger.clone(),
                &global_proof,
            )
            .unwrap()
        });

        #[cfg(not(feature = "perf"))]
        let mut all_permutation_traces = local_segment_proofs
            .into_iter()
            .flat_map(|proof| proof.permutation_traces)
            .collect::<Vec<_>>();
        #[cfg(not(feature = "perf"))]
        all_permutation_traces.extend_from_slice(&global_proof.permutation_traces);

        // Compute the cumulative bus sum from all segments
        // Make sure that this cumulative bus sum is 0.
        #[cfg(not(feature = "perf"))]
        debug_cumulative_sums::<F, EF>(&all_permutation_traces);

        #[cfg(feature = "perf")]
        return (local_segment_proofs, global_proof);

        #[cfg(not(feature = "perf"))]
        (vec![], global_proof)
    }

    pub fn verify<F, EF, SC>(
        &mut self,
        config: &SC,
        challenger: &mut SC::Challenger,
        segments_proofs: &[SegmentProof<SC>],
        global_proof: &SegmentProof<SC>,
    ) -> Result<(), ProgramVerificationError>
    where
        F: PrimeField + TwoAdicField + PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkConfig<Val = F, Challenge = EF> + Send + Sync,
        SC::Challenger: Clone,
        <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::Commitment: Send + Sync,
        <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::ProverData: Send + Sync,
    {
        println!("cycle-tracker-start: observing_challenges_for_all_segments");

        // TODO: Observe the challenges in a tree-like structure for easily verifiable reconstruction
        // in a map-reduce recursion setting.
        #[cfg(feature = "perf")]
        tracing::info_span!("observe challenges for all segments").in_scope(|| {
            segments_proofs.iter().for_each(|proof| {
                challenger.observe(proof.commitment.main_commit.clone());
            });
        });
        println!("cycle-tracker-end: observing_challenges_for_all_segments");

        // Verify the segment proofs.
        println!("cycle-tracker-start: verifying_segment_proofs");
        let segment_chips = Self::segment_chips::<F>();
        for (i, proof) in segments_proofs.iter().enumerate() {
            tracing::info_span!("verifying segment", segment = i).in_scope(|| {
                Verifier::verify(config, &segment_chips, &mut challenger.clone(), proof)
                    .map_err(ProgramVerificationError::InvalidSegmentProof)
            })?;
        }
        println!("cycle-tracker-end: verifying_segment_proofs");

        // Verify the global proof.
        println!("cycle-tracker-start: verifying_global_proof");
        let global_chips = Self::global_chips::<F>();
        tracing::info_span!("verifying global segment").in_scope(|| {
            Verifier::verify(config, &global_chips, &mut challenger.clone(), global_proof)
                .map_err(ProgramVerificationError::InvalidGlobalProof)
        })?;
        println!("cycle-tracker-end: verifying_global_proof");

        // Verify the cumulative sum is 0.
        println!("cycle-tracker-start: verifying_interactions");
        let mut sum = SC::Challenge::zero();
        #[cfg(feature = "perf")]
        {
            for proof in segments_proofs.iter() {
                sum += proof
                    .commulative_sums
                    .iter()
                    .copied()
                    .sum::<SC::Challenge>();
            }
            sum += global_proof
                .commulative_sums
                .iter()
                .copied()
                .sum::<SC::Challenge>();
        }
        println!("cycle-tracker-end verifying_interactions");

        match sum.is_zero() {
            true => Ok(()),
            false => Err(ProgramVerificationError::NonZeroCommulativeSum),
        }
    }
}

#[derive(Debug)]
pub enum ProgramVerificationError {
    InvalidSegmentProof(VerificationError),
    InvalidGlobalProof(VerificationError),
    NonZeroCommulativeSum,
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
    use crate::utils;
    use crate::utils::prove;
    use crate::utils::setup_logger;

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
    fn test_shift_prove() {
        let shift_ops = [Opcode::SRL, Opcode::SRA, Opcode::SLL];
        let operands = [
            (1, 1),
            (1234, 5678),
            (0xffff, 0xffff - 1),
            (u32::MAX - 1, u32::MAX),
            (u32::MAX, 0),
        ];
        for shift_op in shift_ops.iter() {
            for op in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, op.0, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, op.1, false, true),
                    Instruction::new(*shift_op, 31, 29, 3, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                prove(program);
            }
        }
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
        setup_logger();
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
        utils::setup_logger();
        let operands = [
            (1, 1),
            (1234, 5678),
            (8765, 4321),
            (0xffff, 0xffff - 1),
            (u32::MAX - 1, u32::MAX),
        ];
        for mul_op in mul_ops.iter() {
            for operand in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, operand.0, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, operand.1, false, true),
                    Instruction::new(*mul_op, 31, 30, 29, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                prove(program);
            }
        }
    }

    #[test]
    fn test_lt_prove() {
        let less_than = [Opcode::SLT, Opcode::SLTU];
        for lt_op in less_than.iter() {
            let instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
                Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
                Instruction::new(*lt_op, 31, 30, 29, false, false),
            ];
            let program = Program::new(instructions, 0, 0);
            prove(program);
        }
    }

    #[test]
    fn test_bitwise_prove() {
        let bitwise_opcodes = [Opcode::XOR, Opcode::OR, Opcode::AND];

        for bitwise_op in bitwise_opcodes.iter() {
            let instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
                Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
                Instruction::new(*bitwise_op, 31, 30, 29, false, false),
            ];
            let program = Program::new(instructions, 0, 0);
            prove(program);
        }
    }

    #[test]
    fn test_divrem_prove() {
        let div_rem_ops = [Opcode::DIV, Opcode::DIVU, Opcode::REM, Opcode::REMU];
        let operands = [
            (1, 1),
            (123, 456 * 789),
            (123 * 456, 789),
            (0xffff * (0xffff - 1), 0xffff),
            (u32::MAX - 5, u32::MAX - 7),
        ];
        for div_rem_op in div_rem_ops.iter() {
            for op in operands.iter() {
                let instructions = vec![
                    Instruction::new(Opcode::ADD, 29, 0, op.0, false, true),
                    Instruction::new(Opcode::ADD, 30, 0, op.1, false, true),
                    Instruction::new(*div_rem_op, 31, 29, 30, false, false),
                ];
                let program = Program::new(instructions, 0, 0);
                prove(program);
            }
        }
    }

    #[test]
    fn test_fibonacci_prove() {
        let program = fibonacci_program();
        prove(program);
    }

    #[test]
    fn test_simple_memory_program_prove() {
        let program = simple_memory_program();
        prove(program);
    }
}
