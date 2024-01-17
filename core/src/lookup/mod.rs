use crate::alu::divrem::DivRemChip;
use crate::alu::mul::MulChip;
use crate::alu::{AddChip, BitwiseChip, LeftShiftChip, LtChip, RightShiftChip, SubChip};
use crate::bytes::ByteChip;
use crate::cpu::CpuChip;
use crate::precompiles::sha256::{ShaCompressChip, ShaExtendChip};
use crate::program::ProgramChip;
use crate::prover::runtime::NUM_CHIPS;
use crate::utils::{AirChip, Chip};
use p3_air::VirtualPairCol;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use p3_field::Field;
use p3_fri::{FriBasedPcs, FriConfigImpl};
use p3_keccak::Keccak256Hash;
use p3_ldt::QuotientMmcs;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_mds::coset_mds::CosetMds;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
use p3_uni_stark::StarkConfigImpl;

use std::collections::BTreeMap;
use std::fmt::Debug;
mod builder;

pub use builder::InteractionBuilder;

use crate::runtime::Segment;

/// An interaction for a lookup or a permutation argument.
pub struct Interaction<F: Field> {
    pub values: Vec<VirtualPairCol<F>>,
    pub multiplicity: VirtualPairCol<F>,
    pub kind: InteractionKind,
}

// TODO: add debug for VirtualPairCol so that we can derive Debug for Interaction.
impl<F: Field> Debug for Interaction<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interaction")
            .field("kind", &self.kind)
            .finish()
    }
}

/// The type of interaction for a lookup argument.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InteractionKind {
    /// Interaction with the memory table, such as read and write.
    Memory = 1,
    /// Interaction with the program table, loading an instruction at a given pc address.
    Program = 2,
    /// Interaction with instruction oracle.
    Instruction = 3,
    /// Interaction with the ALU operations
    Alu = 4,
    /// Interaction with the byte lookup table for byte operations.
    Byte = 5,
    /// Requesting a range check for a given value and range.
    Range = 6,
}

impl<F: Field> Interaction<F> {
    pub fn new(
        values: Vec<VirtualPairCol<F>>,
        multiplicity: VirtualPairCol<F>,
        kind: InteractionKind,
    ) -> Self {
        Self {
            values,
            multiplicity,
            kind,
        }
    }

    pub fn argument_index(&self) -> usize {
        self.kind as usize
    }
}

#[derive(Debug)]
pub struct InteractionData<F: Field> {
    pub chip_name: String,
    pub kind: InteractionKind,
    pub row: usize,
    pub interaction_number: usize,
    pub is_send: bool,
    pub multiplicity: F,
}

pub fn vec_to_string<F: Field>(vec: Vec<F>) -> String {
    let mut result = String::from("(");
    for (i, value) in vec.iter().enumerate() {
        if i != 0 {
            result.push_str(", ");
        }
        result.push_str(&value.to_string());
    }
    result.push(')');
    result
}

/// Calculate the the number of times we send and receive each event of the given interaction type,
/// and print out the ones for which the set of sends and receives don't match.
pub fn debug_interactions_with_all_chips<F: Field>(
    mut segment: &mut Segment,
    interaction_kind: InteractionKind,
) -> bool {
    let cpu_chip = CpuChip::new();
    let (_, cpu_count) =
        debug_interactions::<BabyBear, _>(cpu_chip, &mut segment, interaction_kind);
    let program_chip = ProgramChip::new();
    let (_, program_count) =
        debug_interactions::<BabyBear, _>(program_chip, &mut segment, interaction_kind);
    let add_chip = AddChip::new();
    let (_, add_count) =
        debug_interactions::<BabyBear, _>(add_chip, &mut segment, interaction_kind);
    let sub_chip = SubChip::new();
    let (_, sub_count) =
        debug_interactions::<BabyBear, _>(sub_chip, &mut segment, interaction_kind);
    let bitwise_chip = BitwiseChip::new();
    let (_, bitwise_count) =
        debug_interactions::<BabyBear, _>(bitwise_chip, &mut segment, interaction_kind);
    let divrem_chip = DivRemChip::new();
    let (_, divrem_count) =
        debug_interactions::<BabyBear, _>(divrem_chip, &mut segment, interaction_kind);
    let mul_chip = MulChip::new();
    let (_, mul_count) =
        debug_interactions::<BabyBear, _>(mul_chip, &mut segment, interaction_kind);
    let shift_right_chip = RightShiftChip::new();
    let (_, shift_right_count) =
        debug_interactions::<BabyBear, _>(shift_right_chip, &mut segment, interaction_kind);
    let shift_left_chip = LeftShiftChip::new();
    let (_, shift_left_count) =
        debug_interactions::<BabyBear, _>(shift_left_chip, &mut segment, interaction_kind);
    let lt_chip = LtChip::new();
    let (_, lt_count) = debug_interactions::<BabyBear, _>(lt_chip, &mut segment, interaction_kind);
    let byte_chip = ByteChip::new();
    let (_, byte_count) =
        debug_interactions::<BabyBear, _>(byte_chip, &mut segment, interaction_kind);
    let sha_extend_chip = ShaExtendChip::new();
    let (_, sha_extend_count) =
        debug_interactions::<BabyBear, _>(sha_extend_chip, &mut segment, interaction_kind);
    let sha_compress_chip = ShaCompressChip::new();
    let (_, sha_compress_count) =
        debug_interactions::<BabyBear, _>(sha_compress_chip, &mut segment, interaction_kind);
    let counts: [(BTreeMap<String, BabyBear>, &str); NUM_CHIPS] = [
        (program_count, "program"),
        (cpu_count, "cpu"),
        (add_count, "add"),
        (sub_count, "sub"),
        (bitwise_count, "bitwise"),
        (mul_count, "mul"),
        (divrem_count, "divrem"),
        (shift_right_count, "shift_right"),
        (shift_left_count, "shift_left"),
        (lt_count, "lt"),
        (byte_count, "byte"),
        (sha_extend_count, "sha_extend"),
        (sha_compress_count, "sha_compress"),
    ];

    let mut final_map = BTreeMap::new();

    for (key, value) in counts.iter().flat_map(|map| map.0.iter()) {
        *final_map.entry(key.clone()).or_insert(BabyBear::zero()) += *value;
    }

    for count in counts.iter() {
        println!("{} chip has {} events", count.1, count.0.len());
    }

    println!("Final counts below. Positive => sent more than received, negative => opposite.");
    println!("=========");

    let mut any_nonzero = false;
    for (key, value) in final_map.clone() {
        if !value.is_zero() {
            println!("Key {} Value {}", key, value);
            any_nonzero = true;
            for count in counts.iter() {
                if count.0.contains_key(&key) {
                    println!("{} chip's value for this key is {}", count.1, count.0[&key]);
                }
            }
        }
    }
    println!("=========");
    !any_nonzero
}

pub fn debug_interactions<F: Field, C: Chip<F>>(
    chip: C,
    segment: &mut Segment,
    interaction_kind: InteractionKind,
) -> (
    BTreeMap<String, Vec<InteractionData<F>>>,
    BTreeMap<String, F>,
) {
    let mut key_to_vec_data = BTreeMap::new();
    let mut key_to_count = BTreeMap::new();

    let trace: RowMajorMatrix<F> = chip.generate_trace(segment);
    let width = chip.width();
    let mut builder = InteractionBuilder::<F>::new(width);
    chip.eval(&mut builder);
    let mut main = trace.clone();
    let all_interactions = chip.all_interactions();
    let nb_send_interactions = chip.sends().len();
    let height = trace.clone().height();
    for row in 0..height {
        for (m, interaction) in all_interactions.iter().enumerate() {
            if interaction.kind != interaction_kind {
                continue;
            }
            let is_send = m < nb_send_interactions;
            let multiplicity_eval = interaction
                .multiplicity
                .apply::<F, F>(&[], &main.row_mut(row));

            if !multiplicity_eval.is_zero() {
                let mut values = vec![];
                for value in &interaction.values {
                    let expr = value.apply::<F, F>(&[], &main.row_mut(row));
                    values.push(expr);
                }
                let key = vec_to_string(values);
                key_to_vec_data
                    .entry(key.clone())
                    .or_insert_with(Vec::new)
                    .push(InteractionData {
                        chip_name: chip.name(),
                        kind: interaction.kind,
                        row,
                        interaction_number: m,
                        is_send,
                        multiplicity: multiplicity_eval,
                    });
                let current = key_to_count.entry(key.clone()).or_insert(F::zero());
                if is_send {
                    *current += multiplicity_eval;
                } else {
                    *current -= multiplicity_eval;
                }
            }
        }
    }

    (key_to_vec_data, key_to_count)
}
