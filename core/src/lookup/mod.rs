mod builder;

pub use builder::InteractionBuilder;

use crate::air::MachineAir;
use crate::stark::ChipRef;
use crate::stark::StarkConfig;
use crate::utils::BabyBearPoseidon2;
use p3_air::VirtualPairCol;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::PrimeField64;
use p3_matrix::Matrix;

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fmt::Display;

use crate::runtime::{ExecutionRecord, Runtime};

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

    /// Interaction with the field op table for field operations.
    Field = 7,
}

impl Display for InteractionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InteractionKind::Memory => write!(f, "Memory"),
            InteractionKind::Program => write!(f, "Program"),
            InteractionKind::Instruction => write!(f, "Instruction"),
            InteractionKind::Alu => write!(f, "Alu"),
            InteractionKind::Byte => write!(f, "Byte"),
            InteractionKind::Range => write!(f, "Range"),
            InteractionKind::Field => write!(f, "Field"),
        }
    }
}

impl<F: Field> Interaction<F> {
    /// Create a new interaction.
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

    /// The index of the argument in the lookup table.
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

fn babybear_to_int(n: BabyBear) -> i32 {
    let modulus = BabyBear::ORDER_U64;
    let val = n.as_canonical_u64();
    if val > modulus / 2 {
        val as i32 - modulus as i32
    } else {
        val as i32
    }
}

/// Calculate the the number of times we send and receive each event of the given interaction type,
/// and print out the ones for which the set of sends and receives don't match.
pub fn debug_interactions_with_all_chips(
    segment: &ExecutionRecord,
    global_segment: Option<&ExecutionRecord>,
    interaction_kinds: Vec<InteractionKind>,
) -> bool {
    if interaction_kinds.contains(&InteractionKind::Memory) && global_segment.is_none() {
        panic!("Memory interactions requires global segment.");
    }

    // Here, we collect all the chips.
    let segment_chips = Runtime::local_chips::<BabyBearPoseidon2>();
    let global_chips = Runtime::global_chips::<BabyBearPoseidon2>();

    let mut final_map = BTreeMap::new();

    let mut segment = segment.clone();

    for chip in &segment_chips {
        let (_, count) =
            debug_interactions::<BabyBear>(chip.as_chip(), &mut segment, interaction_kinds.clone());

        tracing::debug!("{} chip has {} distinct events", chip.name(), count.len());
        for (key, value) in count.iter() {
            let entry = final_map
                .entry(key.clone())
                .or_insert((BabyBear::zero(), BTreeMap::new()));
            entry.0 += *value;
            *entry.1.entry(chip.name()).or_insert(BabyBear::zero()) += *value;
        }
    }

    if let Some(global_segment) = global_segment {
        let mut global_segment = global_segment.clone();
        for chip in global_chips {
            let (_, count) = debug_interactions::<BabyBear>(
                chip.as_chip(),
                &mut global_segment,
                interaction_kinds.clone(),
            );

            tracing::debug!("{} chip has {} distinct events", chip.name(), count.len());
            for (key, value) in count.iter() {
                let entry = final_map
                    .entry(key.clone())
                    .or_insert((BabyBear::zero(), BTreeMap::new()));
                entry.0 += *value;
                *entry.1.entry(chip.name()).or_insert(BabyBear::zero()) += *value;
            }
        }
    }

    tracing::debug!("Final counts below.");
    tracing::debug!("==================");

    let mut any_nonzero = false;
    for (key, (value, chip_values)) in final_map.clone() {
        if !BabyBear::is_zero(&value) {
            tracing::debug!(
                "Interaction key: {} Send-Receive Discrepancy: {}",
                key,
                babybear_to_int(value)
            );
            any_nonzero = true;
            for (chip, chip_value) in chip_values {
                tracing::debug!(
                    " {} chip's send-receive discrepancy for this key is {}",
                    chip,
                    babybear_to_int(chip_value)
                );
            }
        }
    }

    tracing::debug!("==================");
    if !any_nonzero {
        tracing::debug!("All chips have the same number of sends and receives.");
    } else {
        tracing::debug!("Positive values mean sent more than received.");
        tracing::debug!("Negative values mean received more than sent.");
    }

    !any_nonzero
}

pub fn debug_interactions<SC: StarkConfig>(
    chip: &ChipRef<SC>,
    segment: &mut ExecutionRecord,
    interaction_kinds: Vec<InteractionKind>,
) -> (
    BTreeMap<String, Vec<InteractionData<SC::Val>>>,
    BTreeMap<String, SC::Val>,
) {
    let mut key_to_vec_data = BTreeMap::new();
    let mut key_to_count = BTreeMap::new();

    let trace = chip.generate_trace(segment);
    let width = chip.width();
    let mut main = trace.clone();
    let height = trace.clone().height();

    let nb_send_interactions = chip.sends().len();
    for row in 0..height {
        for (m, interaction) in chip
            .sends()
            .iter()
            .chain(chip.receives().iter())
            .enumerate()
        {
            if !interaction_kinds.contains(&interaction.kind) {
                continue;
            }
            let is_send = m < nb_send_interactions;
            let multiplicity_eval = interaction.multiplicity.apply(&[], main.row_mut(row));

            if !multiplicity_eval.is_zero() {
                let mut values = vec![];
                for value in &interaction.values {
                    let expr = value.apply(&[], main.row_mut(row));
                    values.push(expr);
                }
                let key = format!(
                    "{} {}",
                    &interaction.kind.to_string(),
                    vec_to_string(values)
                );
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
                let current = key_to_count.entry(key.clone()).or_insert(SC::Val::zero());
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
