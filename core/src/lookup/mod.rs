use crate::utils::Chip;
use p3_air::VirtualPairCol;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
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
