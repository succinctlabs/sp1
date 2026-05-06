use crate::{
    air::InteractionScope, prover::Traces, record::MachineRecord, Chip,
    DebugPublicValuesConstraintFolder,
};
use slop_algebra::Field;
use slop_alloc::CpuBackend;
use std::{collections::BTreeMap, marker::PhantomData};

use super::InteractionKind;

use crate::air::MachineAir;

/// The data for an interaction.
#[derive(Debug)]
pub struct InteractionData<F: Field> {
    /// The chip name.
    pub chip_name: String,
    /// The kind of interaction.
    pub kind: InteractionKind,
    /// The row of the interaction.
    pub row: usize,
    /// The interaction number.
    pub interaction_number: usize,
    /// Whether the interaction is a send.
    pub is_send: bool,
    /// The multiplicity of the interaction.
    pub multiplicity: F,
}

/// Converts a vector of field elements to a string.
#[allow(clippy::needless_pass_by_value)]
#[must_use]
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

/// Debugs the interactions of a chip.
#[allow(clippy::type_complexity)]
#[allow(clippy::needless_pass_by_value)]
pub fn debug_interactions<F: Field, A: MachineAir<F>>(
    chip: &Chip<F, A>,
    preprocessed_traces: &Traces<F, CpuBackend>,
    traces: &Traces<F, CpuBackend>,
    interaction_kinds: Vec<InteractionKind>,
    scope: InteractionScope,
) -> (BTreeMap<String, Vec<InteractionData<F>>>, BTreeMap<String, F>) {
    let mut key_to_vec_data = BTreeMap::new();
    let mut key_to_count = BTreeMap::new();

    let main = traces.get(chip.name()).cloned().unwrap();
    let pre_traces = preprocessed_traces.get(chip.name()).cloned();

    let height = main.clone().num_real_entries();

    let sends = chip.sends().iter().filter(|s| s.scope == scope).collect::<Vec<_>>();
    let receives = chip.receives().iter().filter(|r| r.scope == scope).collect::<Vec<_>>();

    let nb_send_interactions = sends.len();
    for row in 0..height {
        for (m, interaction) in sends.iter().chain(receives.iter()).enumerate() {
            if !interaction_kinds.contains(&interaction.kind) {
                continue;
            }
            let empty = vec![];
            let preprocessed_row = match pre_traces {
                Some(ref t) => t
                    .inner()
                    .as_ref()
                    .map_or(empty.as_slice(), |t| t.guts().get(row).unwrap().as_slice()),
                None => empty.as_slice(),
            };

            let is_send = m < nb_send_interactions;

            let main_row =
                main.inner().as_ref().unwrap().guts().get(row).unwrap().as_slice().to_vec();

            let multiplicity_eval: F = interaction.multiplicity.apply(preprocessed_row, &main_row);

            if !multiplicity_eval.is_zero() {
                let mut values = vec![];
                for value in &interaction.values {
                    let expr: F = value.apply(preprocessed_row, &main_row);
                    values.push(expr);
                }
                let key =
                    format!("{} {} {}", interaction.scope, interaction.kind, vec_to_string(values));
                key_to_vec_data.entry(key.clone()).or_insert_with(Vec::new).push(InteractionData {
                    chip_name: chip.name().to_string(),
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

/// Calculate the number of times we send and receive each event of the given interaction type,
/// and print out the ones for which the set of sends and receives don't match.
#[allow(clippy::needless_pass_by_value)]
pub fn debug_interactions_with_all_chips<F, A>(
    chips: &[Chip<F, A>],
    // pkey: &MachineProvingKey<PC>,
    preprocessed_traces: &Traces<F, CpuBackend>,
    // shards: &[A::Record],
    traces: &Traces<F, CpuBackend>,
    public_values: Vec<F>,
    interaction_kinds: Vec<InteractionKind>,
    scope: InteractionScope,
) -> bool
where
    F: Field,
    A: MachineAir<F>,
{
    let mut final_map = BTreeMap::new();
    let mut total = F::zero();

    for chip in chips.iter() {
        let mut total_events = 0;

        let (_, count) = debug_interactions::<F, A>(
            chip,
            preprocessed_traces,
            traces,
            interaction_kinds.clone(),
            scope,
        );
        total_events += count.len();
        for (key, value) in count.iter() {
            let entry = final_map.entry(key.clone()).or_insert((F::zero(), BTreeMap::new()));
            entry.0 += *value;
            total += *value;
            *entry.1.entry(chip.name().to_string()).or_insert(F::zero()) += *value;
        }

        tracing::info!("{} chip has {} distinct events", chip.name(), total_events);
    }

    let mut folder = DebugPublicValuesConstraintFolder::<F> {
        perm_challenges: (&F::zero(), &[]),
        alpha: F::zero(),
        accumulator: F::zero(),
        interactions: vec![],
        public_values: &public_values,
        _marker: PhantomData,
    };
    A::Record::eval_public_values(&mut folder);

    for (kind, scope, values, multiplicity) in folder.interactions.iter() {
        let key = format!("{} {} {}", scope, kind, vec_to_string(values.clone()));
        let entry = final_map.entry(key.clone()).or_insert((F::zero(), BTreeMap::new()));
        entry.0 += *multiplicity;
        total += *multiplicity;
        *entry.1.entry("EvalPublicValues".to_string()).or_insert(F::zero()) += *multiplicity;
    }

    tracing::info!("Final counts below.");
    tracing::info!("==================");

    let mut any_nonzero = false;
    for (key, (value, chip_values)) in final_map.clone() {
        if !F::is_zero(&value) {
            tracing::info!("Interaction key: {} Send-Receive Discrepancy: {}", key, value);
            any_nonzero = true;
            for (chip, chip_value) in chip_values {
                tracing::info!(
                    " {} chip's send-receive discrepancy for this key is {}",
                    chip,
                    chip_value
                );
            }
        }
    }

    tracing::info!("==================");
    if !any_nonzero {
        tracing::info!("All chips have the same number of sends and receives.");
    }

    !any_nonzero
}
