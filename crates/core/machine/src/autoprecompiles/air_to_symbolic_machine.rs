use core::fmt;
use std::{collections::BTreeSet, sync::Arc};

use itertools::Itertools;
use powdr_autoprecompiles::{
    bus_map::BusType,
    expression::AlgebraicReference,
    powdr::UniqueReferences,
    symbolic_machine::{SymbolicBusInteraction, SymbolicConstraint, SymbolicMachine},
};
use powdr_constraint_solver::grouped_expression::GroupedExpression;
use powdr_expression::{
    AlgebraicBinaryOperation, AlgebraicBinaryOperator, AlgebraicExpression,
    AlgebraicUnaryOperation, AlgebraicUnaryOperator,
};

use powdr_number::{BabyBearField, ExpressionConvertible, FieldElement};
use slop_air::Air;
use slop_algebra::PrimeField32;
use slop_uni_stark::{
    get_symbolic_constraints, Entry, SymbolicAirBuilder, SymbolicExpression, SymbolicVariable,
};
use sp1_hypercube::{
    air::{InteractionScope, MachineAir},
    InteractionKind, PROOF_MAX_NUM_PVS,
};

use crate::autoprecompiles::{
    bus_map::sp1_bus_map,
    interaction_builder::{Interaction, InteractionBuilder},
};

/// Reorders bus interactions such that they are sorted chronologically, assuming all clk_low
/// values are of the form `<same expression> + <offset>`.
pub fn sort_memory_interactions<F: PrimeField32>(
    machine: SymbolicMachine<F>,
) -> SymbolicMachine<F> {
    // Split bus interactions into memory and other interactions.
    let bus_map = sp1_bus_map();
    let memory_bus_id = bus_map.get_bus_id(&BusType::Memory).unwrap();
    let (memory_bus_interactions, other_interactions): (Vec<_>, Vec<_>) =
        machine.bus_interactions.into_iter().partition(|bi| bi.id == memory_bus_id);

    // Chunk into pairs of send and receive interactions.
    let memory_interaction_pairs = memory_bus_interactions
        .into_iter()
        .chunks(2)
        .into_iter()
        .map(|interaction_pair| {
            let [send, receive] = interaction_pair.collect::<Vec<_>>().try_into().unwrap();
            assert!(is_negation(&receive.mult));
            assert!(!is_negation(&send.mult));

            // Format is: (clk_high, clk_low, addr (3 limbs), value (4 limbs))
            // We'd expect the address to be the same in the pair:
            for i in [2, 3, 4] {
                assert_eq!(send.args[i], receive.args[i]);
            }

            (send, receive)
        })
        .collect::<Vec<_>>();

    // Assert consistency: We expect all receives happen at the same clock, except for a
    // constant offset.
    let mut base_clk = None;
    for (_send, receive) in &memory_interaction_pairs {
        let clk_high = receive.args[0].clone();
        let clk_low = to_grouped_expr(&receive.args[1]);
        let quadratic = clk_low.quadratic_components();
        let linear = clk_low.linear_components();

        // Assert that apart from the offset, all clocks are the same.
        let quadratic = quadratic.to_vec();
        let linear = linear.map(|(r, c)| (r.clone(), *c)).collect::<Vec<_>>();
        let current_base_clk = (clk_high, quadratic, linear);
        match &base_clk {
            None => {
                base_clk = Some(current_base_clk);
            }
            Some(prev_base_clk) => {
                assert_eq!(prev_base_clk, &current_base_clk);
            }
        }
    }

    // Sort pairs by the offset in clk_low and flatten interactions.
    let memory_bus_interactions = memory_interaction_pairs
        .into_iter()
        .sorted_by_key(move |(_send, receive)| {
            let clk_low = to_grouped_expr(&receive.args[1]);
            let offset = clk_low.constant_offset();
            offset.to_degree()
        })
        .flat_map(|(send, receive)| [send, receive])
        .collect::<Vec<_>>();

    SymbolicMachine {
        constraints: machine.constraints,
        bus_interactions: other_interactions.into_iter().chain(memory_bus_interactions).collect(),
        derived_columns: machine.derived_columns,
    }
}

/// Takes a machine and constrains its `is_trusted` variable to 1.
pub fn constrain_is_trusted_to_one<F: PrimeField32>(
    mut machine: SymbolicMachine<F>,
) -> SymbolicMachine<F> {
    let is_trusted = &machine
        .bus_interactions
        .iter()
        .filter(|i| i.id == InteractionKind::Program as u64)
        .exactly_one()
        .expect("Expected exactly one program interaction")
        .mult;
    machine.constraints.push(SymbolicConstraint {
        expr: is_trusted.clone() - AlgebraicExpression::Number(F::one()),
    });
    machine
}

fn is_negation<F: PrimeField32>(expr: &AlgebraicExpression<F, AlgebraicReference>) -> bool {
    matches!(
        expr,
        AlgebraicExpression::UnaryOperation(AlgebraicUnaryOperation {
            op: AlgebraicUnaryOperator::Minus,
            ..
        })
    )
}

fn to_grouped_expr<F: PrimeField32>(
    expr: &AlgebraicExpression<F, AlgebraicReference>,
) -> GroupedExpression<BabyBearField, AlgebraicReference> {
    expr.to_expression(
        &|number| {
            let number = BabyBearField::from_bytes_le(&number.as_canonical_u32().to_le_bytes());
            GroupedExpression::from_number(number)
        },
        &|reference| GroupedExpression::from_unknown_variable(reference.clone()),
    )
}

pub fn air_to_symbolic_machine<
    F: PrimeField32,
    A: MachineAir<F> + Air<SymbolicAirBuilder<F>> + Air<InteractionBuilder<F>>,
>(
    air: &A,
    first_public_input_id: &mut Option<usize>,
) -> Result<SymbolicMachine<F>, UnsupportedConstraintError> {
    let column_names = air.column_names().into_iter().map(Arc::new).collect::<Vec<_>>();

    // Get constraints
    let constraints = get_symbolic_constraints(air, air.preprocessed_width(), PROOF_MAX_NUM_PVS);
    let constraints = constraints
        .into_iter()
        .map(|c| {
            Ok(SymbolicConstraint {
                expr: symbolic_to_algebraic(&c, &column_names, first_public_input_id)?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Get interactions
    let mut builder = InteractionBuilder::new(air.preprocessed_width(), air.width());
    air.eval(&mut builder);
    let interactions = builder.interactions();
    let bus_interactions = interactions
        .into_iter()
        .map(|interaction| {
            sp1_bus_interaction_to_powdr(&interaction, &column_names, first_public_input_id)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut machine =
        SymbolicMachine { constraints, bus_interactions, derived_columns: Vec::new() };
    // In some machines, not all references are used, so we add dummy constraints for the ones
    // that are not
    let referenced: BTreeSet<u64> = machine.unique_references().map(|r| r.id).collect();
    let dummy_constraints =
        column_names.iter().enumerate().map(|(i, n)| (i as u64, n)).filter(|(id, _)| !referenced.contains(id)).map(
            |(id, name)| {
                let r = AlgebraicReference { name: name.clone(), id };
                let e = AlgebraicExpression::Reference(r);
                tracing::error!("Column `{name}` is not referenced in instruction air `{}`. Adding a dummy constraint. This signals that this column could be removed, or that the air is underconstrained.", air.name());
                SymbolicConstraint { expr: e.clone() - e }
            },
        );

    machine.constraints.extend(dummy_constraints);

    Ok(machine)
}

fn sp1_bus_interaction_to_powdr<F: PrimeField32>(
    interaction: &Interaction<F>,
    columns: &[Arc<String>],
    first_public_input_id: &mut Option<usize>,
) -> Result<SymbolicBusInteraction<F>, UnsupportedConstraintError> {
    match interaction.scope {
        InteractionScope::Global => {
            return Err(UnsupportedConstraintError("Global interaction".to_string()));
        }
        InteractionScope::Local => {}
    }

    let id = interaction.message.kind as u64;
    let mult =
        symbolic_to_algebraic(&interaction.message.multiplicity, columns, first_public_input_id)?;
    let args = interaction
        .message
        .values
        .iter()
        .map(|e| symbolic_to_algebraic(e, columns, first_public_input_id))
        .collect::<Result<_, _>>()?;

    Ok(SymbolicBusInteraction { id, mult, args })
}

#[derive(Debug)]
pub struct UnsupportedConstraintError(pub String);

impl fmt::Display for UnsupportedConstraintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn number_to_algebraic<F: PrimeField32>(value: &F) -> AlgebraicExpression<F, AlgebraicReference> {
    AlgebraicExpression::Number(*value)
}

/// Convert a symbolic expression to an algebraic expression
/// Replace the first public input by 0
/// Returns an error if there is more than one public input
fn symbolic_to_algebraic<F: PrimeField32>(
    expr: &SymbolicExpression<F>,
    columns: &[Arc<String>],
    first_public_input_id: &mut Option<usize>,
) -> Result<AlgebraicExpression<F, AlgebraicReference>, UnsupportedConstraintError> {
    Ok(match expr {
        SymbolicExpression::Constant(c) => number_to_algebraic(c),
        SymbolicExpression::Add { x, y, .. } => {
            AlgebraicExpression::BinaryOperation(AlgebraicBinaryOperation {
                left: Box::new(symbolic_to_algebraic(x, columns, first_public_input_id)?),
                right: Box::new(symbolic_to_algebraic(y, columns, first_public_input_id)?),
                op: AlgebraicBinaryOperator::Add,
            })
        }
        SymbolicExpression::Sub { x, y, .. } => {
            AlgebraicExpression::BinaryOperation(AlgebraicBinaryOperation {
                left: Box::new(symbolic_to_algebraic(x, columns, first_public_input_id)?),
                right: Box::new(symbolic_to_algebraic(y, columns, first_public_input_id)?),
                op: AlgebraicBinaryOperator::Sub,
            })
        }
        SymbolicExpression::Mul { x, y, .. } => {
            AlgebraicExpression::BinaryOperation(AlgebraicBinaryOperation {
                left: Box::new(symbolic_to_algebraic(x, columns, first_public_input_id)?),
                right: Box::new(symbolic_to_algebraic(y, columns, first_public_input_id)?),
                op: AlgebraicBinaryOperator::Mul,
            })
        }
        SymbolicExpression::Neg { x, .. } => {
            AlgebraicExpression::UnaryOperation(AlgebraicUnaryOperation {
                expr: Box::new(symbolic_to_algebraic(x, columns, first_public_input_id)?),
                op: AlgebraicUnaryOperator::Minus,
            })
        }
        SymbolicExpression::Variable(SymbolicVariable { entry, index, .. }) => match entry {
            Entry::Main { offset } => {
                if *offset != 0 {
                    return Err(UnsupportedConstraintError(format!("Nonzero offset: {offset}")));
                };
                let name = columns.get(*index).unwrap_or_else(|| {
                    panic!("Column index out of bounds: {index}\nColumns: {columns:?}");
                });
                AlgebraicExpression::Reference(AlgebraicReference {
                    name: name.clone(),
                    id: *index as u64,
                })
            }
            Entry::Preprocessed { .. } => {
                return Err(UnsupportedConstraintError("Preprocessed column".to_string()))
            }
            Entry::Permutation { .. } => {
                return Err(UnsupportedConstraintError("Permutation column".to_string()))
            }
            Entry::Public => {
                // If an id exists, check that it matches the public id. Otherwise, set it to the
                // id.
                if let Some(id) = first_public_input_id {
                    if *id != *index {
                        return Err(UnsupportedConstraintError(
                            "Expected at most one public input, found at least two".to_string(),
                        ));
                    }
                } else {
                    *first_public_input_id = Some(*index);
                }
                number_to_algebraic(&F::zero())
            }
            Entry::Challenge => {
                return Err(UnsupportedConstraintError("Challenge reference".to_string()))
            }
        },
        SymbolicExpression::IsFirstRow => {
            return Err(UnsupportedConstraintError("is_first_row reference".to_string()))
        }
        SymbolicExpression::IsLastRow => {
            return Err(UnsupportedConstraintError("is_last_row reference".to_string()))
        }
        SymbolicExpression::IsTransition => {
            return Err(UnsupportedConstraintError("is_transition reference".to_string()))
        }
    })
}
