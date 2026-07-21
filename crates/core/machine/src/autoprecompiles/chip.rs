use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

use itertools::Itertools;
use powdr_autoprecompiles::{
    blocks::PcStep,
    expression::{AlgebraicExpression, AlgebraicReference},
    Substitution,
};
use powdr_expression::{AlgebraicBinaryOperator, AlgebraicUnaryOperator};
use slop_air::{Air, AirBuilder, BaseAir, PairBuilder};
use slop_algebra::PrimeField32;
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, ParallelIterator, ParallelSlice,
    ParallelSliceMut,
};
use sp1_core_executor::{
    events::ByteLookupEvent, opcode::ByteOpcode, ApcRange, ExecutionRecord, Program, RiscvAirId,
};
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, MachineAir, MessageBuilder, SP1AirBuilder},
    InteractionKind, Machine,
};

use crate::{
    autoprecompiles::{
        instruction::Sp1Instruction,
        instruction_handler::{try_instruction_type_to_air_id, InstructionType},
        Sp1Apc,
    },
    riscv::RiscvAir,
    utils::{next_multiple_of_32, zeroed_f_vec},
};

#[derive(Debug)]
struct CachedApc<F: PrimeField32> {
    /// The APC
    apc: Arc<Sp1Apc<F>>,
    /// The cached columns of the APC.
    columns: Vec<AlgebraicReference>,
}

impl<F: PrimeField32> CachedApc<F> {
    /// The width of the APC.
    pub fn width(&self) -> usize {
        self.columns.len()
    }
}

impl<F: PrimeField32> From<Arc<Sp1Apc<F>>> for CachedApc<F> {
    fn from(apc: Arc<Sp1Apc<F>>) -> Self {
        let columns = apc.machine.main_columns().collect();
        Self { apc, columns }
    }
}

/// Cache of filled APC traces, keyed by `(proof_nonce, initial_timestamp)`.
/// `generate_dependencies` fills the trace to evaluate the byte-bus interactions and stores it here
/// so `generate_trace_into` can restore it instead of regenerating the identical trace. `Mutex`
/// because the chip is shared via `Arc` across concurrent shard workers.
struct CachedTraces<F>(Mutex<HashMap<([u32; 4], u64), Vec<F>>>);

// A derived `Debug` would dump the whole runtime trace cache, so only print the type name.
impl<F> std::fmt::Debug for CachedTraces<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedTraces").finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct ApcChip<F: PrimeField32> {
    /// The ID of the APC.
    id: usize,
    /// The name of this APC
    name: String,
    /// The cached APC.
    cached_apc: CachedApc<F>,
    /// A machine to generate traces for the APC. By construction, it will never have apcs itself.
    machine: Machine<F, RiscvAir<F>>,
    /// Cache of filled APC traces (see [`CachedTraces`]).
    cached_traces: CachedTraces<F>,
}

impl<F: PrimeField32> ApcChip<F> {
    pub fn new(apc: Arc<Sp1Apc<F>>, id: usize) -> Self {
        Self {
            id,
            name: format!("APC_{id}"),
            cached_apc: apc.into(),
            machine: RiscvAir::machine(),
            cached_traces: CachedTraces::default(),
        }
    }

    pub fn apc(&self) -> &Arc<Sp1Apc<F>> {
        &self.cached_apc.apc
    }

    pub fn id(&self) -> usize {
        self.id
    }
}

impl<F: PrimeField32> BaseAir<F> for ApcChip<F> {
    fn width(&self) -> usize {
        self.cached_apc.width()
    }
}

impl<F: PrimeField32> MachineAir<F> for ApcChip<F> {
    // this may have to be changed
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &str {
        &self.name
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let num_apc_events = input.get_apc_events(self.id).map_or(0, |events| events.count);
        let nb_rows = next_multiple_of_32(num_apc_events, input.fixed_log2_rows::<F, _>(self));
        Some(nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        buffer: &mut [std::mem::MaybeUninit<F>],
    ) {
        // Every APC chip runs `generate_dependencies` before `generate_trace_into` (the former runs
        // for all chips during dependency generation), and it fills and caches this trace as a
        // byproduct of byte-bus evaluation. So we only ever restore from that cache — there is no
        // from-scratch path. A miss means the pipeline ran out of order.
        let events = input.get_apc_events(self.id).expect("APC events not found");
        let cached = self
            .cached_traces
            .0
            .lock()
            .unwrap()
            .remove(&(input.public_values.proof_nonce, input.initial_timestamp))
            .unwrap_or_else(|| {
                panic!(
                    "APC chip {} trace not cached: generate_dependencies must run before generate_trace_into",
                    self.id
                )
            });
        let n = cached.len();
        debug_assert_eq!(n, events.count * self.width());
        // SAFETY: `n == cached.len()`, so the first `n` slots are filled from `cached` and the rest
        // (padding rows) are zeroed. `MaybeUninit<F>` has the same layout as `F`.
        unsafe {
            core::ptr::copy_nonoverlapping(cached.as_ptr(), buffer.as_mut_ptr().cast::<F>(), n);
            core::ptr::write_bytes(buffer[n..].as_mut_ptr(), 0, buffer.len() - n);
        }
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        // Get all events for the given APC ID
        let events = input.get_apc_events(self.id);
        // Because `generate_dependencies` is run during execution for all chips, it's not
        // guaranteed that there will be APC events at all.
        if events.is_none() {
            tracing::debug!(
                "No APC events found for APC ID during `generate_dependencies`: {}",
                self.id
            );
            return; // Early return because no dependencies to generate.
        }
        let events = events.unwrap();

        // Mapping from poly_id to contiguous index in apc
        let apc_poly_id_to_index = self
            .apc()
            .machine
            .main_columns()
            .enumerate()
            .map(|(index, c)| (c.id, index))
            .collect::<BTreeMap<_, _>>();

        // Get is_valid_index to manually fill with 1 for witness generation
        let is_valid_column =
            self.apc().machine.main_columns().find(|c| &*c.name == "is_valid").unwrap();
        let is_valid_index = apc_poly_id_to_index[&is_valid_column.id];

        // Generate traces for each included air in parallel
        let chips_and_traces = self
            .machine
            .chips()
            .into_par_iter()
            .filter(|air| air.included(&events.record))
            .map(|air| {
                let trace = air.generate_trace(&events.record, &mut Default::default());
                (air.air.id(), trace)
            })
            .collect::<BTreeMap<_, _>>();

        // Get the AIR IDs for the original instructions
        let original_instruction_air_ids = self
            .apc()
            .block
            .instructions()
            .map(|(_pc, instr)| {
                try_instruction_type_to_air_id(InstructionType::from(instr.0))
                    .expect("Invalid instruction as an original instruction in an APC: {instr.0:?}")
            })
            .collect::<Vec<_>>();

        // Map from AIR ID to number of occurrences
        let air_id_occurrences = original_instruction_air_ids.iter().counts();

        // Vec of dummy trace row offset by original instruction index
        let instruction_index_to_table_offset = original_instruction_air_ids
            .iter()
            .scan(HashMap::default(), |counts: &mut HashMap<RiscvAirId, usize>, air_id| {
                let count = counts.entry(*air_id).or_default();
                let current_count = *count;
                *count += 1;
                Some(current_count)
            })
            .collect::<Vec<_>>();

        // Create slices of dummy values
        let dummy_values_by_event = (0..events.count)
            .into_par_iter()
            .map(|event_index| {
                original_instruction_air_ids
                    .iter()
                    .zip_eq(instruction_index_to_table_offset.iter())
                    .map(|(air_id, offset)| {
                        let dummy_table = chips_and_traces.get(air_id).unwrap();
                        let dummy_width = dummy_table.width();
                        let occurrence_per_event = *air_id_occurrences.get(air_id).unwrap();
                        let start = (event_index * occurrence_per_event + offset) * dummy_width;
                        let end = start + dummy_width;
                        &dummy_table.values[start..end]
                        // return slice so we don't allocate memory
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // A vector of HashMap<dummy_trace_index, apc_trace_index> by instruction, empty HashMap if
        // none maps to apc
        let dummy_trace_index_to_apc_index_by_instruction: Vec<HashMap<usize, usize>> = self
            .apc()
            .subs
            .iter()
            .enumerate()
            .map(|(instruction_index, substitutions)| {
                // build a map only of the (dummy_index -> apc_index) pairs
                let mut map = HashMap::new();
                for sub in substitutions {
                    let Substitution { original_poly_index, apc_poly_id } = sub;
                    let apc_index = apc_poly_id_to_index.get(apc_poly_id).unwrap();
                    tracing::trace!("Mapping dummy_index {original_poly_index} to apc_index {apc_index} for instruction {instruction_index}");
                    map.insert(*original_poly_index, *apc_index);
                }
                tracing::trace!("Map for instruction {instruction_index}: {map:?}");
                map
            })
            .collect();

        assert_eq!(
            self.apc().block.instructions().count(),
            dummy_trace_index_to_apc_index_by_instruction.len()
        );

        // Allocate final trace values
        let trace_width = self.width();
        let mut trace_values = zeroed_f_vec(events.count * trace_width);

        // Fill in the trace values and replay byte lookups in parallel, one chunk of rows per task
        let chunk_size = std::cmp::max(events.count / num_cpus::get(), 1);
        let byte_lookup_effects = trace_values
            .par_chunks_mut(chunk_size * trace_width)
            .zip_eq(dummy_values_by_event.par_chunks(chunk_size))
            .map(|(trace_chunk, dummy_chunk)| {
                // Store effects in a map of ByteLookupEvent to count to apply after parallel
                // execution
                let mut byte_lookup_effect = HashMap::new();

                for (trace_row, dummy_values_by_instruction) in
                    trace_chunk.chunks_mut(trace_width).zip_eq(dummy_chunk.iter())
                {
                    for (dummy_slice, map) in dummy_values_by_instruction
                        .iter()
                        .zip(&dummy_trace_index_to_apc_index_by_instruction)
                    {
                        // By caching `dummy_trace_index_to_apc_index_by_instruction`, we only loop
                        // over the values that are assigned to the APC instead of all values in the
                        // dummy trace
                        for (dummy_index, apc_index) in map.iter() {
                            trace_row[*apc_index] = dummy_slice[*dummy_index];
                        }
                    }

                    // Manually set is_valid column to 1
                    trace_row[is_valid_index] = F::one();

                    tracing::trace!("Final row: {trace_row:?}");

                    // Replay side effects as events
                    // Only need to do this for byte lookup bus, as other buses are implicitly
                    // balanced via main trace values rather than via events
                    let evaluator = RowEvaluator::new(trace_row, Some(&apc_poly_id_to_index));

                    for bus_interaction in
                        self.apc().machine.bus_interactions.iter().filter(|bus_interaction| {
                            bus_interaction.id == InteractionKind::Byte as u64
                        })
                    {
                        let mult = evaluator.eval_expr(&bus_interaction.mult).as_canonical_u32();
                        let mut args = bus_interaction
                            .args
                            .iter()
                            .map(|arg| evaluator.eval_expr(arg).as_canonical_u32());
                        let opcode = args.next().unwrap() as usize;
                        let a = args.next().unwrap() as u16;
                        let b = args.next().unwrap() as u8;
                        let c = args.next().unwrap() as u8;
                        assert!(args.next().is_none());

                        // byte lookup
                        *byte_lookup_effect
                            .entry(ByteLookupEvent {
                                opcode: match opcode {
                                    o if o == ByteOpcode::AND as usize => ByteOpcode::AND,
                                    o if o == ByteOpcode::OR as usize => ByteOpcode::OR,
                                    o if o == ByteOpcode::XOR as usize => ByteOpcode::XOR,
                                    o if o == ByteOpcode::U8Range as usize => ByteOpcode::U8Range,
                                    o if o == ByteOpcode::LTU as usize => ByteOpcode::LTU,
                                    o if o == ByteOpcode::MSB as usize => ByteOpcode::MSB,
                                    o if o == ByteOpcode::Range as usize => ByteOpcode::Range,
                                    _ => unreachable!("Unexpected byte lookup Opcode: {}", opcode),
                                },
                                a,
                                b,
                                c,
                            })
                            .or_insert(0) += mult as usize;
                    }
                }

                byte_lookup_effect
            })
            .collect::<Vec<_>>();

        // Apply effects after parallel execution
        for byte_lookup_effect in byte_lookup_effects {
            for (event, count) in byte_lookup_effect.iter() {
                *output.byte_lookups.entry(*event).or_insert(0) += *count as usize;
            }
        }

        // Cache the filled trace so `generate_trace_into` can restore it instead of regenerating
        // the bit-identical trace. Moves `trace_values` (unused after this point).
        self.cached_traces
            .0
            .lock()
            .unwrap()
            .insert((input.public_values.proof_nonce, input.initial_timestamp), trace_values);
    }

    fn included(&self, shard: &Self::Record) -> bool {
        shard.apc_events.get_events(self.id).is_some()
    }

    fn customize_program(&self, program: Self::Program) -> Self::Program {
        let range = ApcRange::new(
            ((self.apc().block.try_as_basic_block().unwrap().start_pc - program.pc_base)
                / Sp1Instruction::pc_step() as u64) as usize,
            self.apc().block.instructions().count(),
        );
        let apc = sp1_core_executor::Apc::new(
            range,
            self.cached_apc.width() as u64,
            self.apc().optimistic_constraints.clone(),
        );
        program.add_apc(apc)
    }
}

impl<AB: SP1AirBuilder + PairBuilder + MessageBuilder<AirInteraction<AB::Expr>>> Air<AB>
    for ApcChip<AB::F>
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let witnesses = main.row_slice(0);

        let witness_values: BTreeMap<u64, AB::Var> = self
            .cached_apc
            .columns
            .iter()
            .map(|c| c.id)
            .zip_eq(witnesses.iter().cloned())
            .collect();

        let witness_evaluator = WitnessEvaluator::<AB>::new(&witness_values);

        for constraint in &self.cached_apc.apc.machine().constraints {
            let e = witness_evaluator.eval_expr(&constraint.expr);
            builder.assert_zero(e);
        }

        for interaction in &self.cached_apc.apc.machine().bus_interactions {
            let mult = witness_evaluator.eval_expr(&interaction.mult);
            let args =
                interaction.args.iter().map(|arg| witness_evaluator.eval_expr(arg)).collect_vec();

            // All instruction AIRs only use the four buses below.
            let interaction_kind = match interaction.id {
                id if id == InteractionKind::Memory as u64 => InteractionKind::Memory,
                id if id == InteractionKind::Program as u64 => InteractionKind::Program,
                id if id == InteractionKind::Byte as u64 => InteractionKind::Byte,
                id if id == InteractionKind::State as u64 => InteractionKind::State,
                id if id == InteractionKind::InstructionFetch as u64 => {
                    InteractionKind::InstructionFetch
                }
                _ => unreachable!("Unexpected bus ID: {}", interaction.id),
            };

            let air_interaction = AirInteraction::new(args, mult, interaction_kind);

            // We only need to send, because receive is just send with negative multiplicity.
            builder.send(air_interaction, InteractionScope::Local);
        }
    }
}

pub struct WitnessEvaluator<'a, AB: AirBuilder> {
    pub witness: &'a BTreeMap<u64, AB::Var>,
}

impl<'a, AB: AirBuilder> WitnessEvaluator<'a, AB> {
    pub fn new(witness: &'a BTreeMap<u64, AB::Var>) -> Self {
        Self { witness }
    }
}

impl<AB: AirBuilder> WitnessEvaluator<'_, AB> {
    fn eval_const(&self, c: AB::F) -> AB::Expr {
        c.into()
    }

    fn eval_var(&self, symbolic_var: AlgebraicReference) -> AB::Expr {
        (*self.witness.get(&(symbolic_var.id as u64)).unwrap()).into()
    }

    fn eval_expr(&self, algebraic_expr: &AlgebraicExpression<AB::F>) -> AB::Expr {
        match algebraic_expr {
            AlgebraicExpression::Number(n) => self.eval_const(*n),
            AlgebraicExpression::BinaryOperation(binary) => match binary.op {
                AlgebraicBinaryOperator::Add => {
                    self.eval_expr(&binary.left) + self.eval_expr(&binary.right)
                }
                AlgebraicBinaryOperator::Sub => {
                    self.eval_expr(&binary.left) - self.eval_expr(&binary.right)
                }
                AlgebraicBinaryOperator::Mul => {
                    self.eval_expr(&binary.left) * self.eval_expr(&binary.right)
                }
            },
            AlgebraicExpression::UnaryOperation(unary) => match unary.op {
                AlgebraicUnaryOperator::Minus => -self.eval_expr(&unary.expr),
            },
            AlgebraicExpression::Reference(var) => self.eval_var(var.clone()),
        }
    }
}

pub struct RowEvaluator<'a, F: PrimeField32> {
    pub row: &'a [F],
    pub witness_id_to_index: Option<&'a BTreeMap<u64, usize>>,
}

impl<'a, F: PrimeField32> RowEvaluator<'a, F> {
    pub fn new(row: &'a [F], witness_id_to_index: Option<&'a BTreeMap<u64, usize>>) -> Self {
        Self { row, witness_id_to_index }
    }

    fn eval_expr(&self, algebraic_expr: &AlgebraicExpression<F>) -> F {
        match algebraic_expr {
            AlgebraicExpression::Number(n) => self.eval_const(*n),
            AlgebraicExpression::BinaryOperation(binary) => match binary.op {
                AlgebraicBinaryOperator::Add => {
                    self.eval_expr(&binary.left) + self.eval_expr(&binary.right)
                }
                AlgebraicBinaryOperator::Sub => {
                    self.eval_expr(&binary.left) - self.eval_expr(&binary.right)
                }
                AlgebraicBinaryOperator::Mul => {
                    self.eval_expr(&binary.left) * self.eval_expr(&binary.right)
                }
            },
            AlgebraicExpression::UnaryOperation(unary) => match unary.op {
                AlgebraicUnaryOperator::Minus => -self.eval_expr(&unary.expr),
            },
            AlgebraicExpression::Reference(var) => self.eval_var(var.clone()),
        }
    }

    fn eval_const(&self, c: F) -> F {
        c
    }

    fn eval_var(&self, algebraic_var: AlgebraicReference) -> F {
        let index = if let Some(witness_id_to_index) = self.witness_id_to_index {
            witness_id_to_index[&(algebraic_var.id)]
        } else {
            algebraic_var.id as usize
        };
        self.row[index]
    }
}
