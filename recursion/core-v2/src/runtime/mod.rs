pub mod instruction;
mod opcode;
mod program;
mod record;

pub use instruction::Instruction;
pub use opcode::*;
use p3_util::reverse_bits_len;
pub use program::*;
pub use record::*;

use std::borrow::Cow;
use std::{marker::PhantomData, sync::Arc};

use hashbrown::hash_map::Entry;
use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::{AbstractField, ExtensionField, PrimeField32};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{CryptographicPermutation, Permutation};

use sp1_recursion_core::air::Block;

/// TODO expand glob import once things are organized enough
use crate::*;

/// The heap pointer address.
pub const HEAP_PTR: i32 = -4;
pub const HEAP_START_ADDRESS: usize = STACK_SIZE + 4;

pub const STACK_SIZE: usize = 1 << 24;
pub const MEMORY_SIZE: usize = 1 << 28;

/// The width of the Poseidon2 permutation.
pub const PERMUTATION_WIDTH: usize = 16;
pub const POSEIDON2_SBOX_DEGREE: u64 = 7;
pub const HASH_RATE: usize = 8;

/// The current verifier implementation assumes that we are using a 256-bit hash with 32-bit elements.
pub const DIGEST_SIZE: usize = 8;

pub const NUM_BITS: usize = 31;

pub const D: usize = 4;

#[derive(Debug, Clone, Default)]
pub struct MemoryEntry<F> {
    pub val: Block<F>,
    pub mult: F,
}

#[derive(Debug, Clone, Default)]
pub struct CycleTrackerEntry {
    pub span_entered: bool,
    pub span_enter_cycle: usize,
    pub cumulative_cycles: usize,
}

/// TODO fully document.
/// Taken from [`sp1_recursion_core::runtime::Runtime`].
/// Many missing things (compared to the old `Runtime`) will need to be implemented.
pub struct Runtime<F: PrimeField32, EF: ExtensionField<F>, Diffusion> {
    pub timestamp: usize,

    pub nb_poseidons: usize,

    pub nb_ext_ops: usize,

    pub nb_base_ops: usize,

    pub nb_memory_ops: usize,

    pub nb_branch_ops: usize,

    pub nb_exp_reverse_bits: usize,

    pub nb_fri_fold: usize,

    /// The current clock.
    pub clk: F,

    /// The program counter.
    pub pc: F,

    /// The program.
    pub program: RecursionProgram<F>,

    /// Memory.
    pub memory: HashMap<Address<F>, MemoryEntry<F>>,

    /// The execution record.
    pub record: ExecutionRecord<F>,

    pub cycle_tracker: HashMap<String, CycleTrackerEntry>,

    /// Entries for dealing with the Poseidon2 hash state.
    perm: Option<
        Poseidon2<
            F,
            Poseidon2ExternalMatrixGeneral,
            Diffusion,
            PERMUTATION_WIDTH,
            POSEIDON2_SBOX_DEGREE,
        >,
    >,

    _marker_ef: PhantomData<EF>,

    _marker_diffusion: PhantomData<Diffusion>,
}

impl<F: PrimeField32, EF: ExtensionField<F>, Diffusion> Runtime<F, EF, Diffusion>
where
    Poseidon2<
        F,
        Poseidon2ExternalMatrixGeneral,
        Diffusion,
        PERMUTATION_WIDTH,
        POSEIDON2_SBOX_DEGREE,
    >: CryptographicPermutation<[F; PERMUTATION_WIDTH]>,
{
    pub fn new(
        program: &RecursionProgram<F>,
        perm: Poseidon2<
            F,
            Poseidon2ExternalMatrixGeneral,
            Diffusion,
            PERMUTATION_WIDTH,
            POSEIDON2_SBOX_DEGREE,
        >,
    ) -> Self {
        let record = ExecutionRecord::<F> {
            program: Arc::new(program.clone()),
            ..Default::default()
        };
        Self {
            timestamp: 0,
            nb_poseidons: 0,
            nb_exp_reverse_bits: 0,
            nb_ext_ops: 0,
            nb_base_ops: 0,
            nb_memory_ops: 0,
            nb_branch_ops: 0,
            nb_fri_fold: 0,
            clk: F::zero(),
            program: program.clone(),
            pc: F::zero(),
            memory: HashMap::new(),
            record,
            cycle_tracker: HashMap::new(),
            perm: Some(perm),
            _marker_ef: PhantomData,
            _marker_diffusion: PhantomData,
        }
    }

    pub fn print_stats(&self) {
        tracing::debug!("Total Cycles: {}", self.timestamp);
        tracing::debug!("Poseidon Operations: {}", self.nb_poseidons);
        tracing::debug!("Exp Reverse Bits Operations: {}", self.nb_exp_reverse_bits);
        tracing::debug!("Field Operations: {}", self.nb_base_ops);
        tracing::debug!("Extension Operations: {}", self.nb_ext_ops);
        tracing::debug!("Memory Operations: {}", self.nb_memory_ops);
        tracing::debug!("Branch Operations: {}", self.nb_branch_ops);
        for (name, entry) in self.cycle_tracker.iter().sorted_by_key(|(name, _)| *name) {
            tracing::debug!("> {}: {}", name, entry.cumulative_cycles);
        }
    }

    /// Read from a memory address. Decrements the memory entry's mult count,
    /// removing the entry if the mult is no longer positive.
    ///
    /// # Panics
    /// Panics if the address is unassigned.
    fn mr(&mut self, addr: Address<F>) -> Cow<MemoryEntry<F>> {
        self.mr_mult(addr, F::one())
    }

    /// Read from a memory address. Reduces the memory entry's mult count by the given amount,
    /// removing the entry if the mult is no longer positive.
    ///
    /// # Panics
    /// Panics if the address is unassigned.
    fn mr_mult(&mut self, addr: Address<F>, mult: F) -> Cow<MemoryEntry<F>> {
        match self.memory.entry(addr) {
            Entry::Occupied(mut entry) => {
                let entry_mult = &mut entry.get_mut().mult;
                *entry_mult -= mult;
                // We don't check for negative mult because I'm not sure how comparison in F works.
                if entry_mult.is_zero() {
                    Cow::Owned(entry.remove())
                } else {
                    Cow::Borrowed(entry.into_mut())
                }
            }
            Entry::Vacant(_) => panic!("tried to read from unassigned address: {addr:?}",),
        }
    }

    /// Write to a memory address, setting the given value and mult.
    ///
    /// # Panics
    /// Panics if the address is already assigned.
    fn mw(&mut self, addr: Address<F>, val: Block<F>, mult: F) -> &mut MemoryEntry<F> {
        match self.memory.entry(addr) {
            Entry::Occupied(entry) => panic!("tried to write to assigned address: {entry:?}"),
            Entry::Vacant(entry) => entry.insert(MemoryEntry { val, mult }),
        }
    }

    /// Compare to [sp1_recursion_core::runtime::Runtime::run].
    pub fn run(&mut self) {
        let early_exit_ts = std::env::var("RECURSION_EARLY_EXIT_TS")
            .map_or(usize::MAX, |ts: String| ts.parse().unwrap());
        while self.pc < F::from_canonical_u32(self.program.instructions.len() as u32) {
            let idx = self.pc.as_canonical_u32() as usize;
            let instruction = self.program.instructions[idx].clone();

            let next_clk = self.clk + F::from_canonical_u32(4);
            let next_pc = self.pc + F::one();
            match instruction {
                Instruction::BaseAlu(BaseAluInstr {
                    opcode,
                    mult,
                    addrs,
                }) => {
                    self.nb_base_ops += 1;
                    let in1 = self.mr(addrs.in1).val[0];
                    let in2 = self.mr(addrs.in2).val[0];
                    // Do the computation.
                    let out = match opcode {
                        BaseAluOpcode::AddF => in1 + in2,
                        BaseAluOpcode::SubF => in1 - in2,
                        BaseAluOpcode::MulF => in1 * in2,
                        BaseAluOpcode::DivF => in1.try_div(in2).unwrap_or(AbstractField::one()),
                    };
                    self.mw(addrs.out, Block::from(out), mult);
                    self.record
                        .base_alu_events
                        .push(BaseAluEvent { out, in1, in2 });
                }
                Instruction::ExtAlu(ExtAluInstr {
                    opcode,
                    mult,
                    addrs,
                }) => {
                    self.nb_ext_ops += 1;
                    let in1 = self.mr(addrs.in1).val;
                    let in2 = self.mr(addrs.in2).val;
                    // Do the computation.
                    let in1_ef = EF::from_base_slice(&in1.0);
                    let in2_ef = EF::from_base_slice(&in2.0);
                    let out_ef = match opcode {
                        ExtAluOpcode::AddE => in1_ef + in2_ef,
                        ExtAluOpcode::SubE => in1_ef - in2_ef,
                        ExtAluOpcode::MulE => in1_ef * in2_ef,
                        ExtAluOpcode::DivE => {
                            in1_ef.try_div(in2_ef).unwrap_or(AbstractField::one())
                        }
                    };
                    let out = Block::from(out_ef.as_base_slice());
                    self.mw(addrs.out, out, mult);
                    self.record
                        .ext_alu_events
                        .push(ExtAluEvent { out, in1, in2 });
                }
                Instruction::Mem(MemInstr {
                    addrs: MemIo { inner: addr },
                    vals: MemIo { inner: val },
                    mult,
                    kind,
                }) => {
                    self.nb_memory_ops += 1;
                    match kind {
                        MemAccessKind::Read => {
                            let mem_entry = self.mr_mult(addr, mult);
                            assert_eq!(
                                mem_entry.val, val,
                                "stored memory value should be the specified value"
                            );
                        }
                        MemAccessKind::Write => drop(self.mw(addr, val, mult)),
                    }
                    self.record.mem_events.push(MemEvent { inner: val });
                }
                Instruction::Poseidon2Wide(Poseidon2WideInstr {
                    addrs: Poseidon2Io { input, output },
                    mult,
                }) => {
                    self.nb_poseidons += 1;
                    let in_vals = std::array::from_fn(|i| self.mr(input[i]).val[0]);
                    let perm_output = self.perm.as_ref().unwrap().permute(in_vals);

                    perm_output.iter().enumerate().for_each(|(i, &val)| {
                        self.mw(output[i], Block::from(val), mult);
                    });
                    self.record.poseidon2_wide_events.push(Poseidon2WideEvent {
                        input: in_vals,
                        output: perm_output,
                    });
                }
                Instruction::ExpReverseBitsLen(ExpReverseBitsInstr {
                    addrs: ExpReverseBitsIo { base, exp, result },
                    mult,
                }) => {
                    self.nb_exp_reverse_bits += 1;
                    let base_val = self.mr(base).val[0];
                    let exp_bits: Vec<_> = exp.iter().map(|bit| self.mr(*bit).val[0]).collect();
                    let exp_val = exp_bits
                        .iter()
                        .enumerate()
                        .fold(0, |acc, (i, &val)| acc + val.as_canonical_u32() * (1 << i));
                    let out =
                        base_val.exp_u64(reverse_bits_len(exp_val as usize, exp_bits.len()) as u64);
                    self.mw(result, Block::from(out), mult);
                    self.record
                        .exp_reverse_bits_len_events
                        .push(ExpReverseBitsEvent {
                            result: out,
                            base: base_val,
                            exp: exp_bits,
                        });
                }

                Instruction::FriFold(FriFoldInstr {
                    single_addrs,
                    ext_single_addrs,
                    ext_vec_addrs,
                }) => {
                    self.nb_fri_fold += 1;
                    let x = self.mr(single_addrs.x).val[0];
                    let z = self.mr(ext_single_addrs.z).val;
                    let alpha = self.mr(ext_single_addrs.alpha).val;
                    let mat_opening = ext_vec_addrs
                        .mat_opening
                        .iter()
                        .map(|addr| self.mr(*addr).val)
                        .collect_vec();
                    let ps_at_z = ext_vec_addrs
                        .ps_at_z
                        .iter()
                        .map(|addr| self.mr(*addr).val)
                        .collect_vec();
                    let alpha_pow = ext_vec_addrs
                        .alpha_pow
                        .iter()
                        .map(|addr| self.mr(*addr).val)
                        .collect_vec();
                    let ro = ext_vec_addrs
                        .ro
                        .iter()
                        .map(|addr| self.mr(*addr).val)
                        .collect_vec();
                }
            }

            self.pc = next_pc;
            self.clk = next_clk;
            self.timestamp += 1;

            if self.timestamp >= early_exit_ts {
                break;
            }
        }
    }
}
