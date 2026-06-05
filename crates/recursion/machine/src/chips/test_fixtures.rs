use std::{
    borrow::BorrowMut,
    collections::{hash_map, HashMap, VecDeque},
    sync::Arc,
};

use rand::{
    distributions::{Standard, WeightedIndex},
    rngs::StdRng,
    Rng, SeedableRng,
};
use slop_algebra::{extension::BinomialExtensionField, AbstractField};
use sp1_hypercube::inner_perm;
use sp1_primitives::{SP1DiffusionMatrix, SP1Field};
use sp1_recursion_executor::{
    instruction::{HintAddCurveInstr, HintBitsInstr, HintExt2FeltsInstr, HintInstr},
    linear_program, Address, BaseAluInstr, BaseAluIo, BaseAluOpcode, Block,
    CommitPublicValuesInstr, ExecutionRecord, Executor, ExtAluInstr, ExtAluIo, ExtAluOpcode,
    ExtFeltInstr, Instruction, MemAccessKind, MemInstr, MemIo, Poseidon2Instr, Poseidon2Io,
    Poseidon2LinearLayerInstr, Poseidon2LinearLayerIo, Poseidon2SBoxInstr, Poseidon2SBoxIo,
    RecursionProgram, SelectInstr, SelectIo, RECURSIVE_PROOF_NUM_PV_ELTS,
};
use strum::VariantArray;
use tokio::sync::OnceCell;

type F = SP1Field;
type EF = BinomialExtensionField<F, 4>;

#[derive(Debug, Clone, Copy, strum::VariantArray)]
enum InsnTestable {
    BaseAlu,
    ExtAlu,
    Mem,
    Poseidon2,
    Poseidon2LinearLayer,
    Poseidon2SBox,
    ExtFelt,
    Select,
    HintBits,
    HintAddCurve,
    HintExt2Felts,
    CommitPublicValues,
    Hint,
    // We don't generate `Print` and `DebugBacktrace`. They are used for debugging only.
}

impl InsnTestable {
    const fn weight(&self) -> f64 {
        // Just pulled these numbers out of thin air. More accurate numbers could be found by
        // analyzing a representative set of programs, but it's not a big deal.
        match self {
            InsnTestable::BaseAlu => 5.0,
            InsnTestable::ExtAlu => 5.0,
            InsnTestable::Mem => 0.2,
            InsnTestable::Poseidon2 => 3.0,
            InsnTestable::Poseidon2LinearLayer => 3.0,
            InsnTestable::Poseidon2SBox => 3.0,
            InsnTestable::ExtFelt => 3.0,
            InsnTestable::Select => 3.0,
            InsnTestable::HintBits => 0.2,
            InsnTestable::HintAddCurve => 0.3,
            InsnTestable::HintExt2Felts => 1.0,
            InsnTestable::CommitPublicValues => 0.0, // We insert a single one manually.
            InsnTestable::Hint => 3.0,
        }
    }
}

type WitnessStream = VecDeque<Block<F>>;
struct PartialTestProgram {
    rng: StdRng,
    dist: WeightedIndex<f64>,
    consts: HashMap<u32, usize>,
    addrs: Vec<()>,
    instructions: Vec<Instruction<F>>,
    witness_stream: WitnessStream,
}

impl PartialTestProgram {
    fn new() -> Self {
        // Let's just add zero as a constant for now.
        let mut this = Self {
            rng: StdRng::seed_from_u64(0xDEADBEEF),
            dist: rand::distributions::WeightedIndex::new(
                InsnTestable::VARIANTS.iter().map(InsnTestable::weight),
            )
            .unwrap(),
            consts: HashMap::new(),
            addrs: Vec::new(),
            instructions: Vec::new(),
            witness_stream: VecDeque::new(),
        };
        // Add some consts or hints.
        for x in 0..10 {
            this.addr_const(x);
        }
        this
    }

    fn random_insns(mut self, len: usize) -> Self {
        for _ in 0..len {
            self = self.random_insn();
        }
        self
    }

    fn random_insn(mut self) -> Self {
        let insn = InsnTestable::VARIANTS[self.rng.sample(&self.dist)];
        self.random_one(insn)
    }

    fn alloc(&mut self) -> Address<F> {
        Address(F::from_wrapped_u64(self.alloc_usize() as u64))
    }

    fn alloc_usize(&mut self) -> usize {
        let addr = self.addrs.len();
        self.addrs.push(());
        addr
    }

    fn addr_random(&mut self) -> Address<F> {
        Address(F::from_wrapped_u64(self.rng.gen_range(0..self.addrs.len()) as u64))
    }

    fn addr_random_invertible(&mut self) -> Address<F> {
        let x = self.rng.gen_range(1..32);
        self.addr_const(x)
    }

    fn addr_const(&mut self, val: u32) -> Address<F> {
        match self.consts.entry(val) {
            hash_map::Entry::Occupied(occupied_entry) => {
                Address(F::from_wrapped_u64(*occupied_entry.get() as u64))
            }
            hash_map::Entry::Vacant(vacant_entry) => {
                // Inlined alloc_usize because lack of partial mutable borrows.
                let addr = self.addrs.len();
                self.addrs.push(());
                let addr_f = Address(F::from_wrapped_u64(addr as u64));
                self.instructions.push(Instruction::Mem(MemInstr {
                    addrs: MemIo { inner: addr_f },
                    vals: MemIo { inner: Block::from(F::from_canonical_u32(val)) },
                    mult: self.rng.sample(Standard),
                    kind: MemAccessKind::Write,
                }));
                vacant_entry.insert(addr);
                addr_f
            }
        }
    }

    fn random_one(mut self, insn: InsnTestable) -> Self {
        // See `Instruction::io_addrs`.
        // Here, be sure to generate the inputs before generating the outputs.
        let insn = match insn {
            InsnTestable::BaseAlu => {
                let opcode = match self.rng.gen_range(0..4) {
                    0 => BaseAluOpcode::AddF,
                    1 => BaseAluOpcode::SubF,
                    2 => BaseAluOpcode::MulF,
                    _ => BaseAluOpcode::DivF,
                };
                let in1 = self.addr_random();
                let in2 = if opcode == BaseAluOpcode::DivF {
                    self.addr_random_invertible()
                } else {
                    self.addr_random()
                };
                Instruction::BaseAlu(BaseAluInstr {
                    opcode,
                    mult: self.rng.sample(Standard),
                    addrs: BaseAluIo { out: self.alloc(), in1, in2 },
                })
            }
            InsnTestable::ExtAlu => {
                let opcode = match self.rng.gen_range(0..4) {
                    0 => ExtAluOpcode::AddE,
                    1 => ExtAluOpcode::SubE,
                    2 => ExtAluOpcode::MulE,
                    _ => ExtAluOpcode::DivE,
                };
                let in1 = self.addr_random();
                let in2 = if opcode == ExtAluOpcode::DivE {
                    self.addr_random_invertible()
                } else {
                    self.addr_random()
                };
                Instruction::ExtAlu(ExtAluInstr {
                    opcode,
                    mult: self.rng.sample(Standard),
                    addrs: ExtAluIo { out: self.alloc(), in1, in2 },
                })
            }
            InsnTestable::Mem => Instruction::Mem(MemInstr {
                addrs: MemIo { inner: self.alloc() },
                vals: MemIo { inner: Block(self.rng.sample(Standard)) },
                mult: self.rng.sample(Standard),
                kind: MemAccessKind::Write,
            }),
            InsnTestable::Poseidon2 => {
                let input = core::array::from_fn(|_| self.addr_random());
                Instruction::Poseidon2(Box::new(Poseidon2Instr {
                    addrs: Poseidon2Io { input, output: core::array::from_fn(|_| self.alloc()) },
                    mults: self.rng.sample(Standard),
                }))
            }
            InsnTestable::Poseidon2LinearLayer => {
                let input = core::array::from_fn(|_| self.addr_random());
                Instruction::Poseidon2LinearLayer(Box::new(Poseidon2LinearLayerInstr {
                    addrs: Poseidon2LinearLayerIo {
                        input,
                        output: core::array::from_fn(|_| self.alloc()),
                    },
                    // Tested by an assertion in the generate_trace function.
                    mults: core::array::from_fn(|_| F::one()),
                    external: self.rng.sample(Standard),
                }))
            }
            InsnTestable::Poseidon2SBox => {
                let input = self.addr_random();
                Instruction::Poseidon2SBox(Poseidon2SBoxInstr {
                    addrs: Poseidon2SBoxIo { input, output: self.alloc() },
                    // Tested by an assertion in the generate_trace function.
                    mults: F::one(),
                    external: self.rng.sample(Standard),
                })
            }
            InsnTestable::ExtFelt => {
                let ext2felt = self.rng.sample(Standard);
                let addrs = if ext2felt {
                    core::array::from_fn(|i| if i == 0 { self.addr_random() } else { self.alloc() })
                } else {
                    // Need to get the inputs first.
                    let inputs: [Address<F>; 4] = core::array::from_fn(|_| self.addr_random());
                    core::array::from_fn(|i| if i == 0 { self.alloc() } else { inputs[i - 1] })
                };
                Instruction::ExtFelt(ExtFeltInstr {
                    addrs,
                    mults: self.rng.sample(Standard),
                    ext2felt,
                })
            }
            InsnTestable::Select => {
                let [bit, in1, in2] = core::array::from_fn(|_| self.addr_random());
                Instruction::Select(SelectInstr {
                    addrs: SelectIo {
                        bit, // Not a 0 or 1, but the current tests don't enforce constraints.
                        out1: self.alloc(),
                        out2: self.alloc(),
                        in1,
                        in2,
                    },
                    mult1: self.rng.sample(Standard),
                    mult2: self.rng.sample(Standard),
                })
            }
            InsnTestable::HintBits => {
                let len = self.rng.gen_range(0..32);
                let input_addr = self.addr_random();
                Instruction::HintBits(HintBitsInstr {
                    output_addrs_mults: core::iter::repeat_with(|| {
                        let addr = self.alloc();
                        let mult = self.rng.sample(Standard);
                        (addr, mult)
                    })
                    .take(len)
                    .collect(),
                    input_addr,
                })
            }
            InsnTestable::HintAddCurve => {
                // The hash-to-curve curve is over a degree 7 extension of the base field.
                let len = 7;
                let [input1_x_addrs, input1_y_addrs, input2_x_addrs, input2_y_addrs] =
                    core::array::from_fn(|_| {
                        core::iter::repeat_with(|| self.addr_random()).take(len).collect()
                    });
                let [output_x_addrs_mults, output_y_addrs_mults] = core::array::from_fn(|_| {
                    core::iter::repeat_with(|| {
                        let addr = self.alloc();
                        let mult = self.rng.sample(Standard);
                        (addr, mult)
                    })
                    .take(len)
                    .collect()
                });
                Instruction::HintAddCurve(Box::new(HintAddCurveInstr {
                    output_x_addrs_mults,
                    output_y_addrs_mults,
                    input1_x_addrs,
                    input1_y_addrs,
                    input2_x_addrs,
                    input2_y_addrs,
                }))
            }
            InsnTestable::HintExt2Felts => {
                let input_addr = self.addr_random();
                Instruction::HintExt2Felts(HintExt2FeltsInstr {
                    input_addr,
                    output_addrs_mults: core::array::from_fn(|_| {
                        let addr = self.alloc();
                        let mult = self.rng.sample(Standard);
                        (addr, mult)
                    }),
                })
            }
            InsnTestable::CommitPublicValues => {
                Instruction::CommitPublicValues(Box::new(CommitPublicValuesInstr {
                    pv_addrs: {
                        let mut ret: [Address<F>; RECURSIVE_PROOF_NUM_PV_ELTS] =
                            core::array::from_fn(|_| self.addr_random());
                        *ret.as_mut_slice().borrow_mut()
                    },
                }))
            }
            InsnTestable::Hint => {
                let len = self.rng.gen_range(0..32);
                self.witness_stream
                    .extend((&mut self.rng).sample_iter(Standard).map(Block).take(len));
                Instruction::Hint(HintInstr {
                    output_addrs_mults: core::iter::repeat_with(|| {
                        let addr = self.alloc();
                        let mult = self.rng.sample(Standard);
                        (addr, mult)
                    })
                    .take(len)
                    .collect(),
                })
            }
        };
        self.instructions.push(insn);
        self
    }

    fn finish(mut self) -> (Arc<RecursionProgram<F>>, WitnessStream) {
        // Add a single `CommitPublicValues` instruction.
        self = self.random_one(InsnTestable::CommitPublicValues);
        let program = Arc::new(
            linear_program(self.instructions).expect("recursion test program should validate"),
        );
        (program, self.witness_stream)
    }
}

/// Gets a randomly generated program and witness stream. The program has been validated and will
/// execute successfully given the witness stream. However it cannot be proved for multiple reasons:
///
/// - All the multiplicities are randomly generated.
/// - Any "extra" constraints, like requiring that Select's `bit` is 0 or 1, are not observed.
///
/// It is possible to write "mult backfill" code like in the recursion compiler, but this is not
/// currently necessary for tests.
pub async fn program_with_input() -> &'static (Arc<RecursionProgram<F>>, WitnessStream) {
    static PROGRAM: OnceCell<(Arc<RecursionProgram<F>>, WitnessStream)> = OnceCell::const_new();
    PROGRAM
        .get_or_init(|| std::future::ready(PartialTestProgram::new().random_insns(100000).finish()))
        .await
}

/// The `ExecutionRecord` obtained by running the result of [`program_with_input`]. It is unprovable
/// -- see the documentation of [`program_with_input`] for more details.
pub async fn shard() -> &'static ExecutionRecord<SP1Field> {
    static RECORD: OnceCell<ExecutionRecord<F>> = OnceCell::const_new();
    RECORD
        .get_or_init(|| async {
            let (program, witness_stream) = program_with_input().await;
            let mut executor =
                Executor::<F, EF, SP1DiffusionMatrix>::new(program.clone(), inner_perm());
            executor.witness_stream = witness_stream.clone();
            executor.run().unwrap();
            assert!(executor.witness_stream.is_empty());
            executor.record
        })
        .await
}

/// If the test program is big enough, everything should have strictly more rows than the minimum
/// number of rows, which is 16. See [`sp1_hypercube::next_multiple_of_32`].
pub const MIN_ROWS: usize = 16;
