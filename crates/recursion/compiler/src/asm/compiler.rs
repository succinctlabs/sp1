use alloc::{collections::BTreeMap, vec};
use backtrace::Backtrace;
use sp1_recursion_core::runtime::{HEAP_PTR, HEAP_START_ADDRESS};
use std::collections::BTreeSet;

use p3_field::{ExtensionField, PrimeField32, TwoAdicField};
use sp1_recursion_core::runtime::RecursionProgram;

use super::{config::AsmConfig, AssemblyCode, BasicBlock, IndexTriple, ValueOrConst};
use crate::{
    asm::AsmInstruction,
    ir::{Array, DslIr, Ext, Felt, Ptr, Usize, Var},
    prelude::TracedVec,
};

/// The zero address.
pub(crate) const ZERO: i32 = 0;

/// The offset which the stack starts.
pub(crate) const STACK_START_OFFSET: i32 = 16;

/// The address of A0.
pub(crate) const A0: i32 = -8;

/// The assembly compiler.
#[derive(Debug, Clone, Default)]
pub struct AsmCompiler<F, EF> {
    basic_blocks: Vec<BasicBlock<F, EF>>,
    break_label: Option<F>,
    break_label_map: BTreeMap<F, F>,
    break_counter: usize,
    contains_break: BTreeSet<F>,
    function_labels: BTreeMap<String, F>,
}

impl<F> Var<F> {
    /// Gets the frame pointer for a var.
    pub const fn fp(&self) -> i32 {
        -((self.idx as i32) * 3 + 1 + STACK_START_OFFSET)
    }
}

impl<F> Felt<F> {
    /// Gets the frame pointer for a felt.
    pub const fn fp(&self) -> i32 {
        -((self.idx as i32) * 3 + 2 + STACK_START_OFFSET)
    }
}

impl<F, EF> Ext<F, EF> {
    /// Gets the frame pointer for an extension element
    pub const fn fp(&self) -> i32 {
        -((self.idx as i32) * 3 + STACK_START_OFFSET)
    }
}

impl<F> Ptr<F> {
    /// Gets the frame pointer for a pointer.
    pub const fn fp(&self) -> i32 {
        self.address.fp()
    }
}

impl<F: PrimeField32 + TwoAdicField, EF: ExtensionField<F> + TwoAdicField> AsmCompiler<F, EF> {
    /// Creates a new [AsmCompiler].
    pub fn new() -> Self {
        Self {
            basic_blocks: vec![BasicBlock::new()],
            break_label: None,
            break_label_map: BTreeMap::new(),
            contains_break: BTreeSet::new(),
            function_labels: BTreeMap::new(),
            break_counter: 0,
        }
    }

    /// Creates a new break label.
    pub fn new_break_label(&mut self) -> F {
        let label = self.break_counter;
        self.break_counter += 1;
        let label = F::from_canonical_usize(label);
        self.break_label = Some(label);
        label
    }

    /// Builds the operations into assembly instructions.
    pub fn build(&mut self, operations: TracedVec<DslIr<AsmConfig<F, EF>>>) {
        // Set the heap pointer value according to stack size.
        if self.block_label().is_zero() {
            let stack_size = F::from_canonical_usize(HEAP_START_ADDRESS);
            self.push(AsmInstruction::AddFI(HEAP_PTR, ZERO, stack_size), None);
        }

        // For each operation, generate assembly instructions.
        for (op, trace) in operations.clone() {
            match op {
                DslIr::ImmV(dst, src) => {
                    self.push(AsmInstruction::AddFI(dst.fp(), ZERO, src), trace);
                }
                DslIr::ImmF(dst, src) => {
                    self.push(AsmInstruction::AddFI(dst.fp(), ZERO, src), trace);
                }
                DslIr::ImmE(dst, src) => {
                    self.push(AsmInstruction::AddEI(dst.fp(), ZERO, src), trace);
                }
                DslIr::AddV(dst, lhs, rhs) => {
                    self.push(AsmInstruction::AddF(dst.fp(), lhs.fp(), rhs.fp()), trace);
                }
                DslIr::AddVI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::AddFI(dst.fp(), lhs.fp(), rhs), trace);
                }
                DslIr::AddF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::AddF(dst.fp(), lhs.fp(), rhs.fp()), trace);
                }
                DslIr::AddFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::AddFI(dst.fp(), lhs.fp(), rhs), trace);
                }
                DslIr::AddE(dst, lhs, rhs) => {
                    self.push(AsmInstruction::AddE(dst.fp(), lhs.fp(), rhs.fp()), trace);
                }
                DslIr::AddEI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::AddEI(dst.fp(), lhs.fp(), rhs), trace);
                }
                DslIr::AddEF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::AddE(dst.fp(), lhs.fp(), rhs.fp()), trace);
                }
                DslIr::AddEFFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::AddEI(dst.fp(), lhs.fp(), rhs), trace);
                }
                DslIr::AddEFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::AddEI(dst.fp(), lhs.fp(), EF::from_base(rhs)), trace);
                }
                DslIr::SubV(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SubF(dst.fp(), lhs.fp(), rhs.fp()), trace);
                }
                DslIr::SubVI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SubFI(dst.fp(), lhs.fp(), rhs), trace);
                }
                DslIr::SubVIN(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SubFIN(dst.fp(), lhs, rhs.fp()), trace);
                }
                DslIr::SubF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SubF(dst.fp(), lhs.fp(), rhs.fp()), trace);
                }
                DslIr::SubFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SubFI(dst.fp(), lhs.fp(), rhs), trace);
                }
                DslIr::SubFIN(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SubFIN(dst.fp(), lhs, rhs.fp()), trace);
                }
                DslIr::NegV(dst, src) => {
                    self.push(AsmInstruction::SubFIN(dst.fp(), F::zero(), src.fp()), trace);
                }
                DslIr::NegF(dst, src) => {
                    self.push(AsmInstruction::SubFIN(dst.fp(), F::zero(), src.fp()), trace);
                }
                DslIr::DivF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::DivF(dst.fp(), lhs.fp(), rhs.fp()), trace);
                }
                DslIr::DivFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::DivFI(dst.fp(), lhs.fp(), rhs), trace);
                }
                DslIr::DivFIN(dst, lhs, rhs) => {
                    self.push(AsmInstruction::DivFIN(dst.fp(), lhs, rhs.fp()), trace);
                }
                DslIr::InvV(dst, src) => {
                    self.push(AsmInstruction::DivFIN(dst.fp(), F::one(), src.fp()), trace);
                }
                DslIr::InvF(dst, src) => {
                    self.push(AsmInstruction::DivFIN(dst.fp(), F::one(), src.fp()), trace);
                }
                DslIr::DivEF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::DivE(dst.fp(), lhs.fp(), rhs.fp()), trace);
                }
                DslIr::DivEFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::DivEI(dst.fp(), lhs.fp(), EF::from_base(rhs)), trace);
                }
                DslIr::DivEIN(dst, lhs, rhs) => {
                    self.push(AsmInstruction::DivEIN(dst.fp(), lhs, rhs.fp()), trace);
                }
                DslIr::DivEFIN(dst, lhs, rhs) => {
                    self.push(
                        AsmInstruction::DivEIN(dst.fp(), EF::from_base(lhs), rhs.fp()),
                        trace,
                    );
                }
                DslIr::DivE(dst, lhs, rhs) => {
                    self.push(AsmInstruction::DivE(dst.fp(), lhs.fp(), rhs.fp()), trace);
                }
                DslIr::DivEI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::DivEI(dst.fp(), lhs.fp(), rhs), trace);
                }
                DslIr::InvE(dst, src) => {
                    self.push(AsmInstruction::DivEIN(dst.fp(), EF::one(), src.fp()), trace);
                }
                DslIr::SubEF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SubE(dst.fp(), lhs.fp(), rhs.fp()), trace);
                }
                DslIr::SubEFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SubEI(dst.fp(), lhs.fp(), EF::from_base(rhs)), trace);
                }
                DslIr::SubEIN(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SubEIN(dst.fp(), lhs, rhs.fp()), trace);
                }
                DslIr::SubE(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SubE(dst.fp(), lhs.fp(), rhs.fp()), trace);
                }
                DslIr::SubEI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::SubEI(dst.fp(), lhs.fp(), rhs), trace);
                }
                DslIr::NegE(dst, src) => {
                    self.push(AsmInstruction::SubEIN(dst.fp(), EF::zero(), src.fp()), trace);
                }
                DslIr::MulV(dst, lhs, rhs) => {
                    self.push(AsmInstruction::MulF(dst.fp(), lhs.fp(), rhs.fp()), trace);
                }
                DslIr::MulVI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::MulFI(dst.fp(), lhs.fp(), rhs), trace);
                }
                DslIr::MulF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::MulF(dst.fp(), lhs.fp(), rhs.fp()), trace);
                }
                DslIr::MulFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::MulFI(dst.fp(), lhs.fp(), rhs), trace);
                }
                DslIr::MulE(dst, lhs, rhs) => {
                    self.push(AsmInstruction::MulE(dst.fp(), lhs.fp(), rhs.fp()), trace);
                }
                DslIr::MulEI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::MulEI(dst.fp(), lhs.fp(), rhs), trace);
                }
                DslIr::MulEF(dst, lhs, rhs) => {
                    self.push(AsmInstruction::MulE(dst.fp(), lhs.fp(), rhs.fp()), trace);
                }
                DslIr::MulEFI(dst, lhs, rhs) => {
                    self.push(AsmInstruction::MulEI(dst.fp(), lhs.fp(), EF::from_base(rhs)), trace);
                }
                DslIr::IfEq(data) => {
                    let (lhs, rhs, then_block, else_block) = *data;
                    let if_compiler = IfCompiler {
                        compiler: self,
                        lhs: lhs.fp(),
                        rhs: ValueOrConst::Val(rhs.fp()),
                        is_eq: true,
                    };
                    if else_block.is_empty() {
                        if_compiler.then(|builder| builder.build(then_block));
                    } else {
                        if_compiler.then_or_else(
                            |builder| builder.build(then_block),
                            |builder| builder.build(else_block),
                        );
                    }
                }
                DslIr::IfNe(data) => {
                    let (lhs, rhs, then_block, else_block) = *data;
                    let if_compiler = IfCompiler {
                        compiler: self,
                        lhs: lhs.fp(),
                        rhs: ValueOrConst::Val(rhs.fp()),
                        is_eq: false,
                    };
                    if else_block.is_empty() {
                        if_compiler.then(|builder| builder.build(then_block));
                    } else {
                        if_compiler.then_or_else(
                            |builder| builder.build(then_block),
                            |builder| builder.build(else_block),
                        );
                    }
                }
                DslIr::IfEqI(data) => {
                    let (lhs, rhs, then_block, else_block) = *data;
                    let if_compiler = IfCompiler {
                        compiler: self,
                        lhs: lhs.fp(),
                        rhs: ValueOrConst::Const(rhs),
                        is_eq: true,
                    };
                    if else_block.is_empty() {
                        if_compiler.then(|builder| builder.build(then_block));
                    } else {
                        if_compiler.then_or_else(
                            |builder| builder.build(then_block),
                            |builder| builder.build(else_block),
                        );
                    }
                }
                DslIr::IfNeI(data) => {
                    let (lhs, rhs, then_block, else_block) = *data;
                    let if_compiler = IfCompiler {
                        compiler: self,
                        lhs: lhs.fp(),
                        rhs: ValueOrConst::Const(rhs),
                        is_eq: false,
                    };
                    if else_block.is_empty() {
                        if_compiler.then(|builder| builder.build(then_block));
                    } else {
                        if_compiler.then_or_else(
                            |builder| builder.build(then_block),
                            |builder| builder.build(else_block),
                        );
                    }
                }
                DslIr::Break => {
                    let label = self.break_label.expect("No break label set");
                    let current_block = self.block_label();
                    self.contains_break.insert(current_block);
                    self.push(AsmInstruction::Break(label), trace);
                }
                DslIr::For(data) => {
                    let (start, end, step_size, loop_var, block) = *data;
                    let for_compiler =
                        ForCompiler { compiler: self, start, end, step_size, loop_var };
                    for_compiler.for_each(move |_, builder| builder.build(block));
                }
                DslIr::AssertEqV(lhs, rhs) => {
                    // If lhs != rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::Val(rhs.fp()), false, trace)
                }
                DslIr::AssertEqVI(lhs, rhs) => {
                    // If lhs != rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::Const(rhs), false, trace)
                }
                DslIr::AssertNeV(lhs, rhs) => {
                    // If lhs == rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::Val(rhs.fp()), true, trace)
                }
                DslIr::AssertNeVI(lhs, rhs) => {
                    // If lhs == rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::Const(rhs), true, trace)
                }
                DslIr::AssertEqF(lhs, rhs) => {
                    // If lhs != rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::Val(rhs.fp()), false, trace)
                }
                DslIr::AssertEqFI(lhs, rhs) => {
                    // If lhs != rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::Const(rhs), false, trace)
                }
                DslIr::AssertNeF(lhs, rhs) => {
                    // If lhs == rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::Val(rhs.fp()), true, trace)
                }
                DslIr::AssertNeFI(lhs, rhs) => {
                    // If lhs == rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::Const(rhs), true, trace)
                }
                DslIr::AssertEqE(lhs, rhs) => {
                    // If lhs != rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::ExtVal(rhs.fp()), false, trace)
                }
                DslIr::AssertEqEI(lhs, rhs) => {
                    // If lhs != rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::ExtConst(rhs), false, trace)
                }
                DslIr::AssertNeE(lhs, rhs) => {
                    // If lhs == rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::ExtVal(rhs.fp()), true, trace)
                }
                DslIr::AssertNeEI(lhs, rhs) => {
                    // If lhs == rhs, execute TRAP
                    self.assert(lhs.fp(), ValueOrConst::ExtConst(rhs), true, trace)
                }
                DslIr::Alloc(ptr, len, size) => {
                    self.alloc(ptr, len, size, trace);
                }
                DslIr::LoadV(var, ptr, index) => match index.fp() {
                    IndexTriple::Const(index, offset, size) => self.push(
                        AsmInstruction::LoadFI(var.fp(), ptr.fp(), index, offset, size),
                        trace,
                    ),
                    IndexTriple::Var(index, offset, size) => self.push(
                        AsmInstruction::LoadF(var.fp(), ptr.fp(), index, offset, size),
                        trace,
                    ),
                },
                DslIr::LoadF(var, ptr, index) => match index.fp() {
                    IndexTriple::Const(index, offset, size) => self.push(
                        AsmInstruction::LoadFI(var.fp(), ptr.fp(), index, offset, size),
                        trace,
                    ),
                    IndexTriple::Var(index, offset, size) => self.push(
                        AsmInstruction::LoadF(var.fp(), ptr.fp(), index, offset, size),
                        trace,
                    ),
                },
                DslIr::LoadE(var, ptr, index) => match index.fp() {
                    IndexTriple::Const(index, offset, size) => self.push(
                        AsmInstruction::LoadEI(var.fp(), ptr.fp(), index, offset, size),
                        trace,
                    ),
                    IndexTriple::Var(index, offset, size) => self.push(
                        AsmInstruction::LoadE(var.fp(), ptr.fp(), index, offset, size),
                        trace,
                    ),
                },
                DslIr::StoreV(var, ptr, index) => match index.fp() {
                    IndexTriple::Const(index, offset, size) => self.push(
                        AsmInstruction::StoreFI(var.fp(), ptr.fp(), index, offset, size),
                        trace,
                    ),
                    IndexTriple::Var(index, offset, size) => self.push(
                        AsmInstruction::StoreF(var.fp(), ptr.fp(), index, offset, size),
                        trace,
                    ),
                },
                DslIr::StoreF(var, ptr, index) => match index.fp() {
                    IndexTriple::Const(index, offset, size) => self.push(
                        AsmInstruction::StoreFI(var.fp(), ptr.fp(), index, offset, size),
                        trace,
                    ),
                    IndexTriple::Var(index, offset, size) => self.push(
                        AsmInstruction::StoreF(var.fp(), ptr.fp(), index, offset, size),
                        trace,
                    ),
                },
                DslIr::StoreE(var, ptr, index) => match index.fp() {
                    IndexTriple::Const(index, offset, size) => self.push(
                        AsmInstruction::StoreEI(var.fp(), ptr.fp(), index, offset, size),
                        trace,
                    ),
                    IndexTriple::Var(index, offset, size) => self.push(
                        AsmInstruction::StoreE(var.fp(), ptr.fp(), index, offset, size),
                        trace,
                    ),
                },

                DslIr::HintBitsU(dst, src) => match (dst, src) {
                    (Array::Dyn(dst, _), Usize::Var(src)) => {
                        self.push(AsmInstruction::HintBits(dst.fp(), src.fp()), trace);
                    }
                    _ => unimplemented!(),
                },
                DslIr::HintBitsF(dst, src) => match dst {
                    Array::Dyn(dst, _) => {
                        self.push(AsmInstruction::HintBits(dst.fp(), src.fp()), trace);
                    }
                    _ => unimplemented!(),
                },
                DslIr::HintBitsV(dst, src) => match dst {
                    Array::Dyn(dst, _) => {
                        self.push(AsmInstruction::HintBits(dst.fp(), src.fp()), trace);
                    }
                    _ => unimplemented!(),
                },
                DslIr::Poseidon2PermuteBabyBear(data) => match *data {
                    (Array::Dyn(dst, _), Array::Dyn(src, _)) => {
                        self.push(AsmInstruction::Poseidon2Permute(dst.fp(), src.fp()), trace)
                    }
                    _ => unimplemented!(),
                },
                DslIr::Error() => self.push(AsmInstruction::Trap, trace),
                DslIr::PrintF(dst) => self.push(AsmInstruction::PrintF(dst.fp()), trace),
                DslIr::PrintV(dst) => self.push(AsmInstruction::PrintV(dst.fp()), trace),
                DslIr::PrintE(dst) => self.push(AsmInstruction::PrintE(dst.fp()), trace),
                DslIr::HintExt2Felt(dst, src) => match (dst, src) {
                    (Array::Dyn(dst, _), src) => {
                        self.push(AsmInstruction::HintExt2Felt(dst.fp(), src.fp()), trace)
                    }
                    _ => unimplemented!(),
                },
                DslIr::HintLen(dst) => self.push(AsmInstruction::HintLen(dst.fp()), trace),
                DslIr::HintVars(dst) => match dst {
                    Array::Dyn(dst, _) => self.push(AsmInstruction::Hint(dst.fp()), trace),
                    _ => unimplemented!(),
                },
                DslIr::HintFelts(dst) => match dst {
                    Array::Dyn(dst, _) => self.push(AsmInstruction::Hint(dst.fp()), trace),
                    _ => unimplemented!(),
                },
                DslIr::HintExts(dst) => match dst {
                    Array::Dyn(dst, _) => self.push(AsmInstruction::Hint(dst.fp()), trace),
                    _ => unimplemented!(),
                },
                DslIr::FriFold(m, input_ptr) => {
                    if let Array::Dyn(ptr, _) = input_ptr {
                        self.push(AsmInstruction::FriFold(m.fp(), ptr.fp()), trace);
                    } else {
                        unimplemented!();
                    }
                }
                DslIr::Poseidon2CompressBabyBear(data) => match *data {
                    (Array::Dyn(result, _), Array::Dyn(left, _), Array::Dyn(right, _)) => self
                        .push(
                            AsmInstruction::Poseidon2Compress(result.fp(), left.fp(), right.fp()),
                            trace,
                        ),
                    _ => unimplemented!(),
                },
                DslIr::Poseidon2AbsorbBabyBear(p2_hash_and_absorb_num, input) => match input {
                    Array::Dyn(input, input_size) => {
                        if let Usize::Var(input_size) = input_size {
                            self.push(
                                AsmInstruction::Poseidon2Absorb(
                                    p2_hash_and_absorb_num.fp(),
                                    input.fp(),
                                    input_size.fp(),
                                ),
                                trace,
                            );
                        } else {
                            unimplemented!();
                        }
                    }
                    _ => unimplemented!(),
                },
                DslIr::Poseidon2FinalizeBabyBear(p2_hash_num, output) => match output {
                    Array::Dyn(output, _) => {
                        self.push(
                            AsmInstruction::Poseidon2Finalize(p2_hash_num.fp(), output.fp()),
                            trace,
                        );
                    }
                    _ => unimplemented!(),
                },
                DslIr::Commit(val, index) => {
                    self.push(AsmInstruction::Commit(val.fp(), index.fp()), trace);
                }
                DslIr::RegisterPublicValue(val) => {
                    self.push(AsmInstruction::RegisterPublicValue(val.fp()), trace);
                }
                DslIr::LessThan(dst, left, right) => {
                    self.push(AsmInstruction::LessThan(dst.fp(), left.fp(), right.fp()), trace);
                }
                DslIr::CycleTracker(name) => {
                    self.push(AsmInstruction::CycleTracker(name.clone()), trace);
                }
                DslIr::Halt => {
                    self.push(AsmInstruction::Halt, trace);
                }
                DslIr::ExpReverseBitsLen(base, ptr, len) => {
                    self.push(
                        AsmInstruction::ExpReverseBitsLen(base.fp(), ptr.fp(), len.fp()),
                        trace,
                    );
                }
                _ => unimplemented!(),
            }
        }
    }

    pub fn alloc(&mut self, ptr: Ptr<F>, len: Usize<F>, size: usize, backtrace: Option<Backtrace>) {
        // Load the current heap ptr address to the stack value and advance the heap ptr.
        let size = F::from_canonical_usize(size);
        match len {
            Usize::Const(len) => {
                let len = F::from_canonical_usize(len);
                self.push(AsmInstruction::AddFI(ptr.fp(), HEAP_PTR, F::zero()), backtrace.clone());
                self.push(AsmInstruction::AddFI(HEAP_PTR, HEAP_PTR, len * size), backtrace);
            }
            Usize::Var(len) => {
                self.push(AsmInstruction::AddFI(ptr.fp(), HEAP_PTR, F::zero()), backtrace.clone());
                self.push(AsmInstruction::MulFI(A0, len.fp(), size), backtrace.clone());
                self.push(AsmInstruction::AddF(HEAP_PTR, HEAP_PTR, A0), backtrace);
            }
        }
    }

    pub fn assert(
        &mut self,
        lhs: i32,
        rhs: ValueOrConst<F, EF>,
        is_eq: bool,
        backtrace: Option<Backtrace>,
    ) {
        let if_compiler = IfCompiler { compiler: self, lhs, rhs, is_eq };
        if_compiler.then(|builder| builder.push(AsmInstruction::Trap, backtrace));
    }

    pub fn code(self) -> AssemblyCode<F, EF> {
        let labels = self.function_labels.into_iter().map(|(k, v)| (v, k)).collect();
        AssemblyCode::new(self.basic_blocks, labels)
    }

    pub fn compile(self) -> RecursionProgram<F> {
        let code = self.code();
        tracing::debug!("recursion program size: {}", code.size());
        code.machine_code()
    }

    fn basic_block(&mut self) {
        self.basic_blocks.push(BasicBlock::new());
    }

    fn block_label(&mut self) -> F {
        F::from_canonical_usize(self.basic_blocks.len() - 1)
    }

    fn push_to_block(
        &mut self,
        block_label: F,
        instruction: AsmInstruction<F, EF>,
        backtrace: Option<Backtrace>,
    ) {
        self.basic_blocks
            .get_mut(block_label.as_canonical_u32() as usize)
            .unwrap_or_else(|| panic!("Missing block at label: {:?}", block_label))
            .push(instruction, backtrace);
    }

    fn push(&mut self, instruction: AsmInstruction<F, EF>, backtrace: Option<Backtrace>) {
        self.basic_blocks.last_mut().unwrap().push(instruction, backtrace);
    }
}

pub struct IfCompiler<'a, F, EF> {
    compiler: &'a mut AsmCompiler<F, EF>,
    lhs: i32,
    rhs: ValueOrConst<F, EF>,
    is_eq: bool,
}

impl<'a, F: PrimeField32 + TwoAdicField, EF: ExtensionField<F> + TwoAdicField>
    IfCompiler<'a, F, EF>
{
    pub fn then<Func>(self, f: Func)
    where
        Func: FnOnce(&mut AsmCompiler<F, EF>),
    {
        let Self { compiler, lhs, rhs, is_eq } = self;

        // Get the label for the current block.
        let current_block = compiler.block_label();

        // Generate the blocks for the then branch.
        compiler.basic_block();
        f(compiler);

        // Generate the block for returning to the main flow.
        compiler.basic_block();
        let after_if_block = compiler.block_label();

        // Get the branch instruction to push to the `current_block`.
        let instr = Self::branch(lhs, rhs, is_eq, after_if_block);
        compiler.push_to_block(current_block, instr, None);
    }

    pub fn then_or_else<ThenFunc, ElseFunc>(self, then_f: ThenFunc, else_f: ElseFunc)
    where
        ThenFunc: FnOnce(&mut AsmCompiler<F, EF>),
        ElseFunc: FnOnce(&mut AsmCompiler<F, EF>),
    {
        let Self { compiler, lhs, rhs, is_eq } = self;

        // Get the label for the current block, so we can generate the jump instruction into it.
        // conditional branc instruction to it, if the condition is not met.
        let if_branching_block = compiler.block_label();

        // Generate the block for the then branch.
        compiler.basic_block();
        then_f(compiler);
        let last_if_block = compiler.block_label();

        // Generate the block for the else branch.
        compiler.basic_block();
        let else_block = compiler.block_label();
        else_f(compiler);

        // Generate the jump instruction to the else block
        let instr = Self::branch(lhs, rhs, is_eq, else_block);
        compiler.push_to_block(if_branching_block, instr, None);

        // Generate the block for returning to the main flow.
        compiler.basic_block();
        let main_flow_block = compiler.block_label();
        let instr = AsmInstruction::j(main_flow_block);
        compiler.push_to_block(last_if_block, instr, None);
    }

    const fn branch(
        lhs: i32,
        rhs: ValueOrConst<F, EF>,
        is_eq: bool,
        block: F,
    ) -> AsmInstruction<F, EF> {
        match (rhs, is_eq) {
            (ValueOrConst::Const(rhs), true) => AsmInstruction::BneI(block, lhs, rhs),
            (ValueOrConst::Const(rhs), false) => AsmInstruction::BeqI(block, lhs, rhs),
            (ValueOrConst::ExtConst(rhs), true) => AsmInstruction::BneEI(block, lhs, rhs),
            (ValueOrConst::ExtConst(rhs), false) => AsmInstruction::BeqEI(block, lhs, rhs),
            (ValueOrConst::Val(rhs), true) => AsmInstruction::Bne(block, lhs, rhs),
            (ValueOrConst::Val(rhs), false) => AsmInstruction::Beq(block, lhs, rhs),
            (ValueOrConst::ExtVal(rhs), true) => AsmInstruction::BneE(block, lhs, rhs),
            (ValueOrConst::ExtVal(rhs), false) => AsmInstruction::BeqE(block, lhs, rhs),
        }
    }
}

/// A builder for a for loop.
///
/// SAFETY: Starting with end < start will lead to undefined behavior.
pub struct ForCompiler<'a, F, EF> {
    compiler: &'a mut AsmCompiler<F, EF>,
    start: Usize<F>,
    end: Usize<F>,
    step_size: F,
    loop_var: Var<F>,
}

impl<'a, F: PrimeField32 + TwoAdicField, EF: ExtensionField<F> + TwoAdicField>
    ForCompiler<'a, F, EF>
{
    pub(super) fn for_each(mut self, f: impl FnOnce(Var<F>, &mut AsmCompiler<F, EF>)) {
        // The function block structure:
        // - Setting the loop range
        // - Executing the loop body and incrementing the loop variable
        // - the loop condition
        // Set the loop variable to the start of the range.

        // Set the loop variable to the start of the range.
        self.set_loop_var();

        // Save the label of the for loop call.
        let loop_call_label = self.compiler.block_label();

        // Initialize a break label for this loop.
        let break_label = self.compiler.new_break_label();
        self.compiler.break_label = Some(break_label);

        // A basic block for the loop body
        self.compiler.basic_block();

        // Save the loop body label for the loop condition.
        let loop_label = self.compiler.block_label();

        // The loop body.
        f(self.loop_var, self.compiler);

        // If the step size is just one, compile to the optimized branch instruction.
        if self.step_size == F::one() {
            self.jump_to_loop_body_inc(loop_label);
        } else {
            // Increment the loop variable.
            self.compiler.push(
                AsmInstruction::AddFI(self.loop_var.fp(), self.loop_var.fp(), self.step_size),
                None,
            );
        }

        // Add a basic block for the loop condition.
        self.compiler.basic_block();

        // Jump to loop body if the loop condition still holds.
        self.jump_to_loop_body(loop_label);

        // Add a jump instruction to the loop condition in the loop call block.
        let label = self.compiler.block_label();
        let instr = AsmInstruction::j(label);
        self.compiler.push_to_block(loop_call_label, instr, None);

        // Initialize the after loop block.
        self.compiler.basic_block();

        // Resolve the break label.
        let label = self.compiler.block_label();
        self.compiler.break_label_map.insert(break_label, label);

        // Replace the break instruction with a jump to the after loop block.
        for block in self.compiler.contains_break.iter() {
            for instruction in
                self.compiler.basic_blocks[block.as_canonical_u32() as usize].0.iter_mut()
            {
                if let AsmInstruction::Break(l) = instruction {
                    if *l == break_label {
                        *instruction = AsmInstruction::j(label);
                    }
                }
            }
        }

        // self.compiler.contains_break.clear();
    }

    fn set_loop_var(&mut self) {
        match self.start {
            Usize::Const(start) => {
                self.compiler.push(
                    AsmInstruction::AddFI(self.loop_var.fp(), ZERO, F::from_canonical_usize(start)),
                    None,
                );
            }
            Usize::Var(var) => {
                self.compiler
                    .push(AsmInstruction::AddFI(self.loop_var.fp(), var.fp(), F::zero()), None);
            }
        }
    }

    fn jump_to_loop_body(&mut self, loop_label: F) {
        match self.end {
            Usize::Const(end) => {
                let instr = AsmInstruction::BneI(
                    loop_label,
                    self.loop_var.fp(),
                    F::from_canonical_usize(end),
                );
                self.compiler.push(instr, None);
            }
            Usize::Var(end) => {
                let instr = AsmInstruction::Bne(loop_label, self.loop_var.fp(), end.fp());
                self.compiler.push(instr, None);
            }
        }
    }

    fn jump_to_loop_body_inc(&mut self, loop_label: F) {
        match self.end {
            Usize::Const(end) => {
                let instr = AsmInstruction::BneIInc(
                    loop_label,
                    self.loop_var.fp(),
                    F::from_canonical_usize(end),
                );
                self.compiler.push(instr, None);
            }
            Usize::Var(end) => {
                let instr = AsmInstruction::BneInc(loop_label, self.loop_var.fp(), end.fp());
                self.compiler.push(instr, None);
            }
        }
    }
}
