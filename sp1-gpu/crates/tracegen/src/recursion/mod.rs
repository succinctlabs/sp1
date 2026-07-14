mod alu_base;
mod alu_ext;
mod convert;
mod linear_layer;
mod poseidon2_wide;
mod sbox;
mod select;

use std::sync::Arc;

use slop_alloc::mem::CopyError;
use sp1_gpu_cudart::{DeviceMle, TaskScope};
use sp1_recursion_executor::Instruction;
use sp1_recursion_machine::RecursionAir;

use crate::{CudaTracegenAir, PinnedStaging, SectionWriter, F};

impl<const DEGREE: usize, const VAR_EVENTS_PER_ROW: usize> CudaTracegenAir<F>
    for RecursionAir<F, DEGREE, VAR_EVENTS_PER_ROW>
{
    fn supports_device_preprocessed_tracegen(&self) -> bool {
        match self {
            Self::BaseAlu(chip) => chip.supports_device_preprocessed_tracegen(),
            Self::ExtAlu(chip) => chip.supports_device_preprocessed_tracegen(),
            Self::Poseidon2Wide(chip) => chip.supports_device_preprocessed_tracegen(),
            Self::Poseidon2LinearLayer(chip) => chip.supports_device_preprocessed_tracegen(),
            Self::Poseidon2SBox(chip) => chip.supports_device_preprocessed_tracegen(),
            Self::ExtFeltConvert(chip) => chip.supports_device_preprocessed_tracegen(),
            Self::Select(chip) => chip.supports_device_preprocessed_tracegen(),
            Self::PublicValues(_) => false,
            // Other chips don't have `CudaTracegenAir` implemented yet.
            _ => false,
        }
    }

    /// Read the program once and bucket every device chip's instructions into its
    /// staging section, instead of each chip scanning the whole program itself.
    fn bucket_preprocessed_device_instructions(
        program: &Self::Program,
        device_stagings: &mut [(Arc<Self>, PinnedStaging)],
    ) {
        use sp1_recursion_executor::{
            BaseAluInstr, ExtAluInstr, ExtFeltInstr, Poseidon2Instr, Poseidon2LinearLayerInstr,
            Poseidon2SBoxInstr, SelectInstr,
        };

        // One writer per present device chip, tagged with its index in
        // `device_stagings` so we can record the count afterwards. Each writer
        // holds a raw pointer into its (disjoint) pinned section, so the borrow of
        // `device_stagings` ends here.
        let mut base_alu: Option<(SectionWriter<BaseAluInstr<F>>, usize)> = None;
        let mut ext_alu: Option<(SectionWriter<ExtAluInstr<F>>, usize)> = None;
        let mut poseidon2: Option<(SectionWriter<Poseidon2Instr<F>>, usize)> = None;
        let mut linear: Option<(SectionWriter<Poseidon2LinearLayerInstr<F>>, usize)> = None;
        let mut sbox: Option<(SectionWriter<Poseidon2SBoxInstr<F>>, usize)> = None;
        let mut convert: Option<(SectionWriter<ExtFeltInstr<F>>, usize)> = None;
        let mut select: Option<(SectionWriter<SelectInstr<F>>, usize)> = None;
        for (i, (air, staging)) in device_stagings.iter().enumerate() {
            match air.as_ref() {
                Self::BaseAlu(_) => base_alu = Some((SectionWriter::new(staging), i)),
                Self::ExtAlu(_) => ext_alu = Some((SectionWriter::new(staging), i)),
                Self::Poseidon2Wide(_) => poseidon2 = Some((SectionWriter::new(staging), i)),
                Self::Poseidon2LinearLayer(_) => linear = Some((SectionWriter::new(staging), i)),
                Self::Poseidon2SBox(_) => sbox = Some((SectionWriter::new(staging), i)),
                Self::ExtFeltConvert(_) => convert = Some((SectionWriter::new(staging), i)),
                Self::Select(_) => select = Some((SectionWriter::new(staging), i)),
                _ => {}
            }
        }

        // Single pass over the program, routing each instruction to its writer.
        for instruction in program.inner.iter() {
            match instruction.inner() {
                Instruction::BaseAlu(x) => {
                    if let Some((w, _)) = &mut base_alu {
                        w.push(*x)
                    }
                }
                Instruction::ExtAlu(x) => {
                    if let Some((w, _)) = &mut ext_alu {
                        w.push(*x)
                    }
                }
                Instruction::Poseidon2(x) => {
                    if let Some((w, _)) = &mut poseidon2 {
                        w.push(**x)
                    }
                }
                Instruction::Poseidon2LinearLayer(x) => {
                    if let Some((w, _)) = &mut linear {
                        w.push(**x)
                    }
                }
                Instruction::Poseidon2SBox(x) => {
                    if let Some((w, _)) = &mut sbox {
                        w.push(*x)
                    }
                }
                Instruction::ExtFelt(x) => {
                    if let Some((w, _)) = &mut convert {
                        w.push(*x)
                    }
                }
                Instruction::Select(x) => {
                    if let Some((w, _)) = &mut select {
                        w.push(*x)
                    }
                }
                _ => {}
            }
        }

        // Record how many records each writer staged (`None` => overflowed, the
        // chip stages itself).
        for slot in [
            base_alu.map(|(w, i)| (w.finish(), i)),
            ext_alu.map(|(w, i)| (w.finish(), i)),
            poseidon2.map(|(w, i)| (w.finish(), i)),
            linear.map(|(w, i)| (w.finish(), i)),
            sbox.map(|(w, i)| (w.finish(), i)),
            convert.map(|(w, i)| (w.finish(), i)),
            select.map(|(w, i)| (w.finish(), i)),
        ]
        .into_iter()
        .flatten()
        {
            let (count, i) = slot;
            device_stagings[i].1.set_prefilled(count);
        }
    }

    async fn generate_preprocessed_trace_device(
        &self,
        program: &Self::Program,
        staging: PinnedStaging,
        scope: &TaskScope,
    ) -> Result<Option<DeviceMle<F>>, CopyError> {
        match self {
            Self::BaseAlu(chip) => {
                chip.generate_preprocessed_trace_device(program, staging, scope).await
            }
            Self::ExtAlu(chip) => {
                chip.generate_preprocessed_trace_device(program, staging, scope).await
            }
            Self::Poseidon2Wide(chip) => {
                chip.generate_preprocessed_trace_device(program, staging, scope).await
            }
            Self::Poseidon2LinearLayer(chip) => {
                chip.generate_preprocessed_trace_device(program, staging, scope).await
            }
            Self::Poseidon2SBox(chip) => {
                chip.generate_preprocessed_trace_device(program, staging, scope).await
            }
            Self::ExtFeltConvert(chip) => {
                chip.generate_preprocessed_trace_device(program, staging, scope).await
            }
            Self::Select(chip) => {
                chip.generate_preprocessed_trace_device(program, staging, scope).await
            }
            Self::PublicValues(_) => unimplemented!(),
            // Other chips don't have `CudaTracegenAir` implemented yet.
            _ => unimplemented!(),
        }
    }

    fn supports_device_main_tracegen(&self) -> bool {
        match self {
            Self::BaseAlu(chip) => chip.supports_device_main_tracegen(),
            Self::ExtAlu(chip) => chip.supports_device_main_tracegen(),
            Self::Poseidon2Wide(chip) => chip.supports_device_main_tracegen(),
            Self::Poseidon2LinearLayer(chip) => chip.supports_device_main_tracegen(),
            Self::Poseidon2SBox(chip) => chip.supports_device_main_tracegen(),
            Self::ExtFeltConvert(chip) => chip.supports_device_main_tracegen(),
            Self::Select(chip) => chip.supports_device_main_tracegen(),
            Self::PublicValues(_) => false,
            // Other chips don't have `CudaTracegenAir` implemented yet.
            _ => false,
        }
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
        staging: PinnedStaging,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        match self {
            Self::BaseAlu(chip) => chip.generate_trace_device(input, output, staging, scope).await,
            Self::ExtAlu(chip) => chip.generate_trace_device(input, output, staging, scope).await,
            Self::Poseidon2Wide(chip) => {
                chip.generate_trace_device(input, output, staging, scope).await
            }
            Self::Poseidon2LinearLayer(chip) => {
                chip.generate_trace_device(input, output, staging, scope).await
            }
            Self::Poseidon2SBox(chip) => {
                chip.generate_trace_device(input, output, staging, scope).await
            }
            Self::ExtFeltConvert(chip) => {
                chip.generate_trace_device(input, output, staging, scope).await
            }
            Self::Select(chip) => chip.generate_trace_device(input, output, staging, scope).await,
            Self::PublicValues(_) => unimplemented!(),
            // Other chips don't have `CudaTracegenAir` implemented yet.
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use sp1_gpu_cudart::TaskScope;

    use rand::{rngs::StdRng, SeedableRng};

    use slop_tensor::Tensor;

    use sp1_hypercube::air::MachineAir;
    use sp1_recursion_executor::{
        AnalyzedInstruction, BasicBlock, RawProgram, RecursionProgram, RootProgram, SeqBlock,
    };

    use crate::{CudaTracegenAir, PinnedStaging, F};

    pub async fn test_preprocessed_tracegen<A>(
        chip: A,
        mut make_instr: impl FnMut(&mut StdRng) -> AnalyzedInstruction<F>,
        scope: TaskScope,
    ) where
        A: CudaTracegenAir<F> + MachineAir<F, Program = RecursionProgram<F>>,
    {
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);

        let instrs =
            core::iter::repeat_with(|| make_instr(&mut rng)).take(1000).collect::<Vec<_>>();

        // SAFETY: We don't actually execute the program, which requires that the invariants hold.
        // We only generate preprocessed traces, which do not require that the invariants hold.
        let program = unsafe {
            RecursionProgram::new_unchecked(RootProgram {
                inner: RawProgram { seq_blocks: vec![SeqBlock::Basic(BasicBlock { instrs })] },
                total_memory: 0, // Will be filled in.
                shape: None,
                event_counts: Default::default(),
            })
        };

        let trace = Tensor::<F>::from(
            chip.generate_preprocessed_trace(&program)
                .expect("should generate Some(preprocessed_trace)"),
        );

        // Stage the instructions into a temporary pinned buffer sized to the trace.
        let width = MachineAir::<F>::preprocessed_width(&chip);
        let section =
            MachineAir::<F>::preprocessed_num_rows(&chip, &program).map_or(0, |h| h * width);
        let mut pinned = sp1_gpu_cudart::PinnedBuffer::<F>::with_capacity(section.max(1));
        let staging = unsafe {
            PinnedStaging::new(pinned.as_mut_ptr() as *mut u8, section * std::mem::size_of::<F>())
        };

        let gpu_trace = chip
            .generate_preprocessed_trace_device(&program, staging, &scope)
            .await
            .expect("should copy events to device successfully")
            .expect("should generate Some(preprocessed_trace)")
            .to_host()
            .expect("should copy trace to host successfully")
            .into_guts();

        let Some(SeqBlock::Basic(BasicBlock { instrs })) =
            program.into_inner().inner.seq_blocks.pop()
        else {
            unreachable!()
        };

        crate::tests::test_traces_eq(&trace, &gpu_trace, &instrs);
    }

    /// The single-pass bucketing must route each instruction to the same chip its
    /// own `filter_map` would, and record the exact count. Pure CPU (no GPU).
    #[test]
    fn test_bucket_preprocessed_device_instructions() {
        use std::mem::size_of;
        use std::sync::Arc;

        use rand::Rng;
        use slop_algebra::AbstractField;
        use sp1_recursion_executor::{
            Address, BaseAluInstr, BaseAluIo, BaseAluOpcode, ExtAluInstr, ExtAluIo, ExtAluOpcode,
            Instruction,
        };
        use sp1_recursion_machine::chips::alu_base::BaseAluChip;
        use sp1_recursion_machine::chips::alu_ext::ExtAluChip;
        use sp1_recursion_machine::RecursionAir;

        use crate::SectionWriter;

        type A = RecursionAir<F, 3, 2>;

        let mut rng = StdRng::seed_from_u64(1);
        let mut instrs = Vec::new();
        for i in 0..2000usize {
            // Interleave BaseAlu and ExtAlu so routing must actually discriminate.
            let inner = if i % 2 == 0 {
                Instruction::BaseAlu(BaseAluInstr {
                    opcode: BaseAluOpcode::AddF,
                    mult: rng.gen(),
                    addrs: BaseAluIo {
                        out: Address(rng.gen()),
                        in1: Address(rng.gen()),
                        in2: Address(rng.gen()),
                    },
                })
            } else {
                Instruction::ExtAlu(ExtAluInstr {
                    opcode: ExtAluOpcode::MulE,
                    mult: rng.gen(),
                    addrs: ExtAluIo {
                        out: Address(rng.gen()),
                        in1: Address(rng.gen()),
                        in2: Address(rng.gen()),
                    },
                })
            };
            instrs.push(AnalyzedInstruction::new(inner, rng.gen()));
        }
        // SAFETY: only inspected, never executed.
        let program = unsafe {
            RecursionProgram::new_unchecked(RootProgram {
                inner: RawProgram { seq_blocks: vec![SeqBlock::Basic(BasicBlock { instrs })] },
                total_memory: 0,
                shape: None,
                event_counts: Default::default(),
            })
        };

        // Reference: what each chip's own filter would produce.
        let want_base: Vec<BaseAluInstr<F>> = program
            .inner
            .iter()
            .filter_map(|i| match i.inner() {
                Instruction::BaseAlu(x) => Some(*x),
                _ => None,
            })
            .collect();
        let want_ext: Vec<ExtAluInstr<F>> = program
            .inner
            .iter()
            .filter_map(|i| match i.inner() {
                Instruction::ExtAlu(x) => Some(*x),
                _ => None,
            })
            .collect();
        assert_eq!(want_base.len() + want_ext.len(), 2000);

        // Backing store for the two sections (regular memory: `F` and the instr
        // structs are all 4-byte aligned, matching pinned staging).
        let base_bytes = want_base.len() * size_of::<BaseAluInstr<F>>();
        let ext_bytes = want_ext.len() * size_of::<ExtAluInstr<F>>();
        let mut backing = vec![F::zero(); (base_bytes + ext_bytes) / size_of::<F>() + 16];
        let ptr = backing.as_mut_ptr() as *mut u8;

        let check = |base_cap_bytes: usize, ext_cap_bytes: usize| {
            // base at [0, base_bytes); ext right after at [base_bytes, ..).
            let mut stagings: Vec<(Arc<A>, PinnedStaging)> = vec![
                (Arc::new(RecursionAir::BaseAlu(BaseAluChip)), unsafe {
                    PinnedStaging::new(ptr, base_cap_bytes)
                }),
                (Arc::new(RecursionAir::ExtAlu(ExtAluChip)), unsafe {
                    PinnedStaging::new(ptr.add(base_bytes), ext_cap_bytes)
                }),
            ];
            A::bucket_preprocessed_device_instructions(&program, &mut stagings);
            stagings
        };

        // Both sections large enough: exact routing + counts.
        let fit = check(base_bytes, ext_bytes);
        let base_staged = fit[0].1.staged::<BaseAluInstr<F>>().expect("base fits");
        let ext_staged = fit[1].1.staged::<ExtAluInstr<F>>().expect("ext fits");
        assert_eq!(base_staged.len(), want_base.len());
        assert_eq!(ext_staged.len(), want_ext.len());
        for (a, b) in base_staged.iter().zip(&want_base) {
            assert_eq!(format!("{a:?}"), format!("{b:?}"));
        }
        for (a, b) in ext_staged.iter().zip(&want_ext) {
            assert_eq!(format!("{a:?}"), format!("{b:?}"));
        }

        // A too-small ext section must overflow to `None` (chip self-filters),
        // while the base section still fills correctly.
        let overflow = check(base_bytes, size_of::<ExtAluInstr<F>>());
        assert!(overflow[0].1.staged::<BaseAluInstr<F>>().is_some(), "base still fits");
        assert!(overflow[1].1.staged::<ExtAluInstr<F>>().is_none(), "ext overflowed");

        // Direct SectionWriter overflow behavior.
        let mut w =
            SectionWriter::<u32>::new(&unsafe { PinnedStaging::new(ptr, 2 * size_of::<u32>()) });
        w.push(1u32);
        w.push(2u32);
        assert_eq!(w.finish(), Some(2));
        let mut w =
            SectionWriter::<u32>::new(&unsafe { PinnedStaging::new(ptr, size_of::<u32>()) });
        w.push(1u32);
        w.push(2u32);
        assert_eq!(w.finish(), None);
    }
}
