mod builder;
mod compiler;
mod config;

pub use builder::*;
pub use compiler::*;
pub use config::*;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_field::AbstractField;

    use sp1_core_machine::utils::run_test_machine;
    use sp1_recursion_core::{machine::RecursionAir, Runtime, RuntimeError};
    use sp1_stark::{BabyBearPoseidon2Inner, StarkGenericConfig};

    use crate::{
        circuit::{AsmBuilder, AsmCompiler, CircuitV2Builder},
        ir::*,
    };

    const DEGREE: usize = 3;

    type SC = BabyBearPoseidon2Inner;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    type A = RecursionAir<F, DEGREE>;

    #[test]
    fn test_io() {
        let mut builder = AsmBuilder::<F, EF>::default();

        let felts = builder.hint_felts_v2(3);
        assert_eq!(felts.len(), 3);
        let sum: Felt<_> = builder.eval(felts[0] + felts[1]);
        builder.assert_felt_eq(sum, felts[2]);

        let exts = builder.hint_exts_v2(3);
        assert_eq!(exts.len(), 3);
        let sum: Ext<_, _> = builder.eval(exts[0] + exts[1]);
        builder.assert_ext_ne(sum, exts[2]);

        let x = builder.hint_ext_v2();
        builder.assert_ext_eq(x, exts[0] + felts[0]);

        let y = builder.hint_felt_v2();
        let zero: Felt<_> = builder.constant(F::zero());
        builder.assert_felt_eq(y, zero);

        let operations = builder.into_operations();
        let mut compiler = AsmCompiler::default();
        let program = Arc::new(compiler.compile(operations));
        let mut runtime =
            Runtime::<F, EF, DiffusionMatrixBabyBear>::new(program.clone(), SC::new().perm);
        runtime.witness_stream = [
            vec![F::one().into(), F::one().into(), F::two().into()],
            vec![F::zero().into(), F::one().into(), F::two().into()],
            vec![F::one().into()],
            vec![F::zero().into()],
        ]
        .concat()
        .into();
        runtime.run().unwrap();

        let machine = A::compress_machine(SC::new());

        let (pk, vk) = machine.setup(&program);
        let result =
            run_test_machine(vec![runtime.record], machine, pk, vk.clone()).expect("should verify");

        tracing::info!("num shard proofs: {}", result.shard_proofs.len());
    }

    #[test]
    fn test_empty_witness_stream() {
        let mut builder = AsmBuilder::<F, EF>::default();

        let felts = builder.hint_felts_v2(3);
        assert_eq!(felts.len(), 3);
        let sum: Felt<_> = builder.eval(felts[0] + felts[1]);
        builder.assert_felt_eq(sum, felts[2]);

        let exts = builder.hint_exts_v2(3);
        assert_eq!(exts.len(), 3);
        let sum: Ext<_, _> = builder.eval(exts[0] + exts[1]);
        builder.assert_ext_ne(sum, exts[2]);

        let operations = builder.into_operations();
        let mut compiler = AsmCompiler::default();
        let program = Arc::new(compiler.compile(operations));
        let mut runtime =
            Runtime::<F, EF, DiffusionMatrixBabyBear>::new(program.clone(), SC::new().perm);
        runtime.witness_stream =
            [vec![F::one().into(), F::one().into(), F::two().into()]].concat().into();

        match runtime.run() {
            Err(RuntimeError::EmptyWitnessStream) => (),
            Ok(_) => panic!("should not succeed"),
            Err(x) => panic!("should not yield error variant: {}", x),
        }
    }
}
