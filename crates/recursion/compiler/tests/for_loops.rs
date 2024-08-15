use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_recursion_compiler::{
    asm::{AsmBuilder, AsmConfig},
    ir::{Array, SymbolicVar, Var},
};
use sp1_recursion_core::runtime::Runtime;
use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig};

#[test]
fn test_compiler_for_loops() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    let mut builder = AsmBuilder::<F, EF>::default();

    let n_val = BabyBear::from_canonical_u32(10);
    let m_val = BabyBear::from_canonical_u32(5);

    let zero: Var<_> = builder.eval(F::zero());
    let n: Var<_> = builder.eval(n_val);
    let m: Var<_> = builder.eval(m_val);

    let i_counter: Var<_> = builder.eval(F::zero());
    let total_counter: Var<_> = builder.eval(F::zero());
    builder.range(zero, n).for_each(|_, builder| {
        builder.assign(i_counter, i_counter + F::one());

        let j_counter: Var<_> = builder.eval(F::zero());
        builder.range(zero, m).for_each(|_, builder| {
            builder.assign(total_counter, total_counter + F::one());
            builder.assign(j_counter, j_counter + F::one());
        });
        // Assert that the inner loop ran m times, in two different ways.
        builder.assert_var_eq(j_counter, m_val);
        builder.assert_var_eq(j_counter, m);
    });
    // Assert that the outer loop ran n times, in two different ways.
    builder.assert_var_eq(i_counter, n_val);
    builder.assert_var_eq(i_counter, n);
    // Assert that the total counter is equal to n * m, in two ways.
    builder.assert_var_eq(total_counter, n_val * m_val);
    builder.assert_var_eq(total_counter, n * m);

    let program = builder.compile_program();

    let config = SC::default();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run().unwrap();
}

#[test]
fn test_compiler_nested_array_loop() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    let mut builder = AsmBuilder::<F, EF>::default();
    type C = AsmConfig<F, EF>;

    let mut array: Array<C, Array<C, Var<_>>> = builder.array(100);

    builder.range(0, array.len()).for_each(|i, builder| {
        let mut inner_array = builder.array::<Var<_>>(10);
        builder.range(0, inner_array.len()).for_each(|j, builder| {
            builder.set(&mut inner_array, j, i + j);
        });
        builder.set(&mut array, i, inner_array);
    });

    // Test that the array is correctly initialized.
    builder.range(0, array.len()).for_each(|i, builder| {
        let inner_array = builder.get(&array, i);
        builder.range(0, inner_array.len()).for_each(|j, builder| {
            let val = builder.get(&inner_array, j);
            builder.assert_var_eq(val, i + j);
        });
    });

    let code = builder.compile_asm();

    println!("{}", code);

    let program = code.machine_code();

    let config = SC::default();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run().unwrap();
}

#[test]
fn test_compiler_break() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    let mut builder = AsmBuilder::<F, EF>::default();
    type C = AsmConfig<F, EF>;

    let len = 100;
    let break_len = F::from_canonical_usize(10);

    let mut array: Array<C, Var<_>> = builder.array(len);

    builder.range(0, array.len()).for_each(|i, builder| {
        builder.set(&mut array, i, i);

        builder.if_eq(i, break_len).then(|builder| builder.break_loop());
    });

    // Test that the array is correctly initialized.

    builder.range(0, array.len()).for_each(|i, builder| {
        let value = builder.get(&array, i);
        builder.if_eq(i, break_len + F::one()).then_or_else(
            |builder| builder.assert_var_eq(value, i),
            |builder| {
                builder.assert_var_eq(value, F::zero());
                builder.break_loop();
            },
        );
    });

    let is_break: Var<_> = builder.eval(F::one());
    builder.range(0, array.len()).for_each(|i, builder| {
        let exp_value: Var<_> = builder.eval(i * is_break);
        let value = builder.get(&array, i);
        builder.assert_var_eq(value, exp_value);
        builder.if_eq(i, break_len).then(|builder| builder.assign(is_break, F::zero()));
    });

    // Test the break instructions in a nested loop.

    let mut array: Array<C, Var<_>> = builder.array(len);
    builder.range(0, array.len()).for_each(|i, builder| {
        let counter: Var<_> = builder.eval(F::zero());

        builder.range(0, i).for_each(|_, builder| {
            builder.assign(counter, counter + F::one());
            builder.if_eq(counter, break_len).then(|builder| builder.break_loop());
        });

        builder.set(&mut array, i, counter);
    });

    // Test that the array is correctly initialized.

    let is_break: Var<_> = builder.eval(F::one());
    builder.range(0, array.len()).for_each(|i, builder| {
        let exp_value: Var<_> =
            builder.eval(i * is_break + (SymbolicVar::<F>::one() - is_break) * break_len);
        let value = builder.get(&array, i);
        builder.assert_var_eq(value, exp_value);
        builder.if_eq(i, break_len).then(|builder| builder.assign(is_break, F::zero()));
    });

    let code = builder.compile_asm();

    println!("{}", code);

    let program = code.machine_code();

    let config = SC::default();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run().unwrap();
}

#[test]
fn test_compiler_step_by() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    let mut builder = AsmBuilder::<F, EF>::default();

    let n_val = BabyBear::from_canonical_u32(20);

    let zero: Var<_> = builder.eval(F::zero());
    let n: Var<_> = builder.eval(n_val);

    let i_counter: Var<_> = builder.eval(F::zero());
    builder.range(zero, n).step_by(2).for_each(|_, builder| {
        builder.assign(i_counter, i_counter + F::one());
    });
    // Assert that the outer loop ran n times, in two different ways.
    let n_exp = n_val / F::two();
    builder.assert_var_eq(i_counter, n_exp);

    let program = builder.compile_program();

    let config = SC::default();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run().unwrap();
}

#[test]
fn test_compiler_bneinc() {
    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    let mut builder = AsmBuilder::<F, EF>::default();

    let n_val = BabyBear::from_canonical_u32(20);

    let zero: Var<_> = builder.eval(F::zero());
    let n: Var<_> = builder.eval(n_val);

    let i_counter: Var<_> = builder.eval(F::zero());
    builder.range(zero, n).step_by(1).for_each(|_, builder| {
        builder.assign(i_counter, i_counter + F::one());
    });

    let code = builder.clone().compile_asm();

    println!("{}", code);

    let program = builder.compile_program();

    let config = SC::default();
    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run().unwrap();
}
