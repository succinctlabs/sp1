use p3_field::{AbstractExtensionField, AbstractField};
use std::ops::{Add, Mul, MulAssign};

use super::{Array, Builder, Config, DslIr, Ext, Felt, SymbolicExt, Usize, Var, Variable};

impl<C: Config> Builder<C> {
    /// The generator for the field.
    ///
    /// Reference: [p3_baby_bear::BabyBear]
    pub fn generator(&mut self) -> Felt<C::F> {
        self.eval(C::F::from_canonical_u32(31))
    }

    /// Select a variable based on a condition.
    pub fn select_v(&mut self, cond: Var<C::N>, a: Var<C::N>, b: Var<C::N>) -> Var<C::N> {
        let c = self.uninit();
        self.operations.push(DslIr::CircuitSelectV(cond, a, b, c));
        c
    }

    /// Select a felt based on a condition.
    pub fn select_f(&mut self, cond: Var<C::N>, a: Felt<C::F>, b: Felt<C::F>) -> Felt<C::F> {
        let c = self.uninit();
        self.operations.push(DslIr::CircuitSelectF(cond, a, b, c));
        c
    }

    /// Select an extension based on a condition.
    pub fn select_ef(
        &mut self,
        cond: Var<C::N>,
        a: Ext<C::F, C::EF>,
        b: Ext<C::F, C::EF>,
    ) -> Ext<C::F, C::EF> {
        let c = self.uninit();
        self.operations.push(DslIr::CircuitSelectE(cond, a, b, c));
        c
    }

    /// Exponentiates a variable to a power of two.
    pub fn exp_power_of_2<V: Variable<C>, E: Into<V::Expression>>(
        &mut self,
        e: E,
        power_log: usize,
    ) -> V
    where
        V::Expression: MulAssign<V::Expression> + Clone,
    {
        let mut e = e.into();
        for _ in 0..power_log {
            e *= e.clone();
        }
        self.eval(e)
    }

    /// Exponentializes a variable to an array of bits in little endian.
    pub fn exp_bits<V>(&mut self, x: V, power_bits: &Array<C, Var<C::N>>) -> V
    where
        V::Expression: AbstractField,
        V: Copy + Mul<Output = V::Expression> + Variable<C>,
    {
        let result = self.eval(V::Expression::one());
        let power_f: V = self.eval(x);
        self.range(0, power_bits.len()).for_each(|i, builder| {
            let bit = builder.get(power_bits, i);
            builder
                .if_eq(bit, C::N::one())
                .then(|builder| builder.assign(result, result * power_f));
            builder.assign(power_f, power_f * power_f);
        });
        result
    }

    /// Exponentiates a felt to a list of bits in little endian.
    pub fn exp_f_bits(&mut self, x: Felt<C::F>, power_bits: Vec<Var<C::N>>) -> Felt<C::F> {
        let mut result = self.eval(C::F::one());
        let mut power_f: Felt<_> = self.eval(x);
        for i in 0..power_bits.len() {
            let bit = power_bits[i];
            let tmp = self.eval(result * power_f);
            result = self.select_f(bit, tmp, result);
            power_f = self.eval(power_f * power_f);
        }
        result
    }

    /// Exponentiates a extension to a list of bits in little endian.
    pub fn exp_e_bits(
        &mut self,
        x: Ext<C::F, C::EF>,
        power_bits: Vec<Var<C::N>>,
    ) -> Ext<C::F, C::EF> {
        let mut result = self.eval(SymbolicExt::from_f(C::EF::one()));
        let mut power_f: Ext<_, _> = self.eval(x);
        for i in 0..power_bits.len() {
            let bit = power_bits[i];
            let tmp = self.eval(result * power_f);
            result = self.select_ef(bit, tmp, result);
            power_f = self.eval(power_f * power_f);
        }
        result
    }

    /// Exponetiates a varibale to a list of reversed bits with a given length.
    ///
    /// Reference: [p3_util::reverse_bits_len]
    pub fn exp_reverse_bits_len<V>(
        &mut self,
        x: V,
        power_bits: &Array<C, Var<C::N>>,
        bit_len: impl Into<Usize<C::N>>,
    ) -> V
    where
        V::Expression: AbstractField,
        V: Copy + Mul<Output = V::Expression> + Variable<C>,
    {
        let result = self.eval(V::Expression::one());
        let power_f: V = self.eval(x);
        let bit_len = bit_len.into().materialize(self);
        let bit_len_plus_one: Var<_> = self.eval(bit_len + C::N::one());

        self.range(1, bit_len_plus_one).for_each(|i, builder| {
            let index: Var<C::N> = builder.eval(bit_len - i);
            let bit = builder.get(power_bits, index);
            builder
                .if_eq(bit, C::N::one())
                .then(|builder| builder.assign(result, result * power_f));
            builder.assign(power_f, power_f * power_f);
        });
        result
    }

    /// A version of `exp_reverse_bits_len` that uses the ExpReverseBitsLen precompile.
    pub fn exp_reverse_bits_len_fast(
        &mut self,
        x: Felt<C::F>,
        power_bits: &Array<C, Var<C::N>>,
        bit_len: impl Into<Usize<C::N>>,
    ) -> Felt<C::F> {
        // Instantiate an array of length one and store the value of x.
        let mut x_copy_arr: Array<C, Felt<C::F>> = self.dyn_array(1);
        self.set(&mut x_copy_arr, 0, x);

        // Get a pointer to the address holding x.
        let x_copy_arr_ptr = match x_copy_arr {
            Array::Dyn(ptr, _) => ptr,
            _ => panic!("Expected a dynamic array"),
        };

        // Materialize the bit length as a Var.
        let bit_len_var = bit_len.into().materialize(self);
        // Get a pointer to the array of bits in the exponent.
        let ptr = match power_bits {
            Array::Dyn(ptr, _) => ptr,
            _ => panic!("Expected a dynamic array"),
        };

        // Call the DslIR instruction ExpReverseBitsLen, which modifies the memory pointed to by `x_copy_arr_ptr`.
        self.push(DslIr::ExpReverseBitsLen(
            x_copy_arr_ptr,
            ptr.address,
            bit_len_var,
        ));

        // Return the value stored at the address pointed to by `x_copy_arr_ptr`.
        self.get(&x_copy_arr, 0)
    }

    /// Exponentiates a variable to a list of bits in little endian.
    pub fn exp_power_of_2_v<V>(
        &mut self,
        base: impl Into<V::Expression>,
        power_log: impl Into<Usize<C::N>>,
    ) -> V
    where
        V: Variable<C> + Copy + Mul<Output = V::Expression>,
    {
        let mut result: V = self.eval(base);
        let power_log: Usize<_> = power_log.into();
        match power_log {
            Usize::Var(power_log) => {
                self.range(0, power_log)
                    .for_each(|_, builder| builder.assign(result, result * result));
            }
            Usize::Const(power_log) => {
                for _ in 0..power_log {
                    result = self.eval(result * result);
                }
            }
        }
        result
    }

    /// Exponentiates a variable to a list of bits in little endian insid a circuit.
    pub fn exp_power_of_2_v_circuit<V>(
        &mut self,
        base: impl Into<V::Expression>,
        power_log: usize,
    ) -> V
    where
        V: Copy + Mul<Output = V::Expression> + Variable<C>,
    {
        let mut result: V = self.eval(base);
        for _ in 0..power_log {
            result = self.eval(result * result)
        }
        result
    }

    /// Multiplies `base` by `2^{log_power}`.
    pub fn sll<V>(&mut self, base: impl Into<V::Expression>, shift: Usize<C::N>) -> V
    where
        V: Variable<C> + Copy + Add<Output = V::Expression>,
    {
        let result: V = self.eval(base);
        self.range(0, shift)
            .for_each(|_, builder| builder.assign(result, result + result));
        result
    }

    /// Creates an ext from a slice of felts.
    pub fn ext_from_base_slice(&mut self, arr: &[Felt<C::F>]) -> Ext<C::F, C::EF> {
        assert!(arr.len() <= <C::EF as AbstractExtensionField::<C::F>>::D);
        let mut res = SymbolicExt::from_f(C::EF::zero());
        for i in 0..arr.len() {
            res += arr[i] * SymbolicExt::from_f(C::EF::monomial(i));
        }
        self.eval(res)
    }

    pub fn felts2ext(&mut self, felts: &[Felt<C::F>]) -> Ext<C::F, C::EF> {
        assert_eq!(felts.len(), 4);
        let out: Ext<C::F, C::EF> = self.uninit();
        self.push(DslIr::CircuitFelts2Ext(felts.try_into().unwrap(), out));
        out
    }

    /// Converts an ext to a slice of felts.
    pub fn ext2felt(&mut self, value: Ext<C::F, C::EF>) -> Array<C, Felt<C::F>> {
        let result = self.dyn_array(4);
        self.operations
            .push(DslIr::HintExt2Felt(result.clone(), value));

        // Verify that the decomposed extension element is correct.
        let mut reconstructed_ext: Ext<C::F, C::EF> = self.constant(C::EF::zero());
        for i in 0..4 {
            let felt = self.get(&result, i);
            let monomial: Ext<C::F, C::EF> = self.constant(C::EF::monomial(i));
            reconstructed_ext = self.eval(reconstructed_ext + monomial * felt);
        }

        self.assert_ext_eq(reconstructed_ext, value);

        result
    }

    /// Converts an ext to a slice of felts inside a circuit.
    pub fn ext2felt_circuit(&mut self, value: Ext<C::F, C::EF>) -> [Felt<C::F>; 4] {
        let a = self.uninit();
        let b = self.uninit();
        let c = self.uninit();
        let d = self.uninit();
        self.operations
            .push(DslIr::CircuitExt2Felt([a, b, c, d], value));
        [a, b, c, d]
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeField32;
    use p3_util::reverse_bits_len;
    use rand::{thread_rng, Rng};
    use sp1_core::{stark::StarkGenericConfig, utils::BabyBearPoseidon2};
    use sp1_recursion_core::runtime::{Runtime, NUM_BITS};

    use p3_field::AbstractField;

    use crate::{
        asm::AsmBuilder,
        ir::{Felt, Var},
    };

    #[test]
    fn test_num2bits() {
        type SC = BabyBearPoseidon2;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;

        let mut rng = thread_rng();
        let config = SC::default();

        // Initialize a builder.
        let mut builder = AsmBuilder::<F, EF>::default();

        // Get a random var with `NUM_BITS` bits.
        let num_val: F = rng.gen();

        // Materialize the number as a var
        let num: Var<_> = builder.eval(num_val);
        // Materialize the number as a felt
        let num_felt: Felt<_> = builder.eval(num_val);

        // Get the bits.
        let bits = builder.num2bits_v(num);
        let bits_felt = builder.num2bits_f(num_felt);

        // Compare the expected bits with the actual bits.
        for i in 0..NUM_BITS {
            // Get the i-th bit of the number.
            let expected_bit = F::from_canonical_u32((num_val.as_canonical_u32() >> i) & 1);
            // Compare the expected bit of the var with the actual bit.
            let bit = builder.get(&bits, i);
            builder.assert_var_eq(bit, expected_bit);
            // Compare the expected bit of the felt with the actual bit.
            let bit_felt = builder.get(&bits_felt, i);
            builder.assert_var_eq(bit_felt, expected_bit);
        }

        // Test the conversion back to a number.
        let num_back = builder.bits2num_v(&bits);
        builder.assert_var_eq(num_back, num);
        let num_felt_back = builder.bits2num_f(&bits_felt);
        builder.assert_felt_eq(num_felt_back, num_felt);

        let program = builder.compile_program();

        let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
        runtime.run().unwrap();
    }

    #[test]
    fn test_reverse_bits_len() {
        type SC = BabyBearPoseidon2;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;

        let mut rng = thread_rng();
        let config = SC::default();

        // Initialize a builder.
        let mut builder = AsmBuilder::<F, EF>::default();

        // Get a random var with `NUM_BITS` bits.
        let x_val: F = rng.gen();

        // Materialize the number as a var
        let x: Var<_> = builder.eval(x_val);
        let x_bits = builder.num2bits_v(x);

        for i in 1..NUM_BITS {
            // Get the reference value.
            let expected_value = reverse_bits_len(x_val.as_canonical_u32() as usize, i);
            let value_bits = builder.reverse_bits_len(&x_bits, i);
            let value = builder.bits2num_v(&value_bits);
            builder.assert_usize_eq(value, expected_value);
            let var_i: Var<_> = builder.eval(F::from_canonical_usize(i));
            let value_var_bits = builder.reverse_bits_len(&x_bits, var_i);
            let value_var = builder.bits2num_v(&value_var_bits);
            builder.assert_usize_eq(value_var, expected_value);
        }

        let program = builder.compile_program();

        let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
        runtime.run().unwrap();
    }
}
