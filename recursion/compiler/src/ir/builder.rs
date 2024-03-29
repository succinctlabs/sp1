use std::ops::{Add, Mul};

use super::{
    Array, Config, DslIR, Ext, ExtConst, FromConstant, SymbolicExt, SymbolicFelt, SymbolicUsize,
    Usize,
};
use super::{Felt, Var};
use super::{SymbolicVar, Variable};
use alloc::vec::Vec;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use sp1_recursion_core::runtime::{DIGEST_SIZE, NUM_BITS, PERMUTATION_WIDTH};

#[derive(Debug, Clone)]
pub struct Builder<C: Config> {
    pub(crate) felt_count: u32,
    pub(crate) ext_count: u32,
    pub(crate) var_count: u32,
    pub operations: Vec<DslIR<C>>,
}

impl<C: Config> Default for Builder<C> {
    fn default() -> Self {
        Self {
            felt_count: 0,
            ext_count: 0,
            var_count: 0,
            operations: Vec::new(),
        }
    }
}

impl<C: Config> Builder<C> {
    pub fn new(var_count: u32, felt_count: u32, ext_count: u32) -> Self {
        Self {
            felt_count,
            ext_count,
            var_count,
            operations: Vec::new(),
        }
    }

    pub fn push(&mut self, op: DslIR<C>) {
        self.operations.push(op);
    }

    pub fn uninit<V: Variable<C>>(&mut self) -> V {
        V::uninit(self)
    }

    pub fn eval_const<V: FromConstant<C>>(&mut self, value: V::Constant) -> V {
        V::eval_const(value, self)
    }

    pub fn assign<V: Variable<C>, E: Into<V::Expression>>(&mut self, dst: V, expr: E) {
        dst.assign(expr.into(), self);
    }

    pub fn eval<V: Variable<C>, E: Into<V::Expression>>(&mut self, expr: E) -> V {
        let dst = V::uninit(self);
        dst.assign(expr.into(), self);
        dst
    }

    pub fn assert_eq<V: Variable<C>, LhsExpr: Into<V::Expression>, RhsExpr: Into<V::Expression>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        V::assert_eq(lhs, rhs, self);
    }

    pub fn assert_ne<V: Variable<C>, LhsExpr: Into<V::Expression>, RhsExpr: Into<V::Expression>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        V::assert_ne(lhs, rhs, self);
    }

    pub fn assert_var_eq<LhsExpr: Into<SymbolicVar<C::N>>, RhsExpr: Into<SymbolicVar<C::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Var<C::N>, _, _>(lhs, rhs);
    }

    pub fn assert_var_ne<LhsExpr: Into<SymbolicVar<C::N>>, RhsExpr: Into<SymbolicVar<C::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_ne::<Var<C::N>, _, _>(lhs, rhs);
    }

    pub fn assert_felt_eq<LhsExpr: Into<SymbolicFelt<C::F>>, RhsExpr: Into<SymbolicFelt<C::F>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Felt<C::F>, _, _>(lhs, rhs);
    }

    pub fn assert_felt_ne<LhsExpr: Into<SymbolicFelt<C::F>>, RhsExpr: Into<SymbolicFelt<C::F>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_ne::<Felt<C::F>, _, _>(lhs, rhs);
    }

    pub fn assert_usize_eq<
        LhsExpr: Into<SymbolicUsize<C::N>>,
        RhsExpr: Into<SymbolicUsize<C::N>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Usize<C::N>, _, _>(lhs, rhs);
    }

    pub fn assert_usize_ne(&mut self, lhs: SymbolicUsize<C::N>, rhs: SymbolicUsize<C::N>) {
        self.assert_ne::<Usize<C::N>, _, _>(lhs, rhs);
    }

    pub fn assert_ext_eq<
        LhsExpr: Into<SymbolicExt<C::F, C::EF>>,
        RhsExpr: Into<SymbolicExt<C::F, C::EF>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Ext<C::F, C::EF>, _, _>(lhs, rhs);
    }

    pub fn assert_ext_ne<
        LhsExpr: Into<SymbolicExt<C::F, C::EF>>,
        RhsExpr: Into<SymbolicExt<C::F, C::EF>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_ne::<Ext<C::F, C::EF>, _, _>(lhs, rhs);
    }

    pub fn if_eq<LhsExpr: Into<SymbolicVar<C::N>>, RhsExpr: Into<SymbolicVar<C::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) -> IfBuilder<C> {
        IfBuilder {
            lhs: lhs.into(),
            rhs: rhs.into(),
            is_eq: true,
            builder: self,
        }
    }

    pub fn if_ne<LhsExpr: Into<SymbolicVar<C::N>>, RhsExpr: Into<SymbolicVar<C::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) -> IfBuilder<C> {
        IfBuilder {
            lhs: lhs.into(),
            rhs: rhs.into(),
            is_eq: false,
            builder: self,
        }
    }

    pub fn range(
        &mut self,
        start: impl Into<Usize<C::N>>,
        end: impl Into<Usize<C::N>>,
    ) -> RangeBuilder<C> {
        RangeBuilder {
            start: start.into(),
            end: end.into(),
            builder: self,
        }
    }

    pub fn print_v(&mut self, dst: Var<C::N>) {
        self.operations.push(DslIR::PrintV(dst));
    }

    pub fn print_f(&mut self, dst: Felt<C::F>) {
        self.operations.push(DslIR::PrintF(dst));
    }

    pub fn print_e(&mut self, dst: Ext<C::F, C::EF>) {
        self.operations.push(DslIR::PrintE(dst));
    }

    pub fn ext_from_base_slice(&mut self, arr: &[Felt<C::F>]) -> Ext<C::F, C::EF> {
        assert!(arr.len() <= <C::EF as AbstractExtensionField::<C::F>>::D);
        let mut res = SymbolicExt::Const(C::EF::zero());
        for i in 0..arr.len() {
            res += arr[i] * SymbolicExt::Const(C::EF::monomial(i));
        }
        self.eval(res)
    }

    pub fn ext2felt(&mut self, value: Ext<C::F, C::EF>) -> Array<C, Felt<C::F>> {
        let result = self.dyn_array(4);
        self.operations.push(DslIR::Ext2Felt(result.clone(), value));
        result
    }

    pub fn ext2felt_circuit(&mut self, value: Ext<C::F, C::EF>) -> [Felt<C::F>; 4] {
        let a = self.uninit();
        let b = self.uninit();
        let c = self.uninit();
        let d = self.uninit();
        self.operations
            .push(DslIR::CircuitExt2Felt([a, b, c, d], value));
        [a, b, c, d]
    }

    /// Throws an error.
    pub fn error(&mut self) {
        self.operations.push(DslIR::Error());
    }

    /// Converts a usize to a fixed length of bits.
    pub fn num2bits_usize(&mut self, num: impl Into<Usize<C::N>>) -> Array<C, Var<C::N>> {
        // TODO: A separate function for a circuit backend.

        let num = num.into();
        // Allocate an array for the output.
        let output = self.dyn_array::<Var<_>>(NUM_BITS);
        // Hint the bits of the number to the output array.
        self.operations.push(DslIR::HintBitsU(output.clone(), num));

        // Assert that the entries are bits, compute the sum, and compare it to the original number.
        // If the number does not fit in `NUM_BITS`, we will get an error.
        let sum: Var<_> = self.eval(C::N::zero());
        for i in 0..NUM_BITS {
            // Get the bit.
            let bit = self.get(&output, i);
            // Assert that the bit is either 0 or 1.
            self.assert_var_eq(bit * (bit - C::N::one()), C::N::zero());
            // Add `bit * 2^i` to the sum.
            self.assign(sum, sum + bit * C::N::from_canonical_u32(1 << i));
        }
        // Finally, assert that the sum is equal to the original number.
        self.assert_eq::<Usize<_>, _, _>(sum, num);

        output
    }

    /// Converts a var to a fixed length of bits.
    pub fn num2bits_v(&mut self, num: Var<C::N>) -> Array<C, Var<C::N>> {
        // TODO: A separate function for a circuit backend.

        // Allocate an array for the output.
        let output = self.dyn_array::<Var<_>>(NUM_BITS);
        // Hint the bits of the number to the output array.
        self.operations.push(DslIR::HintBitsV(output.clone(), num));

        // Assert that the entries are bits, compute the sum, and compare it to the original number.
        // If the number does not fit in `NUM_BITS`, we will get an error.
        let sum: Var<_> = self.eval(C::N::zero());
        for i in 0..NUM_BITS {
            // Get the bit.
            let bit = self.get(&output, i);
            // Assert that the bit is either 0 or 1.
            self.assert_var_eq(bit * (bit - C::N::one()), C::N::zero());
            // Add `bit * 2^i` to the sum.
            self.assign(sum, sum + bit * C::N::from_canonical_u32(1 << i));
        }
        // Finally, assert that the sum is equal to the original number.
        self.assert_var_eq(sum, num);

        output
    }

    /// Converts a felt to a fixed length of bits.
    pub fn num2bits_f(&mut self, num: Felt<C::F>) -> Array<C, Var<C::N>> {
        // TODO: A separate function for a circuit backend.

        // Allocate an array for the output.
        let output = self.dyn_array::<Var<_>>(NUM_BITS);
        // Hint the bits of the number to the output array.
        self.operations.push(DslIR::HintBitsF(output.clone(), num));

        // Assert that the entries are bits, compute the sum, and compare it to the original number.
        // If the number does not fit in `NUM_BITS`, we will get an error.
        let sum: Felt<_> = self.eval(C::F::zero());
        for i in 0..NUM_BITS {
            // Get the bit.
            let bit = self.get(&output, i);
            // Assert that the bit is either 0 or 1.
            self.assert_var_eq(bit * (bit - C::N::one()), C::N::zero());
            // Add `bit * 2^i` to the sum.
            self.if_eq(bit, C::N::one()).then(|builder| {
                builder.assign(sum, sum + C::F::from_canonical_u32(1 << i));
            });
        }
        // // Finally, assert that the sum is equal to the original number.
        // self.assert_felt_eq(sum, num);

        output
    }

    pub fn bits_to_num_felt(&mut self, bits: &Array<C, Var<C::N>>) -> Felt<C::F> {
        let num: Felt<_> = self.eval(C::F::zero());
        for i in 0..NUM_BITS {
            let bit = self.get(bits, i);
            // Add `bit * 2^i` to the sum.
            self.if_eq(bit, C::N::one()).then(|builder| {
                builder.assign(num, num + C::F::from_canonical_u32(1 << i));
            });
        }
        num
    }

    pub fn bits_to_num_var(&mut self, bits: &Array<C, Var<C::N>>) -> Var<C::N> {
        let num: Var<_> = self.eval(C::N::zero());
        let power: Var<_> = self.eval(C::N::one());
        self.range(0, bits.len()).for_each(|i, builder| {
            let bit = builder.get(bits, i);
            builder.assign(num, num + bit * power);
            builder.assign(power, power * C::N::from_canonical_u32(2));
        });
        num
    }

    pub fn bits_to_num_usize(&mut self, bits: &Array<C, Var<C::N>>) -> Usize<C::N> {
        self.bits_to_num_var(bits).into()
    }

    /// Applies the Poseidon2 permutation to the given array.
    ///
    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/poseidon2/src/lib.rs#L119
    pub fn poseidon2_permute(&mut self, array: &Array<C, Felt<C::F>>) -> Array<C, Felt<C::F>> {
        let output = match array {
            Array::Fixed(values) => {
                assert_eq!(values.len(), PERMUTATION_WIDTH);
                self.array::<Felt<C::F>>(Usize::Const(PERMUTATION_WIDTH))
            }
            Array::Dyn(_, len) => self.array::<Felt<C::F>>(*len),
        };
        self.operations.push(DslIR::Poseidon2PermuteBabyBear(
            output.clone(),
            array.clone(),
        ));
        output
    }

    /// Applies the Poseidon2 permutation to the given array.
    ///
    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/poseidon2/src/lib.rs#L119
    pub fn poseidon2_permute_mut(&mut self, array: &Array<C, Felt<C::F>>) {
        self.operations.push(DslIR::Poseidon2PermuteBabyBear(
            array.clone(),
            array.clone(),
        ));
    }

    /// Applies the Poseidon2 permutation to the given array.
    ///
    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/poseidon2/src/lib.rs#L119
    pub fn poseidon2_hash(&mut self, array: &Array<C, Felt<C::F>>) -> Array<C, Felt<C::F>> {
        let mut state: Array<C, Felt<C::F>> = self.dyn_array(PERMUTATION_WIDTH);
        let eight_ctr: Var<_> = self.eval(C::N::from_canonical_usize(0));
        let target = array.len().materialize(self);

        // TODO: use break, should be target / 8
        self.range(0, target).for_each(|i, builder| {
            let element = builder.get(array, i);
            builder.set(&mut state, eight_ctr, element);

            builder
                .if_eq(eight_ctr, C::N::from_canonical_usize(7))
                .then_or_else(
                    |builder| {
                        builder.poseidon2_permute_mut(&state);
                    },
                    |builder| {
                        builder.if_eq(i, target - C::N::one()).then(|builder| {
                            builder.poseidon2_permute_mut(&state);
                        });
                    },
                );

            builder.assign(eight_ctr, eight_ctr + C::N::from_canonical_usize(1));
            builder
                .if_eq(eight_ctr, C::N::from_canonical_usize(8))
                .then(|builder| {
                    builder.assign(eight_ctr, C::N::from_canonical_usize(0));
                });
        });

        let mut result = self.dyn_array(DIGEST_SIZE);
        for i in 0..DIGEST_SIZE {
            let el = self.get(&state, i);
            self.set(&mut result, i, el);
        }

        result
    }

    /// Applies the Poseidon2 compression function to the given array.
    ///
    /// Assumes we are doing a 2-1 compression function with 8 element chunks.
    ///
    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/symmetric/src/compression.rs#L35
    pub fn poseidon2_compress(
        &mut self,
        left: &Array<C, Felt<C::F>>,
        right: &Array<C, Felt<C::F>>,
    ) -> Array<C, Felt<C::F>> {
        let mut input = self.dyn_array(PERMUTATION_WIDTH);
        for i in 0..DIGEST_SIZE {
            let a = self.get(left, i);
            let b = self.get(right, i);
            self.set(&mut input, i, a);
            self.set(&mut input, i + DIGEST_SIZE, b);
        }
        self.poseidon2_permute_mut(&input);
        input
    }

    /// Materializes a usize into a variable.
    pub fn materialize(&mut self, num: Usize<C::N>) -> Var<C::N> {
        match num {
            Usize::Const(num) => self.eval(C::N::from_canonical_usize(num)),
            Usize::Var(num) => num,
        }
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/baby-bear/src/baby_bear.rs#L306
    pub fn generator(&mut self) -> Felt<C::F> {
        self.eval(C::F::from_canonical_u32(31))
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/baby-bear/src/baby_bear.rs#L302
    #[allow(unused_variables)]
    pub fn two_adic_generator(&mut self, bits: Usize<C::N>) -> Felt<C::F> {
        let generator: Felt<C::F> = self.eval(C::F::from_canonical_usize(440564289));
        let two_adicity: Var<C::N> = self.eval(C::N::from_canonical_usize(27));
        let bits_var = bits.materialize(self);
        let nb_squares: Var<C::N> = self.eval(two_adicity - bits_var);
        self.range(0, nb_squares).for_each(|_, builder| {
            builder.assign(generator, generator * generator);
        });
        generator
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/util/src/lib.rs#L59
    #[allow(unused_variables)]
    ///
    /// *Safety* calling this function with `bit_len` greater [`NUM_BITS`] will result in undefined
    /// behavior.
    pub fn reverse_bits_len_circuit(
        &mut self,
        index_bits: Vec<Var<C::N>>,
        bit_len: usize,
    ) -> Vec<Var<C::N>> {
        let mut result_bits = Vec::new();
        for i in 0..bit_len {
            let idx = bit_len - i - 1;
            result_bits.push(index_bits[idx]);
        }
        result_bits
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/util/src/lib.rs#L59
    #[allow(unused_variables)]
    ///
    /// *Safety* calling this function with `bit_len` greater [`NUM_BITS`] will result in undefined
    /// behavior.
    pub fn reverse_bits_len(
        &mut self,
        index: Var<C::N>,
        bit_len: impl Into<Usize<C::N>>,
    ) -> Usize<C::N> {
        let bits = self.num2bits_usize(index);

        // Compute the reverse bits.
        let bit_len = bit_len.into();
        let mut result_bits = self.dyn_array::<Var<_>>(NUM_BITS);
        self.range(0, bit_len).for_each(|i, builder| {
            let index: Var<C::N> = builder.eval(bit_len - i - C::N::one());
            let entry = builder.get(&bits, index);
            builder.set(&mut result_bits, i, entry);
        });

        self.range(bit_len, NUM_BITS).for_each(|i, builder| {
            builder.set(&mut result_bits, i, C::N::zero());
        });

        self.bits_to_num_usize(&result_bits)
    }

    #[allow(unused_variables)]
    pub fn exp_usize_ef(&mut self, x: Ext<C::F, C::EF>, power: Usize<C::N>) -> Ext<C::F, C::EF> {
        let result = self.eval(C::F::one());
        let power_f: Ext<_, _> = self.eval(x);
        let bits = self.num2bits_usize(power);
        self.range(0, bits.len()).for_each(|i, builder| {
            let bit = builder.get(&bits, i);
            builder
                .if_eq(bit, C::N::one())
                .then(|builder| builder.assign(result, result * power_f));
            builder.assign(power_f, power_f * power_f);
        });
        result
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/field/src/field.rs#L79
    #[allow(unused_variables)]
    pub fn exp_usize_f_bits(&mut self, x: Felt<C::F>, power_bits: Vec<Var<C::N>>) -> Felt<C::F> {
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

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/field/src/field.rs#L79
    #[allow(unused_variables)]
    pub fn exp_usize_ef_bits(
        &mut self,
        x: Ext<C::F, C::EF>,
        power_bits: Vec<Var<C::N>>,
    ) -> Ext<C::F, C::EF> {
        let mut result = self.eval(SymbolicExt::Const(C::EF::one()));
        let mut power_f: Ext<_, _> = self.eval(x);
        for i in 0..power_bits.len() {
            let bit = power_bits[i];
            let tmp = self.eval(result * power_f);
            result = self.select_ef(bit, tmp, result);
            power_f = self.eval(power_f * power_f);
        }
        result
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/field/src/field.rs#L79
    #[allow(unused_variables)]
    pub fn exp_usize_f(&mut self, x: Felt<C::F>, power: Usize<C::N>) -> Felt<C::F> {
        let result = self.eval(C::F::one());
        let power_f: Felt<_> = self.eval(x);
        let bits = self.num2bits_usize(power);
        self.range(0, bits.len()).for_each(|i, builder| {
            let bit = builder.get(&bits, i);
            builder
                .if_eq(bit, C::N::one())
                .then(|builder| builder.assign(result, result * power_f));
            builder.assign(power_f, power_f * power_f);
        });
        result
    }

    /// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/field/src/field.rs#L79
    #[allow(unused_variables)]
    pub fn exp_usize_v(&mut self, x: Var<C::N>, power: Usize<C::N>) -> Var<C::N> {
        let result = self.eval(C::N::one());
        self.range(0, power).for_each(|_, builder| {
            builder.assign(result, result * x);
        });
        result
    }

    pub fn exp_power_of_2_v<V: Variable<C>>(
        &mut self,
        base: impl Into<V::Expression>,
        power_log: Usize<C::N>,
    ) -> V
    where
        V: Copy + Mul<Output = V::Expression>,
    {
        let result: V = self.eval(base);
        self.range(0, power_log)
            .for_each(|_, builder| builder.assign(result, result * result));
        result
    }

    /// Multiplies `base` by `2^{log_power}`.
    pub fn sll<V: Variable<C>>(&mut self, base: impl Into<V::Expression>, shift: Usize<C::N>) -> V
    where
        V: Copy + Add<Output = V::Expression>,
    {
        let result: V = self.eval(base);
        self.range(0, shift)
            .for_each(|_, builder| builder.assign(result, result + result));
        result
    }

    pub fn power_of_two_usize(&mut self, power: Usize<C::N>) -> Usize<C::N> {
        self.sll(Usize::Const(1), power)
    }

    pub fn power_of_two_var(&mut self, power: Usize<C::N>) -> Var<C::N> {
        self.sll(C::N::one(), power)
    }

    pub fn power_of_two_felt(&mut self, power: Usize<C::N>) -> Felt<C::F> {
        self.sll(C::F::one(), power)
    }

    pub fn power_of_two_expr(&mut self, power: Usize<C::N>) -> Ext<C::F, C::EF> {
        self.sll(C::EF::one().cons(), power)
    }
}

pub struct IfBuilder<'a, C: Config> {
    lhs: SymbolicVar<C::N>,
    rhs: SymbolicVar<C::N>,
    is_eq: bool,
    pub(crate) builder: &'a mut Builder<C>,
}

enum Condition<N> {
    EqConst(N, N),
    NeConst(N, N),
    Eq(Var<N>, Var<N>),
    EqI(Var<N>, N),
    Ne(Var<N>, Var<N>),
    NeI(Var<N>, N),
}

impl<'a, C: Config> IfBuilder<'a, C> {
    pub fn then(mut self, mut f: impl FnMut(&mut Builder<C>)) {
        // Get the condition reduced from the expressions for lhs and rhs.
        let condition = self.condition();

        // Execute the `then`` block and collect the instructions.
        let mut f_builder = Builder::<C>::new(
            self.builder.var_count,
            self.builder.felt_count,
            self.builder.ext_count,
        );
        f(&mut f_builder);
        let then_instructions = f_builder.operations;

        // Dispatch instructions to the correct conditional block.
        match condition {
            Condition::EqConst(lhs, rhs) => {
                if lhs == rhs {
                    self.builder.operations.extend(then_instructions);
                }
            }
            Condition::NeConst(lhs, rhs) => {
                if lhs != rhs {
                    self.builder.operations.extend(then_instructions);
                }
            }
            Condition::Eq(lhs, rhs) => {
                let op = DslIR::IfEq(lhs, rhs, then_instructions, Vec::new());
                self.builder.operations.push(op);
            }
            Condition::EqI(lhs, rhs) => {
                let op = DslIR::IfEqI(lhs, rhs, then_instructions, Vec::new());
                self.builder.operations.push(op);
            }
            Condition::Ne(lhs, rhs) => {
                let op = DslIR::IfNe(lhs, rhs, then_instructions, Vec::new());
                self.builder.operations.push(op);
            }
            Condition::NeI(lhs, rhs) => {
                let op = DslIR::IfNeI(lhs, rhs, then_instructions, Vec::new());
                self.builder.operations.push(op);
            }
        }
    }

    pub fn then_or_else(
        mut self,
        mut then_f: impl FnMut(&mut Builder<C>),
        mut else_f: impl FnMut(&mut Builder<C>),
    ) {
        // Get the condition reduced from the expressions for lhs and rhs.
        let condition = self.condition();
        let mut then_builder = Builder::<C>::new(
            self.builder.var_count,
            self.builder.felt_count,
            self.builder.ext_count,
        );

        // Execute the `then` and `else_then` blocks and collect the instructions.
        then_f(&mut then_builder);
        let then_instructions = then_builder.operations;

        let mut else_builder = Builder::<C>::new(
            self.builder.var_count,
            self.builder.felt_count,
            self.builder.ext_count,
        );
        else_f(&mut else_builder);
        let else_instructions = else_builder.operations;

        // Dispatch instructions to the correct conditional block.
        match condition {
            Condition::EqConst(lhs, rhs) => {
                if lhs == rhs {
                    self.builder.operations.extend(then_instructions);
                } else {
                    self.builder.operations.extend(else_instructions);
                }
            }
            Condition::NeConst(lhs, rhs) => {
                if lhs != rhs {
                    self.builder.operations.extend(then_instructions);
                } else {
                    self.builder.operations.extend(else_instructions);
                }
            }
            Condition::Eq(lhs, rhs) => {
                let op = DslIR::IfEq(lhs, rhs, then_instructions, else_instructions);
                self.builder.operations.push(op);
            }
            Condition::EqI(lhs, rhs) => {
                let op = DslIR::IfEqI(lhs, rhs, then_instructions, else_instructions);
                self.builder.operations.push(op);
            }
            Condition::Ne(lhs, rhs) => {
                let op = DslIR::IfNe(lhs, rhs, then_instructions, else_instructions);
                self.builder.operations.push(op);
            }
            Condition::NeI(lhs, rhs) => {
                let op = DslIR::IfNeI(lhs, rhs, then_instructions, else_instructions);
                self.builder.operations.push(op);
            }
        }
    }

    fn condition(&mut self) -> Condition<C::N> {
        match (self.lhs.clone(), self.rhs.clone(), self.is_eq) {
            (SymbolicVar::Const(lhs), SymbolicVar::Const(rhs), true) => {
                Condition::EqConst(lhs, rhs)
            }
            (SymbolicVar::Const(lhs), SymbolicVar::Const(rhs), false) => {
                Condition::NeConst(lhs, rhs)
            }
            (SymbolicVar::Const(lhs), SymbolicVar::Val(rhs), true) => Condition::EqI(rhs, lhs),
            (SymbolicVar::Const(lhs), SymbolicVar::Val(rhs), false) => Condition::NeI(rhs, lhs),
            (SymbolicVar::Const(lhs), rhs, true) => {
                let rhs: Var<C::N> = self.builder.eval(rhs);
                Condition::EqI(rhs, lhs)
            }
            (SymbolicVar::Const(lhs), rhs, false) => {
                let rhs: Var<C::N> = self.builder.eval(rhs);
                Condition::NeI(rhs, lhs)
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Const(rhs), true) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                Condition::EqI(lhs, rhs)
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Const(rhs), false) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                Condition::NeI(lhs, rhs)
            }
            (lhs, SymbolicVar::Const(rhs), true) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                Condition::EqI(lhs, rhs)
            }
            (lhs, SymbolicVar::Const(rhs), false) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                Condition::NeI(lhs, rhs)
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Val(rhs), true) => Condition::Eq(lhs, rhs),
            (SymbolicVar::Val(lhs), SymbolicVar::Val(rhs), false) => Condition::Ne(lhs, rhs),
            (SymbolicVar::Val(lhs), rhs, true) => {
                let rhs: Var<C::N> = self.builder.eval(rhs);
                Condition::Eq(lhs, rhs)
            }
            (SymbolicVar::Val(lhs), rhs, false) => {
                let rhs: Var<C::N> = self.builder.eval(rhs);
                Condition::Ne(lhs, rhs)
            }
            (lhs, SymbolicVar::Val(rhs), true) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                Condition::Eq(lhs, rhs)
            }
            (lhs, SymbolicVar::Val(rhs), false) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                Condition::Ne(lhs, rhs)
            }
            (lhs, rhs, true) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                let rhs: Var<C::N> = self.builder.eval(rhs);
                Condition::Eq(lhs, rhs)
            }
            (lhs, rhs, false) => {
                let lhs: Var<C::N> = self.builder.eval(lhs);
                let rhs: Var<C::N> = self.builder.eval(rhs);
                Condition::Ne(lhs, rhs)
            }
        }
    }
}

pub struct RangeBuilder<'a, C: Config> {
    start: Usize<C::N>,
    end: Usize<C::N>,
    builder: &'a mut Builder<C>,
}

impl<'a, C: Config> RangeBuilder<'a, C> {
    pub fn for_each(self, mut f: impl FnMut(Var<C::N>, &mut Builder<C>)) {
        let loop_variable: Var<C::N> = self.builder.uninit();
        let mut loop_body_builder = Builder::<C>::new(
            self.builder.var_count,
            self.builder.felt_count,
            self.builder.ext_count,
        );

        f(loop_variable, &mut loop_body_builder);

        let loop_instructions = loop_body_builder.operations;

        let op = DslIR::For(self.start, self.end, loop_variable, loop_instructions);
        self.builder.operations.push(op);
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
        asm::VmBuilder,
        prelude::{Felt, Usize, Var},
    };

    #[test]
    fn test_num2bits() {
        type SC = BabyBearPoseidon2;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;

        let mut rng = thread_rng();
        let config = SC::default();

        // Initialize a builder.
        let mut builder = VmBuilder::<F, EF>::default();

        // Get a random var with `NUM_BITS` bits.
        let num_val: F = rng.gen();

        // Materialize the number as a var
        let num: Var<_> = builder.eval(num_val);
        // Materialize the number as a felt
        let num_felt: Felt<_> = builder.eval(num_val);
        // Materialize the number as a usize
        let num_usize: Usize<_> = builder.eval(num_val.as_canonical_u32() as usize);

        // Get the bits.
        let bits = builder.num2bits_v(num);
        let bits_felt = builder.num2bits_f(num_felt);
        let bits_usize = builder.num2bits_usize(num_usize);

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
            // Compare the expected bit of the usize with the actual bit.
            let bit_usize = builder.get(&bits_usize, i);
            builder.assert_var_eq(bit_usize, expected_bit);
        }

        // Test the conversion back to a number.
        let num_back = builder.bits_to_num_var(&bits);
        builder.assert_var_eq(num_back, num);
        let num_felt_back = builder.bits_to_num_felt(&bits_felt);
        builder.assert_felt_eq(num_felt_back, num_felt);
        let num_usize_back = builder.bits_to_num_usize(&bits_usize);
        builder.assert_usize_eq(num_usize_back, num_usize);

        let program = builder.compile();

        let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
        runtime.run();
    }

    #[test]
    fn test_reverse_bits_len() {
        type SC = BabyBearPoseidon2;
        type F = <SC as StarkGenericConfig>::Val;
        type EF = <SC as StarkGenericConfig>::Challenge;

        let mut rng = thread_rng();
        let config = SC::default();

        // Initialize a builder.
        let mut builder = VmBuilder::<F, EF>::default();

        // Get a random var with `NUM_BITS` bits.
        let x_val: F = rng.gen();

        // Materialize the number as a var
        let x: Var<_> = builder.eval(x_val);

        for i in 1..NUM_BITS {
            // Get the reference value.
            let expected_value = reverse_bits_len(x_val.as_canonical_u32() as usize, i);
            let value = builder.reverse_bits_len(x, i);
            builder.assert_usize_eq(value, expected_value);
            let var_i: Var<_> = builder.eval(F::from_canonical_usize(i));
            let value_var = builder.reverse_bits_len(x, var_i);
            builder.assert_usize_eq(value_var, expected_value);
        }

        let program = builder.compile();

        let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
        runtime.run();
    }
}
