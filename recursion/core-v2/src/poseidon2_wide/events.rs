// use crate::{poseidon2_wide::WIDTH, AddressValue};
// use p3_field::PrimeField32;

// /// An event to record a Poseidon2 permutation.
// #[derive(Debug, Clone)]
// pub struct Poseidon2Event<F> {
//     /// The input to the permutation.
//     pub input: [F; WIDTH],

//     /// The output of the permutation.
//     pub output: [F; WIDTH],

//     /// The memory records for the input and output.
//     pub input_records: [AddressValue<F, F>; WIDTH],
//     pub output_records: [AddressValue<F, F>; WIDTH],

//     /// The number of times the output addresses will be read in the future.
//     pub output_mult: [F; WIDTH],
// }
// impl<F: PrimeField32> Poseidon2Event<F> {
//     /// A way to construct a dummy event from an input array, used for testing.
//     pub fn dummy_from_input(input: [F; WIDTH], output: [F; WIDTH]) -> Self {
//         let input_records = core::array::from_fn(|i| AddressValue::new(F::zero(), input[i]));
//         let output_records = core::array::from_fn(|i| AddressValue::new(F::zero(), output[i]));

//         Self {
//             input,
//             output,
//             input_records,
//             output_records,
//             output_mult: [F::zero(); WIDTH],
//         }
//     }
// }
