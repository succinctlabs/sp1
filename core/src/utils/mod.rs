use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

use crate::{lookup::Interaction, Runtime};

pub trait Chip<F: PrimeField> {
    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F>;

    fn sends(&self) -> Vec<Interaction<F>>;

    fn receives(&self) -> Vec<Interaction<F>>;
}

pub const fn indices_arr<const N: usize>() -> [usize; N] {
    let mut indices_arr = [0; N];
    let mut i = 0;
    while i < N {
        indices_arr[i] = i;
        i += 1;
    }
    indices_arr
}

pub fn pad_to_power_of_two<const N: usize, T: Clone + Default>(values: &mut Vec<T>) {
    debug_assert!(values.len() % N == 0);
    let n_real_rows = values.len() / N;
    values.resize(n_real_rows.next_power_of_two() * N, T::default());
}
