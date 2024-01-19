use p3_field::Field;

/// Computes the multiplicative inverse of each element in the given vector.
///
/// In other words, given elements e_1, ..., e_n returns 1/e_i if e_i != 0 and 0 otherwise.
pub fn batch_multiplicative_inverse<F: Field>(values: Vec<F>) -> Vec<F> {
    // Check if values are zero and construct a new vector with only nonzero values.
    let mut nonzero_values = Vec::with_capacity(values.len());
    let mut indices = Vec::with_capacity(values.len());
    for (i, value) in values.iter().cloned().enumerate() {
        if value.is_zero() {
            continue;
        }
        nonzero_values.push(value);
        indices.push(i);
    }

    // Compute the multiplicative inverse of nonzero values.
    let inverse_nonzero_values = p3_field::batch_multiplicative_inverse(&nonzero_values);

    // Reconstruct the original vector.
    let mut result = values.clone();
    for (i, index) in indices.into_iter().enumerate() {
        result[index] = inverse_nonzero_values[i];
    }

    result
}
