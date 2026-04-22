use slop_algebra::Field;

use crate::sparse_matrix::SparseMatrix;

/// Represents a R1CS constraint system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct R1CS<F> {
    pub num_public_inputs: usize,
    pub a: SparseMatrix<F>,
    pub b: SparseMatrix<F>,
    pub c: SparseMatrix<F>,
}

impl<F> Default for R1CS<F>
where
    F: Clone,
{
    fn default() -> Self {
        Self {
            num_public_inputs: 0,
            a: SparseMatrix::new(0, 0),
            b: SparseMatrix::new(0, 0),
            c: SparseMatrix::new(0, 0),
        }
    }
}

impl<F> R1CS<F>
where
    F: Clone,
{
    // Increase the size of the R1CS matrices to the specified dimensions.
    pub fn grow_matrices(&mut self, num_rows: usize, num_cols: usize) {
        self.a.grow(num_rows, num_cols);
        self.b.grow(num_rows, num_cols);
        self.c.grow(num_rows, num_cols);
    }

    /// Add a new witnesses to the R1CS instance.
    pub fn add_witnesses(&mut self, count: usize) {
        self.grow_matrices(self.num_constraints(), self.num_witnesses() + count);
    }

    /// Add an R1CS constraint.
    pub fn add_constraint(&mut self, a: &[(F, usize)], b: &[(F, usize)], c: &[(F, usize)]) {
        let next_constraint_idx = self.num_constraints();
        self.grow_matrices(self.num_constraints() + 1, self.num_witnesses());

        for (coeff, witness_idx) in a.iter().cloned() {
            self.a.set(next_constraint_idx, witness_idx, coeff);
        }
        for (coeff, witness_idx) in b.iter().cloned() {
            self.b.set(next_constraint_idx, witness_idx, coeff);
        }
        for (coeff, witness_idx) in c.iter().cloned() {
            self.c.set(next_constraint_idx, witness_idx, coeff);
        }
    }
}

impl<F> R1CS<F> {
    #[must_use]
    pub const fn a(&self) -> &SparseMatrix<F> {
        &self.a
    }

    #[must_use]
    pub const fn b(&self) -> &SparseMatrix<F> {
        &self.b
    }

    #[must_use]
    pub const fn c(&self) -> &SparseMatrix<F> {
        &self.c
    }

    /// The number of constraints in the R1CS instance.
    pub const fn num_constraints(&self) -> usize {
        self.a.num_rows
    }

    /// The number of witnesses in the R1CS instance (including the constant one
    /// witness).
    pub const fn num_witnesses(&self) -> usize {
        self.a.num_cols
    }
}

// TODO: Do proper error handling
impl<F> R1CS<F>
where
    F: Field,
{
    // Tests R1CS Witness satisfaction given the constraints provided by the
    // R1CS Matrices.
    pub fn test_witness_satisfaction(&self, witness: &[F]) -> Option<()> {
        assert_eq!(witness.len(), self.num_witnesses(), "Witness size does not match");

        // Verify
        let a = self.a() * witness;
        let b = self.b() * witness;
        let c = self.c() * witness;
        for (row, ((a, b), c)) in a.into_iter().zip(b).zip(c).enumerate() {
            assert_eq!(a * b, c, "Constraint {row} failed");
        }
        Some(())
    }
}

// TODO: Add tests
