//! Unit tests for the Poseidon2 AIR operation.
//!
//! The permutation in this module is a hand-rolled, column-shaped re-implementation of the
//! Poseidon2 permutation that the host commitment stack hashes with (`slop_koala_bear`'s
//! `KoalaPerm`, reachable here as [`inner_perm`]). Both the linear layers and the round schedule
//! are written out again so they can be expressed as low-degree constraints, and that duplication
//! is where a silent divergence can appear.
//!
//! This is not uncovered code. `sp1-recursion-machine`'s `poseidon2_wide::tests::test_poseidon2`
//! proves the recursion chip and reads its output back against [`inner_perm`], so a divergence in
//! any of the pieces below would eventually fail that test. What it would not do is say which
//! piece. A transposed matrix, a dropped round constant, and a trace/AIR mismatch all surface the
//! same way: one opaque failed proof, at the end of a full proving run.
//!
//! These tests buy locality and cost instead. Each one is a few microseconds of field arithmetic
//! with no proof anywhere, and each names the layer that broke:
//!   * the two hand-rolled linear layers against Plonky3's matrices,
//!   * the generated witness against the reference permutation, and
//!   * the generated witness against the AIR constraints that consume it.

use std::borrow::Borrow;

use slop_algebra::AbstractField;
use slop_poseidon2::Poseidon2ExternalMatrixGeneral;
use slop_symmetric::Permutation;
use sp1_primitives::{SP1DiffusionMatrix, SP1Field};

use crate::{
    debug::DebugConstraintBuilder,
    inner_perm,
    operations::poseidon2::{
        air::{
            eval_external_round, eval_internal_rounds, external_linear_layer,
            internal_linear_layer_mut,
        },
        permutation::Poseidon2Degree3Cols,
        trace::{populate_perm, populate_perm_deg3},
        NUM_EXTERNAL_ROUNDS, NUM_POSEIDON2_OPERATION_COLUMNS, WIDTH,
    },
};

type EF = slop_algebra::extension::BinomialExtensionField<SP1Field, 4>;

/// A deterministic, non-degenerate state.
///
/// Fixed rather than random so that a failure is reproducible, and non-uniform so that a
/// transposed matrix or a dropped round constant cannot cancel out.
fn seeded_state(seed: u32) -> [SP1Field; WIDTH] {
    core::array::from_fn(|i| {
        SP1Field::from_wrapped_u32(seed.wrapping_mul(0x9e37_79b9) ^ (i as u32 + 1))
    })
}

/// States worth checking: two degenerate ones plus a spread of seeded ones.
fn test_states() -> Vec<[SP1Field; WIDTH]> {
    let mut states = vec![[SP1Field::zero(); WIDTH], [SP1Field::one(); WIDTH]];
    states.extend((0..8).map(seeded_state));
    states
}

#[test]
fn external_linear_layer_matches_plonky3() {
    // `external_linear_layer` unrolls the circulant-of-M4 matrix by hand so it stays degree 1 in
    // the AIR. It must agree with the matrix the host permutation is configured with. A proof
    // catches a mismatch; comparing against the matrix directly says it was this matrix.
    for state in test_states() {
        let mut expected = state;
        Poseidon2ExternalMatrixGeneral.permute_mut(&mut expected);
        assert_eq!(external_linear_layer(&state), expected);
    }
}

#[test]
fn internal_linear_layer_matches_plonky3() {
    // `internal_linear_layer_mut` re-derives the diffusion matrix from the Montgomery-form
    // diagonal and then divides out the Montgomery factor. That round trip is easy to get wrong,
    // and outside this test the only signal is a proof that does not verify.
    for state in test_states() {
        let mut actual = state;
        internal_linear_layer_mut(&mut actual);

        let mut expected = state;
        SP1DiffusionMatrix::default().permute_mut(&mut expected);

        assert_eq!(actual, expected);
    }
}

#[test]
fn witness_output_matches_the_host_permutation() {
    // The bridge between the host commitment stack and every circuit that hashes. The recursion
    // path pins this transitively: it populates witnesses with `expected_output: Some(..)` and
    // `test_poseidon2` checks that output against `inner_perm` through a full proof. Two other
    // call sites pass `expected_output: None` (`global_interaction` padding rows and the Poseidon2
    // precompile chip), so for those the only check is a proof that fails somewhere else. Asserting
    // it directly costs one permutation.
    let perm = inner_perm();
    for state in test_states() {
        let op = populate_perm_deg3(state, None);
        assert_eq!(op.permutation.state.output_state, perm.permute(state));
    }
}

#[test]
fn witness_satisfies_the_air_constraints() {
    // Feed a generated witness row through the constraints that will be applied to it. Outside
    // this test a trace/AIR divergence surfaces only as a failed proof, with nothing pointing at
    // which of the two sides moved.
    for state in test_states() {
        let mut row = vec![SP1Field::zero(); NUM_POSEIDON2_OPERATION_COLUMNS];
        populate_perm::<SP1Field, 3>(state, None, row.as_mut_slice());

        let failing = failing_constraints_for(&row);
        assert!(
            failing.is_empty(),
            "witness violates the Poseidon2 AIR at constraints {failing:?}"
        );
    }
}

/// Evaluate the Poseidon2 constraints against `row` and return the indices that failed.
fn failing_constraints_for(row: &[SP1Field]) -> Vec<usize> {
    let cols: &Poseidon2Degree3Cols<SP1Field> = row.borrow();
    let public_values: Vec<SP1Field> = Vec::new();
    let mut builder =
        DebugConstraintBuilder::<'_, SP1Field, EF>::for_single_row(row, &public_values);

    eval_internal_rounds(&mut builder, cols);
    for r in 0..NUM_EXTERNAL_ROUNDS {
        eval_external_round(&mut builder, cols, r);
    }

    assert!(builder.num_constraints_evaluated() > 0, "no constraints were evaluated");
    builder.failing_constraints().to_vec()
}

#[test]
fn corrupting_any_witness_column_is_caught() {
    // Without this, `witness_satisfies_the_air_constraints` could pass for the wrong reason: an
    // `eval` that constrained nothing, or a column the constraints never read, would look just as
    // healthy. Perturbing every column in turn and requiring a failure each time is what makes
    // that test load bearing.
    let mut row = vec![SP1Field::zero(); NUM_POSEIDON2_OPERATION_COLUMNS];
    populate_perm::<SP1Field, 3>(seeded_state(5), None, row.as_mut_slice());
    assert!(failing_constraints_for(&row).is_empty(), "baseline witness should be valid");

    for column in 0..NUM_POSEIDON2_OPERATION_COLUMNS {
        let mut corrupted = row.clone();
        corrupted[column] += SP1Field::one();
        assert!(
            !failing_constraints_for(&corrupted).is_empty(),
            "column {column} is not constrained: corrupting it left every constraint satisfied"
        );
    }
}

#[test]
#[should_panic(expected = "assertion")]
fn witness_rejects_a_wrong_expected_output() {
    // `populate_perm` takes an optional expected output and asserts against it. Callers in the
    // recursion machine rely on that assert firing, so pin that it actually does.
    let state = seeded_state(3);
    let mut wrong = inner_perm().permute(state);
    wrong[0] += SP1Field::one();
    let _ = populate_perm_deg3(state, Some(wrong));
}
