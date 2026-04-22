use std::marker::PhantomData;

use slop_algebra::{ExtensionField, Field};
use slop_alloc::CpuBackend;
use slop_challenger::{FieldChallenger, GrindingChallenger};
use slop_multilinear::Point;
use slop_sumcheck::reduce_sumcheck_to_evaluation;

use crate::{
    batched_lincheck_poly::BatchedLincheckPoly, prodcheck_poly::ProdcheckPoly,
    proof::PartialSpartanProof, r1cs::R1CS,
};

#[derive(Clone, PartialEq)]
pub struct SpartanR1CSProver<F> {
    pub r1cs: R1CS<F>,
    pub m: usize,
    pub m_0: usize,
    _field: PhantomData<F>,
}

impl<F> SpartanR1CSProver<F>
where
    F: Clone,
{
    pub fn new_for_r1cs(r1cs: &R1CS<F>) -> Self {
        Self::new_for_size(r1cs, r1cs.num_witnesses(), r1cs.num_constraints())
    }

    pub fn new_for_size(r1cs: &R1CS<F>, witnesses: usize, constraints: usize) -> Self {
        // m is equal to ceiling(log(number of variables in constraint system)). It is
        // equal to the log of the width of the matrices.
        let m = witnesses.next_power_of_two().ilog2() as usize;

        // m_0 is equal to ceiling(log(number_of_constraints)). It is equal to the
        // number of variables in the multilinear polynomial we are running our sumcheck
        // on.
        let m_0 = constraints.next_power_of_two().ilog2() as usize;

        Self { m, m_0, _field: PhantomData, r1cs: r1cs.clone() }
    }
}

impl<F> SpartanR1CSProver<F>
where
    F: Field,
{
    pub async fn prove<EF, C>(
        &self,
        witness: Vec<EF>,
        challenger: &mut C,
    ) -> PartialSpartanProof<EF>
    where
        EF: ExtensionField<F> + Send + Sync,
        C: FieldChallenger<F> + GrindingChallenger,
    {
        assert_eq!(
            witness.len(),
            self.r1cs.num_witnesses(),
            "Unexpected witness length for R1CS instance"
        );
        assert!(
            self.r1cs.num_witnesses() <= 1 << self.m,
            "R1CS witness length exceeds scheme capacity"
        );
        assert!(
            self.r1cs.num_constraints() <= 1 << self.m_0,
            "R1CS constraints exceed scheme capacity"
        );

        // Recall Spartan is the following:
        // Want to show that Az * Bz - Cz = 0
        // Implies that \forall b \in {0, 1}^\log m  (Az)_b * (Bz)_b - (Cz)_b = 0
        // So, for r sampled we have sum_b eq(r, b) * (Az)_b * (Bz)_b - (Cz)_b  = 0
        // We first compute a sumcheck on that (which reduces to lincheck)

        // Squeeze the zerocheck randomness
        let mut r = Vec::with_capacity(self.m_0);
        for _ in 0..self.m_0 {
            r.push(challenger.sample_ext_element());
        }
        let r = Point::<EF>::new(r.into());

        // Run the first sumcheck
        // TODO: Backend stuff
        let prodcheck_poly = ProdcheckPoly::<_, CpuBackend>::new(&r, &self.r1cs, &witness);

        let (prodcheck_proof, component_evals) = reduce_sumcheck_to_evaluation(
            vec![prodcheck_poly],
            challenger,
            vec![EF::zero()],
            1,
            EF::one(),
        );

        let v_a = component_evals[0][0];
        let v_b = component_evals[0][1];
        let v_c = component_evals[0][2];

        challenger.observe_ext_element(v_a);
        challenger.observe_ext_element(v_b);
        challenger.observe_ext_element(v_c);

        let alpha = prodcheck_proof.point_and_eval.0.clone();

        // The batching randomness for the claim
        let lambda = challenger.sample_ext_element();

        // At this point, the claims are that (Az)[alpha] = v_a, (Bz)[alpha] = v_b, (Cz)[alpha] =
        // v_c
        let batched_lincheck_poly = BatchedLincheckPoly::<_, CpuBackend>::new(
            &witness,
            [&self.r1cs.a, &self.r1cs.b, &self.r1cs.c],
            &alpha,
            lambda,
        );

        let (lincheck_proof, matrix_component_evals) = reduce_sumcheck_to_evaluation(
            vec![batched_lincheck_poly],
            challenger,
            vec![v_a + lambda * v_b + lambda * lambda * v_c],
            1,
            lambda,
        );

        // Get the evalution claims for the sparse matrices
        let beta = lincheck_proof.point_and_eval.0.clone();

        let a_claim = matrix_component_evals[0][0];
        let b_claim = matrix_component_evals[0][1];
        let c_claim = matrix_component_evals[0][2];

        // Get the evaluation claims for the witness
        let z_claim = matrix_component_evals[0][3];

        PartialSpartanProof {
            alpha,
            beta,
            a_claim,
            b_claim,
            c_claim,
            z_claim,
            v_a,
            v_b,
            v_c,
            lincheck_proof,
            prodcheck_proof,
        }
    }
}
