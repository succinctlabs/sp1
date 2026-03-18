use slop_multilinear::Point;
use thiserror::Error;

use super::{
    sumcheck::{SumcheckError, SumcheckParam, SumcheckView},
    ConstraintCtx, ReadingCtx,
};

#[derive(Debug, Error)]
pub enum ZerocheckError {
    #[error(transparent)]
    Sumcheck(#[from] SumcheckError),
    #[error("zerocheck requires at least one polynomial, got 0")]
    NoPolynomials,
    #[error("unexpected end of transcript")]
    TranscriptExhausted,
}

/// Parameters for a zerocheck protocol: prove that a composition of committed MLEs vanishes on the
/// hypercube.
pub struct ZerocheckParam {
    /// Number of variables (log of hypercube size).
    pub num_variables: u32,
    /// Total degree of the composition polynomial.
    pub degree: usize,
    /// Number of committed input polynomials.
    pub num_polys: usize,
    /// Log of stacking factor for each polynomial commitment.
    pub log_stacking: usize,
}

/// All proof data for a zerocheck instance, read from the transcript.
pub struct ZerocheckView<C: ConstraintCtx> {
    /// Oracle handles for committed input polynomials.
    pub oracles: Vec<C::MleOracle>,
    /// Random challenge used to reduce zerocheck to sumcheck.
    pub z: C::Expr,
    /// The inner sumcheck proof.
    pub sumcheck_view: SumcheckView<C>,
    /// Evaluations of the input polynomials at the sumcheck point.
    pub evals: Vec<C::Expr>,
}

impl ZerocheckParam {
    pub fn new(num_variables: u32, degree: usize, num_polys: usize, log_stacking: usize) -> Self {
        Self { num_variables, degree, num_polys, log_stacking }
    }

    /// Read the zerocheck proof from the transcript.
    pub fn read<C: ReadingCtx>(&self, ctx: &mut C) -> Result<ZerocheckView<C>, ZerocheckError> {
        if self.num_polys == 0 {
            return Err(ZerocheckError::NoPolynomials);
        }

        // Read oracle commitments for each input polynomial.
        let oracles: Vec<C::MleOracle> = (0..self.num_polys)
            .map(|_| {
                ctx.read_oracle(self.num_variables as usize, self.log_stacking)
                    .ok_or(ZerocheckError::TranscriptExhausted)
            })
            .collect::<Result<_, _>>()?;

        // Sample the zerocheck-to-sumcheck reduction challenge.
        let z = ctx.sample();

        // The sumcheck has degree + 1 because the zerocheck multiplies the composition by eq(z, x).
        let sumcheck_param = SumcheckParam::new(self.num_variables, self.degree + 1);
        let sumcheck_view = sumcheck_param.read(ctx)?;

        // Read evaluations of each input polynomial at the sumcheck point.
        let evals: Vec<C::Expr> = (0..self.num_polys)
            .map(|_| ctx.read().ok_or(ZerocheckError::TranscriptExhausted))
            .collect::<Result<_, _>>()?;

        Ok(ZerocheckView { oracles, z, sumcheck_view, evals })
    }
}

impl<C: ConstraintCtx> ZerocheckView<C> {
    /// Emit all zerocheck verification constraints.
    pub fn build_constraints(self, ctx: &mut C) -> Result<(), ZerocheckError> {
        // Capture the point before the sumcheck view is consumed.
        let point = self.sumcheck_view.point.clone();
        self.sumcheck_view.build_constraints(ctx)?;

        // Assert MLE evaluation claims for each committed polynomial.
        let point = Point::from(point);
        for (oracle, eval) in self.oracles.into_iter().zip(self.evals.iter()) {
            ctx.assert_mle_eval(oracle, point.clone(), eval.clone());
        }

        Ok(())
    }
}
