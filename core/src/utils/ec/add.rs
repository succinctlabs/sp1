use crate::precompiles::PrecompileRuntime;

use super::EllipticCurve;

pub trait EllipticCurveAddAssignChip<E: EllipticCurve> {
    fn execute(rt: &mut PrecompileRuntime) -> u32 {
        // Copy the logic from the existing `execute` method here
        todo!("not implemented");
    }
}
