use p3_commit::Pcs;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::StarkConfig;

type Val<SC> = <SC as StarkConfig>::Val;
type Challenge<SC> = <SC as StarkConfig>::Challenge;
type ValMat<SC> = RowMajorMatrix<Val<SC>>;
type ChallengeMat<SC> = RowMajorMatrix<Challenge<SC>>;
type Com<SC> = <<SC as StarkConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Commitment;
type PcsProverData<SC> = <<SC as StarkConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::ProverData;

pub struct SegmentDebugProof<SC: StarkConfig> {
    pub main_commit: Com<SC>,
    pub traces: Vec<ValMat<SC>>,
    pub permutation_traces: Vec<ChallengeMat<SC>>,
}

pub struct MainData<SC: StarkConfig> {
    pub traces: Vec<ValMat<SC>>,
    pub main_commit: Com<SC>,
    pub main_data: PcsProverData<SC>,
}
