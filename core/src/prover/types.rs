use p3_commit::Pcs;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::StarkConfig;

type Val<SC> = <SC as StarkConfig>::Val;
type OpenningProof<SC> = <<SC as StarkConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Proof;
type Challenge<SC> = <SC as StarkConfig>::Challenge;
type ValMat<SC> = RowMajorMatrix<Val<SC>>;
type ChallengeMat<SC> = RowMajorMatrix<Challenge<SC>>;
type Com<SC> = <<SC as StarkConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::Commitment;
type PcsProverData<SC> = <<SC as StarkConfig>::Pcs as Pcs<Val<SC>, ValMat<SC>>>::ProverData;

pub type QuotientOpenedValues<T> = Vec<T>;

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

pub struct SegmentCommitment<C> {
    pub main_commit: C,
    pub permutation_commit: C,
    pub quotient_commit: C,
}

pub struct AirOpenedValues<T> {
    pub local: Vec<T>,
    pub next: Vec<T>,
}

pub struct SegmentOpenedValues<T> {
    pub main: Vec<AirOpenedValues<T>>,
    pub permutation: Vec<AirOpenedValues<T>>,
    pub quotient: Vec<QuotientOpenedValues<T>>,
}

pub struct SegmentProof<SC: StarkConfig> {
    pub commitment: SegmentCommitment<Com<SC>>,
    pub opened_values: SegmentOpenedValues<Val<SC>>,
    pub openning_proof: OpenningProof<SC>,
    pub degree_bits: Vec<usize>,
}
