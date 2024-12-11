// THIS IS JUST A REFERENCE FOR WHAT WE SHOULD TRY TO DO

// pub trait Prover {
//     fn execute() -> {
//         // implemented by default
//     }
//     fn prove()
//     fn verify() -> {
//         // implemented by default
//     }
// }

// struct LocalProver {
//     fn prove_with_options() {
//         // prove with all options
//     }
// }

// struct NetworkProver {
//     rpc_url: String,
//     private_key: String,
//     timeout: Duration,
//     cycle_limit: Option<u64>,
// }

// impl NetworkProver {
//     fn new(rpc_url: String, private_key: String) -> NetworkProver {
//         // set the timeout and cycle limit to default values
//         // initiatilize with reasonable defaults
//     }

//     fn with_timeout(&mut self, timeout: Duration) -> NetworkProver {
//         // set the timeout
//     }

//     fn with_cycle_limit(&mut self, cycle_limit: u64) -> NetworkProver {
//         // set the cycle limit
//     }

//     fn prove_with_options(network_proof_request) -> Result<SP1ProofWithPublicValues> {
//         // prove with all options
//     }
// }

// struct NetworkProofRequest {
//     action: ...,
//     options: NetworkProverOptions,
// }

// struct NetworkProofRequest {
//     pk: SP1ProvingKey,
//     stdin: SP1Stdin,
//     mode: ProofMode,
//     // ALL THE OTHER OPTIONS
// }

// impl NetworkProofRequest {
//     fn new(pk: SP1ProvingKey, stdin: SP1Stdin) -> NetworkProofRequest {
//         // set the mode to default
//         // set the timeout to default
//         // set the cycle limit to default
//         // set the hook to default
//     }
//     fn with_mode(&mut self, mode: ProofMode) -> NetworkProofRequest {
//         // set the mode
//     }
//     fn with_timeout(&mut self, timeout: Duration) -> NetworkProofRequest {
//         // set the timeout
//     }
//     fn with_cycle_limit(&mut self, cycle_limit: u64) -> NetworkProofRequest {
//         // set the cycle limit
//     }
// }

// // Here: return something that can be "awaited" on OR "run" to run in a blocking fashion.
// impl Prover for LocalProver {
//     fn prove() -> Ret {
//         // impl by calling prove_with_options with default options
//     }
// }

// impl Prover for NetworkProver {
//     fn prove() {
//         // impl by calling prove_with_options with default options
//     }
// }

// struct DynamicProver {
//     pub inner_prover: Box<dyn Prover>
// }

// impl DynamicProver {
//     pub fn from_env() -> Box<dyn Prover> {
//         Box::new(LocalProver)
//     }

//     pub fn network() -> Box<dyn Prover> {
//         Box::new(NetworkProver)
//     }

//     pub fn local() -> Box<dyn Prover> {
//         Box::new(LocalProver)
//     }
// }

// impl Prover for DynamicProver {
//     fn prove() {
//         // just call .prove() on the inner prover
//     }
// }
