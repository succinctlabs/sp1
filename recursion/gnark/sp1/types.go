package sp1

type Constraint struct {
	Opcode string     `json:"opcode"`
	Args   [][]string `json:"args"`
}

type WitnessInput struct {
	Vars                 []string   `json:"vars"`
	Felts                []string   `json:"felts"`
	Exts                 [][]string `json:"exts"`
	VkeyHash             string     `json:"vkey_hash"`
	CommitedValuesDigest string     `json:"commited_values_digest"`
}

// Representation of groth16 proof for solidity verification.
type SolidityGroth16Proof struct {
	PublicInputs  [2]string `json:"public_inputs"`
	SolidityProof string    `json:"solidity_proof"`
}

// Representation of groth16 proof for proof output.
type Groth16Proof struct {
	PublicInputs [2]string `json:"public_inputs"`
	EncodedProof string    `json:"encoded_proof"`
}

type PlonkBn254Proof struct {
	Proof        string    `json:"proof"`
	PublicInputs [2]string `json:"public_inputs"`
}
