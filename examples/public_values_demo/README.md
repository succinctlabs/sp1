# SP1PublicValues API Demo for Aggregation Proofs

This example demonstrates how to effectively use the SP1PublicValues API for working with aggregation proofs.

## Overview

When working with recursive proofs in SP1, it's common to need to:
1. Read public values from a previous proof
2. Verify the proof using the hash of public values
3. Extract the program output from the public values

This example shows the recommended pattern for handling these operations using the existing APIs.

## Key API Usage

### Reading Public Values from Input

```rust
// Import SP1PublicValues directly
use sp1_zkvm::SP1PublicValues;

// Read from the input stream
let mut public_values: SP1PublicValues = sp1_zkvm::io::read();
```

### Using Hash for Verification

```rust
// Get the hash of public values for verification
let hash = public_values.hash();
let digest: [u8; 32] = hash.try_into().expect("Hash should be 32 bytes");

// Verify the proof
let program_identifier = sp1_zkvm::io::read::<[u32; 8]>();
sp1_zkvm::lib::verify::verify_sp1_proof(&program_identifier, &digest);
```

### Reading Program Output

```rust
// Create a copy to avoid modifying the original
let mut public_values_copy = public_values.clone();

// Deserialize the program output
let program_output: ProgramOutput = public_values_copy.read();
```

## Multiple Values in Public Values

If your public values buffer contains multiple values, you can read them sequentially:

```rust
let mut public_values_copy = public_values.clone();

// Read multiple values
let value1: Type1 = public_values_copy.read();
let value2: Type2 = public_values_copy.read();
let value3: Type3 = public_values_copy.read();
```

## Building and Running the Example

```bash
# Build the example
cargo build --release -p sp1-public-values-demo

# Run the script
cargo run --release -p sp1-public-values-demo-script
``` 
