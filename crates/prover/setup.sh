# Parameters
NB_CONSTRAINTS_LOG2=26

# Download the trusted setup from snarkjs
echo "Downloading the trusted setup from snarkjs..."
wget https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_${NB_CONSTRAINTS_LOG2}.ptau \
    -O powersOfTau28_hez_final.ptau

# Download the semaphore-gnark-11 CLI tool
echo "Downloading the semaphore-gnark-11 CLI tool..."
wget https://github.com/jtguibas/semaphore-gnark-11/releases/download/v0.0.1/semaphore-mtb-setup-linux_amd64 \
    -O semaphore-gnark-11
chmod +x ./semaphore-gnark-11

# Setup phase1
echo "Setting up phase1..."
./semaphore-gnark-11 p1i powersOfTau28_hez_final.ptau build/phase1

# Setup phase2
echo "Setting up phase2..."
./semaphore-gnark-11 p2n build/phase1 build/groth16_circuit.bin build/phase2 build/evals

# Setup keys
echo "Setting up keys..."
./semaphore-gnark-11 key build/phase1 build/phase2 build/evals build/groth16_circuit.bin