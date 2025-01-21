# Security Model

The goal of SP1 zkVM is to transform an arbitrary program written in an LLVM-compiled language into a sound zero-knowledge proof, proving the program's correct execution. SP1's security model outlines the necessary cryptographic assumptions and program safety requirements to ensure secure proof generation and verification. It also addresses our trusted setup process and additional practical measures to enhance the security of using SP1.

## Cryptographic Security Model 

### Hash Functions and the Random Oracle Model

SP1 utilizes the Poseidon2 hash function over the BabyBear field with a width of 16, rate of 8, capacity of 8, SBOX degree of 7, and 8 external rounds with 13 internal rounds. These parameters were used in [Plonky3](https://github.com/Plonky3/Plonky3/blob/main/poseidon2/src/round_numbers.rs#L42). Readers are referred to the Plonky3 documentation above for more details and theoretical background on the parameter selection for Poseidon2. 

Using the [Random Oracle Model](https://en.wikipedia.org/wiki/Random_oracle), we assume our system remains as secure as if Poseidon2 was replaced with a random oracle. This assumption establishes the security of the [Fiat-Shamir transform](https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic), which converts an interactive protocol into a non-interactive one. This is a common cryptographic assumption used by many teams in the domain; see also the [Poseidon Initiative](https://www.poseidon-initiative.info/). 

### Conjectures for FRI's Security

SP1 uses Conjecture 8.4 from the paper ["Proximity Gaps for Reed-Solomon Codes"](https://eprint.iacr.org/2020/654.pdf). Based on this conjecture, section 3.9.2 of [ethSTARK documentation](https://eprint.iacr.org/2021/582.pdf) describes the number of FRI queries required to achieve a certain level of security, depending on the blowup factor. Additionally, proof of work is used to reduce the required number of FRI queries, as explained in section 3.11.3 of the ethSTARK documentation.

SP1's FRI parameters have `num_queries = 100 / log_blowup` with `proof_of_work_bits = 16`, providing at least 100 bits of security based on these conjectures.

### Recursion's Overhead in Security

We assume that recursive proofs do not incur a loss in security as the number of recursive steps increases. This assumption is widely accepted for recursion-based approaches. 

### Security of Elliptic Curves over Extension Fields

SP1 assumes that the discrete logarithm problem on the elliptic curve over the degree-7 extension of BabyBear is computationally hard. The selected instantiation of the elliptic curve satisfies the criteria outlined in [SafeCurves](https://safecurves.cr.yp.to/index.html), including high embedding degree, prime group order, and a large CM discriminant. 

An analysis based on Thomas Pornin's paper ["EcGFp5: a Specialized Elliptic Curve"](https://eprint.iacr.org/2022/274.pdf), confirmed that the selected elliptic curve provides at least 100 bits of security against known attacks.

This assumption is used in our new memory argument. For more details, see [our notes](.../../../../static/SP1_Turbo_Memory_Argument.pdf) explaining how it works.

### Groth16, PLONK, and the Zero-Knowledgeness of SP1

SP1 utilizes [Gnark's](https://github.com/Consensys/gnark) implementation of Groth16 or PLONK over the BN254 curve to compress a STARK proof into a SNARK proof, which is then used for on-chain verification. SP1 assumes all cryptographic assumptions required for the security of Groth16 and PLONK. While our implementations of Groth16 and PLONK are zero-knowledge, individual STARK proofs in SP1 do not currently satisfy the zero-knowledge property.

## Program Safety Requirements

Since SP1 only aims to provide proof of correct execution for the user-provided program, it is crucial for users to make sure that **their programs are secure**. 

SP1 assumes that the program compiled into SP1 is non-malicious. This includes that the program is memory-safe and the compiled ELF binary has not been tampered with. Compiling unsafe programs with undefined behavior into SP1 could result in undefined or even malicious behavior being provable and verifiable within SP1. Therefore, developers must ensure the safety of their code and the correctness of their SP1 usage through the appropriate toolchain. Similarly, users using SP1's patched crates must ensure that their code is secure when compiled with the original crates. SP1 also has [requirements for safe usage of SP1 Precompiles](./safe-precompile-usage.md), which must be ensured by the developers.

Additionally, SP1 assumes that `0` is not a valid program counter in the compiled program.

## Trusted Setup

The Groth16 and PLONK protocols require a trusted setup to securely setup the proof systems. For PLONK, SP1 relies on the trusted setup ceremony conducted by [Aztec Ignition](https://github.com/AztecProtocol/ignition-verification). For Groth16, SP1 conducted a trusted setup among several contributors to enable its use in the zero-knowledge proof generation pipeline.

### Purpose

A trusted setup ceremony generates cryptographic parameters essential for systems like Groth16 and PLONK. These parameters ensure the validity of proofs and prevent adversaries from creating malicious or invalid proofs. However, the security of the trusted setup process relies on the critical assumption that at least one participant in the ceremony securely discards their intermediary data (commonly referred to as "toxic waste"). If this assumption is violated, the security of the proof system can be compromised.

### Options

SP1 provides two trusted setup options, depending on user preferences and security requirements:

**PLONK’s Universal Trusted Setup:**

For PLONK, SP1 uses the [Aztec Ignition](https://aztec.network/blog/announcing-ignition) ceremony, which is a universal trusted setup designed for reuse across multiple circuits. This approach eliminates the need for circuit-specific ceremonies and minimizes trust assumptions, making it a robust and widely trusted solution.

The details of SP1's usage of this trusted setup can be found in our repository [here](https://github.com/succinctlabs/sp1/blob/dev/crates/recursion/gnark-ffi/go/sp1/trusted_setup/trusted_setup.go) using [Gnark's ignition verifier](https://github.com/Consensys/gnark-ignition-verifier).

The only downside of using PLONK is that it's proving time is slower than Groth16 by 3-4x.

**Groth16 Circuit-Specific Trusted Setup:**

For Groth16, Succinct conducted a circuit-specific trusted setup ceremony among several contributors to the project. While every effort was made to securely generate and discard intermediary parameters following best practices, circuit-specific ceremonies inherently carry higher trust assumptions. The contributors are the following:

1. [John Guibas](https://github.com/jtguibas)
2. [Uma Roy](https://github.com/puma314)
3. [Tamir Hemo](https://github.com/tamirhemo)
4. [Chris Tian](https://github.com/ctian1)
5. [Eli Yang](https://github.com/eliy10)
6. [Kaylee George](https://github.com/kayleegeorge)
7. [Ratan Kaliani](https://github.com/ratankaliani)

The trusted setup artifacts along with the individual contributions can be downloaded from this following [archive](https://sp1-circuits.s3.us-east-2.amazonaws.com/v4.0.0-rc.3-trusted-setup.tar.gz) and were generate by [Semaphore](https://github.com/jtguibas/semaphore-gnark-11/tree/john/gnark-11) which was originally developed by [Worldcoin](https://world.org/). 

Users uncomfortable with these security assumptions are strongly encouraged to use PLONK instead.

## Approved Prover

Zero-knowledge proof (ZKP) systems are highly advanced and complex pieces of software that push the boundaries of cryptographic innovation. As with any complex system, the possibility of bugs or vulnerabilities cannot be entirely eliminated. In particular, issues in the prover implementation may lead to incorrect proofs or security vulnerabilities that could compromise the integrity of the entire proof system.

To mitigate these risks, we officially recommend the use of an approved prover for any application handling critical or sensitive amounts of value. An approved prover refers to an implementation where there is a list of whitelisted provers or oracles who provide an additional sanity check that the proof's claimed outputs are correct.

Over time, as the ecosystem matures and the understanding of ZKP systems improves, we expect to relax these restrictions. Advances in formal verification, fuzz testing, and cryptographic research may provide new tools and methods to achieve high levels of security and confidence of prover implementations.

We strongly advise users to:

- Use only Succinct approved versions of the prover software for critical applications.
- Follow updates and recommendations from the SP1 team regarding approved provers.
- Regularly apply security patches and updates to the prover software.

This careful approach ensures that applications using SP1 maintain the highest possible level of security, while still leaving room for innovation and growth in the ZKP ecosystem.