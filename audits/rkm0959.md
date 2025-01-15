# SP1 V3 Audit Report

## 1. Various Challenger Issues

### 1-1 [Informational] Challenger using full sponge state for output

```rust
fn duplexing(&mut self, builder: &mut Builder<C>) {
        assert!(self.input_buffer.len() <= HASH_RATE);

        self.sponge_state[0..self.input_buffer.len()].copy_from_slice(self.input_buffer.as_slice());
        self.input_buffer.clear();

        self.sponge_state = builder.poseidon2_permute_v2(self.sponge_state);

        self.output_buffer.clear();
        self.output_buffer.extend_from_slice(&self.sponge_state);
    }
```

We are using the full sponge state for the output buffer. This is not an usual behavior for sponge constructions - only the rate part of the sponge state is used for the output usually. One possibility this opens up is that for valid hash result after a single permutation, it is easy to get the hash preimage. Note that this doesn't mean that it's easy to get the hash preimage for any desired hash output result, leading to the low severity.

Note that this is also true for the `MultiFieldChallenger`.

This is triggered when we continuously use many hash outputs before observing a new value, and for  inner recursion this only happens when we are sampling FRI query indices.

```rust
    self.output_buffer.clear();
    for &pf_val in self.sponge_state.iter() {
        let f_vals = split_32(builder, pf_val, self.num_f_elms);
        for f_val in f_vals {
            self.output_buffer.push(f_val);
        }
    }
```

### 1-2 [Medium, Plonky3] `MultiField32Challenger` overwrites the entire state

```rust
pub fn observe(&mut self, builder: &mut Builder<C>, value: Felt<C::F>) {
        self.output_buffer.clear();

        self.input_buffer.push(value);
        if self.input_buffer.len() == self.num_f_elms * SPONGE_SIZE {
            self.duplexing(builder);
        }
    }
```

We are overwriting `SPONGE_STATE` values at once using the input buffer - which means we are overwriting the entire state. This means that hash collisions can be generated easily if we happen to overwrite the entire state. In this case, all the previous inputs to the challenger will be ignored. For this entire overwrite to happen, one would have to observe at least 9 Felts to the challenger before sampling any value from the challenger.

Note that this vulnerability is also present for any user of previous versions of Plonky3, including previous versions of SP1.

**Fix for Issue 1-2:**

- Plonky3: https://github.com/Plonky3/Plonky3/blob/sp1-v3/challenger/src/multi_field_challenger.rs
- SP1: https://github.com/succinctlabs/sp1/pull/1575

## 2. [Informational] Plonky3 compress function uses a permutation

Roughly speaking, our compression function is `Truncate(Permute(left || right))` - but this is not a typical one-way function. Indeed, it’s easy to find collisions for this compression by taking `rand` and using `left || right = Permute^-1(result || rand)`. However, note that we have no real control over the resulting `left` and `right`. This means that it is infeasible to find `left` and `right` alongside their hash preimages. Since our compression is done on hashes, (either `vk` hash or hash of opened values) this means that we cannot attack the system end-to-end currently. However, we cannot use the compression as an “usual merkle black box” - so we need to be aware of this in the future.

## 3. [Low] Bits ↔ Felts ↔ Vars conversion technicalities

### 3-1. [Informational] combining felts with base `2^32` to a `var`

In `hash.rs`, we combine 8 felts to var using base `2^32`.

```rust
fn hash(builder: &mut Builder<C>, input: &[Felt<<C as Config>::F>]) -> Self::DigestVariable {
    assert!(C::N::bits() == p3_bn254_fr::Bn254Fr::bits());
    assert!(C::F::bits() == p3_baby_bear::BabyBear::bits());
    let num_f_elms = C::N::bits() / C::F::bits(); // this is 8
    let mut state: [Var<C::N>; SPONGE_SIZE] =
        [builder.eval(C::N::zero()), builder.eval(C::N::zero()), builder.eval(C::N::zero())];
    for block_chunk in &input.iter().chunks(RATE) {
        for (chunk_id, chunk) in (&block_chunk.chunks(num_f_elms)).into_iter().enumerate() {
            let chunk = chunk.copied().collect::<Vec<_>>();
            state[chunk_id] = reduce_32(builder, chunk.as_slice());
        }
        builder.push_op(DslIr::CircuitPoseidon2Permute(state))
    }

    [state[0]; BN254_DIGEST_SIZE]
}

pub fn reduce_32<C: Config>(builder: &mut Builder<C>, vals: &[Felt<C::F>]) -> Var<C::N> {
    let mut power = C::N::one();
    let result: Var<C::N> = builder.eval(C::N::zero());
    for val in vals.iter() {
        let val = builder.felt2var_circuit(*val);
        builder.assign(result, result + val * power);
        power *= C::N::from_canonical_u64(1u64 << 32);
    }
    result
}
```

The important thing here is for this sum of 8 felts doesn’t lead to a collision in BN254. The reason why this is true is actually very non-trivial - indeed, with base `2^31` combining it’s clear that different set of 8 felts would lead to different BN254 result as there is no chance for a BN254 wraparound (as `(2^31)^8 < BN254`), but for base `2^32` things are different. Indeed, it can be shown that for Mersenne31 prime, this will lead to a collision.

We recommend to change this combining to be done with base `2^31`. 

This is already done in `felts_to_bn254_var` in `utils.rs` as shown below.

```rust
#[allow(dead_code)]
pub fn felts_to_bn254_var<C: Config>(
    builder: &mut Builder<C>,
    digest: &[Felt<C::F>; DIGEST_SIZE],
) -> Var<C::N> {
    let var_2_31: Var<_> = builder.constant(C::N::from_canonical_u32(1 << 31));
    let result = builder.constant(C::N::zero());
    for (i, word) in digest.iter().enumerate() {
        let word_bits = builder.num2bits_f_circuit(*word);
        let word_var = builder.bits2num_v_circuit(&word_bits);
        if i == 0 {
            builder.assign(result, word_var);
        } else {
            builder.assign(result, result * var_2_31 + word_var);
        }
    }
    result
}
```

We decided to not fix this, but give a proof of the fact that no collision exist.

Basically, we have to check that, with $p$ being BabyBear and $q$ being BN254,

$$
\sum_{i=0}^7 2^{32i} x_i \not\equiv \sum_{i=0}^7 2^{32i} y_i \pmod{q}
$$

where $0 \le x_i, y_i < p$, and $(x_0, \cdots, x_7) \neq (y_0, \cdots, y_7)$ holds.

This will ensure that the compression of 8 BabyBears to a single Var is injective. 

To check this, it suffices to show that 

$$
\sum_{i=0}^7 2^{32i} z_i \not\equiv 0 \pmod{q}
$$

where $-p < z_i < p$ and not all $z_i$ is equal to zero. 

For this, we first note that, within the size boundaries, we have

$$
-1000q < \sum_{i=0}^7 2^{32i} z_i < 1000q
$$

So we can just check that 

$$
\sum_{i=0}^{7} 2^{32i} z_i \neq kq
$$

for each $-1000 < k < 1000$. Now, note that we can derive $z_0$, as we know that 

$$
z_0 \equiv kq \pmod{2^{32}}
$$

and there’s only one such $z_0$ within the range $(-p, p)$. We can continue this on for each limb, and then check whether the condition holds. This logic can be implemented easily.

### 3-2. [Low] bitwise decomposition on felts may not be canonical

For inner recursion, to convert a felt to bits, we use the following.

```rust
/// Converts a felt to bits inside a circuit.
fn num2bits_v2_f(&mut self, num: Felt<C::F>, num_bits: usize) -> Vec<Felt<C::F>> {
    let output = std::iter::from_fn(|| Some(self.uninit())).take(num_bits).collect::<Vec<_>>();
    self.push_op(DslIr::CircuitV2HintBitsF(output.clone(), num));

    let x: SymbolicFelt<_> = output
        .iter()
        .enumerate()
        .map(|(i, &bit)| {
            self.assert_felt_eq(bit * (bit - C::F::one()), C::F::zero());
            bit * C::F::from_wrapped_u32(1 << i)
        })
        .sum();

    self.assert_felt_eq(x, num);

    output
}
```

which means that when `num_bits = 31` (which is the case for `sample_bits`), it’s allowed for the 31 bits to represent the felt in a non-canonical way (i.e. use `p + 1` for `1`).

We note that for the outer recursion, this is explicitly checked as follows. 

```rust
/// Converts a felt to bits inside a circuit.
    pub fn num2bits_f_circuit(&mut self, num: Felt<C::F>) -> Vec<Var<C::N>> {
        let mut output = Vec::new();
        for _ in 0..NUM_BITS {
            output.push(self.uninit());
        }

        self.push_op(DslIr::CircuitNum2BitsF(num, output.clone()));

        let output_array = self.vec(output.clone());
        self.less_than_bb_modulus(output_array);

        output
    }
```

This is actually unnecessary, as `CircuitNum2BitsF` uses `ReduceSlow` to enforce the result to be within BabyBear range (canonical) then uses `ToBinary` API of GNARK to decompose the result into 32 bits. Note that the bitwise decomposition here is unique as the equality check is over BN254 (after we reduce everything to BabyBear range via `ReduceSlow`).

This affects `sample_bits` - which is used for PoW grinding check and FRI query index generation. While not critical (this allows one additional representation for 1/15 (i.e. less than 2^27) of the BabyBear elements, which is not much) this may decrease the security parameter of our setup. Also, it’s bad to allow non-canonical things to be possible. 

**Fix for Issue 3-2:** https://github.com/succinctlabs/sp1/pull/1555

## 4. [High] Merkle Root of valid `vk` not loaded as constant

```rust
 /// Verify the proof shape phase of the compress stage.
pub fn verify(
    builder: &mut Builder<C>,
    machine: &StarkMachine<SC, A>,
    input: SP1CompressWithVKeyWitnessVariable<C, SC>,
    value_assertions: bool,
) {
    let values =
        input.compress_var.vks_and_proofs.iter().map(|(vk, _)| vk.hash(builder)).collect_vec();
    SP1MerkleProofVerifier::verify(builder, values, input.merkle_var, value_assertions);
    SP1CompressVerifier::verify(builder, machine, input.compress_var);
}
```

We handle multiple shapes of proofs as follows. We generate a set of valid `vk`'s, then compute the merkle tree/root of them. Then, in the recursive verifier, we check that each `vk` is valid by providing a merkle proof of inclusion. One of the challenges is how to make sure that this merkle root is correct within the verifier. If the merkle tree root is simply loaded as a variable, then an attacker can just put arbitrary merkle root, which is an issue.

We handled this problem throughout multiple commits, and we briefly explain our solution. At the "top" of the recursion we assert that our `vk_root` variable is equal to the fixed, precomputed constant merkle root of all valid `vk`. 

```rust
    // Attest that the merkle tree root is correct.
    let root = input.merkle_var.root;
    for (val, expected) in root.iter().zip(self.vk_root.iter()) {
        builder.assert_felt_eq(*val, *expected);
    }
```

Then, as we move "down" the recursion tree, we assert that 
- all the child node's `vk` has merkle inclusion proof in the `vk_root`
- all the child node's public value `vk_root` is equal to the parent node's `vk_root`

This means that our `vk_root` check "propagates downwards" the tree.

## 5. [Medium] `cumulative_sum` needs to be observed when we observe the `permutation_commit`

Currently, the `cumulative_sum` is never observed when sampling `zeta`, which allows us to use incorrect values of `cumulative_sum` to force the constraints to be true. 

We can fix this by incorporating `cumulative_sum` into the challenger, and this can be done while we are observing the `permutation_commit`. Note that you need to know the `permutation_challenge` before you observe the `cumulative_sum`. 

Note that this vulnerability is theoretically present in previous versions of SP1, although exploiting this is a quite difficult task, as the `cumulative_sum` one can get from this is essentially random, and their sum still has to be zero. While possible, it requires practically infeasible amount of computation and deep knowledge of cryptographic attacks to carry out. 

**Fix for Issue 5:** https://github.com/succinctlabs/sp1/pull/1556

## 6. [High] no check of `cumulative_sum` being zero when respective `InteractionScope` has no interactions

In `permutation.rs`, if there's no sends/receives for a certain `InteractionScope`, then there's no constraints that the `cumulative_sum`  corresponding to that scope is zero. This is because we don't allocate any columns when there's no `sends` or `receives`, and we also just don't apply any constraints in that case as well. Therefore, we can use any value.

```rust
if sends.is_empty() && receives.is_empty() {
       continue;
}
```

This breaks the entire cumulative sum logic. 

To fix, we need to make sure that scopes with no interactions lead to cumulative sum being constrained to zero. For reference, the previous implementation of permutation was fine, as at least 1 column was allocated even when there’s no send/receive - and this column (the “partial sum”) was constrained with the sum of empty vector of expressions.

**Fix for Issue 6**: https://github.com/succinctlabs/sp1/pull/1556

## 7. [Medium] Incorrect `exit_code` verification

 in `machine/core.rs` of the circuit-v2, there's a check that all exit code is zero. However, we aren't checking that `public_values.exit_code` is zero, but that `exit_code` is zero. This `exit_code` is actually just the first (`i == 0`) shard's public value exit code, so we aren't checking the exit code for all shards. 
 
 We can fix this by checking all the `public_values.exit_code`.

```rust
// Exit code constraints.
{
    // Assert that the exit code is zero (success) for all proofs.
    builder.assert_felt_eq(exit_code, C::F::zero());
}

```

**Fix for Issue 7**: 
https://github.com/succinctlabs/sp1/pull/1577
https://github.com/succinctlabs/sp1/commit/bc187d5bc


## 8. [Medium] Syscall Chip’s commit scope is Local, despite them contributing to the global cumulative sum

For the Fiat-Shamir to work out, we need to observe every chip that contributes to the global cumulative sum before we actually sample the global permutation challenge. 

All the syscall chips (ed25519, weierstrass, fp, sha256, etc) do contribute to the global cumulative sum, but their `commit_scope` is `InteractionScope::Local`.

This allows us to break the permutation check within the global interactions.

**Fix for Issue 8**: https://github.com/succinctlabs/sp1/pull/1582

Added an extra syscall table in global scope at each precompile shard that handles receiving the global syscall. Then there is a local lookup with the actual precompile table. 

## 9. [Medium] verifier uses prover-provided chip_scope, which allows incorrect Fiat-Shamir for global commits

```rust
    let ShardProof {
        commitment,
        opened_values,
        opening_proof,
        chip_ordering,
        chip_scopes,
        public_values,
        ..
    } = proof;

    // ...

    // Split the main_domains_points_and_opens to the global and local chips.
    let mut global_trace_points_and_openings = Vec::new();
    let mut local_trace_points_and_openings = Vec::new();
    for (i, points_and_openings) in
        main_domains_points_and_opens.clone().into_iter().enumerate()
    {
        let scope = chip_scopes[i];
        if scope == InteractionScope::Global {
            global_trace_points_and_openings.push(points_and_openings);
        } else {
            local_trace_points_and_openings.push(points_and_openings);
        }
    } 
```

The verifier does have access to chip scope information, as it is in `MachineAir`, yet the verifier uses the `chip_scopes` data that is inside the `ShardProof`. This `chip_scopes` has no prior checks. This allows the prover to fool a global commit as a local commit, which allows Fiat-Shamir break for the global permutation challenge. This can be fixed by using verifier’s chip info. This doesn’t hurt the recursive verifier, as our vkey’s are built using the correct chip scopes in mind. However, this hurts users who uses the “raw” rust verifier.

**Fix for Issue 9**: https://github.com/succinctlabs/sp1/pull/1642/files

## 10. [High] local cumulative sum check is missing

There wasn’t a check that the local cumulative sum was zero for each shard in the recursion circuit, even though there was such a check in the direct rust stark verifier.

**Fix for Issue 10:** https://github.com/succinctlabs/sp1/pull/1531

## 11. [High] incorrect constraints in exp_reverse_bits

```rust
builder
    .when(local_prepr.is_real)
    .when_not(local_prepr.is_last)
    .assert_eq(local.accum, local.prev_accum_squared_times_multiplier);
```

This should use `when_not(local_prepr.is_first)` instead. The fix PR is ready.

**Fix for Issue 11:** https://github.com/succinctlabs/sp1/pull/1482

## 12. [Informational] minor issues connecting `committed_value_digest` and `deferred_proofs_digest` in `core.rs` and `compress.rs`

In core, what we do is, given a list of consecutive shard proofs

- check that once `committed_value_digest` is non-zero, it doesn't change
- check that if it's not a shard with CPU, the `committed_value_digest` doesn't change 
    - i.e, can't change even when the `committed_value_digest` is zero
- take the final `committed_value_digest` and put it in `RecursionPublicValues`

Then, in compress we check that, given a list of proofs

- once `committed_value_digest` is non-zero, it doesn't change
- the final `committed_value_digest` is in compressed `RecursionPublicValues`

There are two ideas. to explain, let's think of the following scenario.

- there are four shards: shard 1, 2, 3, 4
- in `core.rs`, the proof #1 handles shard 1, 2 and proof #2 handles shard 3, 4
- then the proof #1 and proof #2 are compressed in `compress.rs`

**Idea 1**. One idea is to have committed value digest the shards be

- shard 1 and 3's committed_value_digest = `0`
- shard 2 and 4's committed_value_digest = `x`

this passes each core verification, and since the RecursionPublicValue of proof #1 and proof #2 are both `x` , this will also pass the compress proof. However, the `committed_value_digest` of these four shards will go `0, x, 0, x`, which is not what's supposed to happen. However, it's still true that the non-zero `committed_value_digests` must be equal over all the shards, so the attack surface is very limited.

**Idea 2**. Assume that shard 3 has no CPU chip. We can actually do

- shard 1, 2's committed_value_digest = `0`
- shard 3, 4's committed_value_digest = `x`

this passes each core verification, as proof #2 thinks shard 3 is its "first" shard - so it actually thinks that the `committed_value_digest` didn't change. This means that the whole "no cpu chip means `committed_value_digest` equal" thing actually just passes. Then, in the compress verification, we'll just see the committed_value_digest go from `0` to `x`, which is also completely fine. However, the committed_value_digest will go `0, 0, x, x`, where the change occurs on a shard without cpu chip - which isn't supposed to happen.

While this is a slight incompatibility, the main invariant (if nonzero, public digest can only be one non-zero value) is preserved. Therefore, we did not fix this observation. 

## 13. [Informational] execution shard witness gen

Additionally, one small observation regarding our `execution_shard` connection checks in `compress.rs`. so, our `execution_shard` is initialized with the first proof (`i == 0`)'s `start_execution_shard`. Then, for each shard, it

- is checked to be the `start_execution_shard` of the current shard 
    - (if it contains any execution_shard)
- remains the same if the shard doesn't contain any execution_shard
- changes to the `next_execution_shard` of the current shard 
    - (if it contains any execution_shard)

This means that the `start_execution_shard` of the first proof (`i == 0`) must actually be the `start_execution_shard` of the proof which contains an execution shard for the first time in this compress proof. For example, if I have

- shard 5, 6, 7, 8 exist, proof #1 handles shard 5, 6, proof #2 handles shard 7, 8 (in core)
- then proof #1 and proof #2 will be compressed (in compress)
- shard 5, 6 has no cpu, and shard 7, 8 has cpu

then we actually need proof #1 to have `start_execution_shard` assigned to the `start_execution_shard` value for proof #2. This is because when compressing proof #1 and proof #2, `execution_shard` will be initialized with proof #1's `start_execution_shard`, and then later will be checked that this is equal to proof #2's (which contains an execution shard) `start_execution_shard`. This is fine in terms of constraints, but we do need to make sure that our witness generation accounts for this, as our usual mindset of execution shards is that we don't care what they are if the shard doesn't have a cpu table.

**Fix for Issue 13**: https://github.com/succinctlabs/sp1/pull/1576

## 14. [Optimization] `Felt2Var` can be used in `felts_to_bn254_var`

In `circuit-v2/src/utils.rs`

```rust
pub fn felts_to_bn254_var<C: Config>(
    builder: &mut Builder<C>,
    digest: &[Felt<C::F>; DIGEST_SIZE],
) -> Var<C::N> {
    let var_2_31: Var<_> = builder.constant(C::N::from_canonical_u32(1 << 31));
    let result = builder.constant(C::N::zero());
    for (i, word) in digest.iter().enumerate() {
        let word_bits = builder.num2bits_f_circuit(*word);
        let word_var = builder.bits2num_v_circuit(&word_bits);
        if i == 0 {
            builder.assign(result, word_var);
        } else {
            builder.assign(result, result * var_2_31 + word_var);
        }
    }
    result
}
```

We do the num2bits + bits2num thing here. We can do this via the felts to var conversion, (`CircuitFelt2Var`) which is an optimization we already used for 2.0.0 release. 

**Optimization PR**: https://github.com/succinctlabs/sp1/pull/1553