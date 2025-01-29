# SP1 V4 Audit Report

This audit was done by [rkm0959](https://github.com/rkm0959), who also audited SP1's v1.0.0 and v3.0.0 releases.

The audit commit is of SP1 v4.0.0 release, which is 4a1dcea0749021ce6e2596bce5bb45f2def7a95c.

The audit was done between November 25th to December 13th for 3 engineer weeks, prior to the release of SP1 v4.0.0. 

The first two bugs shown in the audit report were in previous versions, and they were fixed before releasing SP1 v4.0.0. For more information, we refer the readers to the security advisory [here](https://github.com/succinctlabs/sp1/security/advisories/GHSA-c873-wfhp-wx5m). This is also linked in the report below.

## 1. [V3] Malicious `chip_ordering` in Rust verifier is not checked

**This bug does not affect usage of SP1 when using on-chain verifiers**. 

This issue was in V3, and is explained in the first section of the security advisory [here](https://github.com/succinctlabs/sp1/security/advisories/GHSA-c873-wfhp-wx5m). 

## 2. [V3] `is_complete` bypass

This issue was in V3, and is explained in the second section of the security advisory [here](https://github.com/succinctlabs/sp1/security/advisories/GHSA-c873-wfhp-wx5m). 

This issue was also found by a combined effort from Aligned, LambdaClass and 3MI Labs.

## 3. [Low] `assume_init_mut` used on uninitialized entry

In the recursion executor, the memory write was implemented as follows.

Here, in the first write to the memory, the `entry` will be in an uninitialized state, but `assume_init_mut` is called to write to the `entry`. This is not memory-safe. 

```rust
pub unsafe fn mw_unchecked(&self, addr: Address<F>, val: Block<F>) {
    match self.0.get(addr.as_usize()).map(|c| unsafe { &mut *c.0.get() }) {
        Some(entry) => *entry.assume_init_mut() = MemoryEntry { val },
        None => panic!(
            "expected address {} to be less than length {}",
            addr.as_usize(),
            self.0.len()
        ),
    }
}
```

This was fixed by writing `entry.write()` instead of using `assume_init_mut`.

## 4. [High] `send_to_table` may be nonzero in padding

In the ECALL specific chip, the `send_syscall` happens with multiplicity `send_to_table`, which is stored in the syscall information. Previously, this was checked to be zero when the row is not handling an ECALL instruction. This check was mistakenly removed during the implementation of ECALL chip, but was added back during the course of the audit. 

```rust=
builder.send_syscall(
    local.shard,
    local.clk,
    syscall_id,
    local.op_b_value.reduce::<AB>(),
    local.op_c_value.reduce::<AB>(),
    send_to_table,
    InteractionScope::Local,
);
```

We added this check to enforce `send_to_table = 0` when the row is a padding.
```rust=
builder.when(AB::Expr::one() - local.is_real).assert_zero(send_to_table);
```

## 5. [High] `is_memory` underconstrained

The new CPU chip had a column `is_memory`, which is used to send shard and timestamp information to the opcode specific chips. The idea is that the information is sent only for memory and syscall instructions. The sent values were computed as follows.

```rust=
let expected_shard_to_send =
    builder.if_else(local.is_memory + local.is_syscall, local.shard, AB::Expr::zero());
let expected_clk_to_send =
    builder.if_else(local.is_memory + local.is_syscall, clk.clone(), AB::Expr::zero());
```

However, `is_memory` was not sent to the opcode specific chips, hence they were underconstrained. This allows arbitrary `is_memory`, which could be used to modify shard and clock information sent to the opcode specific chips, leading to incorrect behavior.

We fixed this by sending the `is_memory` value as well in the interaction, and checking `is_memory = 1` in memory chip and `is_memory = 0` in all other chips. 

## 6. [High] `next_pc` underconstrained on ECALL

In the opcode specific chip design, each chips handle a certain opcode, and they are responsible for constraining key values used for the CPU to keep track of the execution. One of these values is the `next_pc`, the next program counter. 

In the ECALL chip, the `next_pc` was constrained to be `0` when the instruction was determined to be a `HALT`. However, the constraint that the `pc` increased by `4`, i.e. `next_pc == pc + 4`, was missing in the case where the instruction wasn't a `HALT`. 

This was fixed by adding the following constraint.

```rust=
// If the syscall is not halt, then next_pc should be pc + 4.
// `next_pc` is constrained for the case where `is_halt` is false to be `pc + 4`
builder
    .when(local.is_real)
    .when(AB::Expr::one() - local.is_halt)
    .assert_eq(local.next_pc, local.pc + AB::Expr::from_canonical_u32(4));
```

## 7. [High] Global interactions with different `InteractionKind` could lead to the same digest

The global interaction system works as follows. Each chip that needs to send a global interaction, first sends an interaction with `InteractionKind::Global` locally. Then, the `GlobalChip` receives these local interactions with `InteractionKind::Global`, then converts these messages into digests and accumulates them, making the results global. 

However, while these information are sent locally with `InteractionKind::Global`, there are actually two different "actual" `InteractionKind`s - `Memory` and `Syscall`. 

The vulnerability was in that the actual underlying `InteractionKind` was not sent as a part of the local interaction between the chips and `GlobalChip`. Therefore, a "memory" interaction could be regarded as "syscall" interaction, and vice versa. 

We fixed this by adding the underlying `InteractionKind` to the interaction message, then incorporating this `InteractionKind` to the message when hashing it to the digest. 

```rust=
// GlobalChip
builder.receive(
    AirInteraction::new(
        vec![
            local.message[0].into(),
            local.message[1].into(),
            local.message[2].into(),
            local.message[3].into(),
            local.message[4].into(),
            local.message[5].into(),
            local.message[6].into(),
            local.is_send.into(),
            local.is_receive.into(),
            local.kind.into(), // `kind` is added
        ],
        local.is_real.into(),
        InteractionKind::Global,
    ),
    InteractionScope::Local,
);

// GlobalInteractionOperation
let m_trial = [
    // note that `kind` is incorporated with `values[0]`, a 16 bit range checked value
    values[0].clone() + AB::Expr::from_canonical_u32(1 << 16) * kind,
    values[1].clone(),
    values[2].clone(),
    values[3].clone(),
    values[4].clone(),
    values[5].clone(),
    values[6].clone(),
    offset.clone(),
    AB::Expr::zero(),
    AB::Expr::zero(),
    AB::Expr::zero(),
    AB::Expr::zero(),
    AB::Expr::zero(),
    AB::Expr::zero(),
    AB::Expr::zero(),
    AB::Expr::zero(),
];
```

## 8. [High] `vk`'s hash misses initial global cumulative sum

The `vk` now includes `initial_global_cumulative_sum`, which is the preprocessed set of global interactions in digest form. However, in hashing the `vk`, this addition was not incorporated, so the hash did not include this value. This allowed different set of `initial_global_cumulative_sum`, which could lead to incorrect memory state.

We fixed this by adding the `initial_global_cumulative_sum` to the hash.

```rust=
pub fn observe_into<Challenger>(&self, builder: &mut Builder<C>, challenger: &mut Challenger)
where
    Challenger: CanObserveVariable<C, Felt<C::F>> + CanObserveVariable<C, SC::DigestVariable>,
{
    // Observe the commitment.
    challenger.observe(builder, self.commitment);
    // Observe the pc_start.
    challenger.observe(builder, self.pc_start);
    // Observe the initial global cumulative sum.
    challenger.observe_slice(builder, self.initial_global_cumulative_sum.0.x.0);
    challenger.observe_slice(builder, self.initial_global_cumulative_sum.0.y.0);
    // Observe the padding.
    let zero: Felt<_> = builder.eval(C::F::zero());
    challenger.observe(builder, zero);
}

/// Hash the verifying key + prep domains into a single digest.
/// poseidon2( commit[0..8] || pc_start || initial_global_cumulative_sum || prep_domains[N].{log_n, .size, .shift, .g})
pub fn hash(&self, builder: &mut Builder<C>) -> SC::DigestVariable
where
    C::F: TwoAdicField,
    SC::DigestVariable: IntoIterator<Item = Felt<C::F>>,
{
    let prep_domains = self.chip_information.iter().map(|(_, domain, _)| domain);
    let num_inputs = DIGEST_SIZE + 1 + 14 + (4 * prep_domains.len());
    let mut inputs = Vec::with_capacity(num_inputs);
    inputs.extend(self.commitment);
    inputs.push(self.pc_start);
    inputs.extend(self.initial_global_cumulative_sum.0.x.0);
    inputs.extend(self.initial_global_cumulative_sum.0.y.0);
    for domain in prep_domains {
        inputs.push(builder.eval(C::F::from_canonical_usize(domain.log_n)));
        let size = 1 << domain.log_n;
        inputs.push(builder.eval(C::F::from_canonical_usize(size)));
        let g = C::F::two_adic_generator(domain.log_n);
        inputs.push(builder.eval(domain.shift));
        inputs.push(builder.eval(g));
    }

    SC::hash(builder, &inputs)
}
```