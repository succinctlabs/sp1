# SP1 Audit Report - Recursion VM

Audited by rkm0959. Report Published by KALOS.

# Executive Summary

## Codebase Submitted for the Audit

https://github.com/succinctlabs/sp1

For circuits, we audit the AIR constraints that are inside the eval() functions.

core/src

- alu - add_sub, bitwise, divrem, lt, mul, sll, sr
- bytes - air.rs, columns.rs
- cpu: air subfolder, columns subfolder
- memory: global.rs
- operations: all AIRs in folder in scope
- program: all AIRs in folder in scope
- syscall: all AIRs in precompiles/{edwards, keccak256, sha256, weierstrass, uint256}
- air: builder.rs, word.rs, polynomial.rs, extension.rs, subbuilder.rs
- lookup: builder.rs
- utils: ec subfolder, buffer.rs
- stark: verifier.rs, folder.rs, machine.rs, permutation.rs, chip.rs, prover.rs, air.rs
- machine derive macro: https://github.com/succinctlabs/sp1/blob/main/derive/src/lib.rs

recursion/core/src

- cpu: all AIRs in folder in scope
- memory: all AIRs in folder in scope
- program: all AIRs in folder in scope
- poseidon2: all AIRs in scope
- poseidon2_wide: all AIRs in scope
- fri_fold all AIRs in scope
- multi: all AIRs in scope
- range check: all AIRs in scope
- air folder
- stark folder

zkvm

- zkvm/precompiles/src/secp256k1.rs
- zkvm/precompiles/src/io.rs
- zkvm/entrypoint/src/syscalls/ed25519.rs
- zkvm/entrypoint/src/syscalls/secp2561k1.rs
- zkvm/entrypoint/src/syscalls/sha_compress.rs
- zkvm/entrypoint/src/syscalls/io.rs

**This audit report deals with the `recursion/core/src` part of the audit.** The final commit hash is **22f51bb8e1f343661c1a54140401a7cb3e365928** on the `dev` branch.

## Audit Timeline

- 2024/04/15 - 2024/05/31 (6 engineer weeks)

# Findings

## 1. [Critical] `poseidon2/external` is allows memory write at arbitrary location, and hash value is also underconstrained

`Poseidon2Chip` evaluates the Poseidon2 hash in-circuit, with SBOX $x^7$, 8 external rounds and 13 internal rounds. There are several underconstrains in the codebase which lead to a break of soundness of the hash function evaluation and the memory state in general.

First, the `local.rounds` are underconstrained. Currently the only constraint is that they are boolean and at most one of them can be true. These should be handled in a similar way to Plonky3's keccak round flags, keeping track of the 24-cycle. Avoid vuln #11 here.

The computation of `is_external_layer` is incorrect. The range of the iteration has to be `[2, rounds_p_beginning)` and `[rounds_p_end, 2 + rounds_p + rounds_f)`.

```rust=
    // First half of the external rounds.
    let mut is_external_layer = (2..rounds_p_beginning)
        .map(|i| local.rounds[i].into())
        .sum::<AB::Expr>();

    // Second half of the external rounds.
    is_external_layer += (rounds_p_end..rounds_p + rounds_f)
        .map(|i| local.rounds[i].into())
        .sum::<AB::Expr>();
```

The memory read from `left_input` and `right_input` doesn't constrain that the memory value doesn't change. This allows the memory to be overwritten with arbitrary value.

The syscall is received at the row where `local.rounds[0]` is true, so the ground source of truth for `dst_input` should be at this row. However, in `eval_mem`, the actually used address to write the hash value is the `dst_input` value at the row where `is_memory_write = local.rounds[23]` is true. As there is no check that `dst_input` is equal over the 24-cycle, one can write the hash value at an arbitrary location regardless of the actual syscall.

We recommend checking `clk, dst_input, left_input, right_input` to be equal across the 24-cycle. In general, a good point to look out for is to have memory accesses done only when a syscall is actually read, and have the cycle flags constrained regardless of `is_real`.

### Fix Notes

This vulnerability is fixed in [PR #747](https://github.com/succinctlabs/sp1/pull/747), [this commit of PR #821](https://github.com/succinctlabs/sp1/pull/821/commits/0f0a010d11c8473a03169146628990347f694856), [this commit of PR #821](https://github.com/succinctlabs/sp1/pull/821/commits/0ef836cd9c5efcd1600da833ce79f70a54d521b6), and [this commit of PR #821](https://github.com/succinctlabs/sp1/pull/821/commits/38c93b2a5cee3748b063249b10dda32a45288043#diff-c35de0a3834bcf7574826b1c21c18c50db81122f0682d41e1dc8647bb2c3e145). We summarize the fixes below, going over each vulnerability.

The computation of `is_external_layer` is fixed. Also, the row 24-cycle is constrained regardless of `is_real`, starting with `rounds[0]` being true and shifting by one per each row. Also, `clk, dst_input, left_input, right_input` are held equal over the 24-cycle.

The value of `is_real` is held equal over the 24-cycle. Also, with vulnerability #19 fixed, the check in `recursion_eval_memory_access_single` is sufficient to constrain that `is_real` is boolean. When `is_real` is zero, both `do_memory` and `do_receive` is zero, leading to no table receives and memory accesses being done. On `is_real = 1`, the circuit constrains.

Also, on `is_memory_read` (i.e. `rounds[0]`) the memory access is constrained to be read-only.

## 2. [Low] `recursion`'s `eval_memory_access` should constrain `is_real` to be boolean as done in `core`

While `core`'s `eval_memory_access` checks the multiplicity to be boolean, this check is not present in `recursion`'s `recursion_eval_memory_access`. For consistency, unless there is a specific reason, we recommend adding this boolean check to `recursion`.

```rust=
    // core
     fn eval_memory_access<E: Into<Self::Expr> + Clone>(
        &mut self,
        shard: impl Into<Self::Expr>,
        clk: impl Into<Self::Expr>,
        addr: impl Into<Self::Expr>,
        memory_access: &impl MemoryCols<E>,
        do_check: impl Into<Self::Expr>,
    ) {
        let do_check: Self::Expr = do_check.into();
        let shard: Self::Expr = shard.into();
        let clk: Self::Expr = clk.into();
        let mem_access = memory_access.access();

        self.assert_bool(do_check.clone());

        // Verify that the current memory access time is greater than the previous's.
        self.eval_memory_access_timestamp(mem_access, do_check.clone(), shard.clone(), clk.clone());

        // Add to the memory argument.
        let addr = addr.into();
        let prev_shard = mem_access.prev_shard.clone().into();
        let prev_clk = mem_access.prev_clk.clone().into();
        let prev_values = once(prev_shard)
            .chain(once(prev_clk))
            .chain(once(addr.clone()))
            .chain(memory_access.prev_value().clone().map(Into::into))
            .collect();
        let current_values = once(shard)
            .chain(once(clk))
            .chain(once(addr.clone()))
            .chain(memory_access.value().clone().map(Into::into))
            .collect();

        // The previous values get sent with multiplicity = 1, for "read".
        self.send(AirInteraction::new(
            prev_values,
            do_check.clone(),
            InteractionKind::Memory,
        ));

        // The current values get "received", i.e. multiplicity = -1
        self.receive(AirInteraction::new(
            current_values,
            do_check.clone(),
            InteractionKind::Memory,
        ));
    }

    // recursion
    fn recursion_eval_memory_access<E: Into<Self::Expr> + Clone>(
        &mut self,
        timestamp: impl Into<Self::Expr>,
        addr: impl Into<Self::Expr>,
        memory_access: &impl MemoryCols<E, Block<E>>,
        is_real: impl Into<Self::Expr>,
    ) {
        let is_real: Self::Expr = is_real.into();
        let timestamp: Self::Expr = timestamp.into();
        let mem_access = memory_access.access();

        self.eval_memory_access_timestamp(timestamp.clone(), mem_access, is_real.clone());

        let addr = addr.into();
        let prev_timestamp = mem_access.prev_timestamp.clone().into();
        let prev_values = once(prev_timestamp)
            .chain(once(addr.clone()))
            .chain(memory_access.prev_value().clone().map(Into::into))
            .collect();
        let current_values = once(timestamp)
            .chain(once(addr.clone()))
            .chain(memory_access.value().clone().map(Into::into))
            .collect();

        self.receive(AirInteraction::new(
            prev_values,
            is_real.clone(),
            InteractionKind::Memory,
        ));
        self.send(AirInteraction::new(
            current_values,
            is_real,
            InteractionKind::Memory,
        ));
    }
```

### Fix Notes

This is fixed as recommended in [PR #789](https://github.com/succinctlabs/sp1/pull/789/files#diff-f8e74178aadfae0c133554004485bce0a364dfe483c2c538db5d3f18fe9ee9f4).

## 3. [High] `MemoryGlobalChip` allows multiple initializations for one memory address, breaking the memory argument

The `MemoryGlobalChip` allows for memory to be initialized and finalized.
Here, there are no checks that the memory addresses of each row are different.

```rust=
    let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryInitCols<AB::Var> = (*local).borrow();

        // Verify that is_initialize and is_finalize are bool and that at most one is true.
        builder.assert_bool(local.is_initialize);
        builder.assert_bool(local.is_finalize);
        builder.assert_bool(local.is_initialize + local.is_finalize);

        builder.send(AirInteraction::new(
            vec![
                local.timestamp.into(),
                local.addr.into(),
                local.value[0].into(),
                local.value[1].into(),
                local.value[2].into(),
                local.value[3].into(),
            ],
            local.is_initialize.into(),
            InteractionKind::Memory,
        ));
        builder.receive(AirInteraction::new(
            vec![
                local.timestamp.into(),
                local.addr.into(),
                local.value[0].into(),
                local.value[1].into(),
                local.value[2].into(),
                local.value[3].into(),
            ],
            local.is_finalize.into(),
            InteractionKind::Memory,
        ));
    }
```

This allows unexpected behavior - allowing unexpected values of `prev_value` to be read.

We show this with an example. Write memory for a fixed address as `(value, timestamp)`.

- initialize `(5, 0)` and `(7, 0)`
- at clock 1, read previous value 5 from clock 0 and go `(5, 0) -> (8, 1)`
- at clock 2, read previous value 7 from clock 0 and go `(7, 0) -> (9, 2)`
- at clock 3, read previous value 8 from clock 1 and go `(8, 1) -> (10, 3)`
- at clock 4, read previous value 9 from clock 2 and go `(9, 2) -> (11, 4)`
- finalize `(10, 3)` and `(11, 4)`

This allows us to read incorrect previous values - at clock 2, the intuitive previous value is 8, but 7 was read. Note that this attack works with at most one memory access per clock.

The addresses of each row should be enforced to be different - this can be done by constraining that the address increases over the rows via bitwise decomposition. Note that adding this check in the initialize stage only is sufficient to resolve this issue.

Also, the verifier needs to enforce that only one table of `MemoryGlobalChip` exists, so that double initializtion/finalization cannot happen using multiple tables.

As similar vulnerability was found in the Core VM, and similar defenses can be applied here.

### Fix Notes

This was fixed in [this pull request](https://github.com/succinctlabs/sp1/pull/934/files) as recommended.

## 4. [Critical] Recursion VM's cpu doesn't constrain the memory being loaded on to register in LOAD opcodes

For the load opcode, the cpu should load the value from the memory and put it onto the register corresponding to `local.a`. However, the only check for the load opcode is that the memory value doesn't change after the opcode. This means that there are no checks that the new value in the register is the value from the memory itself, allowing arbitrary values.

```rust=
    // Constraints on the memory column depending on load or store.
    // We read from memory when it is a load.
    builder.when(local.selectors.is_load).assert_block_eq(
        *memory_cols.memory.prev_value(),
        *memory_cols.memory.value(),
    );
    // When there is a store, we ensure that we are writing the value of the a operand to the memory.
    builder
        .when(local.selectors.is_store)
        .assert_block_eq(*local.a.value(), *memory_cols.memory.value());
```

We recommend adding the check that `a`'s value is the memory's value also for the case where `is_load` is true. Changing the selector for the second check in the code above suffice.

### Fix Notes

The recommended fix was added in [pull request #789](https://github.com/succinctlabs/sp1/pull/789/files#diff-bb73fc6e2645d5d723046d8384e5f7eb411486dec93a6b73ed9233981d42dd8a).

## 5. [High] Recursion VM's `op_a` register value and `fp` value are underconstrained for jump opcodes

The following is the code for the jump instructions.

```rust=
    pub fn eval_jump<AB>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        next_pc: &mut AB::Expr,
    ) where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        // Verify the next row's fp.
        builder
            .when_first_row()
            .assert_eq(local.fp, F::from_canonical_usize(STACK_SIZE));
        let not_jump_instruction = AB::Expr::one() - self.is_jump_instruction::<AB>(local);
        let expected_next_fp = local.selectors.is_jal * (local.fp + local.c.value()[0])
            + local.selectors.is_jalr * local.a.value()[0]
            + not_jump_instruction * local.fp;
        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(next.fp, expected_next_fp);

        // Add to the `next_pc` expression.
        *next_pc += local.selectors.is_jal * (local.pc + local.b.value()[0]);
        *next_pc += local.selectors.is_jalr * local.b.value()[0];
    }
```

Compare this with the runtime behavior of recursion VM.

```rust=
    Opcode::JAL => {
        self.nb_branch_ops += 1;
        let (a_ptr, b_val, c_offset) = self.alu_rr(&instruction);
        let a_val = Block::from(self.pc);
        self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
        next_pc = self.pc + b_val[0];
        self.fp += c_offset[0];
        (a, b, c) = (a_val, b_val, c_offset);
    }
    Opcode::JALR => {
        self.nb_branch_ops += 1;
        let (a_ptr, b_val, c_val) = self.alu_rr(&instruction);
        let a_val = Block::from(self.pc + F::one());
        self.mw_cpu(a_ptr, a_val, MemoryAccessPosition::A);
        next_pc = b_val[0];
        self.fp = c_val[0];
        (a, b, c) = (a_val, b_val, c_val);
    }
```

We see the following differences which should be fixed accordingly.

- `a` value should be set with the relevant value with the `pc`
- JALR's expected next `fp` value is `c_val[0]`, not `a_val[0]`

### Fix Notes

These two differences were fixed in [pull request #789](https://github.com/succinctlabs/sp1/pull/789/files#diff-3283eead4e1efe6677ac4a7eecfdbfc734892d13fb4a0f50306e469e760763b8).

## 6. [Medium] `BNEINC` opcode of the recursion VM underconstrains the newly written value to the register `a`

```rust=
    // If the instruction is a BNEINC, verify that the a value is incremented by one.
    builder
        .when(local.is_real)
        .when(local.selectors.is_bneinc)
        .assert_eq(local.a.value()[0], local.a.prev_value()[0] + one.clone());
```

The `BNEINC` increments the value in the register `a`, and branches depending on whether or not the new value in `a` matches `op_b_value`. However, note that only the `a.value()[0]` part is constrained in the code above. The check that `a.value()[1..4]` is equal to `a.prev_value()[1..4]` is a missing constraint that should be added to the circuit.

We also note that the comment regarding `BNEINC` is incorrect - indeed, the opcode uses the _new_ value in the register `a`, not the _previous_ value as stated in the comment below.

```rust=
    // Convert operand values from Block<Var> to BinomialExtension<Expr>.  Note that it gets the
    // previous value of the `a` and `b` operands, since BNENIC will modify `a`.
    let a_ext: BinomialExtension<AB::Expr> =
        BinomialExtensionUtils::from_block(local.a.value().map(|x| x.into()));
    let b_ext: BinomialExtension<AB::Expr> =
        BinomialExtensionUtils::from_block(local.b.value().map(|x| x.into()));
```

We recommend adding the constraint as explained above, and fixing the comment as well.

### Fix Notes

This was fixed in [pull request #789](https://github.com/succinctlabs/sp1/pull/789/files#diff-061f406c5a5678477225937d3b2206499c0c76eaafd5ffa11446a2e715e53130) as recommended.

## 7. [Critical] All selectors being zero and `imm_b = imm_c = 1` should be constrained when `is_real` is zero in `CpuChip`

Note that the preprocessed program information is taken from the `ProgramChip` with multiplicity `is_real` at the `CpuChip`. This means that on `is_real = 0`, the program information at that row can be arbitrary and not preprocessed.

```rust=
    // Constrain the program.
    builder.send_program(local.pc, local.instruction, local.selectors, local.is_real);
```

Therefore, in this case, one should avoid any syscalls or lookups being sent over as an interaction. This can be easily done by enforcing all selectors are zero, and `imm_b` and `imm_c` are equal to one. This will set all memory accesses and lookups to be done with multiplicity zero when `is_real = 0`, as desired. Note that without this additional constraint, we can use the rows of `is_real = 0` to do arbitrary memory accesses on arbitrary clock.

### Fix Notes

This was added [here](https://github.com/succinctlabs/sp1/pull/937/files#diff-6e5f27c21716211dcefc022f5bdd52bf1b41eb4c8a8129dbb01086709838db00R41-R58). Note that `selector`'s `is_noop` is turned on to be true, which is correct.

## 8. [Informational] ALU division allows `0/0` to be arbitrary

```rust=
    // For div operation, we assert that b == a * c (equivalent to a == b / c).
    builder
        .when(local.selectors.is_div)
        .assert_ext_eq(b_ext, a_ext * c_ext);
```

To check `a == b / c`, the circuit simply checks `b == a * c`. This works in usual cases, but this allows `a` to be arbitrary when `b = c = 0`. While this by itself is not a serious vulnerability, all usecases of the Recursion VM should be aware of this behavior.

### Fix Notes

The authors made an acknowledgement by adding a comment [here](https://github.com/succinctlabs/sp1/pull/937/files#diff-0f581efab1754ec2057245490521f6cc8a397f43a1fce4c7d8eab1a797fe57ce).

## 9. [Medium] Some selectors are not considered in `is_op_a_read_only_instruction`

Some instructions only use the register `op_a` as read-only, while some instructions use it to write on the register. The read-only behavior is checked as follows.

```rust=
    // If the instruction only reads from operand A, then verify that previous and current values are equal.
    let is_op_a_read_only = self.is_op_a_read_only_instruction::<AB>(local);
    builder
        .when(is_op_a_read_only)
        .assert_block_eq(*local.a.prev_value(), *local.a.value());
```

We quickly go over each instruction.

- all ALU clearly write on `op_a`, so they are not read-only
- for branch, `BEQ` and `BNE` are read-only, but `BNEINC` increment `op_a`
- the heap expansion is done alongside the ADD instruction, so not read-only
- for jump, the instructions write `pc` related values to `op_a`
- for memory, `LOAD` writes a memory value to a register, but `STORE` writes a register value to memory, so `STORE` is read-only while `LOAD` is not read-only
- the syscalls use `op_a` as read-only
- `COMMIT`, `TRAP`, `HALT` should be read-only

Therefore, the `op_a` read-only instructions are `BEQ`, `BNE`, `STORE`, all the syscalls, `COMMIT`, `TRAP`, `HALT`. However, it seems that the newly added instructions are missing.

```rust=
    /// Expr to check for instructions that only read from operand `a`.
    pub fn is_op_a_read_only_instruction<AB>(&self, local: &CpuCols<AB::Var>) -> AB::Expr
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        local.selectors.is_beq
            + local.selectors.is_bne
            + local.selectors.is_fri_fold
            + local.selectors.is_poseidon
            + local.selectors.is_store
            + local.selectors.is_noop
            + local.selectors.is_ext_to_felt
    }
```

In general, we recommend reviewing newly added instructions for read-only-ness.

### Fix Notes

New instructions were added in `is_op_a_read_only_instruction` [here](https://github.com/succinctlabs/sp1/pull/937/files#diff-6e5f27c21716211dcefc022f5bdd52bf1b41eb4c8a8129dbb01086709838db00R231-R234).

## 10. [High] `clk` and `pc` are not initialized in `CpuChip`

The first row of `clk` and `pc` are not constrained in the Recursion VM `CpuChip`. This is different with, for example, Recursion VM's `fp`, which is constrained in `air/jump.rs`.

```rust=
 // Verify the next row's fp.
    builder
        .when_first_row()
        .assert_eq(local.fp, F::from_canonical_usize(STACK_SIZE));
```

Also, note that `clk` and `pc` are constrained in the Core VM by

- for `clk`, it's explicit that the first row has `clk == 0`
- for `pc`, it's constrained that the first row has public input's `pc` as the program counter

We recommend adding appropriate constraints for the first row of `clk` and `pc`.

### Fix Notes

The initial `clk` and `pc` are now both constrained to be zero [here](https://github.com/succinctlabs/sp1/pull/937/files#diff-6e5f27c21716211dcefc022f5bdd52bf1b41eb4c8a8129dbb01086709838db00R61-R62).

## 11. [High] MultiBuilder's handling of the first and last rows of the stacked table is incorrect, leading to potential soundness break

The `MultiChip` aims to "stack" a `FriFoldChip` and `Poseidon2Chip` within a same table. To do so, it has two boolean columns `is_fri_fold` and `is_poseidon2`, denoting whether or not the row belongs to a `FriFold` chunk or a `Poseidon2` chunk. After that, it constrains that the chunks go, in order, a `FriFold` chunk, then a `Poseidon2` chunk, and finally a chunk which is just a padding. The `FriFoldChip`'s constraint system is evoked with a `MultiBuilder`, which uses `is_fri_fold` as whether or not the current row is an "actual row" to be constrained. Also, using the memory accesses and syscall reads are modified to be only turned on when `is_fri_fold` is turned on. A similar strategy is used for the `Poseidon2Chip`.

```rust=
    let mut sub_builder =
            MultiBuilder::new(builder, local.is_fri_fold.into(), next.is_fri_fold.into());
    let fri_columns_local = local.fri_fold();
    sub_builder.assert_eq(
        local.is_fri_fold * FriFoldChip::<3>::do_memory_access::<AB::Var>(fri_columns_local),
        local.fri_fold_memory_access,
    );
    sub_builder.assert_eq(
        local.is_fri_fold * FriFoldChip::<3>::do_receive_table::<AB::Var>(fri_columns_local),
        local.fri_fold_receive_table,
    );
    let fri_fold_chip = FriFoldChip::<3>::default();
    fri_fold_chip.eval_fri_fold(
        &mut sub_builder,
        local.fri_fold(),
        next.fri_fold(),
        local.fri_fold_receive_table,
        local.fri_fold_memory_access,
    );

    // similar for Poseidon2...
```

The `MultiBuilder` works as follows. The builder receives a `local_condition`, whether or not the current row is "real", and a `next_condition`, whether or not the next row is "real". Then,

- `is_first/last_row`: uses the same `is_first/last_row` as the generic builder, also `local_condition` must be turned on for the constraints to be actually placed
- `is_transition_window`: uses the same `is_transition_window` as the generic builder, also `local_condition` and `next_condition` must be turned on for the constraints
- `assert_zero`: requires `local_condition` to be true for the constraints to be placed

Here, while most constraints are fine, the issue arises in the `is_first/last_row` cases. For example, consider the first row of the `Poseidon2Chip`. Here, the `Poseidon2Chip` may have (indeed, after fix of vulnerability #1, it does) constraints on the first row for initialization. However, when constrained through the `MultiBuilder` in the `MultiChip`, this constraint may not be placed. Indeed, if there is a nonempty `FriFoldChip` stack on top, the first row conditions will not be placed as `is_poseidon2` will be zero in the first row.

This is different from the expected behavior, which would be that the `is_first_row` constraints for the `Poseidon2Chip` apply for the first row of the `Poseidon2Chip` stack. A similar idea also applies for the `is_last_row` of the `FriFoldChip` stack - such constraints will require the row being the last row of the entire table for it to be placed.

We recommend either

- removing the `MultiChip` architecture, simply using two tables separately
- adding more columns in `MultiChip` to directly constrain correct stacking
- having `is_first_row`, `is_last_row` to be explicitly sent over to the `MultiBuilder`

In the third case, we recommend the following values to be sent over.

`FriFoldChip`

- `is_first_row`: `is_first_row * is_fri_fold`
- `is_last_row`
  - Case 1: we are in a transition window, next row isn't `FriFold`
    - `is_fri_fold * (1 - next.is_fri_fold)`
  - Case 2: we are in the last row and this is `FriFold`
    - `is_fri_fold`

`Poseidon2Chip`

- `is_first_row`: this one is very tricky as you need access to previous row in some way
  - make a new column for this, call it `start`. constrain it as follows
  - on first row, `start == is_poseidon2`
  - on transition window, `next.start == is_fri_fold * next.is_poseidon2`
- `is_last_row`: similar as `is_last_row` of `FriFoldChip`

### Fix Notes

The fixes are implemented in [Pull Request #997](https://github.com/succinctlabs/sp1/pull/997) as recommended.

## 12. [High] `FriFoldChip` allows incorrect behavior as syscall reads and memory accesses aren't connected properly

The `FriFoldChip` handles syscalls that require a variable number of rows. To handle this, two columns are used, which we will denote `is_real` and `is_last_iteration`. We note that on the case where vulnerability #11 is fixed, then on the case where we are on the `FriFoldChip` stack, `memory_access` is equal to `is_real` and `receive_table` is equal to `is_last_iteration`. Also, in the case where we are not on the `FriFoldChip` stack, both `memory_access` and `receive_table` are forced to be zero, so no syscalls or memory accesses will be done, as we desire. Here, we assume vulnerability #11 to be fixed.

```rust=
    pub const fn do_receive_table<T: Copy>(local: &FriFoldCols<T>) -> T {
            local.is_last_iteration
        }

        pub const fn do_memory_access<T: Copy>(local: &FriFoldCols<T>) -> T {
            local.is_real
        }
```

Also, there is a column `m`, `clk`, `input_ptr` which describes the behavior or the current iteration of the syscall handling. To be more exact, the `m` value starts at zero for each chunk, increments one by each row, and resets to zero on the start of the new chunk handling a new syscall. The `clk` simply increments by one over each chunk, but can be completely different over different chunks. The `input_ptr` must be held equal over a single chunk, as it is one of the syscall parameters received from the `CpuChip`. This is implemented as follows.

```rust=
    builder.assert_bool(local.is_last_iteration);
    // Ensure that all first iteration rows has a m value of 0.
    builder.when_first_row().assert_zero(local.m);
    builder
        .when(local.is_last_iteration)
        .when_transition()
        .when(next.is_real)
        .assert_zero(next.m);

    // Ensure that all rows for a FRI FOLD invocation have the same input_ptr, clk, and sequential m values.
    builder
        .when_transition()
        .when_not(local.is_last_iteration)
        .when(next.is_real)
        .assert_eq(next.m, local.m + AB::Expr::one());
    builder
        .when_transition()
        .when_not(local.is_last_iteration)
        .when(next.is_real)
        .assert_eq(local.input_ptr, next.input_ptr);
    builder
        .when_transition()
        .when_not(local.is_last_iteration)
        .when(next.is_real)
        .assert_eq(local.clk + AB::Expr::one(), next.clk);
```

We outline various attack ideas below, and give concrete list of constraints for defense.

First, there's the case where no syscalls are actually read but memory accesses are being done. One can set `is_last_iteration` zero so that no syscalls are read, then put `is_real` value and other column values in an incorrect manner. Here, one can also note that there's no real constraints put on `is_real` - so this value can behave arbitrarily between zero and one.

This can also be viewed differently - note that this can be also seen as the fact that there's no check that an on-going chunk with all `is_real = 1` will be finalized at some point.

Also, there's the case where `is_last_iteration` is indeed `1`, but `is_real` is just zero - so no memory accesses are actually done. We again note that `is_real` is not being constrained.

To fix this, the goal should be to have

- `is_last_iteration == 1` should have all relevant rows have `is_real == 1`
- no rows within a chunk with `is_last_iteration == 1` should have `is_real == 1`

To do this, we recommend adding the following constraints.

- #1: `local.is_last_iteration`, `local.is_real` are both boolean
- #2: `local.is_last_iteration == 0` implies `local.is_real == next.is_real`
- #3: `local.is_last_iteration == 1` implies `local.is_real == 1`
- #4: `local.is_real == 0` implies `next.is_real == 0`
- #5: on the final row, we have either `local.is_real == 0` or `is_last_iteration == 1`

We note that #1 is already done (note that `is_real` is boolean due to issue #2's fix).

Basically, the idea is to have all `is_real = 1` rows at the top as usual, done via constraint #4.
First, we have to constrain `is_last_iteration` to be zero in the padding rows at the bottom. This is done with constraint #3. Now, all it remains is to check that on the final non-padding row, `is_last_iteration` must be true. If this final non-padding row is not the last row, constraint #2 is sufficient to constrain this fact. If the final non-padding row is simply the last row, then constraint #5 is sufficient to constrain this fact. Completeness is similar.

### Fix Notes

This was fixed in [pull request #946](https://github.com/succinctlabs/sp1/pull/946) as recommended.
