# Guide to Adding Precompiles in SP1

Precompiles are specialized chips that allow you to extend the functionality of vanilla SP1 to execute custom logic more efficiently. 

## Create the Chip
Create a new rust Rust file for your chip in the `core/src/syscall/precompiles` directory. 

### Define the Chip Struct:
Define the core structure of your chip. This struct will represent the chip and its associated logic.

```rust
#[derive(Default)]
pub struct CustomOpChip;

impl CustomOpChip {
    pub const fn new() -> Self {
        Self
    }
}
```

### Define the Chip's Data Structure
Define the necessary data structures that your chip will use. This might include columns for memory operations, input values, and output results. For instance, in the Uint256MulChip, we define the columns as follows:

```rust
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct CustomOpCols<T> {
    pub shard: T,
    pub clk: T,
    pub x_ptr: T,
    pub y_ptr: T,
    pub x_memory: GenericArray<MemoryWriteCols<T>, WordsFieldElement>,
    pub y_memory: GenericArray<MemoryReadCols<T>, WordsFieldElement>,
    pub output: FieldOpCols<T, U256Field>,
}
```
Adjust these fields according to your chip.

### Implement the Chip Logic
The Syscall trait is where the core execution logic of your chip will reside. This involves defining how the chip interacts with the SP1 runtime during execution time.

```rust
impl Syscall for Uint256MulChip {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn execute(&self, rt: &mut SyscallContext, syscall: SyscallCode, arg1: u32, arg2: u32) -> Option<u32> {
        // Your execution logic here
        // Parse input pointers, perform the multiplication, and write the result
    }
}
```

### Implement the `MachineAir` Trait
The `MachineAir` trait integrates your chip with SP1’s Algebraic Intermediate Representation (AIR). This involves generating and evaluating traces that represent the chip's operations.

```rust
impl<F: PrimeField32> MachineAir<F> for CustomOpChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "CustomOp".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Implement trace generation logic
    }

    fn included(&self, shard: &Self::Record) -> bool {
        // Implement logic to determine if this chip should be included
        !shard.custom_op_events.is_empty()
    }
}
```
You will also have to update `core/executor/src/events/precompiles/mod.rs` accordingly to register the new precompile op.
#### Add a new field for your chip's events
In the `PrecompileEvent` enum, add a new variant for you precompile op.

```rust
#[derive(Clone, Debug, Serialize, Deserialize, EnumIter)]
/// Precompile event.  There should be one variant for every precompile syscall.
pub enum PrecompileEvent {
    // Other existing variants...

    /// A variant for your custom operation.
    pub CustomOp(CustomOpEvent),
}
```

#### Update the `get_local_mem_events` method
In the `get_local_mem_events` method, add your variant to the match statement to add an iterator of the op's local
memory events (if it has local memory events).

```rust
fn get_local_mem_events(&self) -> impl IntoIterator<Item = &MemoryLocalEvent> {
    let mut iterators = Vec::new();

    for event in self.iter() {
        match event {
            // Other existing variants...

            PrecompileEvent::CustomOp(e) => {
                iterators.push(e.local_mem_access.iter());
            }
        }
    }

    iterators.into_iter().flatten()
}
```

### Implement the `Air` and `BaseAir` traits
To fully integrate your chip with the SP1 AIR framework, implement the `Air` and `BaseAir` traits. These traits define how your chip’s operations are evaluated within the AIR system.

```rust
impl<F> BaseAir<F> for CustomOpChip {
    fn width(&self) -> usize {
        // Define the number of columns your chip requires
        NUM_COLS
    }
}

impl<AB> Air<AB> for CustomOpChip
where
    AB: SP1AirBuilder,
    Limbs<AB::Var, <U256Field as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        // Implement the evaluation logic for your chip
    }
}
```
> **Important Note**: Make sure that the `eval` method properly accounts for all aspects of your chip’s behavior, as discrepancies between `eval` and the actual execution logic can lead to proof failures or incorrect verification results even when `execute` is correct.

## Register a New Syscall
### Add a New Enum Variant
In the `SyscallCode` enum, define a new variant for your custom syscall. The variant should be given a unique value.

```rust
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, EnumIter, Ord, PartialOrd, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum SyscallCode {
    // Existing syscalls...

    /// Executes the `CUSTOM_OP` precompile.
    CUSTOM_OP = 0x00_01_01_2C,  // Replace with the appropriate unique value
}
```

### Update the `from_u32` method
Ensure the `from_u32` method can map the unique value to the new `SyscallCode` variant.

```rust
impl SyscallCode {
    pub fn from_u32(value: u32) -> Self {
        match value {
            // Existing syscalls...

            0x00_01_01_2C => SyscallCode::CUSTOM_OP,
            _ => panic!("invalid syscall number: {}", value),
        }
    }

    // Other methods...
}
```

### Insert the New Syscall in the `default_syscall_map` 
In the `default_syscall_map` function, register your new syscall by inserting it into the `syscall_map` with its corresponding chip.

```rust
pub fn default_syscall_map() -> HashMap<SyscallCode, Arc<dyn Syscall>> {

    // Other syscall maps...
    syscall_map.insert(
        SyscallCode::CUSTOM_OP,
        Arch::new(CustomOpChip::new())
    )
}
```

## Write Unit Tests for the New Precompile
### Create a New SP1 Test Package
Create a new SP1 crate for your custom precompile test package inside the directory `sp1/tests`. An example `Cargo.toml` for this may look like
```toml
[workspace]
[package]
name = "custom-precompile-test"
version = "1.0.0"
edition = "2021"
publish = false

[dependencies]
sp1-zkvm = { path = "../../zkvm/entrypoint" }
sp1-derive = { path = "../../derive" }
num-bigint = "0.4.6"
rand = "0.8.5"
```
Then implement the tests and run `cargo prove build` to generate an ELF file. 

### Include the ELF File in `program.rs`
In your main SP1 project, include the generated ELF file by updating `program.rs`. 
```rust
pub const CUSTOM_PRECOMPILE_ELF: &[u8] =
    include_bytes!("path/to/generated/elf/file");
// Other ELF files...
```

### Write Tests for Your Custom Precompile
Add tests that use this ELF file in your local SP1 project.
```rust
// /path/to/your/precompile/mod.rs

mod air;

pub use air::*;

#[cfg(test)]
mod tests {
    use crate::{
        io::SP1Stdin,
        runtime::Program,
        utils::{
            self,
            run_test_io,
            tests::CUSTOM_PRECOMPILE_ELF,
        },
    };

    #[test]
    fn test_custom_precompile() {
        utils::setup_logger();
        let program = Program::from(CUSTOM_PRECOMPILE_ELF);
        run_test_io::<CpuProver<_, _>>(program, SP1Stdin::new()).unwrap();
    }

    // Add additional tests as needed
}
```
### Run Your Tests
Finally, run your test to verify that your custom precompile works as expected:
```bash
cargo test --release
```
