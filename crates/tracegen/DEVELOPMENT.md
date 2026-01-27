# Developing `sp1-gpu-tracegen`

This crate supports GPU trace generation via `CudaTracegenAir<F>` trait implementations.

## Adding GPU Tracegen for a Chip

1. **Modify `crates/sys/build.rs`**: Add cbindgen items for required types
2. **Write CUDA kernel**: `lib/tracegen/riscv/<chip>.cu` (or `recursion/`)
3. **Add to CMakeLists**: `lib/tracegen/CMakeLists.txt`
4. **Declare extern fn**: `crates/sys/src/tracegen.rs`
5. **Add kernel trait**: `crates/cuda/src/tracegen.rs`
6. **Implement trait**: `crates/tracegen/src/riscv/<chip>.rs`
7. **Write tests**: Compare GPU vs CPU traces

## Key Patterns

### GPU Event Flattening

Complex Rust types (Option, enums) don't translate to CUDA. Create simplified structs:

```rust
// In crates/sys/src/riscv_events.rs
#[repr(C)]
pub struct GpuMemoryAccess {
    pub prev_value: u64,
    pub prev_timestamp: u64,
    pub current_timestamp: u64,
}
```

### CUDA Kernel Structure

```cpp
template <class T>
__global__ void chip_generate_trace_kernel(
    T* trace, uintptr_t height,
    const Event* events, uintptr_t nb_events) {

    static const size_t COLUMNS = sizeof(Cols<T>) / sizeof(T);
    int i = blockIdx.x * blockDim.x + threadIdx.x;

    for (; i < height; i += blockDim.x * gridDim.x) {
        Cols<T> cols = {}; // zero init
        if (i < nb_events) { /* populate from events[i] */ }
        // Write column-major
        for (size_t k = 0; k < COLUMNS; ++k)
            trace[i + k * height] = reinterpret_cast<T*>(&cols)[k];
    }
}
```

### Rust Implementation

```rust
async fn generate_trace_device(&self, input: &Self::Record, ...) -> Result<DeviceMle<F>, CopyError> {
    // 1. Convert events to GPU format
    let gpu_events: Vec<GpuEvent> = input.events.iter().map(convert).collect();

    // 2. Copy to device
    let events_device = Buffer::try_with_capacity_in(gpu_events.len(), scope.clone())?;
    events_device.extend_from_host_slice(&gpu_events)?;

    // 3. Allocate trace
    let height = self.num_rows(input).unwrap();
    let mut trace = Tensor::<F, TaskScope>::zeros_in([NUM_COLS, height], scope.clone());

    // 4. Launch kernel
    scope.launch_kernel(kernel, grid_dim, BLOCK_DIM, &args!(...), 0)?;

    Ok(DeviceMle::new(Mle::new(trace)))
}
```

## Common Issues

| Issue | Solution |
|-------|----------|
| `WORD_SIZE` undefined in C++ | Add `.with_header("#define WORD_SIZE 4")` to cbindgen |
| `from_canonical_u64` missing | Use `from_canonical_u32(static_cast<uint32_t>(val))` |
| Option types in cbindgen | Flatten to GPU-compatible struct without Options |

## Timestamp Handling

`RegisterAccessTimestamp` columns:
- `prev_low`: If same epoch (`prev_high == current_high`), use prev_low; else 0
- `diff_low_limb`: `(current_low - old_timestamp - 1) & 0xFFFF`

## Word Conversion

```cpp
template <class T>
__device__ void u64_to_word(uint64_t val, Word<T>& word) {
    word._0[0] = T::from_canonical_u32(val & 0xFFFF);
    word._0[1] = T::from_canonical_u32((val >> 16) & 0xFFFF);
    word._0[2] = T::from_canonical_u32((val >> 32) & 0xFFFF);
    word._0[3] = T::from_canonical_u32((val >> 48) & 0xFFFF);
}
```
